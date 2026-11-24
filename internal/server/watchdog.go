// Package server: watchdog.go — 任务看门狗（零策略保活）。
//
// 借鉴 sapper-v2 守护层的三条纪律：守护层不做决策、只认铁信号；处置有界
// （重启循环救不了必死的任务）；到点收卷由非 LLM 代码持有。
//
// 「卡壳不等于死机」：长耗时工具、审批等待、LLM 长思考从外部看都是静默，
// 所以这里刻意不检测「多久没出新发现」——那类情况交给 LLM 客户端与工具
// 超时兜底。只认三个铁信号：
//
//	R1 节点失联：持有任务的节点心跳停止 ≥ nodeOfflineFor
//	R2 任务失联：节点在线，但该任务的执行心跳（intel 轮询）先有后无 ≥ taskSilentFor
//	   ——节点被 systemd 5 秒拉起、界面显示「在线」，任务却早已没人跑
//	R3 到点收卷：任务运行超过上限 → 代停（节点 5s 内经 intel 轮询感知并中断）
//
// R1/R2 的处置是带成果重排（continue_from 指向自身：接手节点的任务书携带本
// 任务已得的漏洞与资产摘要，续测而非重来），最多 maxRequeues 次，超出即代停。
package server

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/wooluo/argus/internal/store"
)

const (
	nodeOfflineFor = 10 * time.Minute // R1：节点心跳停止多久算失联
	taskSilentFor  = 15 * time.Minute // R2：须大于节点最终结果回传的重试窗口（约 8 分钟）
	maxRequeues    = 2                // R1/R2 重排次数上限
	watchEvery     = 30 * time.Second
	defaultTaskMax = 360 * time.Minute // R3：单任务运行时长上限
	watchdogMark   = "【看门狗】"
)

// Watchdog 任务看门狗。polls 是进程内的执行心跳表：server 重启后清空，
// R2 在重新观察到心跳前不生效（旧版节点没有 intel 轮询，同理不受 R2 约束）。
type Watchdog struct {
	DB  *sql.DB
	Bus eventsBus

	mu    sync.Mutex
	polls map[int64]time.Time // taskID → 最近一次执行心跳
}

func NewWatchdog(db *sql.DB, bus eventsBus) *Watchdog {
	return &Watchdog{DB: db, Bus: bus, polls: map[int64]time.Time{}}
}

// Touch 记录任务的执行心跳（NodeIntel 每次轮询调用）。
func (w *Watchdog) Touch(taskID int64, now time.Time) {
	if taskID <= 0 {
		return
	}
	w.mu.Lock()
	w.polls[taskID] = now
	w.mu.Unlock()
}

// Forget 清除任务的执行心跳（重排后用：新节点须重新证明自己在跑）。
func (w *Watchdog) Forget(taskID int64) {
	w.mu.Lock()
	delete(w.polls, taskID)
	w.mu.Unlock()
}

func (w *Watchdog) lastPoll(taskID int64) (time.Time, bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	t, ok := w.polls[taskID]
	return t, ok
}

// Run 常驻巡检，ctx 取消即停。
func (w *Watchdog) Run(ctx context.Context) {
	t := time.NewTicker(watchEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			for _, line := range w.Check(time.Now()) {
				log.Printf("[watchdog] %s", line)
			}
		}
	}
}

// Check 巡检一轮在途（assigned）任务，返回处置说明（空=无需处置）。处置一律
// 带条件更新（仅当任务仍是 assigned）——与节点迟到的结果回传竞争时以后者为准。
func (w *Watchdog) Check(now time.Time) []string {
	rows, err := w.DB.Query(`SELECT t.id, t.retries,
		COALESCE(t.started_at, t.assigned_at, ''), COALESCE(n.id, 0), COALESCE(n.last_seen, '')
		FROM tasks t LEFT JOIN nodes n ON n.id = t.node_id WHERE t.status = 'assigned'`)
	if err != nil {
		log.Printf("[watchdog] query: %v", err)
		return nil
	}
	type item struct {
		id, retries       int64
		started, lastSeen string
		hasNode           bool
	}
	var items []item
	for rows.Next() {
		var it item
		var nodeID int64
		if rows.Scan(&it.id, &it.retries, &it.started, &nodeID, &it.lastSeen) == nil {
			it.hasNode = nodeID != 0
			items = append(items, it)
		}
	}
	rows.Close()

	var out []string
	taskMax := taskTimeLimit(w.DB)
	// 重排资格：超过最长运行时间的失联任务只代停、不重排（上限关闭时按默认值
	// 判）——否则升级前就卡住的陈年僵尸任务会被重新排队，等某个节点上线后
	// 突然对着目标开跑。
	requeueMax := taskMax
	if requeueMax <= 0 {
		requeueMax = defaultTaskMax
	}
	for _, it := range items {
		stale := since(it.started, now) > requeueMax
		var msg string
		var done bool
		switch {
		case taskMax > 0 && since(it.started, now) > taskMax:
			msg, done = w.stopOverdue(it.id, taskMax, now)
		case !it.hasNode || since(it.lastSeen, now) > nodeOfflineFor:
			msg, done = w.abandon(it.id, it.retries, stale,
				"节点失联（心跳停止超过 10 分钟）")
		default:
			if lp, seen := w.lastPoll(it.id); seen && now.Sub(lp) > taskSilentFor {
				msg, done = w.abandon(it.id, it.retries, stale,
					"任务无人执行（节点在线，但执行心跳中断超过 15 分钟）")
			}
		}
		if done {
			out = append(out, fmt.Sprintf("任务 #%d %s", it.id, msg))
		}
	}
	return out
}

// abandon R1/R2 处置：带成果重排；超过次数上限、或任务已超过最长运行时间
// （expired）则只代停。
func (w *Watchdog) abandon(id, retries int64, expired bool, why string) (string, bool) {
	var res sql.Result
	var err error
	var msg string
	if retries < maxRequeues && !expired {
		msg = fmt.Sprintf("%s%s：已重新排队（第 %d/%d 次），接手的节点将携带已得成果续测",
			watchdogMark, why, retries+1, maxRequeues)
		// continue_from 指向自身：Poll 下发本任务已得的漏洞与资产摘要；阶段进度
		// 清零，新一轮从侦察重新投影
		res, err = w.DB.Exec(`UPDATE tasks SET status='pending', node_id=0, assigned_at=NULL,
			retries=retries+1, continue_from=id, current_stage='', stages_done='[]', message=?
			WHERE id=? AND status='assigned'`, msg, id)
	} else {
		if expired {
			msg = fmt.Sprintf("%s%s：已超过最长运行时间，不再重排，代停；已入库的发现保留，需要时用「继续测试」接着跑",
				watchdogMark, why)
		} else {
			msg = fmt.Sprintf("%s%s：已重排 %d 次仍未完成，代停；已入库的发现保留，排查后可用「继续测试」接着跑",
				watchdogMark, why, maxRequeues)
		}
		res, err = w.DB.Exec(`UPDATE tasks SET status='failed', finished_at=?, message=?
			WHERE id=? AND status='assigned'`, store.Now(), msg, id)
	}
	if err != nil {
		log.Printf("[watchdog] task %d: %v", id, err)
		return "", false
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return "", false // 节点的结果回传抢先到了：以节点为准
	}
	w.denyPending(id, "watchdog-requeue")
	w.Forget(id)
	w.publish(id, msg)
	return msg, true
}

// stopOverdue R3 处置：到点代停。节点侧的 intel 轮询 5s 内感知并中断执行，
// 已入库的发现保留。
func (w *Watchdog) stopOverdue(id int64, max time.Duration, now time.Time) (string, bool) {
	msg := fmt.Sprintf("%s运行超过 %d 分钟上限，已代停；已入库的发现保留，可用「继续测试」接着跑",
		watchdogMark, int(max.Minutes()))
	res, err := w.DB.Exec(`UPDATE tasks SET status='stopped', finished_at=?, message=?
		WHERE id=? AND status='assigned'`, store.Now(), msg, id)
	if err != nil {
		log.Printf("[watchdog] task %d: %v", id, err)
		return "", false
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return "", false
	}
	w.denyPending(id, "task-stop")
	w.publish(id, msg)
	return msg, true
}

// denyPending 代停/重排时拒绝该任务遗留的待审批项（发起它们的执行已不在了）。
func (w *Watchdog) denyPending(taskID int64, by string) {
	res, err := w.DB.Exec(`UPDATE approvals SET status='denied', decided_by=?, decided_at=?
		WHERE task_id=? AND status='pending'`, by, store.Now(), taskID)
	if err == nil {
		if n, _ := res.RowsAffected(); n > 0 && w.Bus != nil {
			w.Bus.Publish("approval_done", map[string]any{
				"task_id": taskID, "status": "denied(" + by + ")", "count": n})
		}
	}
}

func (w *Watchdog) publish(taskID int64, msg string) {
	if w.Bus == nil {
		return
	}
	// 与 task_log 事件同形：任务板的单任务 SSE 流按 task_id 放行，实时日志里
	// 以系统行呈现处置原因
	w.Bus.Publish("task_watchdog", map[string]any{
		"task_id": taskID, "type": "watchdog",
		"data": map[string]any{"stage": "", "tool": "watchdog", "content": msg},
		"time": store.Now(),
	})
}

// taskTimeLimit 单任务运行时长上限（看门狗的到点代停与任务下发的时间预算
// 共用）：设置页 limits.max_task_minutes 优先，其次环境变量
// ARGUS_TASK_MAX_MINUTES；0 = 关闭。
func taskTimeLimit(db *sql.DB) time.Duration {
	var limits map[string]any
	_ = json.Unmarshal([]byte(store.GetSetting(db, "limits")), &limits)
	if v, ok := limits["max_task_minutes"].(float64); ok {
		return time.Duration(v * float64(time.Minute))
	}
	if s := strings.TrimSpace(os.Getenv("ARGUS_TASK_MAX_MINUTES")); s != "" {
		if v, err := strconv.ParseFloat(s, 64); err == nil {
			return time.Duration(v * float64(time.Minute))
		}
	}
	return defaultTaskMax
}

// since 解析库内时间戳并求距 now 的时长；空串或无法解析返回 0（视为「不满足
// 超时条件」，宁可不处置也不误杀）。
func since(ts string, now time.Time) time.Duration {
	if ts == "" {
		return 0
	}
	t, err := time.Parse("2006-01-02T15:04:05.000Z", ts)
	if err != nil {
		return 0
	}
	return now.Sub(t)
}
