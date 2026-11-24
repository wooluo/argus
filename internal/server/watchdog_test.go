package server

import (
	"database/sql"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/wooluo/argus/internal/store"
)

type eventRecorder struct {
	mu     sync.Mutex
	events []string
}

func (r *eventRecorder) Publish(event string, _ any) {
	r.mu.Lock()
	r.events = append(r.events, event)
	r.mu.Unlock()
}

func (r *eventRecorder) count(event string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for _, e := range r.events {
		if e == event {
			n++
		}
	}
	return n
}

const tsLayout = "2006-01-02T15:04:05.000Z"

var wdNow = time.Date(2026, 11, 24, 12, 0, 0, 0, time.UTC)

// newWatchdogFixture 内存库：一个项目、节点 #1、assigned 给它的任务 #1。
func newWatchdogFixture(t *testing.T) (*Watchdog, *eventRecorder, *sql.DB) {
	t.Helper()
	db, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.Exec(q, args...); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	exec(`INSERT INTO projects(name) VALUES ('p1')`)
	exec(`INSERT INTO nodes(name,token,status,last_seen) VALUES ('n1','tok','online',?)`, wdNow.Format(tsLayout))
	exec(`INSERT INTO tasks(project_id,status,mode,node_id,assigned_at,started_at) VALUES (1,'assigned','autonomous',1,?,?)`,
		wdNow.Add(-time.Minute).Format(tsLayout), wdNow.Add(-time.Minute).Format(tsLayout))
	rec := &eventRecorder{}
	return NewWatchdog(db, rec), rec, db
}

type taskState struct {
	status, message string
	nodeID          int64
	retries, cont   int64
}

func readTask(t *testing.T, db *sql.DB) taskState {
	t.Helper()
	var s taskState
	var node sql.NullInt64
	if err := db.QueryRow(`SELECT status,message,node_id,retries,continue_from FROM tasks WHERE id=1`).
		Scan(&s.status, &s.message, &node, &s.retries, &s.cont); err != nil {
		t.Fatal(err)
	}
	s.nodeID = node.Int64
	return s
}

func exec(t *testing.T, db *sql.DB, q string, args ...any) {
	t.Helper()
	if _, err := db.Exec(q, args...); err != nil {
		t.Fatalf("%s: %v", q, err)
	}
}

// R1：节点心跳停止 → 带成果重排（续测而非重来），最多两次，之后代停。
func TestWatchdogRequeuesWhenNodeOffline(t *testing.T) {
	w, rec, db := newWatchdogFixture(t)
	offline := wdNow.Add(-11 * time.Minute).Format(tsLayout)

	exec(t, db, `UPDATE nodes SET last_seen=? WHERE id=1`, offline)
	if got := w.Check(wdNow); len(got) != 1 || !strings.Contains(got[0], "重新排队（第 1/2 次）") {
		t.Fatalf("期望重排一次，得到 %v", got)
	}
	s := readTask(t, db)
	if s.status != "pending" || s.nodeID != 0 || s.retries != 1 || s.cont != 1 ||
		!strings.HasPrefix(s.message, watchdogMark) {
		t.Errorf("重排后的任务状态不符: %+v", s)
	}
	if rec.count("task_watchdog") != 1 {
		t.Errorf("应推送一条看门狗事件，实际 %d", rec.count("task_watchdog"))
	}
	if w.Check(wdNow) != nil {
		t.Error("排队中的任务不应被再次处置")
	}

	// 节点恢复、任务被再次领走并正常执行 → 不动
	exec(t, db, `UPDATE nodes SET last_seen=? WHERE id=1`, wdNow.Format(tsLayout))
	exec(t, db, `UPDATE tasks SET status='assigned', node_id=1 WHERE id=1`)
	w.Touch(1, wdNow)
	if got := w.Check(wdNow); got != nil {
		t.Fatalf("健康任务不应被处置: %v", got)
	}

	// 第二次失联 → 第二次重排
	exec(t, db, `UPDATE nodes SET last_seen=? WHERE id=1`, offline)
	w.Check(wdNow)
	if s := readTask(t, db); s.status != "pending" || s.retries != 2 {
		t.Fatalf("期望第二次重排: %+v", s)
	}

	// 第三次 → 次数用尽，代停
	exec(t, db, `UPDATE tasks SET status='assigned', node_id=1 WHERE id=1`)
	if got := w.Check(wdNow); len(got) != 1 || !strings.Contains(got[0], "代停") {
		t.Fatalf("期望代停，得到 %v", got)
	}
	if s := readTask(t, db); s.status != "failed" || !strings.Contains(s.message, "已重排 2 次仍未完成") {
		t.Errorf("代停状态不符: %+v", s)
	}
}

// R2：节点在线（被 systemd 拉起）但任务无人执行——靠执行心跳「先有后无」识别。
func TestWatchdogTaskSilentWhileNodeOnline(t *testing.T) {
	w, _, db := newWatchdogFixture(t)
	assign := func() {
		exec(t, db, `UPDATE tasks SET status='assigned', node_id=1 WHERE id=1`)
	}

	// 从未观察到心跳（server 刚重启 / 旧版节点没有 intel 轮询）→ 不误杀
	if got := w.Check(wdNow); got != nil {
		t.Fatalf("未观察到心跳不应处置: %v", got)
	}

	w.Touch(1, wdNow.Add(-16*time.Minute))
	if got := w.Check(wdNow); len(got) != 1 || !strings.Contains(got[0], "任务无人执行") {
		t.Fatalf("期望按任务失联重排，得到 %v", got)
	}

	// 重排后心跳已清除：新节点接手但尚未证明自己在跑 → 先不动
	assign()
	if got := w.Check(wdNow); got != nil {
		t.Fatalf("重排后不应沿用旧心跳: %v", got)
	}
	// 接手节点在正常轮询 → 不动
	w.Touch(1, wdNow.Add(-time.Second))
	if got := w.Check(wdNow); got != nil {
		t.Fatalf("执行中的任务不应被处置: %v", got)
	}
	// 沉默 14 分钟（可能只是最终结果在重试回传）→ 仍不动；满 15 分钟才处置
	w.Touch(1, wdNow.Add(-14*time.Minute))
	if got := w.Check(wdNow); got != nil {
		t.Fatalf("未到阈值不应处置: %v", got)
	}
	w.Touch(1, wdNow.Add(-16*time.Minute))
	if got := w.Check(wdNow); len(got) != 1 {
		t.Fatalf("期望处置，得到 %v", got)
	}
}

// 升级前就卡住的陈年僵尸任务（节点早已离线）：只代停，不重新排队——否则等某个
// 节点上线就会突然对着目标开跑。上限被关掉（0）时按默认值判。
func TestWatchdogDoesNotRequeueStaleZombie(t *testing.T) {
	w, _, db := newWatchdogFixture(t)
	exec(t, db, `UPDATE nodes SET last_seen=? WHERE id=1`, wdNow.Add(-11*time.Minute).Format(tsLayout))
	_ = store.SetSetting(db, "limits", `{"max_task_minutes":0}`) // 关闭到点收卷
	exec(t, db, `UPDATE tasks SET started_at=? WHERE id=1`, wdNow.Add(-7*time.Hour).Format(tsLayout))

	if got := w.Check(wdNow); len(got) != 1 || !strings.Contains(got[0], "不再重排") {
		t.Fatalf("陈年僵尸任务应只代停，得到 %v", got)
	}
	if s := readTask(t, db); s.status != "failed" || s.retries != 0 || s.cont != 0 {
		t.Errorf("不应被重排: %+v", s)
	}

	// 近期失联的任务照常重排
	exec(t, db, `UPDATE tasks SET status='assigned', node_id=1, started_at=? WHERE id=1`,
		wdNow.Add(-30*time.Minute).Format(tsLayout))
	if got := w.Check(wdNow); len(got) != 1 || !strings.Contains(got[0], "重新排队") {
		t.Fatalf("近期失联的任务应重排，得到 %v", got)
	}
}

// R3：到点收卷由 server 持有；代停原因不被节点随后的收尾回传覆盖。
func TestWatchdogStopsOverdue(t *testing.T) {
	w, rec, db := newWatchdogFixture(t)
	exec(t, db, `INSERT INTO approvals(task_id,project_id,tool) VALUES (1,1,'nmap_scan')`)
	exec(t, db, `UPDATE tasks SET started_at=? WHERE id=1`, wdNow.Add(-361*time.Minute).Format(tsLayout))
	w.Touch(1, wdNow) // 节点活着、任务也在跑——到点照样收卷

	if got := w.Check(wdNow); len(got) != 1 || !strings.Contains(got[0], "360 分钟上限") {
		t.Fatalf("期望超时代停，得到 %v", got)
	}
	s := readTask(t, db)
	if s.status != "stopped" || !strings.HasPrefix(s.message, watchdogMark) {
		t.Errorf("代停状态不符: %+v", s)
	}
	var apStatus, decidedBy string
	_ = db.QueryRow(`SELECT status,decided_by FROM approvals WHERE task_id=1`).Scan(&apStatus, &decidedBy)
	if apStatus != "denied" || decidedBy != "task-stop" {
		t.Errorf("代停应拒绝遗留的待审批项: %s/%s", apStatus, decidedBy)
	}
	if rec.count("approval_done") != 1 || rec.count("task_watchdog") != 1 {
		t.Errorf("事件推送不符: approval_done=%d task_watchdog=%d",
			rec.count("approval_done"), rec.count("task_watchdog"))
	}

	// 节点 5s 内感知停止并回传收尾说明：状态保持 stopped，原因保留
	n := &NodeAPI{DB: db, Bus: rec}
	wrec := httptest.NewRecorder()
	n.ReportResult(wrec, httptest.NewRequest(http.MethodPost, "/api/nodes/result", strings.NewReader(
		`{"task_id":1,"status":"stopped","message":"任务被取消（node n1, 21660.2s）"}`)))
	if wrec.Code != 200 {
		t.Fatalf("result code=%d body=%s", wrec.Code, wrec.Body.String())
	}
	s = readTask(t, db)
	if s.status != "stopped" || !strings.HasPrefix(s.message, watchdogMark) || !strings.Contains(s.message, "节点侧：") {
		t.Errorf("代停原因应保留并接上节点说明: %+v", s)
	}

	// 上限可配：0 关闭；30 分钟则 31 分钟即收卷
	exec(t, db, `UPDATE tasks SET status='assigned', message='' WHERE id=1`)
	_ = store.SetSetting(db, "limits", `{"max_task_minutes":0}`)
	if got := w.Check(wdNow); got != nil {
		t.Fatalf("上限关闭后不应收卷: %v", got)
	}
	_ = store.SetSetting(db, "limits", `{"max_task_minutes":30}`)
	exec(t, db, `UPDATE tasks SET started_at=? WHERE id=1`, wdNow.Add(-31*time.Minute).Format(tsLayout))
	if got := w.Check(wdNow); len(got) != 1 || !strings.Contains(got[0], "30 分钟上限") {
		t.Fatalf("应按配置的上限收卷，得到 %v", got)
	}
}

// 与节点迟到的结果回传竞争：任务已不是 assigned 时看门狗不动它。
func TestWatchdogYieldsToLateResult(t *testing.T) {
	w, rec, db := newWatchdogFixture(t)
	exec(t, db, `UPDATE nodes SET last_seen=? WHERE id=1`, wdNow.Add(-11*time.Minute).Format(tsLayout))
	// 巡检与结果回传之间的窗口里，节点把结果送到了
	n := &NodeAPI{DB: db, Bus: rec, Watchdog: w}
	wrec := httptest.NewRecorder()
	n.ReportResult(wrec, httptest.NewRequest(http.MethodPost, "/api/nodes/result", strings.NewReader(
		`{"task_id":1,"status":"done","message":"全部阶段完成"}`)))
	if wrec.Code != 200 {
		t.Fatalf("result code=%d", wrec.Code)
	}
	if got := w.Check(wdNow); got != nil {
		t.Fatalf("已完成的任务不应被处置: %v", got)
	}
	if s := readTask(t, db); s.status != "done" || s.message != "全部阶段完成" {
		t.Errorf("节点结果应原样保留: %+v", s)
	}
}
