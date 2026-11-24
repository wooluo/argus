package pipeline

// flush_test.go: 增量上报的投递语义回归。
// 曾「先推游标、再异步发送」，而节点侧 onFlush 距上次不足 5s 直接 return——
// 窗口内的发现/资产/日志既不在 progress 里、也被最终结果的增量范围越过，
// 静默丢失。现在以 server 确认为准：onFlush 返回 error 即未送达，游标不动，
// 下个周期连同期间新增一起重发。

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/wooluo/argus/internal/tools"
)

func TestFlushAdvancesOnlyOnAck(t *testing.T) {
	ctx := context.Background()
	m := &memReporter{res: &Result{}, brief: Brief{}}
	var sent []Result
	calls := 0
	m.onFlush = func(_ context.Context, _ Brief, inc Result) error {
		calls++
		if calls == 1 {
			return errors.New("server restarting")
		}
		sent = append(sent, inc)
		return nil
	}
	save := func(name string) {
		if _, err := m.SaveFinding(ctx, tools.Finding{Name: name}); err != nil {
			t.Fatal(err)
		}
	}
	for _, n := range []string{"f1", "f2", "f3"} {
		save(n)
	}
	m.SaveAsset(ctx, "url", "http://a", nil)
	m.Log(ctx, "system", "hunt", "hi")

	m.flush(ctx) // 未送达
	if calls != 1 || m.sentF != 0 || m.sentA != 0 || m.sentL != 0 || !m.inflight {
		t.Fatalf("未送达却动了游标/状态: calls=%d sent=%d/%d/%d inflight=%v",
			calls, m.sentF, m.sentA, m.sentL, m.inflight)
	}

	save("f4") // 回传失败期间的新增——必须随下次重发一起送达
	m.flush(ctx)
	if calls != 2 || m.sentF != 4 || m.sentA != 1 || m.sentL != 1 || m.inflight {
		t.Fatalf("送达后游标应覆盖全部 4+1+1 条: calls=%d sent=%d/%d/%d inflight=%v",
			calls, m.sentF, m.sentA, m.sentL, m.inflight)
	}

	m.flush(ctx) // 无新增不应再发
	if calls != 2 {
		t.Fatalf("无新增却再次上报（calls=%d）", calls)
	}

	save("f5")
	m.flush(ctx)
	if calls != 3 || m.sentF != 5 || m.inflight {
		t.Fatalf("后续增量应只带新增: calls=%d sentF=%d inflight=%v", calls, m.sentF, m.inflight)
	}

	// 汇总：每条恰好送达一次（不丢不重）
	var names []string
	assets, logs := 0, 0
	for _, s := range sent {
		for _, f := range s.Findings {
			names = append(names, f.Name)
		}
		assets += len(s.Assets)
		logs += len(s.Logs)
	}
	if got := strings.Join(names, ","); got != "f1,f2,f3,f4,f5" {
		t.Errorf("发现送达序列不符: %s", got)
	}
	if assets != 1 || logs != 1 {
		t.Errorf("资产/日志送达次数不符: assets=%d logs=%d", assets, logs)
	}
}

// Run 收尾契约：progress 已确认的条数 = Reported；未经确认的随最终结果走。
// 两者拼起来恰好是全部日志——无论 server 全程正常还是全程不可达。
func TestRunDeliversLogsExactlyOnce(t *testing.T) {
	for _, tc := range []struct {
		name string
		down bool
	}{
		{"progress 正常", false},
		{"server 全程不可达", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := fakeLLM(t, "# 渗透测试报告\n"+strings.Repeat("详", 700))
			defer srv.Close()
			var mu sync.Mutex
			var delivered []LogItem
			res := Run(context.Background(), briefFor("autonomous", srv.URL), func(inc Result) error {
				if tc.down {
					return errors.New("server down") // 未确认：不计入已送达
				}
				mu.Lock()
				delivered = append(delivered, inc.Logs...)
				mu.Unlock()
				return nil
			})
			if res.Status != "done" {
				t.Fatalf("status=%s message=%s", res.Status, res.Message)
			}
			if n := len(delivered); n != res.Reported.Logs {
				t.Fatalf("Reported.Logs=%d 但 progress 实际确认 %d 条", res.Reported.Logs, n)
			}
			rest := res.Logs[res.Reported.Logs:]
			if tc.down && (len(delivered) != 0 || len(rest) != len(res.Logs)) {
				t.Fatalf("server 不可达时全部日志应留给最终结果: delivered=%d rest=%d", len(delivered), len(rest))
			}
			if !reflect.DeepEqual(append(append([]LogItem{}, delivered...), rest...), res.Logs) {
				t.Fatalf("progress + 最终结果 ≠ 全部日志（丢了或重了）: delivered=%d rest=%d total=%d",
					len(delivered), len(rest), len(res.Logs))
			}
		})
	}
}

// token 用量按客户端口径累计：Run 结束时 res.Tokens 覆盖本次任务的全部 LLM 调用
// （原先只在自主模式按单个 Agent 会话统计，且节点回传不带——tasks.tokens 恒空）。
func TestRunReportsTokens(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"choices": []map[string]any{{
				"message": map[string]any{"role": "assistant",
					"content": "# 渗透测试报告\n" + strings.Repeat("详", 700)},
			}},
			"usage": map[string]any{"prompt_tokens": 120, "completion_tokens": 80},
		})
	}))
	defer srv.Close()
	for _, mode := range []string{"autonomous", "staged"} {
		res := Run(context.Background(), briefFor(mode, srv.URL), nil)
		if res.Tokens["prompt"] <= 0 || res.Tokens["completion"] <= 0 || res.Tokens["calls"] < 1 {
			t.Errorf("%s: token 统计为空或不成比例: %v", mode, res.Tokens)
		}
		if res.Tokens["prompt"] != 120*res.Tokens["calls"] {
			t.Errorf("%s: prompt 累计与调用次数不匹配: %v", mode, res.Tokens)
		}
	}
}
