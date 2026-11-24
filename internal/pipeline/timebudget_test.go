package pipeline

// timebudget_test.go: 时间预算写进任务书（两种模式），以及收敛提前量。

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/wooluo/argus/internal/llm"
)

func TestTimeBudgetLeadAndLine(t *testing.T) {
	var zero Brief
	if tb := zero.timeBudget(time.Now()); tb != (timeBudget{}) || tb.line() != "" {
		t.Errorf("未下发时间预算时应为不限时: %+v %q", tb, tb.line())
	}
	now := time.Now()
	tb := Brief{TimeBudgetSeconds: 1800, TimeLimitSeconds: 7200}.timeBudget(now)
	if tb.Limit != 2*time.Hour || tb.Deadline != now.Add(30*time.Minute) {
		t.Errorf("预算折算不符: %+v", tb)
	}
	if tb.lead() != 15*time.Minute { // 2 小时的四分之一是 30 分钟，封顶 15
		t.Errorf("提前量应封顶 15 分钟: %v", tb.lead())
	}
	if short := (Brief{TimeBudgetSeconds: 600, TimeLimitSeconds: 1200}.timeBudget(now)).lead(); short != 5*time.Minute {
		t.Errorf("短任务的提前量应是总时长的四分之一: %v", short)
	}
	line := tb.line()
	for _, want := range []string{"- 时间预算：本任务最长运行约 120 分钟", "目前剩余约 30 分钟"} {
		if !strings.Contains(line, want) {
			t.Errorf("任务书时间预算行缺 %q: %s", want, line)
		}
	}
}

// 首个 Agent 请求的任务书里写明时间预算；不限时时没有这一行。
func TestBriefCarriesTimeBudget(t *testing.T) {
	for _, mode := range []string{"autonomous", "staged"} {
		for _, limited := range []bool{true, false} {
			var first string
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var req struct {
					Tools    []json.RawMessage `json:"tools"`
					Messages []llm.Message     `json:"messages"`
				}
				_ = json.NewDecoder(r.Body).Decode(&req)
				if len(req.Tools) > 0 && first == "" {
					for _, m := range req.Messages {
						if m.Role == "user" {
							first = m.Content
							break
						}
					}
				}
				_, _ = w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"# 渗透测试报告\n` +
					strings.Repeat("详", 700) + `"}}]}`))
			}))
			b := briefFor(mode, srv.URL)
			if limited {
				b.TimeBudgetSeconds, b.TimeLimitSeconds = 1200, 3600
			}
			if res := Run(context.Background(), b, nil); res.Status != "done" {
				t.Fatalf("%s: status=%s message=%s", mode, res.Status, res.Message)
			}
			srv.Close()
			has := strings.Contains(first, "- 时间预算：本任务最长运行约 60 分钟")
			if has != limited {
				t.Errorf("%s(限时=%v): 任务书是否含时间预算行应为 %v:\n%.300s", mode, limited, limited, first)
			}
		}
	}
}
