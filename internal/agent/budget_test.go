package agent

// budget_test.go: 时间预算的收敛提醒、无进展提醒。
// captureLLM 在 scriptedLLM 之上记录每次带工具请求里的 user 消息。

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/wooluo/argus/internal/llm"
	"github.com/wooluo/argus/internal/tools"
)

type captureLLM struct {
	scriptedLLM
	mu    sync.Mutex
	users [][]string // 每次带工具的请求里的 user 消息
	last  []string   // 每次请求的最后一条消息：角色 + 内容
}

func (c *captureLLM) handler() http.Handler {
	inner := c.scriptedLLM.handler()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var req struct {
			Messages []llm.Message `json:"messages"`
		}
		_ = json.Unmarshal(body, &req)
		if len(req.Messages) > 0 && req.Messages[0].Role == "system" { // 带工具的 Agent 请求（system 在首位）
			c.mu.Lock()
			var users []string
			for _, m := range req.Messages {
				if m.Role == "user" {
					users = append(users, m.Content)
				}
			}
			c.users = append(c.users, users)
			c.last = append(c.last, req.Messages[len(req.Messages)-1].Role+":"+req.Messages[len(req.Messages)-1].Content)
			c.mu.Unlock()
		}
		inner.ServeHTTP(w, httptest.NewRequest(r.Method, r.URL.String(), bytes.NewReader(body)))
	})
}

// tail 第 i 次请求的最后一条消息；越界返回 "?"。
func (c *captureLLM) tail(i int) string {
	c.mu.Lock()
	defer c.mu.Unlock()
	if i >= len(c.last) {
		return "?"
	}
	return c.last[i]
}

func (c *captureLLM) countIn(i int, prefix string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	if i >= len(c.users) {
		return -1
	}
	n := 0
	for _, u := range c.users[i] {
		if strings.HasPrefix(u, prefix) {
			n++
		}
	}
	return n
}

func newAgentWithHandler(t *testing.T, h http.Handler, opts Options, rep *countingReporter) *Agent {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	opts.ContextLimit = 40
	return New(llm.NewClient(llm.DefaultProvider(llm.Config{BaseURL: srv.URL, APIKey: "k", Model: "m"})),
		opts, []tools.Tool{echoTool{}}, &tools.Context{Reporter: rep})
}

func countLog(rep *countingReporter, sub string) int {
	rep.mu.Lock()
	defer rep.mu.Unlock()
	n := 0
	for _, l := range rep.logs {
		if strings.Contains(l, sub) {
			n++
		}
	}
	return n
}

func toolScript(n int, end string) []string {
	s := make([]string, n)
	for i := range s {
		s[i] = toolCall(i + 1)
	}
	if end != "" {
		s[n-1] = finalText(end)
	}
	return s
}

// 临近强制结束：收敛提醒作为 user 消息注入，且整个会话只有一条。
func TestDeadlineReminderInjectedOnce(t *testing.T) {
	c := &captureLLM{scriptedLLM: scriptedLLM{script: toolScript(6, report)}}
	rep := &countingReporter{}
	a := newAgentWithHandler(t, c.handler(), Options{Stage: "hunt", MaxSteps: 10, RequireReport: true,
		Deadline: time.Now().Add(5 * time.Minute), WrapUpLead: 10 * time.Minute}, rep)
	if _, err := a.Run(context.Background(), "sys", "brief"); err != nil {
		t.Fatal(err)
	}
	if len(c.users) != 6 {
		t.Fatalf("应有 6 次 Agent 请求，实际 %d", len(c.users))
	}
	for i := range c.users {
		if n := c.countIn(i, "⏰ 时间预算"); n != 1 {
			t.Fatalf("第 %d 次请求应有且只有一条收敛提醒，实际 %d: %v", i+1, n, c.users[i])
		}
	}
	if countLog(rep, "已提醒收敛") != 1 {
		t.Errorf("应记一条收敛提醒日志: %v", rep.logs)
	}

	// 未进入收敛期 / 不限时时：不提醒
	for _, tc := range []struct {
		name string
		opts Options
	}{
		{"还早", Options{Deadline: time.Now().Add(time.Hour), WrapUpLead: 10 * time.Minute}},
		{"不限时", Options{}},
		{"没设提前量", Options{Deadline: time.Now().Add(time.Minute)}},
	} {
		c2 := &captureLLM{scriptedLLM: scriptedLLM{script: toolScript(3, report)}}
		a2 := newAgentWithHandler(t, c2.handler(), Options{Stage: "hunt", MaxSteps: 5,
			RequireReport: true, Deadline: tc.opts.Deadline, WrapUpLead: tc.opts.WrapUpLead},
			&countingReporter{})
		_, _ = a2.Run(context.Background(), "sys", "brief")
		for i := range c2.users {
			if n := c2.countIn(i, "⏰"); n != 0 {
				t.Errorf("%s: 第 %d 次请求不应有收敛提醒（%d 条）", tc.name, i+1, n)
			}
		}
	}
}

// 连续 15 步没有任何新资产 / 新发现 → 第 17 次 Agent 请求前注入一条无进展提醒；
// 之后同一节奏再提醒，但整个会话至多 3 次。
func TestIdleReminderAfterStreak(t *testing.T) {
	c := &captureLLM{scriptedLLM: scriptedLLM{script: toolScript(60, report)}}
	rep := &countingReporter{assets: 3} // 资产数恒定：每一步都算无进展
	a := newAgentWithHandler(t, c.handler(), Options{Stage: "hunt", MaxSteps: 80, RequireReport: true}, rep)
	if _, err := a.Run(context.Background(), "sys", "brief"); err != nil {
		t.Fatal(err)
	}
	// 第 16 次工具调用后凑满连续 15 步 → 第 17 次请求（下标 16）才带提醒
	if n := c.countIn(15, "【无进展提醒】"); n != 0 {
		t.Errorf("第 16 次请求不应有提醒（%d 条）", n)
	}
	if n := c.countIn(16, "【无进展提醒】"); n != 1 {
		t.Errorf("第 17 次请求应带一条无进展提醒，实际 %d", n)
	}
	// 提醒在下一轮 LLM 调用前注入：紧跟在上一轮的 tool 结果之后，而不是夹进
	// 同一轮的 tool 消息中间（有些接口要求 tool 消息紧跟发起它们的 assistant 消息）
	if tail := c.tail(15); !strings.HasPrefix(tail, "tool:") {
		t.Errorf("第 16 次请求应以 tool 结果收尾: %.60q", tail)
	}
	if tail := c.tail(16); !strings.HasPrefix(tail, "user:【无进展提醒】") {
		t.Errorf("第 17 次请求应以提醒收尾: %.60q", tail)
	}
	if n := countLog(rep, "连续 15 步没有新资产或新发现"); n != 3 {
		t.Errorf("60 步内应提醒 3 次（第 16、31、46 步后），实际 %d", n)
	}
}

// 每一步都有新资产：不提醒。
type growingReporter struct {
	countingReporter
	n int
}

func (r *growingReporter) AssetCount() int { r.n++; return r.n }

func TestNoIdleReminderWhileYielding(t *testing.T) {
	c := &captureLLM{scriptedLLM: scriptedLLM{script: toolScript(20, report)}}
	rep := &growingReporter{}
	a := newAgentWithHandler(t, c.handler(), Options{Stage: "hunt", MaxSteps: 30, RequireReport: true}, &rep.countingReporter)
	_, _ = a.Run(context.Background(), "sys", "brief")
	if countLog(&rep.countingReporter, "无进展") != 0 {
		t.Errorf("持续有新资产时不应提醒: %v", rep.logs)
	}
}
