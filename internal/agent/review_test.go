package agent

// review_test.go: 步数预算的运行中上调、收工前审查、预算耗尽时的报告兜底。
// 假 LLM 按「带工具的请求 = Agent 轮次」取脚本；无工具的请求（收工前审查）另走一份脚本。

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/wooluo/argus/internal/llm"
	"github.com/wooluo/argus/internal/tools"
)

// echoTool 测试用工具：参数原样回显。
type echoTool struct{}

func (echoTool) Name() string        { return "echo_probe" }
func (echoTool) Description() string { return "探测" }
func (echoTool) Parameters() map[string]any {
	return tools.Schema(map[string]any{"n": tools.Prop("integer", "序号")}, "n")
}
func (echoTool) Execute(_ context.Context, args map[string]any, _ *tools.Context) (string, error) {
	return fmt.Sprintf("probe %v done", args["n"]), nil
}

// countingReporter 假 Reporter：资产数可设，记录日志。
type countingReporter struct {
	mu     sync.Mutex
	assets int
	logs   []string
}

func (r *countingReporter) SaveAsset(context.Context, string, string, map[string]any) {}
func (r *countingReporter) SaveTraffic(context.Context, string, string, string, int, string, string) {
}
func (r *countingReporter) SaveSession(context.Context, string, string, map[string]string) {}
func (r *countingReporter) SaveEvidence(context.Context, string, string, map[string]any)   {}
func (r *countingReporter) SaveKnowledge(context.Context, tools.Knowledge) error           { return nil }
func (r *countingReporter) SearchKnowledge(context.Context, string, int) []map[string]any  { return nil }
func (r *countingReporter) SaveFinding(context.Context, tools.Finding) (int64, error)      { return 1, nil }
func (r *countingReporter) UpdateFinding(context.Context, int64, map[string]any) error     { return nil }
func (r *countingReporter) LLMDesc() string                                                { return "fake" }
func (r *countingReporter) AssetCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.assets
}
func (r *countingReporter) FindingCount() int { return 0 }
func (r *countingReporter) Log(_ context.Context, _, _, message string) {
	r.mu.Lock()
	r.logs = append(r.logs, message)
	r.mu.Unlock()
}
func (r *countingReporter) hasLog(sub string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, l := range r.logs {
		if strings.Contains(l, sub) {
			return true
		}
	}
	return false
}

// scriptedLLM 两份脚本：带工具的请求按序取 script，无工具的请求按序取 reviews；
// 超出脚本后重复最后一条。
type scriptedLLM struct {
	mu      sync.Mutex
	calls   int
	script  []string // 每条是一个 message 的 JSON
	reviews []string // 每条是审查员的纯文本回复
	noTools int
}

func (s *scriptedLLM) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Tools []json.RawMessage `json:"tools"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		s.mu.Lock()
		defer s.mu.Unlock()
		if len(req.Tools) == 0 {
			i := min(s.noTools, len(s.reviews)-1)
			s.noTools++
			b, _ := json.Marshal(s.reviews[i])
			_, _ = fmt.Fprintf(w, `{"choices":[{"message":{"role":"assistant","content":%s}}]}`, b)
			return
		}
		i := min(s.calls, len(s.script)-1)
		s.calls++
		_, _ = fmt.Fprintf(w, `{"choices":[{"message":%s}]}`, s.script[i])
	})
}

func toolCall(n int) string {
	return fmt.Sprintf(`{"role":"assistant","content":"","tool_calls":[{"id":"c%d","type":"function",`+
		`"function":{"name":"echo_probe","arguments":"{\"n\":%d}"}}]}`, n, n)
}

func finalText(s string) string {
	b, _ := json.Marshal(map[string]string{"role": "assistant", "content": s})
	return string(b)
}

var report = "# 渗透测试报告\n" + strings.Repeat("详", 700)

func newAgent(t *testing.T, s *scriptedLLM, opts Options, rep *countingReporter) (*Agent, *llm.Client) {
	t.Helper()
	srv := httptest.NewServer(s.handler())
	t.Cleanup(srv.Close)
	opts.ContextLimit = 40
	client := llm.NewClient(llm.DefaultProvider(llm.Config{BaseURL: srv.URL, APIKey: "k", Model: "m"}))
	return New(client, opts, []tools.Tool{echoTool{}}, &tools.Context{Reporter: rep}), client
}

// reviewingHook 经假 LLM 发起审查：回复里有非空 blindspots 就不许收工。
func reviewingHook(client *llm.Client) func(context.Context, string, string) string {
	return func(ctx context.Context, _, _ string) string {
		out, err := client.ChatText(ctx, "", "审查", 0.1)
		if err != nil || strings.Contains(out, `"blindspots": []`) || strings.Contains(out, `"blindspots":[]`) {
			return ""
		}
		return "【收工前盲区审查：发现缺口，现在不能收尾】继续补齐"
	}
}

// 运行中按已发现资产量上调预算：开局 30 步，25 步时账上已有 200 项资产 →
// 预算放宽到 60 步，Agent 实际跑到 60 步而不是 30 步就停。
func TestBudgetUpscalesMidRun(t *testing.T) {
	script := make([]string, 70)
	for i := range script {
		script[i] = toolCall(i + 1)
	}
	s := &scriptedLLM{script: script}
	rep := &countingReporter{assets: 200}
	a, _ := newAgent(t, s, Options{Stage: "hunt", MaxSteps: 30, BudgetBase: 30}, rep)
	_, _ = a.Run(context.Background(), "sys", "brief")
	if n := a.ToolCalls(); n != 60 {
		t.Fatalf("预算上调后应跑满 60 步，实际 %d", n)
	}
	if !rep.hasLog("自适应预算上调: 步数 30 → 60") {
		t.Errorf("应记录一次预算上调: %v", rep.logs)
	}

	// 不设基准（BudgetBase=0）→ 不上调
	s2 := &scriptedLLM{script: script}
	a2, _ := newAgent(t, s2, Options{Stage: "hunt", MaxSteps: 30}, &countingReporter{assets: 5000})
	_, _ = a2.Run(context.Background(), "sys", "brief")
	if n := a2.ToolCalls(); n != 30 {
		t.Errorf("未启用上调时应停在 30 步，实际 %d", n)
	}
}

// 收工前审查发现缺口 → 不许收工，补完后再次收工、审查通过 → 才结束。
func TestFinishReviewBlocksThenAccepts(t *testing.T) {
	s := &scriptedLLM{
		script: []string{toolCall(1), finalText(report), toolCall(2), finalText(report + "（补齐版）")},
		reviews: []string{
			`{"blindspots":[{"area":"认证后功能面","risk":"high","question":"登录后的页面测了吗","suggestion":"web_login 后遍历"}]}`,
			`{"blindspots": []}`,
		},
	}
	rep := &countingReporter{}
	a, client := newAgent(t, s, Options{Stage: "hunt", MaxSteps: 50, RequireReport: true}, rep)
	a.opts.FinishReview = reviewingHook(client)

	out, err := a.Run(context.Background(), "sys", "brief")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "补齐版") {
		t.Fatalf("应在补齐后以第二份报告收工: %.60q", out)
	}
	if n := a.ToolCalls(); n != 2 || s.noTools != 2 {
		t.Errorf("审查应拦下一次、放行一次: toolCalls=%d reviews=%d", n, s.noTools)
	}
	if !rep.hasLog("收工前审查发现缺口") {
		t.Errorf("拦截应留日志: %v", rep.logs)
	}
}

// 审查连续挑刺也不至于死循环：拦到上限后无条件放行。
func TestFinishReviewIsBounded(t *testing.T) {
	s := &scriptedLLM{script: []string{finalText(report)}}
	a, _ := newAgent(t, s, Options{Stage: "hunt", MaxSteps: 50, RequireReport: true,
		FinishReview: func(context.Context, string, string) string { return "还有缺口，继续" }},
		&countingReporter{})
	if _, err := a.Run(context.Background(), "sys", "brief"); err != nil {
		t.Fatal(err)
	}
	if a.reviews != maxFinishReviews {
		t.Errorf("应恰好拦下 %d 次，实际 %d", maxFinishReviews, a.reviews)
	}
}

// 审查后继续跑却把预算耗尽：交付留底的那份报告，而不是空手而归。
func TestExhaustedBudgetKeepsLastReport(t *testing.T) {
	script := []string{finalText(report)}
	for i := 0; i < 60; i++ {
		script = append(script, toolCall(i+1))
	}
	s := &scriptedLLM{script: script}
	a, _ := newAgent(t, s, Options{Stage: "hunt", MaxSteps: 20, RequireReport: true,
		FinishReview: func(context.Context, string, string) string { return "继续补" }},
		&countingReporter{})
	out, err := a.Run(context.Background(), "sys", "brief")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(strings.TrimSpace(out), "# 渗透测试报告") {
		t.Fatalf("预算耗尽时应返回留底的报告，得到 %.60q", out)
	}
}

// 预算只剩一成时不再审查：没有余量照着补。
func TestFinishReviewSkippedWhenBudgetNearlySpent(t *testing.T) {
	called := false
	s := &scriptedLLM{script: []string{finalText(report)}}
	a, _ := newAgent(t, s, Options{Stage: "hunt", MaxSteps: 10, RequireReport: true,
		FinishReview: func(context.Context, string, string) string { called = true; return "继续" }},
		&countingReporter{})
	a.step = 9 // 已用 9/10
	if _, err := a.Run(context.Background(), "sys", "brief"); err != nil {
		t.Fatal(err)
	}
	if called {
		t.Error("预算将尽时不应再发起收工前审查")
	}
}
