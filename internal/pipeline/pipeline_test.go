// pipeline 冒烟：假 LLM 驱动 staged/autonomous 全链路（无真实网络）。
package pipeline

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/wooluo/argus/internal/llm"
	"github.com/wooluo/argus/internal/scope"
	"github.com/wooluo/argus/internal/tools"
)

// fakeLLM OpenAI 兼容假服务器：始终返回最终文本（无 tool_calls）。
func fakeLLM(t *testing.T, final string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"choices": []map[string]any{{
				"message": map[string]any{"role": "assistant", "content": final},
			}},
		})
	}))
}

func briefFor(mode, baseURL string) Brief {
	return Brief{
		TaskID: 1, Mode: mode, ProjectID: 1, ProjectName: "smoke",
		Description: "测试规范",
		Scope:       []scope.Rule{{Type: "domain", Value: "example.com"}},
		LLM:         llm.Config{BaseURL: baseURL, APIKey: "k", Model: "fake"},
	}
}

func TestRunStaged(t *testing.T) {
	srv := fakeLLM(t, "# 报告\n"+strings.Repeat("内容", 400))
	defer srv.Close()
	res := Run(context.Background(), briefFor("staged", srv.URL), nil)
	if res.Status != "done" {
		t.Fatalf("status=%s message=%s logs=%d", res.Status, res.Message, len(res.Logs))
	}
	if !strings.Contains(res.Report, "# 报告") {
		t.Fatalf("report missing, got %q", res.Report[:50])
	}
	// 五阶段进入日志 + 启动日志
	joined := logJoin(res)
	for _, st := range STAGES {
		if !strings.Contains(joined, STAGE_NAMES[st]) {
			t.Fatalf("stage %s not logged", st)
		}
	}
	if !strings.Contains(joined, "example.com/*") {
		t.Fatalf("scope desc missing: %s", joined[:200])
	}
}

func TestRunAutonomous(t *testing.T) {
	final := "# 渗透测试报告\n" + strings.Repeat("详", 700)
	srv := fakeLLM(t, final)
	defer srv.Close()
	res := Run(context.Background(), briefFor("autonomous", srv.URL), nil)
	if res.Status != "done" {
		t.Fatalf("status=%s message=%s", res.Status, res.Message)
	}
	if res.Report != final {
		t.Fatalf("autonomous report should adopt agent output verbatim")
	}
}

func TestRunStagedFailure(t *testing.T) {
	// LLM 服务器直接 500 → 退避重试耗尽后任务 failed 而非 panic
	//（策略调快，免得等满默认的 3 分钟退避序列）
	fast := llm.RetryPolicy{MaxAttempts: 3, BaseDelay: time.Millisecond, MaxDelay: 2 * time.Millisecond, Budget: time.Second}
	llm.SetRetryPolicy(fast)
	defer llm.SetRetryPolicy(llm.DefaultRetryPolicy())
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
	}))
	defer srv.Close()
	res := Run(context.Background(), briefFor("staged", srv.URL), nil)
	if res.Status != "failed" {
		t.Fatalf("expected failed, got %s", res.Status)
	}
	if !strings.Contains(res.Message, "已重试 2 次") {
		t.Fatalf("失败信息应说明重试情况: %s", res.Message)
	}
}

func TestReporterRoundtrip(t *testing.T) {
	m := &memReporter{res: &Result{}, brief: Brief{LLM: llm.Config{BaseURL: "http://x/y", Model: "m"}}}
	if _, err := m.SaveFinding(context.Background(), tools.Finding{
		Name: "SQL注入", Severity: "high", Target: "example.com", Status: "confirmed",
	}); err != nil {
		t.Fatal(err)
	}
	if err := m.UpdateFinding(context.Background(), 1, map[string]any{"status": "false_positive"}); err != nil {
		t.Fatal(err)
	}
	if m.res.Findings[0].Status != "false_positive" {
		t.Fatalf("update failed")
	}
	if m.LLMDesc() != "m @ x" {
		t.Fatalf("LLMDesc=%s", m.LLMDesc())
	}
}

func logJoin(r *Result) string {
	var b strings.Builder
	for _, l := range r.Logs {
		b.WriteString(l.Content)
		b.WriteString("\n")
	}
	return b.String()
}
