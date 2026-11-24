package pipeline

// roles_test.go: 分层用脑——主循环 / 审查核验 / 报告复盘各走各的模型端点；
// 没分工时都走主配置那一个。分模型 token 用量随之拆开。

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
)

// roleServer 一个角色的假模型端点：带工具的请求按脚本先发 nTool 次工具调用再
// 收工；无工具的请求回 fixed。每个响应都带 usage，便于核对分模型用量。
type roleServer struct {
	mu        sync.Mutex
	hits      int
	withTools int
	nTool     int
	fixed     string
	model     string
	url       string
}

func newRoleServer(t *testing.T, model string, nTool int, fixed string) *roleServer {
	t.Helper()
	s := &roleServer{nTool: nTool, fixed: fixed, model: model}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Tools    []json.RawMessage `json:"tools"`
			Messages []llm.Message     `json:"messages"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		s.mu.Lock()
		s.hits++
		turn := s.withTools
		usage := fmt.Sprintf(`"usage":{"prompt_tokens":10,"completion_tokens":5}`)
		if len(req.Tools) == 0 {
			s.mu.Unlock()
			b, _ := json.Marshal(s.fixed)
			_, _ = fmt.Fprintf(w, `{"choices":[{"message":{"role":"assistant","content":%s}}],%s}`, b, usage)
			return
		}
		s.withTools++
		s.mu.Unlock()
		if turn < s.nTool {
			args, _ := json.Marshal(fmt.Sprintf(`{"query":"q%d"}`, turn))
			_, _ = fmt.Fprintf(w, `{"choices":[{"message":{"role":"assistant","content":"",`+
				`"tool_calls":[{"id":"c%d","type":"function","function":{"name":"knowledge_search","arguments":%s}}]}}],%s}`,
				turn, args, usage)
			return
		}
		final, _ := json.Marshal(agentReport)
		_, _ = fmt.Fprintf(w, `{"choices":[{"message":{"role":"assistant","content":%s}}],%s}`, final, usage)
	}))
	t.Cleanup(srv.Close)
	s.url = srv.URL
	return s
}

func (s *roleServer) count() (hits, withTools int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.hits, s.withTools
}

// 三类工作各用各的模型：主循环 8 步 + 收工走强模型；收工前审查走审查模型；
// 任务后复盘走报告模型。用量按模型拆开，合计等于三者之和。
func TestRoleModelsAreUsedPerRole(t *testing.T) {
	hunt := newRoleServer(t, "glm-5.4", 8, "")
	review := newRoleServer(t, "glm-5.3-flash", 0, `{"blindspots": []}`)
	aux := newRoleServer(t, "local-m", 0, "# 复盘\n没有值得沉淀的经验。")

	b := briefFor("autonomous", hunt.url)
	b.LLM.Model = hunt.model
	b.LLMReview = llm.Config{BaseURL: review.url, Model: review.model}
	b.LLMAux = llm.Config{BaseURL: aux.url, Model: aux.model}
	b.VerifyFindings = false // 本用例只看模型分工
	res := Run(context.Background(), b, nil)
	if res.Status != "done" {
		t.Fatalf("status=%s message=%s", res.Status, res.Message)
	}

	hh, ht := hunt.count()
	if hh != 9 || ht != 9 {
		t.Errorf("主循环模型应收到 9 次带工具的请求（8 步 + 收工），实际 hits=%d withTools=%d", hh, ht)
	}
	rh, rt := review.count()
	if rh != 1 || rt != 0 {
		t.Errorf("审查模型应只收到 1 次无工具的请求（收工前审查），实际 hits=%d withTools=%d", rh, rt)
	}
	ah, at := aux.count()
	if ah < 1 || at != 0 {
		t.Errorf("报告模型应收到复盘请求且不带工具，实际 hits=%d withTools=%d", ah, at)
	}
	if res.Tokens["calls"] != int64(hh+rh+ah) || res.Tokens["prompt"] != int64(10*(hh+rh+ah)) {
		t.Errorf("合计用量应等于三个模型之和: %v (hits %d/%d/%d)", res.Tokens, hh, rh, ah)
	}
	for model, want := range map[string]int64{"glm-5.4": int64(hh), "glm-5.3-flash": int64(rh), "local-m": int64(ah)} {
		if got := res.TokensByModel[model]["calls"]; got != want {
			t.Errorf("%s 的调用次数应为 %d，实际 %d（全部: %v）", model, want, got, res.TokensByModel)
		}
	}
	if len(res.TokensByModel) != 3 {
		t.Errorf("应恰好三个模型的用量: %v", res.TokensByModel)
	}
	joined := strings.Join(logContents(res), "\n")
	if !strings.Contains(joined, "主循环 glm-5.4 @ ") || !strings.Contains(joined, "审查核验 glm-5.3-flash @ ") {
		t.Errorf("启动日志应逐类写明所用模型:\n%.300s", joined)
	}
}

// 没分工：所有请求都走主配置那一个端点，用量也只有一项。
func TestNoRolesUsesSingleModel(t *testing.T) {
	// 主循环 8 步：收工前审查与任务后复盘都会发生，但都落到同一个端点。
	// 审查回复放行；复盘拿到的同一段文本里没有 JSON 数组 → 无经验可沉淀
	main := newRoleServer(t, "local-m", 8, `{"blindspots": []}`)
	b := briefFor("autonomous", main.url)
	b.LLM.Model = main.model
	res := Run(context.Background(), b, nil)
	if res.Status != "done" {
		t.Fatalf("status=%s message=%s", res.Status, res.Message)
	}
	hh, ht := main.count()
	if hh <= ht {
		t.Errorf("审查与复盘也应走主配置端点: hits=%d withTools=%d", hh, ht)
	}
	if len(res.TokensByModel) != 1 || res.TokensByModel["local-m"]["calls"] != int64(hh) {
		t.Errorf("没分工时用量应只有主配置一项: %v (hits=%d)", res.TokensByModel, hh)
	}
}

func logContents(res *Result) []string {
	out := make([]string, 0, len(res.Logs))
	for _, l := range res.Logs {
		out = append(out, l.Content)
	}
	return out
}
