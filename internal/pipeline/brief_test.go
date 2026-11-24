package pipeline

// brief_test.go: 任务书上下文回归。项目情报 / 知识库索引 / Skills / 断点续测成果
// 原先只有自主模式拼进任务书——阶段模式的漏洞扫描阶段目标里写着「若操作员
// 情报提供了登录凭据：先 web_login」，凭据却根本不在任务书里。

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/wooluo/argus/internal/llm"
	"github.com/wooluo/argus/internal/tools"
)

func TestBriefCarriesContextInBothModes(t *testing.T) {
	var mu sync.Mutex
	var briefs []string // 每次 LLM 调用收到的 user 消息
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Messages []llm.Message `json:"messages"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		mu.Lock()
		for _, m := range req.Messages {
			if m.Role == "user" {
				briefs = append(briefs, m.Content)
			}
		}
		mu.Unlock()
		_, _ = w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"# 渗透测试报告\n` +
			strings.Repeat("详", 700) + `"}}]}`))
	}))
	defer srv.Close()

	// 带任务书的 LLM 调用次数：自主 1 次；阶段模式 4 次（侦察/测绘/扫描/验证，
	// 报告生成与事实校验不带任务书）
	for _, tc := range []struct {
		mode string
		want int
	}{{"autonomous", 1}, {"staged", 4}} {
		mu.Lock()
		briefs = nil
		mu.Unlock()
		b := briefFor(tc.mode, srv.URL)
		b.Intel = []string{"", "admin/admin 可登录 http://x"} // 含空条目：旧实现对空条目做切片会 panic
		b.Knowledge = "## 知识库索引（历史任务沉淀）\n- [k-9f2a41c0] DVWA 默认凭据 —— 测 DVWA 时先试"
		b.Skills = "## Skill 领域知识（已启用）\n Skill 正文"
		b.ContinueSummary = "### 上轮任务 #7 成果\n- 漏洞: [high] SQL 注入"

		res := Run(context.Background(), b, nil)
		if res.Status != "done" {
			t.Fatalf("%s: status=%s message=%s", tc.mode, res.Status, res.Message)
		}
		mu.Lock()
		got := briefs
		mu.Unlock()
		withIntel := 0
		for _, s := range got {
			// 任务书里的情报块标题（收工前审查的提示词里另有一行「- 项目情报：N 条」，不算）
			if !strings.Contains(s, "## 项目情报（已知信息") {
				continue
			}
			withIntel++
			for _, want := range []string{"1. admin/admin 可登录 http://x", "[k-9f2a41c0]",
				"Skill 领域知识", "上轮任务 #7"} {
				if !strings.Contains(s, want) {
					t.Errorf("%s: 带情报的任务书缺 %q", tc.mode, want)
				}
			}
		}
		if withIntel != tc.want {
			t.Errorf("%s: 应有 %d 份任务书携带项目情报，实际 %d", tc.mode, tc.want, withIntel)
		}
	}
}

// 知识条目走同一条增量通道：server 确认后才计入 Reported；会话内检索照常可用；
// 日志行只留标题，不重复整篇正文。
func TestFlushCarriesKnowledge(t *testing.T) {
	ctx := context.Background()
	m := &memReporter{res: &Result{}, brief: Brief{}}
	var got []tools.Knowledge
	m.onFlush = func(_ context.Context, _ Brief, inc Result) error {
		got = append(got, inc.Knowledge...)
		return nil
	}
	for _, title := range []string{"经验一", "经验二"} {
		if err := m.SaveKnowledge(ctx, tools.Knowledge{Title: title, Content: "正文内容", Kind: "agent"}); err != nil {
			t.Fatal(err)
		}
	}

	if hits := m.SearchKnowledge(ctx, "经验一", 5); len(hits) == 0 || hits[0]["id"] != "k1" {
		t.Errorf("本任务内沉淀的条目应可被 knowledge_search 检索到: %v", hits)
	}
	if last := m.res.Logs[len(m.res.Logs)-1]; last.Tool != "knowledge_save" ||
		!strings.Contains(last.Content, "经验二") || strings.Contains(last.Content, "正文内容") {
		t.Errorf("日志行应只记标题: %+v", last)
	}

	m.flush(ctx)
	if len(got) != 2 || m.sentK != 2 || m.inflight {
		t.Fatalf("两条知识应一次性送达并推进游标: delivered=%d sentK=%d inflight=%v",
			len(got), m.sentK, m.inflight)
	}
	// 沉淀知识各写一行「已沉淀」日志，日志游标随之前进；发现/资产游标不动
	if m.sentF != 0 || m.sentA != 0 || m.sentL != 2 {
		t.Errorf("游标不符（只应有 2 行知识日志）: findings=%d assets=%d logs=%d",
			m.sentF, m.sentA, m.sentL)
	}
}
