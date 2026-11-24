package pipeline

// review_test.go: 收工前盲区审查与收工后独立核验。
//
// 假 LLM 把请求分三类：带工具的请求按序取 script（Agent 轮次与核验轮次共用一个
// 计数）；无工具的请求里，第一个是收工前审查、其余是报告生成与事实校验。

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

type flowLLM struct {
	mu      sync.Mutex
	tools   int
	script  []string // 带工具的请求：每条一个 message 的 JSON
	reviews []string // 无工具的请求：第一个起按序；超出后重复最后一条
	noTools int
}

func (f *flowLLM) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Tools  []json.RawMessage `json:"tools"`
			System string            `json:"system"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		f.mu.Lock()
		defer f.mu.Unlock()
		if len(req.Tools) == 0 {
			i := min(f.noTools, len(f.reviews)-1)
			f.noTools++
			b, _ := json.Marshal(f.reviews[i])
			_, _ = fmt.Fprintf(w, `{"choices":[{"message":{"role":"assistant","content":%s}}]}`, b)
			return
		}
		i := min(f.tools, len(f.script)-1)
		f.tools++
		_, _ = fmt.Fprintf(w, `{"choices":[{"message":%s}]}`, f.script[i])
	})
}

// call 一次工具调用的 assistant 消息；args 是函数参数的 JSON 文本。
func call(name, args string) string {
	esc, _ := json.Marshal(args)
	return fmt.Sprintf(`{"role":"assistant","content":"","tool_calls":[{"id":"c","type":"function",`+
		`"function":{"name":%q,"arguments":%s}}]}`, name, string(esc))
}

func say(text string) string {
	b, _ := json.Marshal(map[string]string{"role": "assistant", "content": text})
	return string(b)
}

var (
	// agentReport Agent 自己写的报告（以 # 开头、篇幅够长）。
	agentReport = "# 渗透测试报告\n\n" + "发现若干问题。" + strings.Repeat("正文内容详述。", 60)
	// templateReport 模板报告，便于与 Agent 的报告区分。
	templateReport = "# 模板生成的报告\n\n" + strings.Repeat("模板正文。", 80)
)

func runFlow(t *testing.T, mode string, b Brief, f *flowLLM) (*Result, []string) {
	t.Helper()
	srv := httptest.NewServer(f.handler())
	t.Cleanup(srv.Close)
	b.Mode = mode
	b.LLM = llm.Config{BaseURL: srv.URL, APIKey: "k", Model: "fake"}
	llm.SetRetryPolicy(llm.RetryPolicy{MaxAttempts: 1})
	t.Cleanup(func() { llm.SetRetryPolicy(llm.DefaultRetryPolicy()) })
	res := Run(context.Background(), b, nil)
	var logs []string
	for _, l := range res.Logs {
		logs = append(logs, l.Content)
	}
	return res, logs
}

func logsContain(logs []string, sub string) bool {
	for _, l := range logs {
		if strings.Contains(l, sub) {
			return true
		}
	}
	return false
}

// 收工前审查发现缺口：不许收工 → Agent 补一步 → 再次收工、审查通过 → 才结束。
func TestFinishReviewInAutonomousRun(t *testing.T) {
	b := briefFor("autonomous", "")
	b.VerifyFindings = false // 本用例只看收工前审查
	f := &flowLLM{
		script: []string{
			say(agentReport + "（第一版）"),
			call("knowledge_search", `{"query":"x"}`), // 审查后补一步（会话内检索，无网络）
			say(agentReport + "（补齐版）"),
		},
		reviews: []string{
			"审查意见如下：\n```json\n" + `{"blindspots":[` +
				`{"area":"认证后功能面","risk":"low","question":"登录后的页面测了吗","suggestion":"web_login 后遍历"},` +
				`{"area":"未记录的漏洞","risk":"high","question":"有没有验证过却没入库的漏洞","suggestion":"用 report_finding 入库"}]}` +
				"\n```",
			`{"blindspots": []}`,
		},
	}
	res, logs := runFlow(t, "autonomous", b, f)
	if res.Status != "done" {
		t.Fatalf("status=%s message=%s", res.Status, res.Message)
	}
	if !strings.Contains(res.Report, "补齐版") || strings.Contains(res.Report, "第一版") {
		t.Fatalf("应在补齐后以第二份报告收工: %.80q", res.Report)
	}
	if !logsContain(logs, "收工前审查发现缺口") {
		t.Errorf("拦截应留日志: %v", logs)
	}
	if f.noTools != 2 || f.tools != 3 {
		t.Errorf("应审查两次、Agent 跑三轮: reviews=%d turns=%d", f.noTools, f.tools)
	}
}

// 收工后独立核验：核验者改判一条误报 → 报告按数据重写并附核验结果；
// 另两条一条确认、一条未动。
func TestIndependentVerificationOverturnsFinding(t *testing.T) {
	b := briefFor("autonomous", "")
	b.VerifyFindings = true // server 下发的开关
	f := &flowLLM{
		script: []string{
			call("report_finding", `{"name":"SQL 注入","severity":"high","target":"http://t/a","detail":"id 参数回显报错","status":"confirmed"}`),
			call("report_finding", `{"name":"XSS","severity":"medium","target":"http://t/b","detail":"搜索框回显","status":"confirmed"}`),
			call("report_finding", `{"name":"信息泄露","severity":"low","target":"http://t/c","detail":"备份文件可访问","status":"confirmed"}`),
			say(agentReport + "（执行者的报告）"),
			// —— 以下为核验者的轮次 ——
			call("update_finding", `{"finding_id":1,"status":"false_positive","note":"任何参数都回显同样报错，是 WAF 拦截页"}`),
			call("update_finding", `{"finding_id":2,"status":"confirmed","note":"对比正常与异常参数，响应差异稳定复现"}`),
			say("核验完成：1 条误报，1 条确认，1 条未能复核（目标不可达）。"),
		},
		reviews: []string{`{"blindspots": []}`, templateReport},
	}
	res, logs := runFlow(t, "autonomous", b, f)
	if res.Status != "done" {
		t.Fatalf("status=%s message=%s", res.Status, res.Message)
	}

	if !strings.Contains(res.Message, "独立核验改判了 1 条发现") {
		t.Errorf("任务结论应说明改判: %s", res.Message)
	}
	// 执行者的报告已不成立：按模板重写
	if strings.Contains(res.Report, "执行者的报告") || !strings.Contains(res.Report, "模板生成的报告") {
		t.Errorf("改判后应按模板重写报告: %.80q", res.Report)
	}
	// 核验结果附在报告里
	for _, want := range []string{"## 独立核验", "SQL 注入 @ http://t/a | ❌ 改判为误报：任何参数都回显同样报错",
		"XSS @ http://t/b | ✅ 复核确认：对比正常与异常参数", "信息泄露 @ http://t/c | ⚠️ 未复核"} {
		if !strings.Contains(res.Report, want) {
			t.Errorf("报告的核验段落缺 %q:\n%s", want, res.Report[len(res.Report)-700:])
		}
	}
	// 核验结论写回了发现本身
	byName := map[string]Finding{}
	for _, f := range res.Findings {
		byName[f.Name] = f
	}
	if f := byName["SQL 注入"]; f.Status != "false_positive" || !strings.Contains(f.Detail, "【误报判定】") {
		t.Errorf("误报结论未写回: %+v", f)
	}
	if f := byName["XSS"]; f.Status != "confirmed" || !strings.Contains(f.Detail, "【核验确认】对比正常与异常参数") {
		t.Errorf("确认说明未写回: %+v", f)
	}
	if f := byName["信息泄露"]; f.Status != "confirmed" || strings.Contains(f.Detail, "【核验") {
		t.Errorf("未复核的条目不应被改动: %+v", f)
	}
	if !logsContain(logs, "✓ 独立核验完成：确认 1 条、改判误报 1 条、未复核 1 条") {
		t.Errorf("应留核验汇总日志: %v", logs)
	}
}

// 核验全部通过：执行者的报告原样采用，只在末尾附核验结果。
func TestIndependentVerificationKeepsAgentReport(t *testing.T) {
	b := briefFor("autonomous", "")
	b.VerifyFindings = true
	f := &flowLLM{
		script: []string{
			call("report_finding", `{"name":"XSS","severity":"medium","target":"http://t/b","detail":"搜索框回显","status":"confirmed"}`),
			say(agentReport),
			call("update_finding", `{"finding_id":1,"status":"confirmed","note":"复核回显成立"}`),
			say("核验完成。"),
		},
		reviews: []string{`{"blindspots": []}`},
	}
	res, _ := runFlow(t, "autonomous", b, f)
	if res.Status != "done" {
		t.Fatalf("status=%s message=%s", res.Status, res.Message)
	}
	if !strings.HasPrefix(res.Report, "# 渗透测试报告") || !strings.Contains(res.Report, "✅ 复核确认：复核回显成立") {
		t.Fatalf("应保留执行者的报告并附核验结果: %.80q … %s", res.Report, res.Report[len(res.Report)-300:])
	}
	if !strings.Contains(res.Message, "含独立核验结果") {
		t.Errorf("message=%s", res.Message)
	}
}

// 没有发现 → 不起核验会话；设置关闭 → 也不核验。
func TestVerificationSkippedWhenNothingToDoOrDisabled(t *testing.T) {
	b := briefFor("autonomous", "")
	b.VerifyFindings = true
	f := &flowLLM{script: []string{say(agentReport)}, reviews: []string{`{"blindspots": []}`}}
	if res, logs := runFlow(t, "autonomous", b, f); logsContain(logs, "独立核验") || f.tools != 1 {
		t.Errorf("没有发现时不应核验: turns=%d logs=%v", f.tools, logs)
	} else if res.Status != "done" {
		t.Fatalf("status=%s", res.Status)
	}

	b2 := briefFor("autonomous", "")
	b2.VerifyFindings = false
	f2 := &flowLLM{
		script: []string{
			call("report_finding", `{"name":"XSS","severity":"medium","target":"http://t/b","detail":"回显","status":"confirmed"}`),
			say(agentReport),
		},
		reviews: []string{`{"blindspots": []}`},
	}
	if _, logs := runFlow(t, "autonomous", b2, f2); logsContain(logs, "独立核验") || f2.tools != 2 {
		t.Errorf("设置关闭时不应核验: turns=%d logs=%v", f2.tools, logs)
	}
}

func TestParseBlindspots(t *testing.T) {
	out := "我先看了一下记录。\n```json\n" + `{"blindspots":[` +
		`{"area":"低风险项","risk":"low","question":"q1","suggestion":"s1"},` +
		`{"area":"","risk":"high","question":"空条目","suggestion":"应被跳过"},` +
		`{"area":"高风险项","risk":"HIGH","question":"q2","suggestion":"s2"},` +
		`{"area":"缺补法","risk":"weird","question":"q3"},` +
		`{"area":"含花括号 } 与 \"引号\"","risk":"medium","question":"q4","suggestion":"s4"}]}` +
		"\n```\n以上。"
	spots := parseBlindspots(out)
	if len(spots) != 4 {
		t.Fatalf("应解析出 4 条: %+v", spots)
	}
	want := []string{"高风险项", "缺补法", "含花括号 } 与 \"引号\"", "低风险项"}
	for i, w := range want {
		if spots[i].Area != w {
			t.Errorf("第 %d 条应为 %q，得到 %+v", i, w, spots[i])
		}
	}
	if spots[1].Risk != "medium" || spots[3].Risk != "low" {
		t.Errorf("未知风险应归为 medium，且保持同风险的录入顺序: %+v", spots)
	}
	for _, empty := range []string{`{"blindspots": []}`, "没有缺口", "", "not json {"} {
		if got := parseBlindspots(empty); got != nil {
			t.Errorf("%q 应解析为空，得到 %+v", empty, got)
		}
	}
}

// 核验者的任务书只列未被判误报的发现，按严重度排序；超出上限的部分记为未复核。
func TestVerifyBriefOrdersAndCaps(t *testing.T) {
	rep := &memReporter{res: &Result{}, brief: Brief{}}
	ctx := context.Background()
	for _, f := range []tools.Finding{
		{Name: "低危", Severity: "low", Target: "http://t/low", Status: "confirmed"},
		{Name: "严重", Severity: "critical", Target: "http://t/crit", Status: "confirmed",
			Steps: []tools.FindingStep{{Note: "触发", Request: "GET http://t/crit?a=1", Response: "500", Conclusion: "报错"}}},
		{Name: "已判误报", Severity: "high", Target: "http://t/fp", Status: "false_positive"},
	} {
		if _, err := rep.SaveFinding(ctx, f); err != nil {
			t.Fatal(err)
		}
	}
	brief := verifyBrief(briefFor("autonomous", ""), rep.snapshot(), []int{1, 0})
	if i, j := strings.Index(brief, "#2 [critical] 严重"), strings.Index(brief, "#1 [low] 低危"); i < 0 || j < 0 || i > j {
		t.Errorf("应按严重度从高到低列出，且沿用节点内编号:\n%s", brief)
	}
	if strings.Contains(brief, "已判误报") {
		t.Errorf("已判误报的发现不应进入核验清单")
	}
	for _, want := range []string{"步骤 1：GET http://t/crit?a=1 → 500", "结论：报错", "finding_id 即下方的 #编号"} {
		if !strings.Contains(brief, want) {
			t.Errorf("任务书缺 %q", want)
		}
	}

	if v := (&verifyResult{Skipped: 3}).section(); !strings.Contains(v, "另有 3 条超出单次核验上限") {
		t.Errorf("超出上限应注明: %s", v)
	}
	if verifyNote("原理\n\n【误报判定】WAF 拦截页") != "WAF 拦截页" || verifyNote("没有标记") != "" {
		t.Error("核验说明应取详情末尾的标记段")
	}
}
