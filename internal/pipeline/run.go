// run.go: 任务执行核心（staged 五阶段 / autonomous 单会话），移植自
// pipeline.py _execute_stages / _run_autonomous / _stage_prompts / _gen_report。
package pipeline

import (
	"context"
	"fmt"
	"math"
	"net/netip"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/wooluo/argus/internal/llm"
	"github.com/wooluo/argus/internal/scope"
	"github.com/wooluo/argus/internal/tools"
)

// snapshot memReporter 的并发安全快照（dataSummary 用）。
func (m *memReporter) snapshot() Result {
	m.mu.Lock()
	defer m.mu.Unlock()
	return Result{
		Status:   m.res.Status,
		Findings: append([]Finding(nil), m.res.Findings...),
		Assets:   append([]Asset(nil), m.res.Assets...),
		Logs:     append([]LogItem(nil), m.res.Logs...),
		Traffic:  append([]TrafficItem(nil), m.res.Traffic...),
	}
}

// Run 执行任务，返回最终结果（含 findings/assets/logs 与报告）。
// 取消 ctx 即停止任务（工具侧检查 ctx；结果照常回传）。
// onFlush 可为 nil；非 nil 时由内置 flusher 按节流周期调用（只带未经确认
// 的增量），返回 error 表示未送达——下个周期重发，任务收尾时并入最终结果。
func Run(ctx context.Context, b Brief, onFlush func(Result) error) *Result {
	res := &Result{Status: "done"}
	rep := &memReporter{res: res, brief: b}
	if onFlush != nil {
		rep.onFlush = func(_ context.Context, _ Brief, inc Result) error { return onFlush(inc) }
		rep.startFlusher(ctx)
	}
	defer rep.stopFlusher() // 执行途中 panic 也不留下上报协程
	tc := &tools.Context{
		TaskID: b.TaskID, ProjectID: b.ProjectID, ProjectName: b.ProjectName,
		Description: b.Description,
		Reporter:    rep, Limits: b.Limits,
	}
	// scope 护栏
	tc.Scope = scope.New(b.ProjectID, b.Scope, b.AllowHosts)
	// 知识条目全文拉取（knowledge_get 工具经此回连 server）
	if b.KnowledgeFetch != nil {
		if tc.Extra == nil {
			tc.Extra = map[string]any{}
		}
		tc.Extra["knowledge_fetch"] = b.KnowledgeFetch
	}
	// HITL 审批门：名单 + 门实现注入 Extra（agent executeOne 执行前检查）
	if len(b.ApprovalsRequire) > 0 || b.ApprovalGate != nil {
		if tc.Extra == nil {
			tc.Extra = map[string]any{}
		}
		tc.Extra["approvals_require"] = b.ApprovalsRequire
		if b.ApprovalGate != nil {
			tc.Extra["approval_gate"] = b.ApprovalGate
		}
	}
	// 运行中情报队列（节点轮询 server 攒入；agent 每步 Drain 注入高优先级消息）
	if b.IntelQueue != nil {
		if tc.Extra == nil {
			tc.Extra = map[string]any{}
		}
		tc.Extra["intel_queue"] = b.IntelQueue
	}
	// FOFA 凭据下发（覆盖节点环境变量；掩码值在工具侧回落 env）
	if b.FOFAEmail != "" || b.FOFAKey != "" {
		if tc.Extra == nil {
			tc.Extra = map[string]any{}
		}
		tc.Extra["fofa_email"], tc.Extra["fofa_key"] = b.FOFAEmail, b.FOFAKey
	}

	// 分层用脑：主循环 / 审查核验 / 报告复盘各用各的模型；没分工的角色与主循环
	// 共用同一个客户端
	rc := roleClients{hunt: llm.NewClient(llm.DefaultProvider(b.LLM))}
	rc.review, rc.aux = rc.hunt, rc.hunt
	if b.LLMReview != b.LLM && b.LLMReview.BaseURL != "" {
		rc.review = llm.NewClient(llm.DefaultProvider(b.LLMReview))
	}
	if b.LLMAux != b.LLM && b.LLMAux.BaseURL != "" {
		rc.aux = llm.NewClient(llm.DefaultProvider(b.LLMAux))
	}

	rep.Log(ctx, "system", "", fmt.Sprintf(
		"任务启动 · 授权范围: %s · 模式: %s · 模型: %s",
		tc.Scope.Describe(), modeName(b.Mode), rc.desc(b.LLM)))

	// 时间预算：server 按单任务最长运行时间下发；到点由看门狗代停
	tb := b.timeBudget(time.Now())
	if b.Mode == "autonomous" {
		runAutonomous(ctx, b, tc, rep, res, rc, tb)
	} else {
		runStaged(ctx, b, tc, rep, res, rc, tb)
	}
	// 停上报协程（收尾时再送一次剩余增量），以已确认游标定格最终结果的增量范围
	rep.stopFlusher()
	rep.mu.Lock()
	res.Reported.Findings, res.Reported.Assets = rep.sentF, rep.sentA
	res.Reported.Logs, res.Reported.Traffic = rep.sentL, rep.sentT
	res.Reported.Knowledge = rep.sentK
	rep.mu.Unlock()
	// 自我迭代：任务完成后自动复盘（尽力而为，失败不影响结果）
	reflectAfterRun(ctx, b, res, rep, rc.aux)
	// Token 用量：客户端级累计（含阶段模式各会话、报告生成与任务后复盘），落
	// tasks.tokens；分工后另按模型拆开。须排在复盘之后——早先算在复盘之前，
	// 复盘那几次调用从未计入。
	if p, c, calls := rc.totalTokens(); calls > 0 {
		res.Tokens = map[string]int64{"prompt": p, "completion": c, "calls": calls}
		res.TokensByModel = rc.tokensByModel()
	}
	return res
}

// roleClients 分层用脑：三类工作各自的模型客户端（没分工时是同一个）。
type roleClients struct {
	hunt, review, aux *llm.Client
}

// unique 去重后的客户端（没分工时只有一个）。
func (rc roleClients) unique() []*llm.Client {
	var out []*llm.Client
	for _, c := range []*llm.Client{rc.hunt, rc.review, rc.aux} {
		dup := false
		for _, u := range out {
			if u == c {
				dup = true
				break
			}
		}
		if !dup {
			out = append(out, c)
		}
	}
	return out
}

// totalTokens 各客户端合计（同一客户端只算一次）。
func (rc roleClients) totalTokens() (prompt, completion, calls int64) {
	for _, c := range rc.unique() {
		p, k, n := c.Tokens()
		prompt, completion, calls = prompt+p, completion+k, calls+n
	}
	return
}

// tokensByModel 按模型 ID 拆开的用量；没分工时也照样给出（一个模型一项）。
func (rc roleClients) tokensByModel() map[string]map[string]int64 {
	out := map[string]map[string]int64{}
	for _, c := range rc.unique() {
		p, k, n := c.Tokens()
		if n == 0 {
			continue
		}
		m := out[c.ModelName()]
		if m == nil {
			m = map[string]int64{}
			out[c.ModelName()] = m
		}
		m["prompt"] += p
		m["completion"] += k
		m["calls"] += n
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// desc 启动日志里的模型说明；分工后逐类列出。
func (rc roleClients) desc(main llm.Config) string {
	if rc.review == rc.hunt && rc.aux == rc.hunt {
		return modelDesc(main)
	}
	return fmt.Sprintf("主循环 %s · 审查核验 %s · 报告复盘 %s",
		modelDesc(main), modelDesc(rc.review.Config()), modelDesc(rc.aux.Config()))
}

// modelDesc 「模型 @ 主机」（主机名取自接入点）。
func modelDesc(c llm.Config) string {
	host := c.BaseURL
	if i := strings.Index(host, "://"); i >= 0 {
		host = host[i+3:]
	}
	if i := strings.Index(host, "/"); i >= 0 {
		host = host[:i]
	}
	if host == "" {
		host = "?"
	}
	return c.Model + " @ " + host
}

func modeName(mode string) string {
	if mode == "autonomous" {
		return "自主"
	}
	return "阶段流水线"
}

// timeBudget 任务的时间预算（server 按单任务最长运行时间下发）。零值=不限时。
type timeBudget struct {
	// Deadline 强制结束时刻：领取时刻 + server 给的剩余秒数，不用两端的绝对
	// 时钟相减，时钟偏差不影响。
	Deadline time.Time
	// Limit 总时长上限。
	Limit time.Duration
}

// timeBudget 由任务书字段折算（见 Brief.TimeBudgetSeconds）。
func (b Brief) timeBudget(pickedAt time.Time) timeBudget {
	if b.TimeBudgetSeconds <= 0 || b.TimeLimitSeconds <= 0 {
		return timeBudget{}
	}
	return timeBudget{
		Deadline: pickedAt.Add(time.Duration(b.TimeBudgetSeconds) * time.Second),
		Limit:    time.Duration(b.TimeLimitSeconds) * time.Second,
	}
}

// lead 提前多久提醒收敛：总时长的四分之一，至多 15 分钟。
func (tb timeBudget) lead() time.Duration {
	if lead := tb.Limit / 4; lead < 15*time.Minute {
		return lead
	}
	return 15 * time.Minute
}

// line 任务书里说明时间预算的一行；不限时返回空串。
func (tb timeBudget) line() string {
	if tb.Deadline.IsZero() {
		return ""
	}
	return fmt.Sprintf(
		"- 时间预算：本任务最长运行约 %s，目前剩余约 %s；临近结束会收到收敛提醒，到点由平台强制停止",
		minutesText(tb.Limit), minutesText(time.Until(tb.Deadline)))
}

// minutesText 时长的分钟数表述（四舍五入：29 分 59 秒不该显示成 29 分钟）。
func minutesText(d time.Duration) string {
	if d < 30*time.Second {
		return "不足 1 分钟"
	}
	return fmt.Sprintf("%d 分钟", int(math.Round(d.Minutes())))
}

// classifyScope 授权范围分成 (ips, domains)。
func classifyScope(b Brief) (ips, domains []string) {
	for _, r := range b.Scope {
		v := strings.TrimSpace(r.Value)
		if v == "" {
			continue
		}
		if _, err := netip.ParseAddr(v); err == nil {
			ips = append(ips, v)
			continue
		}
		if _, err := netip.ParsePrefix(v); err == nil {
			ips = append(ips, v)
			continue
		}
		domains = append(domains, v)
	}
	return
}

// dataSummary 当前资产与漏洞的紧凑摘要（阶段间上下文，替代原版查库）。
func dataSummary(rep *memReporter) string {
	m := rep.snapshot()
	var domains, urls, ports, techs []string
	for _, a := range m.Assets {
		switch a.Type {
		case "domain":
			domains = append(domains, a.Value)
		case "url":
			urls = append(urls, a.Value)
		case "port":
			ports = append(ports, a.Value)
		case "tech":
			techs = append(techs, a.Value)
		}
	}
	uniq := func(in []string) []string {
		seen := map[string]bool{}
		out := []string{}
		for _, v := range in {
			if !seen[v] {
				seen[v] = true
				out = append(out, v)
			}
		}
		return out
	}
	var fLines []string
	for i, f := range m.Findings {
		status := f.Status
		if status == "" {
			status = "pending"
		}
		fLines = append(fLines, fmt.Sprintf("#%d [%s] %s @ %s (%s)",
			i+1, f.Severity, f.Name, f.Target, status))
	}
	join := func(in []string, n int) string {
		if len(in) > n {
			in = in[:n]
		}
		if len(in) == 0 {
			return "无"
		}
		return strings.Join(in, ", ")
	}
	techStr := "未知"
	if len(uniq(techs)) > 0 {
		techStr = join(uniq(techs), 50)
	}
	fStr := "暂无"
	if len(fLines) > 0 {
		fStr = strings.Join(fLines, "\n")
	}
	return fmt.Sprintf(
		"### 已发现资产\n子域名(%d): %s\nURL(%d): %s\n开放端口(%d): %s\n技术栈: %s\n### 漏洞库(%d条)\n%s",
		len(domains), join(domains, 40),
		len(urls), join(urls, 60),
		len(ports), join(ports, 40),
		techStr, len(m.Findings), fStr)
}

func orDefault(s, def string) string {
	if strings.TrimSpace(s) == "" {
		return def
	}
	return s
}

// contextBlocks 两种模式共用的任务书上下文块：项目情报、知识库索引、Skills、
// 断点续测成果。原先只有自主模式拼这些块——阶段模式的漏洞扫描阶段目标里
// 写着「若操作员情报提供了登录凭据：先 web_login」，凭据却不在任务书里。
func contextBlocks(b Brief) (intelBlock, knowledgeBlock, skillsBlock, continueBlock string) {
	var lines []string
	for _, s := range b.Intel {
		if s = strings.TrimSpace(s); s == "" {
			continue
		}
		lines = append(lines, fmt.Sprintf("%d. %s", len(lines)+1, cutBytes(s, 600))) // 连续编号，空条目不留空号
	}
	if len(lines) > 0 {
		intelBlock = "## 项目情报（已知信息，第一步优先验证使用，勿浪费步数重复侦察）\n" +
			strings.Join(lines, "\n") + "\n"
	}
	if strings.TrimSpace(b.Knowledge) != "" {
		knowledgeBlock = b.Knowledge
	}
	if strings.TrimSpace(b.Skills) != "" {
		skillsBlock = b.Skills
	}
	if strings.TrimSpace(b.ContinueSummary) != "" {
		continueBlock = "## 断点续测：上一轮任务已完成的成果（勿重复，直接从缺口继续）\n" +
			b.ContinueSummary + "\n"
	}
	return
}

// cutBytes 按字节上限截断，退到字符边界（不切出半个汉字）。
func cutBytes(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}
