package agent

// digest.go: 工作纪要与滚动压缩（移植自 AutoPentest agent.py _digest/_compact/_note_digest）
// + STAGE_BY_TOOL 阶段推断 + 过早收工检测 + 情报注入。
// 上下文压缩后攻击链与待办不丢——长任务（120+ 步）的关键记忆机制。

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/wooluo/argus/internal/llm"
	"github.com/wooluo/argus/internal/tools"
)

// ---------- STAGE_BY_TOOL：工具 → 渗透环节推断（进度条/决策树分层用） ----------

var StageByTool = map[string]string{
	"host_discovery": "recon", "subfinder": "recon", "http_alive": "recon",
	"httpx_probe": "recon", "osint_lookup": "recon", "fofa_search": "recon",
	"nmap_scan": "mapping", "port_scan": "mapping", "katana_crawl": "mapping",
	"web_crawl": "mapping", "web_login": "mapping",
	"nuclei_scan": "vulnscan", "sqlmap_detect": "vulnscan",
	"dir_brute": "vulnscan", "dnslog_payload": "vulnscan",
	"update_finding": "verify", "dnslog_check": "verify",
	"http_fetch": "verify", "report_finding": "verify",
	"finding_step": "verify",
}

// StageOf 按工具名推断渗透环节（未知工具返回当前阶段）。
func StageOf(tool, curStage string) string {
	if s, ok := StageByTool[tool]; ok {
		return s
	}
	return curStage
}

// ---------- 工作纪要（digest） ----------

const (
	digestMax  = 80 // 超过时裁掉前半，保留近期
	digestKeep = 40
	digestLine = 120
)

// noteDigest 每次工具调用记一行，供上下文压缩后的纪要重建。
func (a *Agent) noteDigest(name string, args map[string]any, ok bool, result string) {
	var kv []string
	for k, v := range args {
		s := fmt.Sprintf("%v", v)
		if len(s) > 36 {
			s = s[:36]
		}
		kv = append(kv, k+"="+s)
	}
	brief := strings.Join(kv, " ")
	if len(brief) > digestLine {
		brief = brief[:digestLine]
	}
	outcome := "成功"
	if !ok {
		outcome = "失败"
		if strings.Contains(result, "BLOCKED") || strings.Contains(result, "拦截") {
			outcome = "拦截"
		}
	}
	first := result
	if i := strings.IndexByte(first, '\n'); i > 0 {
		first = first[:i]
	}
	if len(first) > 100 {
		first = first[:100]
	}
	a.digest = append(a.digest, fmt.Sprintf("- %s(%s) → %s: %s", name, brief, outcome, first))
	if len(a.digest) > digestMax {
		a.digest = a.digest[len(a.digest)-digestKeep:]
	}
}

// noteThought 思考进纪要（计划/判断，压缩后攻击链不丢）。
func (a *Agent) noteThought(content string) {
	if len(content) > 120 {
		content = content[:120]
	}
	a.digest = append(a.digest, "[计划/判断] "+content)
	if len(a.digest) > digestMax {
		a.digest = a.digest[len(a.digest)-digestKeep:]
	}
}

// compactMessages 滚动窗口：system + 任务书 + 工作纪要 + 最近 16 轮，替换久远对话。
func (a *Agent) compactMessages(messages []llm.Message, limit int) []llm.Message {
	if len(messages) <= limit+1 {
		return messages
	}
	const keepRecent = 16
	head := messages[:2] // system + 任务书（user brief）
	var recent []llm.Message
	if len(messages) > keepRecent {
		recent = messages[len(messages)-keepRecent:]
	} else {
		recent = messages
	}
	digestText := "[工作纪要｜此前步骤的压缩记录，据此继续：含已定的计划/攻击链（未完成的" +
		"待办按依赖继续执行）与已做动作（勿重复）]\n" +
		strings.Join(a.digest[min(60, len(a.digest)):], "\n")
	out := append(head, llm.Message{Role: "user", Content: digestText})
	return append(out, recent...)
}

// ---------- 已用工具摘要（过早收工检测用） ----------

var digestToolRe = regexp.MustCompile(`^-\s+([a-z_][a-z0-9_]*)\(`)

func (a *Agent) toolsUsedSummary() string {
	seen := map[string]bool{}
	var names []string
	for _, line := range a.digest {
		if m := digestToolRe.FindStringSubmatch(line); m != nil && !seen[m[1]] {
			seen[m[1]] = true
			names = append(names, m[1])
		}
	}
	return strings.Join(names, ", ")
}

// ---------- 过早收工检测（防早退 nudge） ----------

// prematureFinish 检测：未产出报告且步数 <60% 时拒绝结束，注入检查表继续。
// 返回 nudge 消息（空串=允许结束）。
func (a *Agent) prematureFinish(finalText string, step, maxSteps, nudges int) string {
	if !a.opts.RequireReport || nudges >= 3 {
		return ""
	}
	looksReport := len(finalText) > 600 && strings.HasPrefix(strings.TrimSpace(finalText), "#")
	usedRatio := float64(step) / float64(maxSteps)
	if looksReport || usedRatio >= 0.6 {
		return ""
	}
	tools := a.toolsUsedSummary()
	return fmt.Sprintf(`【任务尚未完成，禁止现在收尾】
你目前只执行了 %d/%d 步，已用工具：%s。
距离完成一次完整渗透测试还差很远。请立即继续，按以下检查表补齐，
每项都要真实调用工具而不是口头描述：
1) 是否已用 web_login 登录？（项目情报里有凭据就必须登录）
2) 登录后是否用 web_crawl/http_fetch 遍历了各功能页面？
3) 是否对每个带参数的入口做了注入类验证（sqlmap_detect 或 http_fetch 对比响应）？
4) 是否跑了 nuclei_scan / dir_brute 等漏洞扫描？
5) 每个确认漏洞是否用 finding_step 记录了利用链步骤？
**只有当上述都做完，才能输出以 # 开头的完整 Markdown 报告来结束任务。**
现在：先说出你的下一步，然后调用工具。`, step, maxSteps, tools)
}

// ---------- 运行中情报注入 ----------

// IntelQueue 操作员实时情报通道（pipeline 在 Context.Extra 传入，线程安全）。
type IntelQueue interface {
	Drain() []string
}

// drainIntel 取出运行期间操作员提交的情报，返回要注入的 user 消息（空=无）。
func drainIntel(tc *tools.Context) []llm.Message {
	if tc == nil || tc.Extra == nil {
		return nil
	}
	q, ok := tc.Extra["intel_queue"].(IntelQueue)
	if !ok {
		return nil
	}
	var msgs []llm.Message
	for _, intel := range q.Drain() {
		msgs = append(msgs, llm.Message{Role: "user", Content: fmt.Sprintf(
			"【操作员情报（高优先级，立即采纳）】%s\n请立即在下一步使用该情报，不要重复之前失败的尝试。", intel)})
	}
	return msgs
}
