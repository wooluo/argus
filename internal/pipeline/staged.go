// staged.go: staged 五阶段循环，移植自 pipeline.py _execute_stages。
package pipeline

import (
	"context"
	"fmt"
	"strings"

	"github.com/wooluo/argus/internal/agent"
	"github.com/wooluo/argus/internal/llm"
	"github.com/wooluo/argus/internal/tools"
)

// runStaged 五阶段：recon → mapping → vulnscan → verify → report。
func runStaged(ctx context.Context, b Brief, tc *tools.Context, rep *memReporter,
	res *Result, client *llm.Client) {
	for _, stage := range STAGES {
		if ctx.Err() != nil {
			res.Status, res.Message = "stopped", "任务被取消"
			return
		}
		rep.Log(ctx, "system", stage, fmt.Sprintf("—— 进入阶段【%s】——", STAGE_NAMES[stage]))

		var summary string
		if stage == "report" {
			summary = genReport(ctx, b, rep, client)
			res.Report = summary
		} else {
			system, brief := stagePrompts(stage, b, rep)
			toolSet := toolsForStage(stage)
			if len(toolSet) == 0 {
				res.Status, res.Message = "failed", "阶段 "+stage+" 无可用工具"
				return
			}
			// 每阶段步数：蓝本 limits.max_agent_steps（默认 25），自定义 Agent 可覆盖
			stageSteps := 25
			if b.AgentMaxSteps > 0 {
				stageSteps = b.AgentMaxSteps
			}
			a := agent.New(client, agent.Options{
				TaskID: b.TaskID, Stage: stage, ContextLimit: 40, MaxSteps: stageSteps,
			}, toolSet, tc)
			out, err := a.Run(ctx, system, brief)
			if err != nil {
				res.Status, res.Message = failStatus(ctx, err)
				return
			}
			summary = out
		}
		rep.Log(ctx, "system", stage, "✓ 阶段完成（总结见上方思考记录）")
		_ = summary
	}
	res.Status, res.Message = "done", "全部阶段完成"
}

// failStatus 区分取消与真实失败（原版 ToolError=停止 / LLMError=失败）。
func failStatus(ctx context.Context, err error) (string, string) {
	if ctx.Err() != nil {
		return "stopped", "任务被取消"
	}
	return "failed", err.Error()
}

// toolsForStage 阶段工具集（按 STAGE_TOOLS 过滤注册表）。
func toolsForStage(stage string) []tools.Tool {
	names := STAGE_TOOLS[stage]
	if names == nil {
		return tools.All()
	}
	all := tools.All()
	out := make([]tools.Tool, 0, len(names))
	for _, t := range all {
		for _, n := range names {
			if t.Name() == n {
				out = append(out, t)
				break
			}
		}
	}
	return out
}

// stagePrompts 阶段提示词（移植 _stage_prompts）。
func stagePrompts(stage string, b Brief, rep *memReporter) (system, brief string) {
	// 自定义 Agent（staged 角色）覆盖：%s 占位符注入阶段名，安全红线保留
	if strings.TrimSpace(b.AgentPrompt) != "" {
		return strings.ReplaceAll(b.AgentPrompt, "%s", STAGE_NAMES[stage]) + "\n\n" + SAFETY_RULES,
			stagedBrief(stage, b, rep)
	}
	return fmt.Sprintf(STAGED_SYSTEM_PROMPT, STAGE_NAMES[stage]) + SAFETY_RULES,
		stagedBrief(stage, b, rep)
}

// stagedBrief 阶段任务书（内置/自定义 system 共用）。
func stagedBrief(stage string, b Brief, rep *memReporter) string {
	ips, domains := classifyScope(b)
	scopeDesc := scopeDescOf(b)
	var scopeLines []string
	if len(domains) > 0 {
		scopeLines = append(scopeLines, fmt.Sprintf(
			"- 域名目标 %d 个: %s（可做子域名枚举）", len(domains), strings.Join(domains, ", ")))
	}
	if len(ips) > 0 {
		scopeLines = append(scopeLines, fmt.Sprintf(
			"- IP/网段目标 %d 个: %s（不是域名，禁止对其调用 subfinder，直接端口/存活探测）",
			len(ips), strings.Join(ips, ", ")))
	}
	scopeBrief := strings.Join(scopeLines, "\n")
	if scopeBrief == "" {
		scopeBrief = "- （空）"
	}

	rulesLine := ""
	if strings.TrimSpace(b.Description) != "" {
		d := b.Description
		if len(d) > 2000 {
			d = d[:2000]
		}
		rulesLine = "\n## 项目说明 / 测试规范（委托方要求，必须遵守并优先应用）\n" + d + "\n"
	}

	common := "\n\n项目名称: " + b.ProjectName + "\n授权范围: " + scopeDesc + "\n" +
		rulesLine + "\n" + scopeBrief + "\n\n" + dataSummary(rep) + "\n"

	goals := map[string]string{
		"recon": reconGoal(ips, domains),
		"mapping": "## 阶段目标：资产测绘\n" +
			"1. 网段目标先用 host_discovery 摸存活（nmap -sn 在非 root 下不可用）；" +
			"对存活主机做端口与服务扫描（nmap_scan 或 port_scan，两者都支持 CIDR）\n" +
			"2. 对存活 Web 站点爬取 URL 与表单（katana_crawl 或 web_crawl）\n" +
			"3. 总结：攻击面概况（高危端口、可疑端点、技术栈）",
		"vulnscan": "## 阶段目标：漏洞扫描\n" +
			"0. 若操作员情报提供了登录凭据：先 web_login 登录建立会话，再用 " +
			"http_fetch 遍历登录后的功能页面（菜单/链接逐一访问），记录各模块与" +
			"参数入口——认证后的功能页是重点测试对象\n" +
			"1. 用 nuclei_scan 对所有存活 URL 批量扫描（建议 severity >= medium）\n" +
			"2. 对带参数的 URL 用 sqlmap_detect 做 SQL 注入检测（无参数可跳过）；" +
			"登录后的带参页面优先\n" +
			"3. 对重点站点做敏感目录探测（dir_brute）\n" +
			"4. 总结：发现漏洞的数量与严重度分布",
		"verify": "## 阶段目标：AI 分析验证\n" +
			"逐条分析漏洞库中状态为 pending 的漏洞：\n" +
			"1. 结合 evidence/poc 判断真实性；必要时用 http_alive/http_fetch 做良性" +
			"复核（如对比 ?id=1 与异常参数的响应差异，只验证不利用）\n" +
			"2. 用 update_finding 更新状态：确认(confirmed)/误报(false_positive)，附验证说明\n" +
			"3. 排除明显误报（如 WAF 页面误判、通用告警）\n" +
			"4. 总结：确认漏洞清单与误报数量",
	}
	return goals[stage] + common
}

// reconGoal 侦察阶段目标（按范围形态分派）。
func reconGoal(ips, domains []string) string {
	var steps []string
	steps = append(steps, "1. 判断范围条目形态（上方已给出分类）：")
	if len(domains) > 0 {
		steps = append(steps, fmt.Sprintf(
			"   - 域名（%s）→ 先 subfinder 子域名枚举，把发现的子域并入探测清单",
			strings.Join(domains, ", ")))
	}
	if len(ips) > 0 {
		steps = append(steps, fmt.Sprintf(
			"   - IP/网段（%s）→ 跳过子域名枚举，直接进入下一步", strings.Join(ips, ", ")))
	}
	steps = append(steps,
		"2. 对全部目标（含子域）批量做 HTTP 存活探测（httpx_probe 或 http_alive）",
		"3. 网段目标（含 /xx）先用 host_discovery 做存活发现，再对存活主机端口扫描"+
			"（port_scan 直接吃 CIDR，单主机用 nmap_scan 或 port_scan）",
		"4. 总结：存活资产数量、开放服务概况、值得后续关注的目标")
	return "## 阶段目标：侦察\n" + strings.Join(steps, "\n")
}

func scopeDescOf(b Brief) string {
	var parts []string
	for _, r := range b.Scope {
		v := r.Value
		if r.Type == "domain" {
			v += "/*"
		}
		parts = append(parts, v)
	}
	if len(parts) == 0 {
		return "(空)"
	}
	return strings.Join(parts, ", ")
}
