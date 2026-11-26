// report.go: 报告生成（LLM 汇总），移植 report.py generate_report 核心。
package pipeline

import (
	"context"
	"fmt"
	"strings"

	"github.com/wooluo/argus/internal/llm"
)

// genReport 报告阶段。遵守以下原则（源自 aibugbounty llms.txt）：
//   - 模型是记录员，不是研究员：只依据已记录事实写报告；缺的步骤写「缺失」
//     不编造；不在漏洞数、CVSS、影响上加油添醋。
//   - pending 状态的发现不进正文，放在「待核实」一节单列。
//   - 证据必须脱敏（Cookie / 密钥 / token 用 *** 替代）。
//   - 所有命中提示：由人工复现后再确认，不应视为最终结论。
func genReport(ctx context.Context, b Brief, rep *memReporter, client *llm.Client) string {
	summary := dataSummary(rep)
	m := rep.snapshot()
	// 分两类：已确认（confirmed / verified / false_positive）和待核实（pending）
	var confirmed []string
	var pending []string
	for _, f := range m.Findings {
		item := fmt.Sprintf("- [%s] %s @ %s（%s）\n  详情: %s\n  PoC: %s",
			f.Severity, f.Name, f.Target, orDefault(f.Status, "unknown"),
			trunc(redactEvidence(f.Detail), 500),
			trunc(redactEvidence(f.PoC), 300))
		if f.Status == "pending" || f.Status == "" {
			pending = append(pending, item)
		} else if f.Status != "false_positive" {
			confirmed = append(confirmed, item)
		}
	}
	var facts strings.Builder
	facts.WriteString(summary + "\n\n")
	if len(confirmed) > 0 {
		facts.WriteString("### 确认漏洞\n")
		facts.WriteString(strings.Join(confirmed, "\n") + "\n\n")
	} else {
		facts.WriteString("### 确认漏洞\n无确认漏洞\n\n")
	}
	if len(pending) > 0 {
		facts.WriteString("### 待核实\n以下发现状态为「待确认」，尚未人工复现，不计入漏洞数：\n")
		facts.WriteString(strings.Join(pending, "\n") + "\n\n")
	}
	system := `你是资深渗透测试报告撰写专家。输出严谨专业的中文 Markdown 报告。

报告规则：
1. 只依据下方"漏洞详情数据"写报告。如果一个步骤在数据中找不到记录，就写"缺失"，不要补上你凭推理填补的步骤。
2. 漏洞数目与严重度以数据为准。不要自行推算 CVSS 分数，不夸大影响。
3. 所有发现都应标注"需人工复现确认"。
4. 正文只包含 status 为 confirmed 或 verified 的漏洞。pending 状态的发现放在"待核实"一节。
5. 不得编造复现步骤、出站域名或外网地址。`

	prompt := "根据以下渗透测试数据生成完整中文 Markdown 报告，结构：\n" +
		"# 概述（项目背景/范围/方法）\n# 资产统计\n# 漏洞汇总（按严重度表格：编号/名称/严重度/目标/状态）\n" +
		"# 漏洞详情（每个漏洞：描述/危害/证据/复现/修复建议）\n# 待核实\n# 总结与整体安全建议\n\n" +
		"项目名称: " + b.ProjectName + "\n\n### 漏洞详情数据\n" + facts.String()
	md, err := client.ChatText(ctx, system, prompt, 0.2)
	if err != nil || strings.TrimSpace(md) == "" {
		return "## 渗透测试数据报告（LLM 生成失败，原始数据）\n\n" + summary + "\n\n### 确认漏洞\n" + strings.Join(confirmed, "\n") + "\n\n### 待核实\n" + strings.Join(pending, "\n")
	}

	// verify_report 事实校验 + 一次修正重生成
	if issues := verifyReport(ctx, md, facts.String(), client); issues != "" {
		rep.Log(context.Background(), "system", "report", "报告自校验发现问题，重生成一次："+issues)
		fixed, err2 := client.ChatText(ctx,
			"你是资深渗透测试报告撰写专家，输出严谨专业的中文 Markdown 报告。",
			prompt+"\n\n【上一版报告的事实校验问题，必须修正】\n"+issues+
				"\n\n上一版报告：\n"+md, 0.2)
		if err2 == nil && strings.TrimSpace(fixed) != "" {
			if re := verifyReport(ctx, fixed, facts.String(), client); re != "" {
				return fixed + "\n\n---\n> ⚠ 报告自校验仍存在待核对项：" + re
			}
			return fixed
		}
		return md + "\n\n---\n> ⚠ 报告自校验发现问题（重生成失败，请人工核对）：" + issues
	}
	return md
}

// redactEvidence 脱敏：把 Cookie、Authorization、token 等敏感字段的值替换为 ***。
func redactEvidence(s string) string {
	if s == "" {
		return s
	}
	replacer := strings.NewReplacer(
		"Cookie: ", "Cookie: *** ",
		"Set-Cookie: ", "Set-Cookie: *** ",
		"Authorization: ", "Authorization: *** ",
		"Bearer ", "Bearer ***",
		"token=", "token=***",
		"secret=", "secret=***",
		"api_key=", "api_key=***",
		"apiKey=", "apiKey=***",
	)
	return replacer.Replace(s)
}

// verifyReport 报告事实校验（蓝本 verify_report）：LLM 对照原始数据核查报告，
// 返回性质/数量/严重度不一致清单（空=通过）。
func verifyReport(ctx context.Context, report, facts string, client *llm.Client) string {
	verdict, err := client.ChatText(ctx,
		"你是报告质量审核员。只依据提供的原始数据核查报告，不引入外部知识。",
		"核对以下渗透测试报告与原始数据是否一致（漏洞数量、严重度、目标、状态），\n"+
			"发现不一致逐条列出；完全一致时只输出「PASS」。\n\n"+
			"### 原始数据\n"+facts+"\n\n### 报告\n"+report, 0.1)
	if err != nil || verdict == "" {
		return "" // 校验失败不阻塞交付
	}
	v := strings.TrimSpace(verdict)
	if v == "PASS" || strings.HasPrefix(v, "PASS") {
		return ""
	}
	if len(v) > 600 {
		v = v[:600]
	}
	return v
}

// trunc 字符截断（避免 PoC/Detail 超长撑爆上下文）。
func trunc(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
