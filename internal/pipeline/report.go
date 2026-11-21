// report.go: 报告生成（LLM 汇总），移植 report.py generate_report 核心。
package pipeline

import (
	"context"
	"fmt"
	"strings"

	"github.com/wooluo/argus/internal/llm"
)

// genReport 报告阶段：用 dataSummary + 漏洞详情让 LLM 生成中文 Markdown，
// 生成后走 verify_report 事实校验（蓝本 verify_report：LLM 依据数据核查报告，
// 不一致时携带修正意见重生成一次，仍不一致则附校验说明兜底交付）。
func genReport(ctx context.Context, b Brief, rep *memReporter, client *llm.Client) string {
	summary := dataSummary(rep)
	m := rep.snapshot()
	var details []string
	for _, f := range m.Findings {
		if f.Status == "false_positive" {
			continue
		}
		detail := f.Detail
		if len(detail) > 500 {
			detail = detail[:500]
		}
		poc := f.PoC
		if len(poc) > 300 {
			poc = poc[:300]
		}
		details = append(details, fmt.Sprintf(
			"- [%s] %s @ %s（%s）\n  详情: %s\n  PoC: %s",
			f.Severity, f.Name, f.Target, orDefault(f.Status, "pending"), detail, poc))
	}
	detailStr := strings.Join(details, "\n")
	if detailStr == "" {
		detailStr = "无确认漏洞"
	}
	facts := summary + "\n\n### 漏洞详情数据\n" + detailStr
	prompt := "根据以下渗透测试数据生成完整中文 Markdown 报告，结构：\n" +
		"# 概述（项目背景/范围/方法）\n# 资产统计\n# 漏洞汇总（按严重度表格：编号/名称/严重度/目标/状态）\n" +
		"# 漏洞详情（每个漏洞：描述/危害/证据/复现/修复建议）\n# 总结与整体安全建议\n\n" +
		"项目名称: " + b.ProjectName + "\n\n" + facts
	md, err := client.ChatText(ctx,
		"你是资深渗透测试报告撰写专家，输出严谨专业的中文 Markdown 报告。",
		prompt, 0.2)
	if err != nil || strings.TrimSpace(md) == "" {
		// LLM 失败兜底：数据事实清单即报告
		return "## 渗透测试数据报告（LLM 生成失败，原始数据）\n\n" + summary + "\n\n" + detailStr
	}

	// verify_report 事实校验 + 一次修正重生成
	if issues := verifyReport(ctx, md, facts, client); issues != "" {
		rep.Log(context.Background(), "system", "report", "报告自校验发现问题，重生成一次："+issues)
		fixed, err2 := client.ChatText(ctx,
			"你是资深渗透测试报告撰写专家，输出严谨专业的中文 Markdown 报告。",
			prompt+"\n\n【上一版报告的事实校验问题，必须修正】\n"+issues+
				"\n\n上一版报告：\n"+md, 0.2)
		if err2 == nil && strings.TrimSpace(fixed) != "" {
			if re := verifyReport(ctx, fixed, facts, client); re != "" {
				return fixed + "\n\n---\n> ⚠ 报告自校验仍存在待核对项：" + re
			}
			return fixed
		}
		return md + "\n\n---\n> ⚠ 报告自校验发现问题（重生成失败，请人工核对）：" + issues
	}
	return md
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
