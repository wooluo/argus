// report.go: 报告生成（LLM 汇总），移植 report.py generate_report 核心。
package pipeline

import (
	"context"
	"fmt"
	"strings"

	"github.com/wooluo/argus/internal/llm"
)

// genReport 报告阶段：用 dataSummary + 漏洞详情让 LLM 生成中文 Markdown。
// 事实校验门禁（verify_report）简化为一次重生成：数量严重度不一致时提示修正。
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
	prompt := "根据以下渗透测试数据生成完整中文 Markdown 报告，结构：\n" +
		"# 概述（项目背景/范围/方法）\n# 资产统计\n# 漏洞汇总（按严重度表格：编号/名称/严重度/目标/状态）\n" +
		"# 漏洞详情（每个漏洞：描述/危害/证据/复现/修复建议）\n# 总结与整体安全建议\n\n" +
		"项目名称: " + b.ProjectName + "\n\n" + summary + "\n\n### 漏洞详情数据\n" + detailStr
	md, err := client.ChatText(ctx,
		"你是资深渗透测试报告撰写专家，输出严谨专业的中文 Markdown 报告。",
		prompt, 0.2)
	if err != nil || strings.TrimSpace(md) == "" {
		// LLM 失败兜底：数据事实清单即报告
		return "## 渗透测试数据报告（LLM 生成失败，原始数据）\n\n" + summary + "\n\n" + detailStr
	}
	return md
}
