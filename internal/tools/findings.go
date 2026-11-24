package tools

import (
	"context"
	"strings"
)

// ===== 漏洞上报/管理（对应 builtin/report_finding.py + manage_findings.py） =====
//
// 原版直连 SQLAlchemy；argus 节点体系下经 Reporter 落 server（去重由 server 侧负责）。

var sevSet = map[string]bool{"critical": true, "high": true, "medium": true, "low": true, "info": true}

// ReportFindingTool report_finding：Agent 主动创建漏洞条目。
type ReportFindingTool struct{}

func (ReportFindingTool) Name() string { return "report_finding" }
func (ReportFindingTool) Description() string {
	return "创建（上报）一个新漏洞条目——凡是你通过工具验证确认的漏洞（注入回显、响应差异、" +
		"CSRF、XSS、信息泄露、配置错误等），**必须**用本工具入库。已有条目改状态才用 update_finding。" +
		"上报后系统自动去重（同名+同目标只保留一条）。"
}
func (ReportFindingTool) Parameters() map[string]any {
	return Schema(map[string]any{
		"name":     Prop("string", "漏洞名称，如「DVWA 命令注入（exec 模块）」"),
		"severity": PropEnum("严重度", "critical", "high", "medium", "low", "info"),
		"target":   Prop("string", "漏洞位置 URL（尽量精确到参数）"),
		"detail":   Prop("string", "原理与影响描述（中文）"),
		"evidence": Prop("string", "关键证据原文（回显内容/响应差异摘录）"),
		"poc":      Prop("string", "复现请求（METHOD URL + 参数）"),
		"status":   PropEnum("已验证到证据即 confirmed，默认 confirmed", "confirmed", "pending"),
	}, "name", "severity", "target", "detail")
}
func (ReportFindingTool) Execute(ctx context.Context, args map[string]any, tc *Context) (string, error) {
	name := strings.TrimSpace(ArgString(args, "name", ""))
	target := strings.TrimSpace(ArgString(args, "target", ""))
	if name == "" || target == "" {
		return "", Errorf("name 与 target 必填")
	}
	severity := ArgString(args, "severity", "high")
	if !sevSet[severity] {
		return "", Errorf("severity 必须是 critical/high/medium/low/info")
	}
	status := ArgString(args, "status", "confirmed")
	if status != "confirmed" && status != "pending" {
		status = "confirmed"
	}
	f := Finding{
		Name:     Truncate(name, 256),
		Severity: severity,
		Target:   Truncate(target, 512),
		Detail:   Truncate(ArgString(args, "detail", ""), 20000),
		Evidence: Truncate(ArgString(args, "evidence", ""), 20000),
		PoC:      Truncate(ArgString(args, "poc", ""), 20000),
		Source:   "agent",
		Status:   status,
	}
	fid, err := tc.Reporter.SaveFinding(ctx, f)
	if err != nil {
		return "", err
	}
	return MustJSON(map[string]any{
		"ok": true, "finding_id": fid,
		"note": "已入库（同名同目标只保留一条）。接下来用 finding_step 记录利用链步骤、update_finding 更新状态",
	}), nil
}

func init() { Register(ReportFindingTool{}) }

// UpdateFindingTool update_finding：更新已有条目状态（对应 manage_findings.py）。
type UpdateFindingTool struct{}

func (UpdateFindingTool) Name() string { return "update_finding" }
func (UpdateFindingTool) Description() string {
	return "更新**已存在**漏洞条目的状态（确认为真 confirmed / 误报 false_positive）。" +
		"⚠ 只能更新漏洞库里已有的条目；你新验证出来的漏洞请先用 report_finding 创建入库，" +
		"再用本工具或 finding_step 补充。"
}
func (UpdateFindingTool) Parameters() map[string]any {
	return Schema(map[string]any{
		"finding_id": Prop("integer", "漏洞 ID"),
		"status":     PropEnum("目标状态", "confirmed", "false_positive"),
		"note":       Prop("string", "验证说明 / 误报原因：写清依据（复核了什么、看到什么），会附在该条目的详情里"),
	}, "finding_id", "status", "note")
}
func (UpdateFindingTool) Execute(ctx context.Context, args map[string]any, tc *Context) (string, error) {
	fid := int64(ArgInt(args, "finding_id", 0))
	status := ArgString(args, "status", "")
	if status != "confirmed" && status != "false_positive" {
		return "", Errorf("status 只能是 confirmed 或 false_positive")
	}
	note := ArgString(args, "note", "")
	patch := map[string]any{"status": status}
	if note != "" {
		patch["note"] = note
	}
	if err := tc.Reporter.UpdateFinding(ctx, fid, patch); err != nil {
		return "", err
	}
	return MustJSON(map[string]any{
		"ok": true, "finding_id": fid, "status": status,
		"note": "状态与验证说明已写回该条目，并同步到 server 的发现库",
	}), nil
}

func init() { Register(UpdateFindingTool{}) }
