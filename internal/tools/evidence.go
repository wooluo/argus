package tools

import (
	"context"
	"strings"
)

// ===== finding_step（对应 builtin/evidence.py：利用链步骤就地落库） =====

// FindingStepTool finding_step：为漏洞记录利用链的一个步骤。
type FindingStepTool struct{}

func (FindingStepTool) Name() string { return "finding_step" }
func (FindingStepTool) Description() string {
	return "为漏洞记录利用链的一个步骤（证据驱动交付：挖洞的同时固定复现过程）。" +
		"每步含：note 本步骤做什么、request 实际请求（如 GET http://t/a?id=1'），" +
		"response 关键响应（状态码+关键片段）、conclusion 本步证明了什么。" +
		"从入口/前置条件开始按顺序逐步记录，最终报告将按此渲染复现步骤。" +
		"每个已确认漏洞至少 2 步（触发 + 验证差异）。"
}
func (FindingStepTool) Parameters() map[string]any {
	return Schema(map[string]any{
		"finding_id": Prop("integer", "漏洞 ID（update_finding/nuclei 等返回）"),
		"note":       Prop("string", "本步骤自然语言说明（做什么/为什么）"),
		"request":    Prop("string", "真实请求：METHOD URL（+ 关键参数/载荷）"),
		"response":   Prop("string", "关键响应：状态码 + 证明片段（原文摘录，勿编造）"),
		"conclusion": Prop("string", "本步验证结论（证明了什么）"),
	}, "finding_id", "note", "request", "response")
}
func (FindingStepTool) Execute(ctx context.Context, args map[string]any, tc *Context) (string, error) {
	fid := int64(ArgInt(args, "finding_id", 0))
	if fid <= 0 {
		return "", Errorf("finding_id 必填")
	}
	note := strings.TrimSpace(ArgString(args, "note", ""))
	request := strings.TrimSpace(ArgString(args, "request", ""))
	response := strings.TrimSpace(ArgString(args, "response", ""))
	if note == "" || request == "" || response == "" {
		return "", Errorf("note/request/response 必填")
	}
	// 结构化步骤经 UpdateFinding 的 "step" 键追加（随发现的更新同步到 server，
	// 落 finding_steps——复测功能按它重放）。原先传的是无人处理的 "append_step"
	// 字符串，步骤被静默丢弃。
	err := tc.Reporter.UpdateFinding(ctx, fid, map[string]any{"step": FindingStep{
		Note: note, Request: request, Response: response,
		Conclusion: strings.TrimSpace(ArgString(args, "conclusion", "")),
	}})
	if err != nil {
		return "", err
	}
	return MustJSON(map[string]any{
		"ok": true, "finding_id": fid,
		"note": "已记录；利用链完整后用 update_finding 置 confirmed",
	}), nil
}

func init() { Register(FindingStepTool{}) }
