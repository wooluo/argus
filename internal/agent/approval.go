package agent

// approval.go: HITL 审批门（移植自蓝本 agent.py _exec_tool 526-534 + core/approvals.py）。
// approvals.require 名单内的工具执行前先经 ApprovalGate 请求人工批准：
// 拒绝/超时返回 BLOCKED，模型换思路或收尾。名单由 server 经 Poll 下发
// （Extra["approvals_require"]），门实现由节点注入（Extra["approval_gate"]，
// 经 server HTTP 写 pending 并轮询决定，见 cmd/argus-node/approval.go）。

import (
	"context"
	"fmt"
	"strings"

	"github.com/wooluo/argus/internal/llm"
	"github.com/wooluo/argus/internal/tools"
)

// ApprovalGate 审批门实现：Request 阻塞等待人工决定（含超时自动拒绝），返回是否放行。
type ApprovalGate interface {
	Request(ctx context.Context, tool string, args map[string]any, purpose string) bool
}

// approvalRequire 解析审批名单（Extra["approvals_require"]，nil/空 = 无审批）。
func approvalRequire(tc *tools.Context) map[string]bool {
	if tc == nil || tc.Extra == nil {
		return nil
	}
	list, _ := tc.Extra["approvals_require"].([]string)
	if len(list) == 0 {
		return nil
	}
	m := make(map[string]bool, len(list))
	for _, t := range list {
		m[strings.TrimSpace(t)] = true
	}
	return m
}

// checkApproval 审批门检查：命中名单 → 请求人工决定。
// 返回 (BLOCKED 消息, true) 表示拦截；(空, false) 放行。
func (a *Agent) checkApproval(ctx context.Context, call llm.ToolCall, args map[string]any) (string, bool) {
	require := approvalRequire(a.ctx)
	if require == nil || !require[call.Function.Name] {
		return "", false
	}
	gate, _ := a.ctx.Extra["approval_gate"].(ApprovalGate)
	if gate == nil {
		// 名单非空但门未接线（异常配置）——fail-closed，宁拒勿放。
		if a.ctx.Reporter != nil {
			a.ctx.Reporter.Log(ctx, "agent", a.opts.Stage,
				"⛔ "+call.Function.Name+" 在审批名单但审批门未接线，按拒绝处理")
		}
		return blockedMsg("审批门未接线（配置异常）"), true
	}
	purpose := ""
	for _, k := range []string{"purpose", "why"} {
		if v, ok := args[k].(string); ok && v != "" {
			purpose = v
			break
		}
	}
	if len(purpose) > 100 {
		purpose = purpose[:100]
	}
	if a.ctx.Reporter != nil {
		a.ctx.Reporter.Log(ctx, "agent", a.opts.Stage,
			fmt.Sprintf("⛔ 调用 %s 需人工审批（等待决定中）", call.Function.Name))
	}
	if gate.Request(ctx, call.Function.Name, args, purpose) {
		if a.ctx.Reporter != nil {
			a.ctx.Reporter.Log(ctx, "agent", a.opts.Stage,
				"✅ 审批通过: "+call.Function.Name+"，继续执行")
		}
		return "", false
	}
	return blockedMsg("操作员拒绝或超时"), true
}

// blockedMsg 统一的审批拦截回话（蓝本原文）。
func blockedMsg(why string) string {
	return "BLOCKED 人工审批未通过（" + why + "）。" +
		"请换一种不触发审批的方式，或输出总结结束。"
}
