// Package agent 移植自 AutoPentest core/agent.py —— Agent 循环。
// 单一连续会话 + 全工具 function calling，模型自主决策；带步数预算、
// 上下文裁剪（保 system + 尾部 N 条）、进度日志、最终报告判定。
package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"regexp"
	"sync"
	"time"

	"github.com/wooluo/argus/internal/llm"
	"github.com/wooluo/argus/internal/tools"
)

// Options Agent 运行参数。
type Options struct {
	BudgetBase    int // 动态预算基准（0=不启用上调）
	TaskID        int64
	Stage         string // hunt / recon / mapping / vulnscan / verify / report
	ContextLimit  int    // 上下文裁剪保留的消息条数（原版 40）
	MaxSteps      int    // 步数预算（原版自适应 60–300）
	RequireReport bool   // 自主模式要求最终输出报告
}

// Agent LLM function-calling 循环。
type Agent struct {
	opts   Options
	client *llm.Client
	tools  []tools.Tool
	ctx    *tools.Context

	mu        sync.Mutex
	step      int
	toolCalls int
	started   time.Time

	// 推理防空转（移植自 AutoPentest agent.py）：
	// recentCalls 近 16 次工具调用签名（同参重复直接拦截）
	recentCalls   map[string]string // 签名 → 上次结果摘要
	callOrder     []string          // 签名时效（LRU 裁剪）
	digest        []string          // 工作纪要（上下文压缩后的攻击链记忆）
	nudges        int               // 过早收工纠正次数（上限 3）
	failStreak    map[string]int    // 同签名（工具+参数）连续失败计数（蓝本 _track_failure）
	tokPrompt     int64             // LLM token 累计（prompt）
	tokCompletion int64             // LLM token 累计（completion）
	tokCalls      int64             // LLM 调用次数
	// resHist 响应收敛检测：归一化指纹滑窗 3 次，全同即注入换思路提示
	resHist   [3]string
	resHistN  int
	convNoted string // 本轮收敛指纹（同轮只提示一次）
}

// New 构造 Agent。
func New(client *llm.Client, opts Options, toolSet []tools.Tool, tc *tools.Context) *Agent {
	if opts.ContextLimit <= 0 {
		opts.ContextLimit = 40
	}
	if opts.MaxSteps <= 0 {
		opts.MaxSteps = 120
	}
	return &Agent{opts: opts, client: client, tools: toolSet, ctx: tc,
		recentCalls: map[string]string{}, failStreak: map[string]int{}}
}

// Steps 实际执行步数。
func (a *Agent) Steps() int { a.mu.Lock(); defer a.mu.Unlock(); return a.step }

// ToolCalls 累计工具调用次数。
func (a *Agent) ToolCalls() int { a.mu.Lock(); defer a.mu.Unlock(); return a.toolCalls }

// Run 主循环：LLM 产生 tool_calls → 执行 → 结果回填 → 继续，直到模型给出
// 最终文本（无工具调用）或步数耗尽。返回最终输出。
func (a *Agent) Run(ctx context.Context, system, brief string) (string, error) {
	a.started = time.Now()
	// 工具 schema
	specs := make([]llm.ToolSpec, 0, len(a.tools))
	byName := map[string]tools.Tool{}
	for _, t := range a.tools {
		specs = append(specs, llm.NewToolSpec(t.Name(), t.Description(), t.Parameters()))
		byName[t.Name()] = t
	}

	messages := []llm.Message{
		{Role: "system", Content: system},
		{Role: "user", Content: brief},
	}

	for a.step < a.opts.MaxSteps {
		// 操作员运行中情报注入（高优先级，立即采纳）
		if intelMsgs := drainIntel(a.ctx); len(intelMsgs) > 0 {
			messages = append(messages, intelMsgs...)
		}
		// 预算动态上调：每 25 步按已发现资产量重算（发现远超初始估计时放宽）
		if a.step > 0 && a.step%25 == 0 && a.opts.BudgetBase > 0 {
			if snap := a.ctx; snap != nil && snap.Reporter != nil {
				if sc, ok := snap.Reporter.(interface{ AssetCount() int }); ok {
					need := budgetFor(a.opts.BudgetBase, sc.AssetCount())
					if need > a.opts.MaxSteps {
						if a.ctx.Reporter != nil {
							a.ctx.Reporter.Log(ctx, "agent", a.opts.Stage, fmt.Sprintf(
								"📈 自适应预算上调: 步数 %d → %d", a.opts.MaxSteps, need))
						}
						a.opts.MaxSteps = need
					}
				}
			}
		}
		resp, err := a.client.Chat(ctx, messages, specs, 0.2)
		if err != nil {
			return "", fmt.Errorf("LLM 调用失败: %w", err)
		}
		if len(resp.Choices) == 0 {
			return "", fmt.Errorf("LLM 返回空 choices")
		}
		a.recordTokens(resp)
		choice := resp.Choices[0]
		msg := choice.Message

		// 无工具调用 → 最终输出（过早收工检测：未产出报告且步数 <60% 时 nudge 继续）
		if len(msg.ToolCalls) == 0 {
			if msg.Content != "" {
				a.noteThought(msg.Content)
			}
			if nudge := a.prematureFinish(msg.Content, a.step, a.opts.MaxSteps, a.nudges); nudge != "" {
				a.nudges++
				if a.ctx != nil && a.ctx.Reporter != nil {
					a.ctx.Reporter.Log(ctx, "agent", a.opts.Stage, fmt.Sprintf(
						"⚠ 检测到过早收工（第 %d/%d 步），已要求继续（第 %d 次）",
						a.step, a.opts.MaxSteps, a.nudges))
				}
				messages = append(messages,
					llm.Message{Role: "assistant", Content: msg.Content},
					llm.Message{Role: "user", Content: nudge})
				continue
			}
			return msg.Content, nil
		}

		// 记录 assistant 消息（含 tool_calls）
		messages = append(messages, llm.Message{
			Role:      "assistant",
			Content:   msg.Content,
			ToolCalls: msg.ToolCalls,
		})

		// 执行每个工具调用
		for _, call := range msg.ToolCalls {
			a.mu.Lock()
			a.step++
			a.toolCalls++
			n := a.step
			a.mu.Unlock()

			toolMsg, final := a.executeOne(ctx, call, byName, n)
			messages = append(messages, toolMsg)
			if final != "" {
				return final, nil
			}
		}

		// 上下文滚动压缩：system+任务书+工作纪要+近期对话（攻击链压缩后不丢）
		messages = a.compactMessages(messages, a.opts.ContextLimit)
	}
	// 步数耗尽：返回已积累的内容（pipeline 侧模板生成报告兜底）
	if a.ctx != nil && a.ctx.Reporter != nil {
		a.ctx.Reporter.Log(ctx, "agent", a.opts.Stage,
			fmt.Sprintf("步数预算耗尽（%d 步）", a.opts.MaxSteps))
	}
	return "", nil
}

// executeOne 执行单个工具调用，返回 tool 消息；fatal 错误时返回 final 文本。
func (a *Agent) executeOne(ctx context.Context, call llm.ToolCall, byName map[string]tools.Tool, step int) (llm.Message, string) {
	var args map[string]any
	if err := json.Unmarshal([]byte(call.Function.Arguments), &args); err != nil {
		args = map[string]any{}
	}
	tool, ok := byName[call.Function.Name]
	if !ok {
		return llm.Message{
			Role: "tool", ToolCallID: call.ID, Name: call.Function.Name,
			Content: "错误: 未知工具 " + call.Function.Name,
		}, ""
	}
	// ── 重复调用闸门（近 16 次内同签名直接拦截，回上次结果摘要）──
	sig := call.Function.Name + "|" + call.Function.Arguments
	if prev, dup := a.recentCalls[sig]; dup {
		if a.ctx != nil && a.ctx.Reporter != nil {
			a.ctx.Reporter.Log(ctx, "agent", a.opts.Stage,
				"⛔ 重复调用拦截: "+call.Function.Name+"（同参数已执行过）")
		}
		tip := "⛔ 重复调用已拦截：你刚才已用完全相同的参数调用过 " + call.Function.Name +
			"，结果不会改变。上次结果摘要：" + tools.Truncate(prev, 250) +
			"。请更换参数、换一个工具，或换一条测试思路。"
		return llm.Message{Role: "tool", ToolCallID: call.ID,
			Name: call.Function.Name, Content: tip}, ""
	}
	// ── HITL 审批门：approvals.require 名单内工具执行前需人工批准（蓝本 _exec_tool）──
	if msg, blocked := a.checkApproval(ctx, call, args); blocked {
		a.noteDigest(call.Function.Name, args, false, msg)
		return llm.Message{Role: "tool", ToolCallID: call.ID,
			Name: call.Function.Name, Content: msg}, ""
	}
	started := time.Now()
	out, err := tool.Execute(ctx, args, a.ctx)
	dur := time.Since(started)
	if err == nil {
		a.recentCalls[sig] = out
		a.callOrder = append(a.callOrder, sig)
		if len(a.callOrder) > 16 {
			delete(a.recentCalls, a.callOrder[0])
			a.callOrder = a.callOrder[1:]
		}
	}
	// 工作纪要：成功/失败/拦截均记一行（上下文压缩后据此重建攻击链）
	a.noteDigest(call.Function.Name, args, err == nil, out)
	if a.ctx != nil && a.ctx.Reporter != nil {
		a.ctx.Reporter.Log(ctx, "agent", a.opts.Stage, fmt.Sprintf(
			"[%d] %s(%s) → %s (%.1fs)",
			step, call.Function.Name, compactArgs(args), resultSummary(out, err), dur.Seconds()))
	}
	if err != nil {
		// 失败连击：同签名（工具+参数）连续失败 ≥2 次注入纠正提示（蓝本 _track_failure）
		a.failStreak[sig]++
		content := "错误: " + err.Error()
		if n := a.failStreak[sig]; n >= 2 {
			content += "\n\n⚠ 注意：该调用已原样重复失败 " + fmt.Sprint(n) +
				" 次。禁止再次原样重试！请仔细阅读上面的错误说明，" +
				"按其建议更换工具或修正参数；若确无可用手段，直接输出阶段总结结束本阶段。"
		}
		return llm.Message{
			Role: "tool", ToolCallID: call.ID, Name: call.Function.Name,
			Content: content,
		}, ""
	}
	delete(a.failStreak, sig) // 成功即重置该签名的计数
	content := tools.Truncate(out, 6000)
	// ── 响应收敛检测：归一化（数字→N）指纹，滑窗 3 次全同提示换思路 ──
	if conv := a.noteConverge(out); conv != "" {
		content += "\n\n" + conv
	}
	return llm.Message{
		Role: "tool", ToolCallID: call.ID, Name: call.Function.Name,
		Content: content,
	}, ""
}

// noteConverge 归一化指纹滑窗检测；返回提示文本（空=不提示）。
func (a *Agent) noteConverge(out string) string {
	norm := digitsToN(tools.Truncate(out, 600))
	a.resHist[a.resHistN%3] = norm
	a.resHistN++
	if a.resHistN < 3 || a.convNoted == norm {
		return ""
	}
	if a.resHist[0] != a.resHist[1] || a.resHist[1] != a.resHist[2] {
		return ""
	}
	a.convNoted = norm
	a.resHistN = 0
	return "⚠ 响应收敛检测：最近 3 次工具调用返回完全相同的响应模式（仅数字不同）。" +
		"该参数空间已无新信息，禁止继续同类尝试——请立即更换目标、参数类型、工具，或转入其他攻击面。"
}

var digitRe = regexp.MustCompile(`\d+`)

func digitsToN(s string) string { return digitRe.ReplaceAllString(s, "N") }

func trimMessages(messages []llm.Message, limit int) []llm.Message {
	if len(messages) <= limit+1 {
		return messages
	}
	head := messages[:1] // system
	tail := messages[len(messages)-limit:]
	return append(head, tail...)
}

func compactArgs(args map[string]any) string {
	s := tools.MustJSON(args)
	if len(s) > 200 {
		return s[:200] + "…"
	}
	return s
}

func resultSummary(out string, err error) string {
	if err != nil {
		return "错误: " + err.Error()
	}
	if len(out) > 80 {
		return out[:80] + "…"
	}
	return out
}

// budgetFor 对数缩放步数预算（与 pipeline.adaptiveSteps 同式，agent 运行中上调用）。
func budgetFor(base, assets int) int {
	if assets <= 0 {
		return base
	}
	f := math.Log2(1+float64(assets)) / 6
	if f < 1 {
		f = 1
	}
	n := int(float64(base)*f + 0.5)
	if n < 60 {
		n = 60
	} else if n > 300 {
		n = 300
	}
	return n
}

// recordTokens 累计 LLM token 用量（蓝本 _record_tokens → tasks.tokens）。
func (a *Agent) recordTokens(resp *llm.ChatResp) {
	if resp == nil || resp.Usage == nil {
		return
	}
	a.mu.Lock()
	a.tokPrompt += int64(resp.Usage.PromptTokens)
	a.tokCompletion += int64(resp.Usage.CompletionTokens)
	a.tokCalls++
	a.mu.Unlock()
}

// Tokens 返回累计 token 用量（pipeline 写入任务记录）。
func (a *Agent) Tokens() (prompt, completion, calls int64) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.tokPrompt, a.tokCompletion, a.tokCalls
}
