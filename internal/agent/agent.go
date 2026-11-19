// Package agent 移植自 AutoPentest core/agent.py —— Agent 循环。
// 单一连续会话 + 全工具 function calling，模型自主决策；带步数预算、
// 上下文裁剪（保 system + 尾部 N 条）、进度日志、最终报告判定。
package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/wooluo/argus/internal/llm"
	"github.com/wooluo/argus/internal/tools"
)

// Options Agent 运行参数。
type Options struct {
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
}

// New 构造 Agent。
func New(client *llm.Client, opts Options, toolSet []tools.Tool, tc *tools.Context) *Agent {
	if opts.ContextLimit <= 0 {
		opts.ContextLimit = 40
	}
	if opts.MaxSteps <= 0 {
		opts.MaxSteps = 120
	}
	return &Agent{opts: opts, client: client, tools: toolSet, ctx: tc}
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
		resp, err := a.client.Chat(ctx, messages, specs, 0.2)
		if err != nil {
			return "", fmt.Errorf("LLM 调用失败: %w", err)
		}
		if len(resp.Choices) == 0 {
			return "", fmt.Errorf("LLM 返回空 choices")
		}
		choice := resp.Choices[0]
		msg := choice.Message

		// 无工具调用 → 最终输出
		if len(msg.ToolCalls) == 0 {
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

		// 上下文裁剪：保 system + 尾部 ContextLimit 条
		messages = trimMessages(messages, a.opts.ContextLimit)
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
	started := time.Now()
	out, err := tool.Execute(ctx, args, a.ctx)
	dur := time.Since(started)
	if a.ctx != nil && a.ctx.Reporter != nil {
		a.ctx.Reporter.Log(ctx, "agent", a.opts.Stage, fmt.Sprintf(
			"[%d] %s(%s) → %s (%.1fs)",
			step, call.Function.Name, compactArgs(args), resultSummary(out, err), dur.Seconds()))
	}
	if err != nil {
		// 工具错误回给模型继续推理（原版行为），fatal（如 ScopeViolation）也回模型
		return llm.Message{
			Role: "tool", ToolCallID: call.ID, Name: call.Function.Name,
			Content: "错误: " + err.Error(),
		}, ""
	}
	return llm.Message{
		Role: "tool", ToolCallID: call.ID, Name: call.Function.Name,
		Content: tools.Truncate(out, 6000),
	}, ""
}

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
