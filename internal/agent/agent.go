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
	"strings"
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
	// FinishReview 收工前审查（pipeline 注入；nil=不做）。Agent 给出最终输出时先
	// 交给它过目：返回非空消息即「不许收工」，消息注入对话让其补齐；返回空才
	// 接受收工。审查在独立上下文里进行——干活的 Agent 在同一个上下文里既执行
	// 又自评，容易把自己做过的事当成做全了。
	FinishReview func(ctx context.Context, finalText, digest string) string
	// Deadline 任务强制结束时刻（server 的看门狗到点代停）；零值=不限时。
	Deadline time.Time
	// WrapUpLead 距 Deadline 多久提醒收敛（只提醒一次；0=不提醒）。
	WrapUpLead time.Duration
}

const (
	// maxFinishReviews 收工前审查最多拦下几次。审查员总能挑出点什么，不能让它
	// 把任务拖成死循环；超过后无条件接受收工。
	maxFinishReviews = 2
	// budgetCheckEvery 每隔多少步按已发现资产量重算一次步数预算。
	budgetCheckEvery = 25
	// idleStreakLimit 连续多少步没有任何新资产 / 新发现算一次「无进展」；
	// maxIdleNudges 每个会话最多提醒几次。
	//
	// 这是提醒而不是熔断：深度手工验证阶段连续多步不出新资产是正常的，
	// 而 sapper-v2 那种「一步之内图没变就停」只适用于「每步都必须落事实」的
	// 执行者。已有的闸门各管一种打转——同参重复、响应收敛、同调用连败；
	// 这一条补的是「换着花样调用却一无所获」的游走。
	idleStreakLimit = 15
	maxIdleNudges   = 3
)

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

	reviews         int      // 收工前审查已拦下的次数
	nextBudgetCheck int      // 下一次重算步数预算的步数
	lastReport      string   // 最近一份像报告的收工输出（预算耗尽时兜底返回）
	warnedDeadline  bool     // 已发过收敛提醒
	pendingNudges   []string // 工具消息之后才注入的提醒（不打乱 tool 消息的次序）
	lastYield       int      // 上一步时的「资产 + 发现」总数
	yieldSeen       bool     // lastYield 是否已初始化
	idleStreak      int      // 连续无进展的步数
	idleNudges      int      // 已发出的无进展提醒次数

	// 推理防空转（移植自 AutoPentest agent.py）：
	// recentCalls 近 16 次工具调用签名（同参重复直接拦截）
	recentCalls map[string]string // 签名 → 上次结果摘要
	callOrder   []string          // 签名时效（LRU 裁剪）
	digest      []string          // 工作纪要（上下文压缩后的攻击链记忆）
	nudges      int               // 过早收工纠正次数（上限 3）
	failStreak  map[string]int    // 同签名（工具+参数）连续失败计数（蓝本 _track_failure）
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
		recentCalls: map[string]string{}, failStreak: map[string]int{},
		nextBudgetCheck: budgetCheckEvery}
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
		// 时间预算：临近强制结束前提醒收敛（只提醒一次）——到点由 server 的
		// 看门狗代停，不提醒的话长任务多半是被拦腰截断、连报告都没写
		if nudge := a.deadlineNudge(ctx); nudge != "" {
			messages = append(messages, llm.Message{Role: "user", Content: nudge})
		}
		// 上一轮工具调用触发的无进展提醒
		for _, nudge := range a.pendingNudges {
			messages = append(messages, llm.Message{Role: "user", Content: nudge})
		}
		a.pendingNudges = nil
		// 预算动态上调：每 25 步按已发现资产量重算（发现远超初始估计时放宽）。
		// 用「下次检查点」而不是 step%25：一轮可能连发多个工具调用，步数会跨过
		// 整除点而永远检查不到（原先即如此，加上 BudgetBase 从未被赋值、Reporter
		// 的 AssetCount 未导出，这段上调一直是死代码）。
		if a.step >= a.nextBudgetCheck && a.opts.BudgetBase > 0 {
			a.nextBudgetCheck += budgetCheckEvery
			if snap := a.ctx; snap != nil && snap.Reporter != nil {
				if sc, ok := snap.Reporter.(interface{ AssetCount() int }); ok {
					need := budgetFor(a.opts.BudgetBase, sc.AssetCount())
					if need > a.opts.MaxSteps {
						a.ctx.Reporter.Log(ctx, "agent", a.opts.Stage, fmt.Sprintf(
							"📈 自适应预算上调: 步数 %d → %d", a.opts.MaxSteps, need))
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
			// 像报告的收工输出先留底：审查后继续跑却把预算耗尽时，宁可交付这一版
			if looksReport(msg.Content) {
				a.lastReport = msg.Content
			}
			if nudge := a.finishReview(ctx, msg.Content); nudge != "" {
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
			a.noteYield(ctx)
		}

		// 上下文滚动压缩：system+任务书+工作纪要+近期对话（攻击链压缩后不丢）
		messages = a.compactMessages(messages, a.opts.ContextLimit)
	}
	// 步数耗尽：有留底的报告就交付它，否则交 pipeline 用模板生成
	if a.ctx != nil && a.ctx.Reporter != nil {
		a.ctx.Reporter.Log(ctx, "agent", a.opts.Stage,
			fmt.Sprintf("步数预算耗尽（%d 步）", a.opts.MaxSteps))
	}
	if a.lastReport != "" {
		return a.lastReport, nil
	}
	return "", nil
}

// looksReport 文本是否像一份报告（以 # 标题开头且有足够篇幅）。
func looksReport(s string) bool {
	return len(s) > 600 && strings.HasPrefix(strings.TrimSpace(s), "#")
}

// deadlineNudge 进入收敛期时返回一条提醒（每个会话至多一次）。
func (a *Agent) deadlineNudge(ctx context.Context) string {
	if a.opts.Deadline.IsZero() || a.warnedDeadline || a.opts.WrapUpLead <= 0 ||
		time.Until(a.opts.Deadline) > a.opts.WrapUpLead {
		return ""
	}
	a.warnedDeadline = true
	left := time.Until(a.opts.Deadline).Round(time.Minute)
	if left < 0 {
		left = 0
	}
	if a.ctx != nil && a.ctx.Reporter != nil {
		a.ctx.Reporter.Log(ctx, "agent", a.opts.Stage, fmt.Sprintf(
			"⏰ 时间预算：距强制结束约 %s，已提醒收敛", left))
	}
	return fmt.Sprintf("⏰ 时间预算：本任务距强制结束还剩约 %s。从现在起不要再开辟新的测试方向："+
		"把手上这一步收尾；给已验证的漏洞补齐利用链步骤（finding_step）与状态（update_finding）；"+
		"然后输出完整的最终报告，没来得及测的在报告里单列「未覆盖项及原因」。", left)
}

// noteYield 一步工具调用之后盘点进展：连续多步没有任何新资产 / 新发现就排入
// 一条提醒（见 idleStreakLimit）。提醒在下一轮 LLM 调用前注入，而不是夹在
// tool 消息中间——有些接口要求 tool 消息紧跟在发起它们的 assistant 消息之后。
func (a *Agent) noteYield(ctx context.Context) {
	if a.idleNudges >= maxIdleNudges || a.ctx == nil || a.ctx.Reporter == nil {
		return
	}
	sc, ok := a.ctx.Reporter.(interface {
		AssetCount() int
		FindingCount() int
	})
	if !ok {
		return
	}
	total := sc.AssetCount() + sc.FindingCount()
	if !a.yieldSeen || total != a.lastYield {
		a.lastYield, a.yieldSeen, a.idleStreak = total, true, 0
		return
	}
	if a.idleStreak++; a.idleStreak < idleStreakLimit {
		return
	}
	a.idleStreak, a.idleNudges = 0, a.idleNudges+1
	a.ctx.Reporter.Log(ctx, "agent", a.opts.Stage, fmt.Sprintf(
		"🌀 连续 %d 步没有新资产或新发现，已提醒换方向（第 %d/%d 次）",
		idleStreakLimit, a.idleNudges, maxIdleNudges))
	a.pendingNudges = append(a.pendingNudges, fmt.Sprintf(
		"【无进展提醒】最近连续 %d 步工具调用没有带来任何新的资产或发现。"+
			"如果你正在做深度手工验证，继续；如果是在原地打转，请立刻改变：换攻击面、换手法，"+
			"或先用 knowledge_search / knowledge_get 看看以前的经验。"+
			"走不通的路径同样有价值——用 knowledge_save 记下「试了什么、为什么不行、下一条线索」，然后转向。",
		idleStreakLimit))
}

// finishReview 收工前审查：独立上下文过目收工声明与工作纪要，指出盲区。
// 返回非空消息即不许收工。预算只剩一成时不再审查——没有余量照着补，
// 强行继续只会以「预算耗尽、没有报告」收场。
func (a *Agent) finishReview(ctx context.Context, finalText string) string {
	if a.opts.FinishReview == nil || a.reviews >= maxFinishReviews ||
		a.step*10 >= a.opts.MaxSteps*9 {
		return ""
	}
	nudge := a.opts.FinishReview(ctx, finalText, strings.Join(a.digest, "\n"))
	if nudge == "" {
		return ""
	}
	a.reviews++
	if a.ctx != nil && a.ctx.Reporter != nil {
		a.ctx.Reporter.Log(ctx, "agent", a.opts.Stage, fmt.Sprintf(
			"🔍 收工前审查发现缺口，要求补齐后再收尾（第 %d/%d 次）", a.reviews, maxFinishReviews))
	}
	return nudge
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
