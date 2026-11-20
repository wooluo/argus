package pipeline

// reflect.go: 任务后自动复盘（移植自 AutoPentest core/reflection.py）。
// 任务成功完成后 LLM 复盘本次得失，提炼 ≤2 条可复用经验写入知识库，
// 下个任务开局自动携带——渗透能力随任务数累积。
// 失败不影响任务结果（尽力而为）。

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/wooluo/argus/internal/llm"
)

var reflectJSONRe = regexp.MustCompile(`(?s)\[.*\]`)

// reflectAfterRun 任务完成后复盘（completed 且 ≥8 步工具调用才值得）。
func reflectAfterRun(ctx context.Context, b Brief, res *Result, rep *memReporter, client *llm.Client) {
	snap := rep.snapshot()
	// 工具调用数：agent 日志行计数
	toolCalls := 0
	for _, l := range snap.Logs {
		if l.Tool == "agent" {
			toolCalls++
		}
	}
	if res.Status != "done" || toolCalls < 8 {
		return
	}
	var findings []string
	for _, f := range snap.Findings {
		findings = append(findings, fmt.Sprintf("[%s] %s(%s)", f.Severity, f.Name, f.Status))
	}
	findingLine := strings.Join(findings, "；")
	if findingLine == "" {
		findingLine = "无"
	}

	prompt := fmt.Sprintf(`你是资深渗透测试专家，刚完成一次自动化渗透测试任务。请复盘并提炼**可复用的经验**沉淀到团队知识库。

## 本次任务数据
- 目标/授权范围：%s（项目 %s）
- 工具调用 %d 次；产出发现：%s
- 资产 %d 条；审计日志 %d 条

## 提炼要求
1. 只写可复用的通用经验：目标环境知识（框架/防护特征与应对）、有效绕过手法、攻击路径经验、工具适配要点、踩坑与捷径
2. 不写一次性细节；每条 ≤1000 字，结论先行
3. 没有值得沉淀的就返回 []（宁缺毋滥）
只输出 JSON 数组（可空），每项 {"title": "...", "content": "..."}，最多 2 条：`,
		strings.Join(scopeValues(b), ", "), b.ProjectName, toolCalls,
		findingLine, len(snap.Assets), len(snap.Logs))

	out, err := client.ChatText(ctx, "", prompt, 0.2)
	if err != nil {
		rep.Log(ctx, "system", "", "🧠 自我迭代：复盘 LLM 调用失败（不影响任务）: "+err.Error())
		return
	}
	m := reflectJSONRe.FindString(out)
	if m == "" {
		rep.Log(ctx, "system", "", "🧠 自我迭代：复盘完成，无新的可复用经验。")
		return
	}
	var entries []struct {
		Title   string `json:"title"`
		Content string `json:"content"`
	}
	if err := json.Unmarshal([]byte(m), &entries); err != nil || len(entries) == 0 {
		rep.Log(ctx, "system", "", "🧠 自我迭代：复盘完成，无新的可复用经验。")
		return
	}
	saved := []string{}
	for i, e := range entries {
		if i >= 2 || strings.TrimSpace(e.Title) == "" || strings.TrimSpace(e.Content) == "" {
			continue
		}
		if err := rep.SaveKnowledge(ctx,
			fmt.Sprintf("任务 #%d 复盘：%s", b.TaskID, e.Title),
			e.Content); err == nil {
			saved = append(saved, e.Title)
		}
	}
	if len(saved) > 0 {
		rep.Log(ctx, "system", "", fmt.Sprintf(
			"🧠 自我迭代：本次复盘沉淀 %d 条经验 → 知识库（%s）。下个任务开局自动携带。",
			len(saved), strings.Join(saved, "；")))
	} else {
		rep.Log(ctx, "system", "", "🧠 自我迭代：复盘完成，无新的可复用经验。")
	}
}

func scopeValues(b Brief) []string {
	out := []string{}
	for _, r := range b.Scope {
		out = append(out, r.Value)
	}
	return out
}
