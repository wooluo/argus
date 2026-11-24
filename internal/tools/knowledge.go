package tools

// 移植自 AutoPentest tools/builtin/knowledge.py —— 知识库（AI 自我迭代「沉淀」环节）。
//
// 三层文档 + 推索引、拉全文（知识库结构借鉴 sapper-v2，打分沿用 BM25）：
//   - knowledge_save：Title / Summary（一句话：教什么、何时用）/ Content（全文），
//     并声明适用范围（仅本项目 / 跨目标通用）；
//   - 任务书只带知识索引（标题 + 何时用它），条目再多也不撑爆上下文；
//   - knowledge_get：命中后按 id 拉全文（经节点注入的 knowledge_fetch 回连 server）。
//
// 持久化、去重与相关性排序都在 server 侧（api.SaveKnowledgeAuto /
// api.KnowledgeIndexFor）；会话内的条目另由 Reporter 的 SearchKnowledge 检索。

import (
	"context"
	"regexp"
	"strings"
)

// KnowledgeFetcher 节点注入的全文拉取回调（Extra["knowledge_fetch"]）。
type KnowledgeFetcher func(id string) (string, error)

type KnowledgeSaveTool struct{}

func (KnowledgeSaveTool) Name() string { return "knowledge_save" }

func (KnowledgeSaveTool) Description() string {
	return "把本轮验证过的经验沉淀为知识条目（AI 自我进化）：POC 用法与适配要点、" +
		"目标环境知识（版本差异/路径/防护特征）、有效的测试思路与绕过经验。" +
		"标题要具体到一眼能认出（不带任务编号）；summary 用一句话说清教什么、何时用。" +
		"后续任务的任务书会列出它的标题与适用场景，需要时再拉取全文。"
}

func (KnowledgeSaveTool) Parameters() map[string]any {
	return Schema(map[string]any{
		"title":   Prop("string", "知识标题：具体、可复用，如 'CSRF token 表单要先取 token 再原子提交'（不带任务编号）"),
		"summary": Prop("string", "一句话：这条经验教什么、何时用它（≤80 字，进任务书的知识索引）"),
		"content": Prop("string", "Markdown 全文：结论/步骤/注意事项（≤20000 字，只写验证过的事实）"),
		"scope":   Prop("string", "project=仅对本项目成立的事实（凭据、目标环境细节），默认；global=跨目标通用的方法论"),
	}, "title", "summary", "content")
}

func (KnowledgeSaveTool) Execute(ctx context.Context, args map[string]any, tc *Context) (string, error) {
	title := strings.TrimSpace(ArgString(args, "title", ""))
	content := strings.TrimSpace(ArgString(args, "content", ""))
	if title == "" || content == "" {
		return "", Errorf("title 与 content 必填")
	}
	if len(content) > 20000 {
		return "", Errorf("内容过长（≤20000 字）")
	}
	summary := strings.TrimSpace(ArgString(args, "summary", ""))
	if summary == "" { // 未给说明：取正文首个非空行兜底
		summary = firstLine(content)
	}
	k := Knowledge{
		Title: ClipRunes(title, 80), Content: content,
		Summary: ClipRunes(summary, 80), Kind: "agent",
		Scope: KnowledgeScopeProject,
	}
	if strings.EqualFold(strings.TrimSpace(ArgString(args, "scope", "")), KnowledgeScopeGlobal) {
		k.Scope = KnowledgeScopeGlobal
	}
	if err := tc.Reporter.SaveKnowledge(ctx, k); err != nil {
		return "", Errorf("保存失败: %v", err)
	}
	return MustJSON(map[string]any{
		"tool": "knowledge_save", "ok": true, "scope": k.Scope,
		"note": "已沉淀到知识库：后续任务的任务书会列出它的标题与适用场景，需要时再拉取全文",
	}), nil
}

func firstLine(s string) string {
	for _, line := range strings.Split(s, "\n") {
		if l := strings.TrimSpace(line); l != "" {
			return l
		}
	}
	return ""
}

// KnowledgeGetTool 按需拉取知识条目全文。
type KnowledgeGetTool struct{}

func (KnowledgeGetTool) Name() string { return "knowledge_get" }

func (KnowledgeGetTool) Description() string {
	return "按 id 拉取一条知识库条目的全文。任务书「知识库索引」只给标题与适用场景，" +
		"其中某条与当前目标/问题相关时调用它取具体步骤、命令与证据。"
}

func (KnowledgeGetTool) Parameters() map[string]any {
	return Schema(map[string]any{
		"id": Prop("string", "知识条目 id，取自任务书知识索引里方括号中的 id"),
	}, "id")
}

var knowledgeIDRe = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,80}$`)

func (KnowledgeGetTool) Execute(_ context.Context, args map[string]any, tc *Context) (string, error) {
	id := strings.TrimSpace(ArgString(args, "id", ""))
	if id == "" {
		return "", Errorf("id 必填")
	}
	if !knowledgeIDRe.MatchString(id) {
		return "", Errorf("id %q 格式非法", id)
	}
	fetch, _ := tc.Extra["knowledge_fetch"].(KnowledgeFetcher)
	if fetch == nil {
		return "", Errorf("当前环境未接知识库（节点未连接 server）")
	}
	content, err := fetch(id)
	if err != nil {
		return "", Errorf("拉取失败: %v", err)
	}
	return content, nil
}

type KnowledgeSearchTool struct{}

func (KnowledgeSearchTool) Name() string { return "knowledge_search" }

func (KnowledgeSearchTool) Description() string {
	return "检索本任务内已沉淀的经验（knowledge_save 存入的条目，按关键词 BM25 匹配）。" +
		"历史任务的条目见任务书的知识库索引，用 knowledge_get 拉取全文。"
}

func (KnowledgeSearchTool) Parameters() map[string]any {
	return Schema(map[string]any{
		"query": Prop("string", "关键词，如 'DVWA'、'盲注'、'Apache'"),
	}, "query")
}

func (KnowledgeSearchTool) Execute(ctx context.Context, args map[string]any, tc *Context) (string, error) {
	query := strings.TrimSpace(ArgString(args, "query", ""))
	if query == "" {
		return "", Errorf("query 为空")
	}
	results := tc.Reporter.SearchKnowledge(ctx, query, 5)
	return MustJSON(map[string]any{
		"tool": "knowledge_search", "query": query,
		"found": len(results), "results": results,
	}), nil
}

func init() {
	Register(KnowledgeSaveTool{})
	Register(KnowledgeGetTool{})
	Register(KnowledgeSearchTool{})
}
