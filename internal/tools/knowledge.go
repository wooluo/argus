package tools

// 移植自 AutoPentest tools/builtin/knowledge.py —— 知识库（AI 自我迭代「沉淀」环节）。
// 原版：本地 md 文件 + settings 元数据 + BM25/贝叶斯置信度排序 + 项目情报同步。
// argus 节点/服务端模型下：持久化与检索经 Reporter 落到 server 侧
// （server 实现 BM25 排序与置信度计数，工具侧保持轻量契约）。

import (
	"context"
	"strings"
)

type KnowledgeSaveTool struct{}

func (KnowledgeSaveTool) Name() string { return "knowledge_save" }

func (KnowledgeSaveTool) Description() string {
	return "把本轮验证过的经验沉淀为知识条目（AI 自我进化）：POC 用法与适配要点、" +
		"目标环境知识（版本差异/路径/防护特征）、有效的攻击思路与绕过经验。" +
		"保存后自动入库（并入项目情报），**后续任务开局自动携带**，形成迭代积累。"
}

func (KnowledgeSaveTool) Parameters() map[string]any {
	return Schema(map[string]any{
		"title":   Prop("string", "知识标题，如 'DVWA v1.10 各模块验证要点'"),
		"content": Prop("string", "Markdown 内容：结论/步骤/注意事项（≤20000 字，只写验证过的事实）"),
	}, "title", "content")
}

func (KnowledgeSaveTool) Execute(ctx context.Context, args map[string]any, tc *Context) (string, error) {
	title := strings.TrimSpace(ArgString(args, "title", ""))
	content := strings.TrimSpace(ArgString(args, "content", ""))
	if title == "" || content == "" {
		return "", Errorf("title 与 content 必填")
	}
	if len(title) > 80 {
		title = title[:80] // 与原版 [:80] 一致（按字节近似）
	}
	if len(content) > 20000 {
		return "", Errorf("内容过长（≤20000 字）")
	}
	if err := tc.Reporter.SaveKnowledge(ctx, title, content); err != nil {
		return "", Errorf("保存失败: %v", err)
	}
	return MustJSON(map[string]any{
		"tool": "knowledge_save", "ok": true,
		"note": "已沉淀到知识库并同步项目情报，后续任务开局自动携带",
	}), nil
}

type KnowledgeSearchTool struct{}

func (KnowledgeSearchTool) Name() string { return "knowledge_search" }

func (KnowledgeSearchTool) Description() string {
	return "检索本地知识库（历史任务沉淀的经验/POC 用法/环境知识）。按关键词全文匹配。"
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
	Register(KnowledgeSearchTool{})
}
