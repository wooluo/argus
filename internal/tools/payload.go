package tools

// 移植自 AutoPentest tools/builtin/payloads.py —— 内置渗透 Payload 库检索。
// 数据文件 toolbox.json 从原版 tools/data/ 原样拷贝，go:embed 内嵌进二进制。

import (
	"context"
	_ "embed"
	"encoding/json"
	"sort"
	"strings"
	"sync"
)

//go:embed data/toolbox.json
var toolboxJSON []byte

type toolboxData struct {
	Payloads map[string][]string `json:"payloads"`
	Revshell []struct {
		Name     string   `json:"name"`
		Category string   `json:"category"`
		Tags     []string `json:"tags"`
		Template string   `json:"template"`
	} `json:"revshell"`
	Cheatsheet map[string][]struct {
		Name    string `json:"name"`
		Command string `json:"command"`
	} `json:"cheatsheet"`
	TtySpawn []struct {
		Name    string `json:"name"`
		Command string `json:"command"`
	} `json:"tty_spawn"`
}

var (
	tbxOnce sync.Once
	tbx     toolboxData
	tbxErr  error
)

// ToolboxData 返回内嵌工具箱数据（导出给 api 层复用）。
func ToolboxData() (*toolboxData, error) {
	tbxOnce.Do(func() {
		if err := json.Unmarshal(toolboxJSON, &tbx); err != nil {
			tbxErr = err
		}
	})
	if tbxErr != nil {
		return nil, tbxErr
	}
	return &tbx, nil
}

type PayloadSearchTool struct{}

func (PayloadSearchTool) Name() string { return "payload_search" }

func (PayloadSearchTool) Description() string {
	return "检索内置渗透测试 Payload 库（XSS / SQL 注入 / LFI / SSRF / 命令注入 / SSTI / " +
		"Reverse Shell 模板 / TTY 升级 / 提权与端口转发速查）。按关键词全文匹配，" +
		"构造攻击请求或编写利用脚本前先检索，直接复用成熟 payload。"
}

func (PayloadSearchTool) Parameters() map[string]any {
	return Schema(map[string]any{
		"query": Prop("string", "关键词，如 'union select'、'xss'、'reverse shell'、'suid'、'file_transfer'"),
		"limit": Prop("integer", "返回条数 1-30，默认 12"),
	}, "query")
}

type payloadHit struct {
	score    int
	source   string
	category string
	content  string
}

func (PayloadSearchTool) Execute(ctx context.Context, args map[string]any, tc *Context) (string, error) {
	query := strings.ToLower(strings.TrimSpace(ArgString(args, "query", "")))
	if query == "" {
		return "", Errorf("query 为空")
	}
	limit := ArgInt(args, "limit", 12)
	if limit < 1 {
		limit = 1
	} else if limit > 30 {
		limit = 30
	}
	var tokens []string
	for _, t := range strings.Fields(strings.ReplaceAll(query, ",", " ")) {
		if len(t) >= 2 {
			tokens = append(tokens, t)
		}
	}
	d, err := ToolboxData()
	if err != nil {
		return "", Errorf("payload 库加载失败: %v", err)
	}
	score := func(text string) int {
		low := strings.ToLower(text)
		n := 0
		for _, t := range tokens {
			if strings.Contains(low, t) {
				n++
			}
		}
		return n
	}
	var hits []payloadHit
	for cat, items := range d.Payloads {
		for _, p := range items {
			if s := score(p); s > 0 {
				hits = append(hits, payloadHit{s, "payload", cat, p})
			}
		}
	}
	for _, r := range d.Revshell {
		s := score(r.Name + " " + r.Category + " " + strings.Join(r.Tags, " ") + " " + r.Template)
		if s > 0 {
			hits = append(hits, payloadHit{s, "revshell", r.Name, r.Template})
		}
	}
	for group, items := range d.Cheatsheet {
		for _, it := range items {
			s := score(it.Name + " " + it.Command + " " + group)
			if s > 0 {
				hits = append(hits, payloadHit{s, "cheatsheet", group + "/" + it.Name, it.Command})
			}
		}
	}
	for _, it := range d.TtySpawn {
		s := score(it.Name + " " + it.Command)
		if s > 0 {
			hits = append(hits, payloadHit{s, "tty_spawn", it.Name, it.Command})
		}
	}
	sort.SliceStable(hits, func(i, j int) bool { return hits[i].score > hits[j].score })
	totalPool := len(d.Revshell)
	for _, v := range d.Payloads {
		totalPool += len(v)
	}
	results := make([]map[string]any, 0, limit)
	for _, h := range hits {
		if len(results) >= limit {
			break
		}
		results = append(results, map[string]any{
			"source": h.source, "category": h.category, "content": h.content,
		})
	}
	return MustJSON(map[string]any{
		"tool": "payload_search", "query": query,
		"found": len(results), "total_pool": totalPool,
		"results": results,
		"note":    "payload 中 {IP}/{PORT} 占位符需替换为目标回连地址（仅良性验证用途）",
	}), nil
}

func init() { Register(PayloadSearchTool{}) }
