// Package tools 移植自 AutoPentest tools/base.py + registry.py —— 工具框架。
// 每个内置工具实现 Tool 接口，注册进全局 Registry，由 Agent 循环调度。
package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

// Error 工具执行错误（会作为 tool 消息回给模型继续推理，不终止任务）。
type Error struct{ Msg string }

func (e *Error) Error() string { return e.Msg }

// Errorf 构造工具错误。
func Errorf(format string, args ...any) error {
	return &Error{Msg: fmt.Sprintf(format, args...)}
}

// Finding 工具上报的漏洞条目（report_finding / update_finding 用）。
type Finding struct {
	ID       int64    `json:"id"`
	Name     string   `json:"name"`
	Severity string   `json:"severity"` // critical/high/medium/low/info
	Target   string   `json:"target"`
	Detail   string   `json:"detail"`
	PoC      string   `json:"poc,omitempty"`
	Evidence string   `json:"evidence,omitempty"`
	Source   string   `json:"source"`          // 工具名 / agent
	Status   string   `json:"status"`          // pending/confirmed/false_positive
	Steps    []string `json:"steps,omitempty"` // 利用链步骤记录
}

// Reporter 节点侧数据上报通道：工具产出（资产/漏洞/证据）经此回传 server。
type Reporter interface {
	// SaveAsset 上报或更新资产（type: domain/ip/port/url/tech）。
	SaveAsset(ctx context.Context, typ, value string, meta map[string]any)
	// SaveFinding 创建漏洞条目，返回 finding_id。
	SaveFinding(ctx context.Context, f Finding) (int64, error)
	// UpdateFinding 更新已有条目（状态/详情/利用链步骤）。
	UpdateFinding(ctx context.Context, id int64, patch map[string]any) error
	// SaveEvidence 固化证据（http 流量/命令输出）。
	SaveEvidence(ctx context.Context, typ, content string, meta map[string]any)
	// SaveKnowledge 沉淀可复用经验（后续任务自动携带）。
	SaveKnowledge(ctx context.Context, title, content string) error
	// SearchKnowledge 检索历史经验。
	SearchKnowledge(ctx context.Context, query string, limit int) []map[string]any
	// Log 审计日志（stage/actor/内容）。
	Log(ctx context.Context, actor, stage, message string)
	// LLMDesc 当前模型描述（任务启动日志用）。
	LLMDesc() string
}

// Session HTTP 会话（web_login 建立后 http_fetch/web_crawl 复用：cookie 桶 + 基址）。
type Session struct {
	Cookies map[string]string
	BaseURL string
	User    string
}

// Context 工具执行上下文（对应原版 ToolContext）。
type Context struct {
	TaskID      int64
	ProjectID   int64
	ProjectName string
	Description string      // 项目说明 / 测试规范
	Scope       interface { // 范围护栏（避免包循环，结构体接口化）
		CheckHost(host string) bool
		CheckURL(url string) bool
		EnsureHost(host string) error
		EnsureURL(url string) error
		Describe() string
	}
	Reporter Reporter
	Session  *Session       // 登录会话（auth_session 维护）
	Workdir  string         // 节点本地工作目录（脚本/产物）
	Extra    map[string]any // 扩展位（MCP 工具/节点元数据）
}

// Tool 内置工具接口。
type Tool interface {
	Name() string
	Description() string
	// Parameters JSON schema（OpenAI function calling 格式）。
	Parameters() map[string]any
	// Execute 执行；返回给模型看的文本结果。
	Execute(ctx context.Context, args map[string]any, tc *Context) (string, error)
}

// ---------- Registry（对应 registry.py） ----------

var registry = map[string]Tool{}

// Register 注册工具（重名后者覆盖，便于测试替换）。
func Register(t Tool) { registry[t.Name()] = t }

// All 全量工具（自主模式全量放开，与原版一致）。
func All() []Tool {
	out := make([]Tool, 0, len(registry))
	for _, t := range registry {
		out = append(out, t)
	}
	return out
}

// Get 按名取工具。
func Get(name string) (Tool, bool) { t, ok := registry[name]; return t, ok }

// Names 已注册工具名。
func Names() []string {
	out := make([]string, 0, len(registry))
	for n := range registry {
		out = append(out, n)
	}
	return out
}

// ---------- schema 构造辅助 ----------

// Schema 快速构造 JSON schema。
func Schema(props map[string]any, required ...string) map[string]any {
	m := map[string]any{
		"type":       "object",
		"properties": props,
	}
	if len(required) > 0 {
		m["required"] = required
	}
	return m
}

// Prop 字段 schema 简写。
func Prop(typ, desc string) map[string]any {
	return map[string]any{"type": typ, "description": desc}
}

// PropEnum 枚举字段。
func PropEnum(desc string, values ...string) map[string]any {
	return map[string]any{"type": "string", "description": desc, "enum": values}
}

// ArgString 取字符串参数（缺省回退）。
func ArgString(args map[string]any, key, def string) string {
	if v, ok := args[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return def
}

// ArgInt 取整数参数。
func ArgInt(args map[string]any, key string, def int) int {
	if v, ok := args[key]; ok {
		switch n := v.(type) {
		case float64:
			return int(n)
		case int:
			return n
		case string:
			var i int
			if _, err := fmt.Sscanf(n, "%d", &i); err == nil {
				return i
			}
		}
	}
	return def
}

// ArgStrings 取字符串列表参数。
func ArgStrings(args map[string]any, key string) []string {
	if v, ok := args[key]; ok {
		if arr, ok := v.([]any); ok {
			out := make([]string, 0, len(arr))
			for _, it := range arr {
				if s, ok := it.(string); ok {
					out = append(out, s)
				}
			}
			return out
		}
	}
	return nil
}

// MustJSON 序列化辅助（工具结果美化）。
func MustJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return fmt.Sprintf("%v", v)
	}
	return string(b)
}

// Truncate 截断长输出（防爆 context）。
func Truncate(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	return s[:n] + fmt.Sprintf("\n…(截断，全文 %d 字符)", len(s))
}
