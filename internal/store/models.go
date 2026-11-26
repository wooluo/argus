package store

import (
	"bytes"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// Now 返回与 Python 端一致的 ISO8601 UTC 时间戳。
func Now() string { return time.Now().UTC().Format("2006-01-02T15:04:05.000Z") }

// NullTime 空值安全序列化。
func sqlNull(s sql.NullString) any {
	if s.Valid {
		return s.String
	}
	return nil
}

// RawJSON: TEXT 列 <-> JSON 字段。modernc/sqlite 对 TEXT 返回 string，
// json.RawMessage([]byte) 直接 Scan 会类型不匹配。
type RawJSON json.RawMessage

func (r *RawJSON) Scan(src any) error {
	switch v := src.(type) {
	case nil:
		*r = RawJSON("null")
	case string:
		*r = RawJSON(v)
	case []byte:
		*r = RawJSON(v)
	default:
		return fmt.Errorf("RawJSON.Scan: unsupported %T", src)
	}
	return nil
}

// MarshalJSON: 避免 []byte 默认 base64 序列化。
//
// 库里存了空串或不合法的 JSON 时也不能让整份响应失败：encoding/json 遇到
// 一个字段出错就一个字节都不输出（状态码还是 200）——资产中心曾因此整页
// 空白，962 条资产的 detail 是空串。空的输出 null，不合法的包进 _invalid。
func (r RawJSON) MarshalJSON() ([]byte, error) {
	trimmed := bytes.TrimSpace(r)
	if len(trimmed) == 0 {
		return []byte("null"), nil
	}
	if json.Valid(trimmed) {
		return trimmed, nil
	}
	b, _ := json.Marshal(map[string]string{"_invalid": string(trimmed)})
	return b, nil
}

// NormalizeJSON 把要存进 JSON 文本列的值收拾成合法 JSON：空的用 {}，不合法的
// 包进 _raw 字段——读出来永远能过 json_valid。
func NormalizeJSON(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return "{}"
	}
	if json.Valid([]byte(s)) {
		return s
	}
	b, _ := json.Marshal(map[string]string{"_raw": s})
	return string(b)
}

func (r RawJSON) Value() (driver.Value, error) {
	if r == nil {
		return "null", nil
	}
	return string(r), nil
}

// ---- 模型（JSON 序列化字段用 RawJSON 保持 schema 灋活）----

type Project struct {
	ID          int     `json:"id"`
	Name        string  `json:"name"`
	Description string  `json:"description"`
	Scope       RawJSON `json:"scope"` // [{type,value}]
	Authorized  bool    `json:"authorized"`
	AllowHosts  RawJSON `json:"allow_hosts"` // [{type,value}]
	CreatedAt   string  `json:"created_at"`
}

type Task struct {
	ID        int `json:"id"`
	ProjectID int `json:"project_id"`
	// ProjectName 查询时带出（非 DB 列）：任务中心「项目」列读它；项目已删或
	// 无名时是 #<id>
	ProjectName  string  `json:"project_name"`
	Name         string  `json:"name"`
	Status       string  `json:"status"`
	Mode         string  `json:"mode"`
	CurrentStage string  `json:"current_stage"`
	Tokens       RawJSON `json:"tokens"`
	StagesDone   RawJSON `json:"stages_done"`
	Message      string  `json:"message"`
	CreatedAt    string  `json:"created_at"`
	StartedAt    any     `json:"started_at"`
	FinishedAt   any     `json:"finished_at"`
	NodeID       int     `json:"node_id"`
	AssignedAt   any     `json:"assigned_at"`
	// IsLive 运行时计算（非 DB 列）：pull 架构下 pending/assigned/running 均为
	// 在途（蓝本 is_live 契约，前端启停按钮依赖）。
	IsLive bool `json:"is_live"`
}

// MarkLive 按状态计算 is_live。
func (t *Task) MarkLive() {
	t.IsLive = t.Status == "pending" || t.Status == "assigned" || t.Status == "running"
}

// PresentStatus 任务状态的管理面呈现值。Go 执行面比蓝本多了两个状态值：
// assigned（已派给节点）与 done（正常完成），而前端与仪表盘按蓝本只认
// running / completed——不映射的话完成的任务显示成红色、进度条走不完、
// 「继续测试」不出现、仪表盘完成数恒为 0。库内状态不变，只在出口换词。
func PresentStatus(status string) string {
	switch status {
	case "assigned", "running":
		return "running"
	case "done":
		return "completed"
	}
	return status
}

// Present 管理面出口统一处理：先按库内状态算 is_live，再换状态词。
func (t *Task) Present() {
	t.MarkLive()
	t.Status = PresentStatus(t.Status)
}

type Asset struct {
	ID        int `json:"id"`
	ProjectID int `json:"project_id"`
	// ProjectName 查询时带出（非 DB 列）：资产中心「所属项目」列读它；项目已删
	// 或无名时是 #<id>
	ProjectName string  `json:"project_name"`
	Type        string  `json:"type"`
	Value       string  `json:"value"`
	Detail      RawJSON `json:"detail"`
	Source      string  `json:"source"`
	CreatedAt   string  `json:"created_at"`
}

type Finding struct {
	ID        int    `json:"id"`
	ProjectID int    `json:"project_id"`
	Name      string `json:"name"`
	Severity  string `json:"severity"`
	Target    string `json:"target"`
	Detail    string `json:"detail"`
	Evidence  string `json:"evidence"`
	PoC       string `json:"poc"`
	Status    string `json:"status"`
	ReadAt    any    `json:"read_at"`
	Source    string `json:"source"`
	CreatedAt string `json:"created_at"`
	// Unread 未读标记（蓝本契约：read_at is None；发现页徽标/已读逻辑依赖）
	Unread bool `json:"unread"`
}

// MarkUnread 按 read_at 计算 unread（列表响应前调用）。
func (f *Finding) MarkUnread() { f.Unread = f.ReadAt == nil }

type AgentLog struct {
	ID            int     `json:"id"`
	TaskID        int     `json:"task_id"`
	Stage         string  `json:"stage"`
	Type          string  `json:"type"`
	Tool          string  `json:"tool"`
	Args          RawJSON `json:"args"`
	Content       string  `json:"content"`
	ResultSummary string  `json:"result_summary"`
	CreatedAt     string  `json:"created_at"`
}

type Report struct {
	ID        int    `json:"id"`
	ProjectID int    `json:"project_id"`
	TaskID    int    `json:"task_id"`
	Markdown  string `json:"markdown"`
	CreatedAt string `json:"created_at"`
}

type Node struct {
	ID           int     `json:"id"`
	Name         string  `json:"name"`
	Token        string  `json:"-"`
	Capabilities RawJSON `json:"capabilities"`
	Platform     string  `json:"platform"`
	Hostname     string  `json:"hostname"`
	Version      string  `json:"version"`
	Tags         RawJSON `json:"tags"`
	Status       string  `json:"status"`
	LastSeen     string  `json:"last_seen"`
	CreatedAt    string  `json:"created_at"`
}

type NodeJob struct {
	ID         int     `json:"id"`
	NodeID     int     `json:"node_id"`
	TaskID     int     `json:"task_id"`
	Tool       string  `json:"tool"`
	Args       RawJSON `json:"args"`
	Status     string  `json:"status"`
	Result     string  `json:"result"`
	Error      string  `json:"error"`
	CreatedAt  string  `json:"created_at"`
	FinishedAt any     `json:"finished_at"`
}
