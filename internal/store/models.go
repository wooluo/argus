package store

import (
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"fmt"
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
func (r RawJSON) MarshalJSON() ([]byte, error) {
	if r == nil {
		return []byte("null"), nil
	}
	return r, nil
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
	ID           int     `json:"id"`
	ProjectID    int     `json:"project_id"`
	Name         string `json:"name"`
	Status       string `json:"status"`
	Mode         string `json:"mode"`
	CurrentStage string `json:"current_stage"`
	Tokens       RawJSON `json:"tokens"`
	StagesDone   RawJSON `json:"stages_done"`
	Message      string `json:"message"`
	CreatedAt    string `json:"created_at"`
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

type Asset struct {
	ID        int     `json:"id"`
	ProjectID int     `json:"project_id"`
	Type      string  `json:"type"`
	Value     string  `json:"value"`
	Detail    RawJSON `json:"detail"`
	Source    string  `json:"source"`
	CreatedAt string  `json:"created_at"`
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
