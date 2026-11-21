package api

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/wooluo/argus/internal/intel"
	"github.com/wooluo/argus/internal/store"
)

// ================= Tasks =================
// 对齐原 api/tasks.py：启动/停止/详情/日志。

func (a *API) ListTasks(w http.ResponseWriter, r *http.Request) {
	pid, _ := strconv.ParseInt(r.URL.Query().Get("project_id"), 10, 64)
	q := `SELECT id,project_id,status,mode,current_stage,tokens,stages_done,message,created_at,started_at,finished_at FROM tasks`
	var rows *sql.Rows
	var err error
	if pid > 0 {
		rows, err = a.DB.Query(q+` WHERE project_id=? ORDER BY id DESC`, pid)
	} else {
		rows, err = a.DB.Query(q + ` ORDER BY id DESC`)
	}
	if err != nil {
		respondErr(w, 500, err.Error())
		return
	}
	defer rows.Close()
	out := []store.Task{}
	for rows.Next() {
		var t store.Task
		var started, finished sql.NullString
		if err := rows.Scan(&t.ID, &t.ProjectID, &t.Status, &t.Mode, &t.CurrentStage, &t.Tokens, &t.StagesDone, &t.Message, &t.CreatedAt, &started, &finished); err != nil {
			respondErr(w, 500, err.Error())
			return
		}
		t.StartedAt = nilStr(started)
		t.FinishedAt = nilStr(finished)
		t.MarkLive()
		out = append(out, t)
	}
	respondJSON(w, 200, out)
}

func (a *API) GetTask(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		respondErr(w, 422, err.Error())
		return
	}
	var t store.Task
	var started, finished sql.NullString
	err = a.DB.QueryRow(`SELECT id,project_id,status,mode,current_stage,tokens,stages_done,message,created_at,started_at,finished_at FROM tasks WHERE id=?`, id).
		Scan(&t.ID, &t.ProjectID, &t.Status, &t.Mode, &t.CurrentStage, &t.Tokens, &t.StagesDone, &t.Message, &t.CreatedAt, &started, &finished)
	if errors.Is(err, sql.ErrNoRows) {
		respondErr(w, 404, "task not found")
		return
	}
	if err != nil {
		respondErr(w, 500, err.Error())
		return
	}
	t.StartedAt = nilStr(started)
	t.FinishedAt = nilStr(finished)
	respondJSON(w, 200, t)
}

// StartTask: POST /api/projects/{pid}/tasks — 前置校验项目授权（对齐原版 authorized 必须为 True）。
func (a *API) StartTask(w http.ResponseWriter, r *http.Request) {
	pid, err := pathID(r)
	if err != nil {
		respondErr(w, 422, err.Error())
		return
	}
	var authz int
	var scope store.RawJSON
	err = a.DB.QueryRow(`SELECT authorized,scope FROM projects WHERE id=?`, pid).Scan(&authz, &scope)
	if errors.Is(err, sql.ErrNoRows) {
		respondErr(w, 404, "project not found")
		return
	}
	if err != nil {
		respondErr(w, 500, err.Error())
		return
	}
	if authz != 1 {
		respondErr(w, 400, "project not authorized")
		return
	}
	if len(scope) == 0 || string(scope) == "[]" || string(scope) == "null" {
		respondErr(w, 400, "project scope empty")
		return
	}

	var req struct {
		Mode         string `json:"mode"`          // autonomous/staged
		ContinueFrom int64  `json:"continue_from"` // 断点续测：携带指定任务的成果
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	if req.Mode == "" {
		req.Mode = "autonomous"
	}
	if req.Mode != "autonomous" && req.Mode != "staged" {
		respondErr(w, 422, "mode must be autonomous|staged")
		return
	}

	contNote := ""
	if req.ContinueFrom > 0 {
		contNote = fmt.Sprintf("[continue_from=%d]", req.ContinueFrom)
	}
	res, err := a.DB.Exec(`INSERT INTO tasks(project_id,mode,status,current_stage,message,continue_from) VALUES(?,?,?,?,?,?)`,
		pid, req.Mode, "pending", "", contNote, req.ContinueFrom)
	if err != nil {
		respondErr(w, 500, err.Error())
		return
	}
	id, _ := res.LastInsertId()
	// Runner 若存在则异步驱动（v0: pipeline 由 runner 接口注入）
	if a.Runner != nil {
		go a.Runner.Run(int(id))
	}
	a.Bus.Publish("task_started", map[string]any{"id": id, "project_id": pid, "mode": req.Mode})
	a.getTaskByID(w, id)
}

func (a *API) getTaskByID(w http.ResponseWriter, id int64) {
	var t store.Task
	var started, finished sql.NullString
	err := a.DB.QueryRow(`SELECT id,project_id,status,mode,current_stage,tokens,stages_done,message,created_at,started_at,finished_at FROM tasks WHERE id=?`, id).
		Scan(&t.ID, &t.ProjectID, &t.Status, &t.Mode, &t.CurrentStage, &t.Tokens, &t.StagesDone, &t.Message, &t.CreatedAt, &started, &finished)
	if err != nil {
		respondErr(w, 500, err.Error())
		return
	}
	t.StartedAt = nilStr(started)
	t.FinishedAt = nilStr(finished)
	t.MarkLive()
	respondJSON(w, 200, t)
}

// StopTask: POST /api/tasks/{id}/stop。
func (a *API) StopTask(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		respondErr(w, 422, err.Error())
		return
	}
	var status string
	if err := a.DB.QueryRow(`SELECT status FROM tasks WHERE id=?`, id).Scan(&status); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			respondErr(w, 404, "task not found")
			return
		}
		respondErr(w, 500, err.Error())
		return
	}
	if status != "running" && status != "pending" && status != "assigned" {
		respondErr(w, 400, "task not running")
		return
	}
	if a.Runner != nil {
		a.Runner.Stop(int(id))
	}
	_, err = a.DB.Exec(`UPDATE tasks SET status='stopped', finished_at=? WHERE id=?`, store.Now(), id)
	if err != nil {
		respondErr(w, 500, err.Error())
		return
	}
	// 停止即拒绝该任务全部待审批项（蓝本 deny_pending：节点侧轮询随即解锁）
	if res, err := a.DB.Exec(
		`UPDATE approvals SET status='denied',decided_by='task-stop',decided_at=?
		 WHERE task_id=? AND status='pending'`, store.Now(), id); err == nil {
		if n, _ := res.RowsAffected(); n > 0 {
			a.Bus.Publish("approval_done", map[string]any{
				"task_id": id, "status": "denied(task-stop)", "count": n})
		}
	}
	a.Bus.Publish("task_stopped", map[string]any{"id": id})
	respondJSON(w, 200, map[string]bool{"ok": true})
}

// ================= 运行中情报 / 项目情报（蓝本 api/tasks.py intel 域） =================

// SubmitIntel POST /api/tasks/{id}/intel — 向运行中任务实时注入情报。
// Go 版链路：管理面 Push → 节点每 5s 轮询 /api/nodes/intel 拉走 → agent 下一步注入。
func (a *API) SubmitIntel(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		respondErr(w, 422, err.Error())
		return
	}
	var req struct {
		Content string `json:"content"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || strings.TrimSpace(req.Content) == "" {
		respondErr(w, 400, "情报内容不能为空")
		return
	}
	var status string
	if err := a.DB.QueryRow(`SELECT status FROM tasks WHERE id=?`, id).Scan(&status); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			respondErr(w, 404, "任务不存在")
			return
		}
		respondErr(w, 500, err.Error())
		return
	}
	if status != "running" && status != "pending" && status != "assigned" {
		respondErr(w, 400, "任务不在运行中，无法注入情报")
		return
	}
	intel.Push(id, strings.TrimSpace(req.Content))
	respondJSON(w, 200, map[string]any{"ok": true, "queued": truncate(req.Content, 100)})
}

// GetProjectIntel GET /api/projects/{id}/intel — 项目情报库（跨任务持久）。
func (a *API) GetProjectIntel(w http.ResponseWriter, r *http.Request) {
	pid, err := pathID(r)
	if err != nil {
		respondErr(w, 422, err.Error())
		return
	}
	rows, err := a.DB.Query(
		`SELECT id,content,source,created_at FROM project_intel WHERE project_id=? ORDER BY id DESC LIMIT 50`, pid)
	if err != nil {
		respondErr(w, 500, err.Error())
		return
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var id int64
		var content, source, createdAt string
		if rows.Scan(&id, &content, &source, &createdAt) == nil {
			out = append(out, map[string]any{
				"id": id, "content": content, "source": source, "created_at": createdAt})
		}
	}
	respondJSON(w, 200, out)
}

// AddProjectIntel POST /api/projects/{id}/intel — 手动添加项目情报（下个任务生效）。
func (a *API) AddProjectIntel(w http.ResponseWriter, r *http.Request) {
	pid, err := pathID(r)
	if err != nil {
		respondErr(w, 422, err.Error())
		return
	}
	var req struct {
		Content string `json:"content"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || strings.TrimSpace(req.Content) == "" {
		respondErr(w, 400, "情报内容不能为空")
		return
	}
	if _, err := a.DB.Exec(
		`INSERT INTO project_intel(project_id,content,source) VALUES(?,?,'manual')`,
		pid, strings.TrimSpace(req.Content)); err != nil {
		respondErr(w, 500, err.Error())
		return
	}
	respondJSON(w, 200, map[string]any{"ok": true})
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// ================= Agent Logs =================

func (a *API) ListAgentLogs(w http.ResponseWriter, r *http.Request) {
	tid, _ := strconv.ParseInt(r.URL.Query().Get("task_id"), 10, 64)
	limit := clampInt(r.URL.Query().Get("limit"), 500, 1, 2000)
	offset := clampInt(r.URL.Query().Get("offset"), 0, 0, 1<<30)
	var rows *sql.Rows
	var err error
	if tid > 0 {
		rows, err = a.DB.Query(`SELECT id,task_id,stage,type,tool,args,content,result_summary,created_at FROM agent_logs WHERE task_id=? ORDER BY id DESC LIMIT ? OFFSET ?`, tid, limit, offset)
	} else {
		rows, err = a.DB.Query(`SELECT id,task_id,stage,type,tool,args,content,result_summary,created_at FROM agent_logs ORDER BY id DESC LIMIT ? OFFSET ?`, limit, offset)
	}
	if err != nil {
		respondErr(w, 500, err.Error())
		return
	}
	defer rows.Close()
	out := []store.AgentLog{}
	for rows.Next() {
		var l store.AgentLog
		if err := rows.Scan(&l.ID, &l.TaskID, &l.Stage, &l.Type, &l.Tool, &l.Args, &l.Content, &l.ResultSummary, &l.CreatedAt); err != nil {
			respondErr(w, 500, err.Error())
			return
		}
		out = append(out, l)
	}
	respondJSON(w, 200, out)
}

func clampInt(s string, def, min, max int) int {
	n, err := strconv.Atoi(s)
	if err != nil || n < min {
		return def
	}
	if n > max {
		return max
	}
	return n
}

func nilStr(s sql.NullString) any {
	if s.Valid {
		return s.String
	}
	return nil
}

var _ = chi.URLParam
