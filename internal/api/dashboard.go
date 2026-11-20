package api

import (
	"encoding/json"
	"math"
	"net/http"

	"github.com/go-chi/chi/v5"
	"time"
	"strconv"
	"database/sql"
)

// ============ Dashboard 域（蓝本 api/dashboard.py dashboard_stats） ============

// tokenUsage: tasks.tokens JSON 列（{"prompt":..,"completion":..,"calls":..}）。
type tokenUsage struct {
	Prompt     int64 `json:"prompt"`
	Completion int64 `json:"completion"`
	Calls      int64 `json:"calls"`
}

// parseTokens 容错解析 tokens JSON 列，坏数据按零值处理。
func parseTokens(s string) tokenUsage {
	var t tokenUsage
	_ = json.Unmarshal([]byte(s), &t)
	return t
}

// dayStat: 近7日趋势中的一天（任务量 + token 出入）。
type dayStat struct {
	Date      string `json:"date"`
	Tasks     int64  `json:"tasks"`
	TokensIn  int64  `json:"tokensIn"`
	TokensOut int64  `json:"tokensOut"`
}

type recentTask struct {
	ID           int64  `json:"id"`
	ProjectID    int64  `json:"project_id"`
	Status       string `json:"status"`
	Mode         string `json:"mode"`
	CurrentStage string `json:"current_stage"`
	Tokens       int64  `json:"tokens"`
	CreatedAt    string `json:"created_at"`
}

type activityItem struct {
	ID        int64  `json:"id"`
	Type      string `json:"type"`
	Tool      string `json:"tool"`
	Stage     string `json:"stage"`
	Content   string `json:"content"`
	TaskID    int64  `json:"task_id"`
	CreatedAt string `json:"created_at"`
}

type recentFinding struct {
	ID          int64  `json:"id"`
	ProjectID   int64  `json:"project_id"`
	ProjectName string `json:"project_name"`
	Name        string `json:"name"`
	Severity    string `json:"severity"`
	Status      string `json:"status"`
	CreatedAt   string `json:"created_at"`
}

// GetDashboard GET /api/dashboard —— 全局统计聚合：卡片计数、token 汇总、
// 近7日趋势、严重度/任务状态分布、活动流与最近发现（蓝本 dashboard_stats）。
func (a *API) GetDashboard(w http.ResponseWriter, r *http.Request) {
	// ---- 顶栏卡片计数 ----
	var projects, assets, traffic int64
	if err := a.DB.QueryRow(`SELECT (SELECT COUNT(*) FROM projects),
		(SELECT COUNT(*) FROM assets), (SELECT COUNT(*) FROM traffic_logs)`).
		Scan(&projects, &assets, &traffic); err != nil {
		respondErr(w, 500, err.Error())
		return
	}

	// 发现三态计数：未读 / 已确认 / 高危（critical+high）
	var unread, confirmed, high int64
	if err := a.DB.QueryRow(`SELECT COALESCE(SUM(read_at IS NULL),0),
		COALESCE(SUM(status='confirmed'),0),
		COALESCE(SUM(severity IN ('critical','high')),0) FROM findings`).
		Scan(&unread, &confirmed, &high); err != nil {
		respondErr(w, 500, err.Error())
		return
	}

	// ---- 严重度分布（只保留固定四档，蓝本同） ----
	sevMap := map[string]int64{"critical": 0, "high": 0, "medium": 0, "low": 0}
	rows, err := a.DB.Query(`SELECT severity, COUNT(*) FROM findings GROUP BY severity`)
	if err != nil {
		respondErr(w, 500, err.Error())
		return
	}
	for rows.Next() {
		var s string
		var n int64
		if err := rows.Scan(&s, &n); err != nil {
			rows.Close()
			respondErr(w, 500, err.Error())
			return
		}
		if _, ok := sevMap[s]; ok {
			sevMap[s] = n
		}
	}
	rows.Close()

	// ---- 任务状态分解 + token 汇总 + 近7日趋势（一次全表扫，任务量小，蓝本同思路） ----
	taskStatus := map[string]int64{}
	var total tokenUsage
	now := time.Now().UTC()
	days := make([]dayStat, 7)
	dayIdx := map[string]int{}
	for i := range days {
		d := now.AddDate(0, 0, i-6).Format("2006-01-02")
		days[i].Date = d
		dayIdx[d] = i
	}
	rows, err = a.DB.Query(`SELECT status, tokens, created_at FROM tasks`)
	if err != nil {
		respondErr(w, 500, err.Error())
		return
	}
	for rows.Next() {
		var status, tokens, createdAt string
		if err := rows.Scan(&status, &tokens, &createdAt); err != nil {
			rows.Close()
			respondErr(w, 500, err.Error())
			return
		}
		taskStatus[status]++
		tk := parseTokens(tokens)
		total.Prompt += tk.Prompt
		total.Completion += tk.Completion
		total.Calls += tk.Calls
		// created_at 形如 2026-11-20T08:00:00.123Z，日期键取前 10 字符（UTC，建表默认）
		if len(createdAt) >= 10 {
			if i, ok := dayIdx[createdAt[:10]]; ok {
				days[i].Tasks++
				days[i].TokensIn += tk.Prompt
				days[i].TokensOut += tk.Completion
			}
		}
	}
	rows.Close()

	tasksTotal := int64(0)
	for _, n := range taskStatus {
		tasksTotal += n
	}

	// ---- 最近 8 个任务 ----
	recent := []recentTask{}
	rows, err = a.DB.Query(`SELECT id, project_id, status, mode, current_stage, tokens, created_at
		FROM tasks ORDER BY id DESC LIMIT 8`)
	if err != nil {
		respondErr(w, 500, err.Error())
		return
	}
	for rows.Next() {
		var t recentTask
		var tokens string
		if err := rows.Scan(&t.ID, &t.ProjectID, &t.Status, &t.Mode, &t.CurrentStage, &tokens, &t.CreatedAt); err != nil {
			rows.Close()
			respondErr(w, 500, err.Error())
			return
		}
		tk := parseTokens(tokens)
		t.Tokens = tk.Prompt + tk.Completion
		recent = append(recent, t)
	}
	rows.Close()

	// ---- 待审批数 ----
	var pending int64
	if err := a.DB.QueryRow(`SELECT COUNT(*) FROM approvals WHERE status='pending'`).Scan(&pending); err != nil {
		respondErr(w, 500, err.Error())
		return
	}

	// ---- 活动流：最近 30 条 Agent 事件（内容截 120 字，蓝本同） ----
	activity := []activityItem{}
	rows, err = a.DB.Query(`SELECT id, type, tool, stage, content, task_id, created_at
		FROM agent_logs ORDER BY id DESC LIMIT 30`)
	if err != nil {
		respondErr(w, 500, err.Error())
		return
	}
	for rows.Next() {
		var it activityItem
		if err := rows.Scan(&it.ID, &it.Type, &it.Tool, &it.Stage, &it.Content, &it.TaskID, &it.CreatedAt); err != nil {
			rows.Close()
			respondErr(w, 500, err.Error())
			return
		}
		if runes := []rune(it.Content); len(runes) > 120 {
			it.Content = string(runes[:120])
		}
		activity = append(activity, it)
	}
	rows.Close()

	// ---- 最近发现（带项目名，无项目名回退 #id，蓝本同） ----
	findings := []recentFinding{}
	rows, err = a.DB.Query(`SELECT f.id, f.project_id, COALESCE(NULLIF(p.name,''), '#'||f.project_id),
		f.name, f.severity, f.status, f.created_at
		FROM findings f LEFT JOIN projects p ON p.id = f.project_id
		ORDER BY f.id DESC LIMIT 8`)
	if err != nil {
		respondErr(w, 500, err.Error())
		return
	}
	for rows.Next() {
		var f recentFinding
		if err := rows.Scan(&f.ID, &f.ProjectID, &f.ProjectName, &f.Name, &f.Severity, &f.Status, &f.CreatedAt); err != nil {
			rows.Close()
			respondErr(w, 500, err.Error())
			return
		}
		findings = append(findings, f)
	}
	rows.Close()

	respondJSON(w, 200, struct {
		Projects         int64            `json:"projects"`
		Assets           int64            `json:"assets"`
		Findings         int64            `json:"findings"`
		Confirmed        int64            `json:"confirmed"`
		HighCritical     int64            `json:"high_critical"`
		Traffic          int64            `json:"traffic"`
		Tokens           tokenUsage       `json:"tokens"`
		TokensK          float64          `json:"tokens_k"`
		TasksTotal       int64            `json:"tasks_total"`
		TaskStatus       map[string]int64 `json:"task_status"`
		Running          int64            `json:"running"`
		Completed        int64            `json:"completed"`
		Failed           int64            `json:"failed"`
		Stopped          int64            `json:"stopped"`
		Sev              map[string]int64 `json:"sev"`
		RecentTasks      []recentTask     `json:"recent_tasks"`
		Days             []dayStat        `json:"days"`
		PendingApprovals int64            `json:"pending_approvals"`
		Activity         []activityItem   `json:"activity"`
		RecentFindings   []recentFinding  `json:"recent_findings"`
	}{
		Projects: projects, Assets: assets, Findings: unread,
		Confirmed: confirmed, HighCritical: high, Traffic: traffic,
		Tokens: total,
		// 蓝本 round((p+c)/1000, 1)
		TokensK:    math.Round(float64(total.Prompt+total.Completion)/100) / 10,
		TasksTotal: tasksTotal, TaskStatus: taskStatus,
		Running:   taskStatus["running"],
		Completed: taskStatus["completed"],
		Failed:    taskStatus["failed"],
		Stopped:   taskStatus["stopped"],
		Sev:         sevMap,
		RecentTasks: recent, Days: days,
		PendingApprovals: pending,
		Activity:       activity,
		RecentFindings: findings,
	})
}


// SystemLogs GET /api/system/logs?limit=200 — 跨项目审计日志（蓝本 system_logs 路由）。
func (a *API) SystemLogs(w http.ResponseWriter, r *http.Request) {
	limit := 200
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 1000 {
			limit = n
		}
	}
	rows, err := a.DB.Query(`
		SELECT l.id, l.task_id, l.stage, l.tool, l.content, l.created_at,
		       t.project_id, p.name
		FROM agent_logs l
		LEFT JOIN tasks t ON t.id = l.task_id
		LEFT JOIN projects p ON p.id = t.project_id
		ORDER BY l.id DESC LIMIT ?`, limit)
	if err != nil {
		respondErr(w, 500, err.Error())
		return
	}
	defer rows.Close()
	type logItem struct {
		ID        int64  `json:"id"`
		TaskID    int64  `json:"task_id"`
		Stage     string `json:"stage"`
		Tool      string `json:"tool"`
		Content   string `json:"content"`
		CreatedAt string `json:"created_at"`
		ProjectID int64  `json:"project_id"`
		Project   string `json:"project"`
	}
	out := []logItem{}
	for rows.Next() {
		var it logItem
		var stage, tool, content sql.NullString
		var projID sql.NullInt64
		var proj sql.NullString
		if err := rows.Scan(&it.ID, &it.TaskID, &stage, &tool, &content, &it.CreatedAt, &projID, &proj); err != nil {
			continue
		}
		it.Stage, it.Tool, it.Content = stage.String, tool.String, content.String
		it.ProjectID, it.Project = projID.Int64, proj.String
		out = append(out, it)
	}
	respondJSON(w, 200, out)
}

// ============ Approvals 域（蓝本 api/approvals.py：待审批列表 + 批准/拒绝 + 规则配置） ============

// ListApprovals GET /api/approvals — 待审批的工具调用列表。
func (a *API) ListApprovals(w http.ResponseWriter, r *http.Request) {
	status := r.URL.Query().Get("status")
	if status == "" {
		status = "pending"
	}
	rows, err := a.DB.Query(`
		SELECT id, task_id, project_id, tool, args, status, decided_by, reason, created_at
		FROM approvals WHERE status=? ORDER BY id DESC LIMIT 100`, status)
	if err != nil {
		respondErr(w, 500, err.Error())
		return
	}
	defer rows.Close()
	type approval struct {
		ID        int64          `json:"id"`
		TaskID    int64          `json:"task_id"`
		ProjectID int64          `json:"project_id"`
		Tool      string         `json:"tool"`
		Args      map[string]any `json:"args"`
		Status    string         `json:"status"`
		DecidedBy string         `json:"decided_by"`
		Reason    string         `json:"reason"`
		CreatedAt string         `json:"created_at"`
	}
	out := []approval{}
	for rows.Next() {
		var it approval
		var args sql.NullString
		var decidedBy, reason sql.NullString
		if err := rows.Scan(&it.ID, &it.TaskID, &it.ProjectID, &it.Tool, &args, &it.Status, &decidedBy, &reason, &it.CreatedAt); err != nil {
			continue
		}
		it.Args = map[string]any{}
		if args.Valid && args.String != "" {
			_ = json.Unmarshal([]byte(args.String), &it.Args)
		}
		it.DecidedBy, it.Reason = decidedBy.String, reason.String
		out = append(out, it)
	}
	respondJSON(w, 200, out)
}

// DecideApproval POST /api/approvals/{id}/decide — 批准或拒绝。
func (a *API) DecideApproval(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		respondErr(w, 422, "missing id")
		return
	}
	var req struct {
		Approve bool   `json:"approve"`
		Reason  string `json:"reason"`
		By      string `json:"by"` // 决策人（缺省 operator；蓝本截断 32）
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondErr(w, 422, err.Error())
		return
	}
	by := orDefault(req.By, "operator")
	if len(by) > 32 {
		by = by[:32]
	}
	status := "denied"
	if req.Approve {
		status = "approved"
	}
	res, err := a.DB.Exec(
		`UPDATE approvals SET status=?, decided_by=?, reason=? WHERE id=? AND status='pending'`,
		status, by, req.Reason, id)
	if err != nil {
		respondErr(w, 500, err.Error())
		return
	}
	if n, _ := res.RowsAffected(); n == 0 {
		respondErr(w, 404, "approval not found or already decided")
		return
	}
	// 决策即时通知（节点轮询最迟 3s 后解锁；前端审批页可订阅刷新）
	a.Bus.Publish("approval_done", map[string]any{"id": id, "status": status, "by": by})
	respondJSON(w, 200, map[string]any{"ok": true, "status": status})
}

// GetApprovalConfig GET /api/approvals/config — 哪些工具需要审批。
func (a *API) GetApprovalConfig(w http.ResponseWriter, r *http.Request) {
	v := settingStr(a.DB, "approvals_require")
	tools := []string{}
	_ = json.Unmarshal([]byte(v), &tools)
	respondJSON(w, 200, map[string]any{"require": tools})
}

// PutApprovalConfig PUT /api/approvals/config — 设置需要审批的工具列表。
func (a *API) PutApprovalConfig(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Require []string `json:"require"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondErr(w, 422, err.Error())
		return
	}
	b, _ := json.Marshal(req.Require)
	if err := settingSet(a.DB, "approvals_require", string(b)); err != nil {
		respondErr(w, 500, err.Error())
		return
	}
	respondJSON(w, 200, map[string]any{"ok": true})
}


func settingStr(db *sql.DB, key string) string {
	var v sql.NullString
	_ = db.QueryRow("SELECT value FROM settings WHERE key=?", key).Scan(&v)
	return v.String
}

func settingSet(db *sql.DB, key, val string) error {
	_, err := db.Exec("INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", key, val)
	return err
}
