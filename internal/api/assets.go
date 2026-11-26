package api

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/wooluo/argus/internal/store"
)

// ================= Assets =================

// ListAssets GET /api/assets（全局）与 /api/projects/{id}/assets（withPID 注入
// project_id）。
//
// 带 page 参数时按页返回 {items,total,page,size}——资产中心和项目资产页都是
// 这么请求的；不带 page 仍返回数组（旧调用方）。曾几何时这里只返回数组也
// 不认 page，页面读 data.items 得到 undefined，表永远是空的。
func (a *API) ListAssets(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	pid, _ := strconv.ParseInt(q.Get("project_id"), 10, 64)
	where, args := assetWhere(pid, q.Get("type"), q.Get("q"))

	if q.Get("page") != "" {
		page := clampInt(q.Get("page"), 1, 1, 1_000_000)
		size := clampInt(q.Get("size"), 100, 1, 5000)
		var total int64
		if err := a.DB.QueryRow(`SELECT COUNT(*) FROM assets a`+where, args...).Scan(&total); err != nil {
			respondErr(w, 500, err.Error())
			return
		}
		pageArgs := append(append([]any{}, args...), size, (page-1)*size)
		items, err := a.queryAssets(where+` ORDER BY a.id DESC LIMIT ? OFFSET ?`, pageArgs)
		if err != nil {
			respondErr(w, 500, err.Error())
			return
		}
		respondJSON(w, 200, map[string]any{"items": items, "total": total, "page": page, "size": size})
		return
	}

	limit := clampInt(q.Get("limit"), 500, 1, 5000)
	out, err := a.queryAssets(where+` ORDER BY a.id DESC LIMIT ?`, append(append([]any{}, args...), limit))
	if err != nil {
		respondErr(w, 500, err.Error())
		return
	}
	respondJSON(w, 200, out)
}

// assetWhere 过滤条件：项目 / 类型 / 值模糊匹配。返回的 where 以 " WHERE " 开头或为空串。
func assetWhere(pid int64, typ, kw string) (string, []any) {
	cond := []string{}
	args := []any{}
	// 列名带表别名：查询里 LEFT JOIN 了 projects，id 两张表都有
	if pid > 0 {
		cond = append(cond, "a.project_id=?")
		args = append(args, pid)
	}
	if typ != "" {
		cond = append(cond, "a.type=?")
		args = append(args, typ)
	}
	if kw != "" {
		cond = append(cond, "a.value LIKE ?")
		args = append(args, "%"+kw+"%")
	}
	if len(cond) == 0 {
		return "", args
	}
	return " WHERE " + joinAnd(cond), args
}

// queryAssets 取资产并带出所属项目名（资产中心「所属项目」列读 project_name）。
func (a *API) queryAssets(tail string, args []any) ([]store.Asset, error) {
	rows, err := a.DB.Query(`SELECT a.id,a.project_id,COALESCE(NULLIF(p.name,''),'#'||a.project_id),
		a.type,a.value,a.detail,a.source,a.created_at
		FROM assets a LEFT JOIN projects p ON p.id=a.project_id`+tail, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []store.Asset{}
	for rows.Next() {
		var s store.Asset
		if err := rows.Scan(&s.ID, &s.ProjectID, &s.ProjectName, &s.Type, &s.Value, &s.Detail, &s.Source, &s.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

func joinAnd(parts []string) string {
	out := ""
	for i, p := range parts {
		if i > 0 {
			out += " AND "
		}
		out += p
	}
	return out
}

// ================= Findings =================

func (a *API) ListFindings(w http.ResponseWriter, r *http.Request) {
	pid, _ := strconv.ParseInt(r.URL.Query().Get("project_id"), 10, 64)
	sev := r.URL.Query().Get("severity")
	status := r.URL.Query().Get("status")
	q := r.URL.Query().Get("q")
	limit := clampInt(r.URL.Query().Get("limit"), 500, 1, 5000)

	sqlw := `SELECT id,project_id,name,severity,target,detail,evidence,poc,status,read_at,source,created_at FROM findings`
	cond := []string{}
	args := []any{}
	if pid > 0 {
		cond = append(cond, "project_id=?")
		args = append(args, pid)
	}
	if sev != "" {
		cond = append(cond, "severity=?")
		args = append(args, sev)
	}
	if status != "" {
		cond = append(cond, "status=?")
		args = append(args, status)
	}
	if q != "" {
		cond = append(cond, "(name LIKE ? OR target LIKE ?)")
		args = append(args, "%"+q+"%", "%"+q+"%")
	}
	if len(cond) > 0 {
		sqlw += " WHERE " + joinAnd(cond)
	}
	sqlw += " ORDER BY id DESC LIMIT ?"
	args = append(args, limit)

	rows, err := a.DB.Query(sqlw, args...)
	if err != nil {
		respondErr(w, 500, err.Error())
		return
	}
	defer rows.Close()
	out := []store.Finding{}
	for rows.Next() {
		var f store.Finding
		var readAt sqlNull
		if err := rows.Scan(&f.ID, &f.ProjectID, &f.Name, &f.Severity, &f.Target, &f.Detail, &f.Evidence, &f.PoC, &f.Status, &readAt, &f.Source, &f.CreatedAt); err != nil {
			respondErr(w, 500, err.Error())
			return
		}
		f.ReadAt = readAt.value()
		f.MarkUnread()
		out = append(out, f)
	}
	respondJSON(w, 200, out)
}

// CreateFinding: POST /api/projects/{pid}/findings — Agent/节点上报。
func (a *API) CreateFinding(w http.ResponseWriter, r *http.Request) {
	pid, err := pathID(r)
	if err != nil {
		respondErr(w, 422, err.Error())
		return
	}
	var req struct {
		Name     string `json:"name"`
		Severity string `json:"severity"`
		Target   string `json:"target"`
		Detail   string `json:"detail"`
		Evidence string `json:"evidence"`
		PoC      string `json:"poc"`
		Source   string `json:"source"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Name == "" {
		respondErr(w, 422, "name required")
		return
	}
	if req.Severity == "" {
		req.Severity = "info"
	}
	res, err := a.DB.Exec(`INSERT INTO findings(project_id,name,severity,target,detail,evidence,poc,source) VALUES(?,?,?,?,?,?,?,?)`,
		pid, req.Name, req.Severity, req.Target, req.Detail, req.Evidence, req.PoC, req.Source)
	if err != nil {
		respondErr(w, 500, err.Error())
		return
	}
	id, _ := res.LastInsertId()
	a.Bus.Publish("finding_created", map[string]any{"id": id, "project_id": pid, "name": req.Name, "severity": req.Severity})
	respondJSON(w, 201, map[string]any{"id": id})
}

// UpdateFindingStatus: PATCH /api/findings/{id} — 标记已读/确认/误报。
func (a *API) UpdateFindingStatus(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		respondErr(w, 422, err.Error())
		return
	}
	var req struct {
		Status *string `json:"status"`
		Read   *bool   `json:"read"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondErr(w, 422, err.Error())
		return
	}
	if req.Status != nil {
		switch *req.Status {
		case "pending", "confirmed", "false_positive":
		default:
			respondErr(w, 422, "status must be pending|confirmed|false_positive")
			return
		}
		if _, err := a.DB.Exec(`UPDATE findings SET status=? WHERE id=?`, *req.Status, id); err != nil {
			respondErr(w, 500, err.Error())
			return
		}
	}
	if req.Read != nil && *req.Read {
		if _, err := a.DB.Exec(`UPDATE findings SET read_at=? WHERE id=?`, store.Now(), id); err != nil {
			respondErr(w, 500, err.Error())
			return
		}
	}
	a.getFinding(w, id)
}

func (a *API) getFinding(w http.ResponseWriter, id int64) {
	var f store.Finding
	var readAt sqlNull
	err := a.DB.QueryRow(`SELECT id,project_id,name,severity,target,detail,evidence,poc,status,read_at,source,created_at FROM findings WHERE id=?`, id).
		Scan(&f.ID, &f.ProjectID, &f.Name, &f.Severity, &f.Target, &f.Detail, &f.Evidence, &f.PoC, &f.Status, &readAt, &f.Source, &f.CreatedAt)
	if err != nil {
		respondErr(w, 404, "finding not found")
		return
	}
	f.ReadAt = readAt.value()
	respondJSON(w, 200, f)
}
