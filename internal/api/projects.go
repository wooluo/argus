// Package api: REST API（chi 路由，对齐原 FastAPI 契约的核心子集）。
package api

import (
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"

	"github.com/wooluo/argus/internal/store"
)

// ================= 通用辅助 =================

func respondJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func respondErr(w http.ResponseWriter, code int, msg string) {
	respondJSON(w, code, map[string]string{"detail": msg})
}

func pathID(r *http.Request) (int64, error) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil || id <= 0 {
		return 0, errors.New("invalid id")
	}
	return id, nil
}

// ================= Projects =================

// projectStats / projectLastTask 项目列表每一行都要显示的汇总和最近一条任务。
type projectStats struct {
	Domains  int64 `json:"domains"`
	URLs     int64 `json:"urls"`
	Ports    int64 `json:"ports"`
	Findings int64 `json:"findings"`
}

type projectLastTask struct {
	ID        int64  `json:"id"`
	Status    string `json:"status"`
	CreatedAt string `json:"created_at"`
}

type projectRow struct {
	store.Project
	Stats    projectStats     `json:"stats"`
	LastTask *projectLastTask `json:"last_task"` // 没跑过任务为 null
}

// ListProjects GET /api/projects —— 每行带 stats（资产/漏洞计数）和 last_task。
//
// 页面那两格按这两个字段渲染。接口曾一度不带它们：「资产/漏洞」一格读取
// stats 时报错，整格被丢掉，右边的列全部左移一格——「最近任务」下面是操作
// 按钮、「操作」列是空的。汇总按项目一次分组查出来，不逐行查。
func (a *API) ListProjects(w http.ResponseWriter, r *http.Request) {
	rows, err := a.DB.Query(`SELECT id,name,description,scope,authorized,allow_hosts,created_at FROM projects ORDER BY id DESC`)
	if err != nil {
		respondErr(w, 500, err.Error())
		return
	}
	defer rows.Close()
	out := []projectRow{}
	for rows.Next() {
		var p projectRow
		var auth int
		if err := rows.Scan(&p.ID, &p.Name, &p.Description, &p.Scope, &auth, &p.AllowHosts, &p.CreatedAt); err != nil {
			respondErr(w, 500, err.Error())
			return
		}
		p.Authorized = auth == 1
		out = append(out, p)
	}
	stats, err := projectStatsBy(a.DB)
	if err != nil {
		respondErr(w, 500, err.Error())
		return
	}
	last, err := lastTasksBy(a.DB)
	if err != nil {
		respondErr(w, 500, err.Error())
		return
	}
	for i := range out {
		if s := stats[int64(out[i].ID)]; s != nil {
			out[i].Stats = *s
		}
		out[i].LastTask = last[int64(out[i].ID)]
	}
	respondJSON(w, 200, out)
}

// projectStatsBy 各项目的资产数（按类型）与漏洞数；没有记录的项目不在结果里。
func projectStatsBy(db *sql.DB) (map[int64]*projectStats, error) {
	out := map[int64]*projectStats{}
	get := func(id int64) *projectStats {
		s := out[id]
		if s == nil {
			s = &projectStats{}
			out[id] = s
		}
		return s
	}
	rows, err := db.Query(`SELECT project_id, type, COUNT(*) FROM assets GROUP BY project_id, type`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var id int64
		var typ string
		var n int64
		if err := rows.Scan(&id, &typ, &n); err != nil {
			rows.Close()
			return nil, err
		}
		switch s := get(id); typ {
		case "domain":
			s.Domains = n
		case "url":
			s.URLs = n
		case "port":
			s.Ports = n
		}
	}
	rows.Close()
	rows, err = db.Query(`SELECT project_id, COUNT(*) FROM findings GROUP BY project_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id, n int64
		if err := rows.Scan(&id, &n); err != nil {
			return nil, err
		}
		get(id).Findings = n
	}
	return out, rows.Err()
}

// lastTasksBy 各项目编号最大的一条任务；状态词与管理面其它出口一致
// （done → completed 等）。
func lastTasksBy(db *sql.DB) (map[int64]*projectLastTask, error) {
	rows, err := db.Query(`SELECT project_id, id, status, created_at FROM tasks
		WHERE id IN (SELECT MAX(id) FROM tasks GROUP BY project_id)`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[int64]*projectLastTask{}
	for rows.Next() {
		var pid int64
		var status string
		t := &projectLastTask{}
		if err := rows.Scan(&pid, &t.ID, &status, &t.CreatedAt); err != nil {
			return nil, err
		}
		t.Status = store.PresentStatus(status)
		out[pid] = t
	}
	return out, rows.Err()
}

func (a *API) CreateProject(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name        string          `json:"name"`
		Description string          `json:"description"`
		Scope       json.RawMessage `json:"scope"`
		AllowHosts  json.RawMessage `json:"allow_hosts"`
		Authorized  *bool           `json:"authorized"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondErr(w, 422, err.Error())
		return
	}
	if req.Name == "" {
		respondErr(w, 422, "name required")
		return
	}
	if len(req.Scope) == 0 {
		req.Scope = json.RawMessage("[]")
	}
	if len(req.AllowHosts) == 0 {
		req.AllowHosts = json.RawMessage("[]")
	}
	authz := 0
	if req.Authorized != nil && *req.Authorized {
		authz = 1
	}
	res, err := a.DB.Exec(`INSERT INTO projects(name,description,scope,allow_hosts,authorized) VALUES(?,?,?,?,?)`,
		req.Name, req.Description, string(req.Scope), string(req.AllowHosts), authz)
	if err != nil {
		respondErr(w, 500, err.Error())
		return
	}
	id, _ := res.LastInsertId()
	a.Bus.Publish("project_created", map[string]any{"id": id, "name": req.Name})
	a.getProject(w, id)
}

func (a *API) getProject(w http.ResponseWriter, id int64) {
	var p store.Project
	var auth int
	err := a.DB.QueryRow(`SELECT id,name,description,scope,authorized,allow_hosts,created_at FROM projects WHERE id=?`, id).
		Scan(&p.ID, &p.Name, &p.Description, &p.Scope, &auth, &p.AllowHosts, &p.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		respondErr(w, 404, "project not found")
		return
	}
	if err != nil {
		respondErr(w, 500, err.Error())
		return
	}
	p.Authorized = auth == 1
	respondJSON(w, 200, p)
}

func (a *API) GetProject(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		respondErr(w, 422, err.Error())
		return
	}
	a.getProject(w, id)
}

func (a *API) UpdateProject(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		respondErr(w, 422, err.Error())
		return
	}
	var req struct {
		Name        *string         `json:"name"`
		Description *string         `json:"description"`
		Scope       json.RawMessage `json:"scope"`
		AllowHosts  json.RawMessage `json:"allow_hosts"`
		Authorized  *bool           `json:"authorized"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondErr(w, 422, err.Error())
		return
	}
	cur, err := a.DB.Query(`SELECT name,description,scope,allow_hosts,authorized FROM projects WHERE id=?`, id)
	if err != nil {
		respondErr(w, 500, err.Error())
		return
	}
	defer cur.Close()
	if !cur.Next() {
		respondErr(w, 404, "project not found")
		return
	}
	var name, desc string
	var scope, allow store.RawJSON
	var authz int
	_ = cur.Scan(&name, &desc, &scope, &allow, &authz)
	cur.Close()

	if req.Name != nil {
		name = *req.Name
	}
	if req.Description != nil {
		desc = *req.Description
	}
	if len(req.Scope) > 0 {
		scope = store.RawJSON(req.Scope)
	}
	if len(req.AllowHosts) > 0 {
		allow = store.RawJSON(req.AllowHosts)
	}
	authBool := authz == 1
	if req.Authorized != nil {
		authBool = *req.Authorized
	}
	if _, err := a.DB.Exec(`UPDATE projects SET name=?,description=?,scope=?,allow_hosts=?,authorized=? WHERE id=?`,
		name, desc, string(scope), string(allow), boolInt(authBool), id); err != nil {
		respondErr(w, 500, err.Error())
		return
	}
	a.getProject(w, id)
}

func (a *API) DeleteProject(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		respondErr(w, 400, err.Error())
		return
	}
	res, err := a.DB.Exec(`DELETE FROM projects WHERE id=?`, id)
	if err != nil {
		respondErr(w, 500, err.Error())
		return
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		respondErr(w, 404, "project not found")
		return
	}
	a.Bus.Publish("project_deleted", map[string]any{"id": id})
	respondJSON(w, 200, map[string]bool{"ok": true})
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
