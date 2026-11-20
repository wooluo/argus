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

func (a *API) ListProjects(w http.ResponseWriter, r *http.Request) {
	rows, err := a.DB.Query(`SELECT id,name,description,scope,authorized,allow_hosts,created_at FROM projects ORDER BY id DESC`)
	if err != nil {
		respondErr(w, 500, err.Error())
		return
	}
	defer rows.Close()
	out := []store.Project{}
	for rows.Next() {
		var p store.Project
		var auth int
		if err := rows.Scan(&p.ID, &p.Name, &p.Description, &p.Scope, &auth, &p.AllowHosts, &p.CreatedAt); err != nil {
			respondErr(w, 500, err.Error())
			return
		}
		p.Authorized = auth == 1
		out = append(out, p)
	}
	respondJSON(w, 200, out)
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
