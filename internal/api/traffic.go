package api

// traffic.go: 流量录制域 + 漏洞补充端点（蓝本 api/assets.py 对应部分）。
// 流量由节点 http_fetch/web_login 结构化上报（traffic_logs），可一键重放
// （server 侧重发 + ScopeGuard + repeater 留痕）。

import (
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/wooluo/argus/internal/scope"
	"github.com/wooluo/argus/internal/store"
)

// trafficRow 流量记录（蓝本 TrafficLog 列表形状）。
type trafficRow struct {
	ID              int64  `json:"id"`
	Method          string `json:"method"`
	URL             string `json:"url"`
	RequestBody     string `json:"request_body"`
	Status          int    `json:"status"`
	ResponseSnippet string `json:"response_snippet"`
	SourceTool      string `json:"source_tool"`
	CreatedAt       string `json:"created_at"`
}

// ListTraffic GET /api/traffic?project_id= — 全局/项目流量录制列表。
func (a *API) ListTraffic(w http.ResponseWriter, r *http.Request) {
	limit := clampInt(r.URL.Query().Get("limit"), 200, 1, 1000)
	q := `SELECT id,method,url,request_body,status,response_snippet,source_tool,created_at FROM traffic_logs`
	var rows *sql.Rows
	var err error
	if pid, _ := strconv.ParseInt(r.URL.Query().Get("project_id"), 10, 64); pid > 0 {
		rows, err = a.DB.Query(q+` WHERE project_id=? ORDER BY id DESC LIMIT ?`, pid, limit)
	} else {
		rows, err = a.DB.Query(q+` ORDER BY id DESC LIMIT ?`, limit)
	}
	if err != nil {
		respondErr(w, 500, err.Error())
		return
	}
	defer rows.Close()
	out := []trafficRow{}
	for rows.Next() {
		var t trafficRow
		if rows.Scan(&t.ID, &t.Method, &t.URL, &t.RequestBody, &t.Status,
			&t.ResponseSnippet, &t.SourceTool, &t.CreatedAt) == nil {
			out = append(out, t)
		}
	}
	respondJSON(w, 200, out)
}

// ReplayTraffic POST /api/traffic/{id}/replay — 按录制请求重发，返回与原响应对比。
// server 侧重发（无节点登录会话——pull 架构限制，hint 注明）；ScopeGuard 拦截范围外；
// 重放进 repeater_logs 留痕（source=replay）。
func (a *API) ReplayTraffic(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		respondErr(w, 422, err.Error())
		return
	}
	var t struct {
		ProjectID            int64
		Method, URL, ReqBody string
		Status               int
		Snippet              string
	}
	if err := a.DB.QueryRow(
		`SELECT project_id,method,url,request_body,status,response_snippet FROM traffic_logs WHERE id=?`, id).
		Scan(&t.ProjectID, &t.Method, &t.URL, &t.ReqBody, &t.Status, &t.Snippet); err != nil {
		if err == sql.ErrNoRows {
			respondErr(w, 404, "流量记录不存在")
			return
		}
		respondErr(w, 500, err.Error())
		return
	}
	// 范围护栏：重放目标必须在项目授权范围内
	var scopeRaw, allowRaw []byte
	_ = a.DB.QueryRow(`SELECT scope,allow_hosts FROM projects WHERE id=?`, t.ProjectID).
		Scan(&scopeRaw, &allowRaw)
	var rules []scope.Rule
	var allowHosts []string
	_ = json.Unmarshal(scopeRaw, &rules)
	_ = json.Unmarshal(allowRaw, &allowHosts)
	guard := scope.New(t.ProjectID, rules, allowHosts)
	if err := guard.EnsureURL(t.URL); err != nil {
		respondErr(w, 400, "重放被范围护栏拦截: "+err.Error())
		return
	}

	method := strings.ToUpper(t.Method)
	if method != "POST" {
		method = "GET"
	}
	// 附项目最近登录会话（web_login 时节点回传的 cookie 快照）——
	// pull 架构下 server 无法共享节点内存会话，登录时刻快照是唯一途径
	cookies, sessUser := a.latestSession(t.ProjectID)
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	var bodyReader io.Reader
	if method == "POST" && t.ReqBody != "" {
		bodyReader = strings.NewReader(t.ReqBody)
	}
	req2, err := http.NewRequestWithContext(ctx, method, t.URL, bodyReader)
	if err != nil {
		respondErr(w, 400, err.Error())
		return
	}
	if method == "POST" && t.ReqBody != "" {
		req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	for k, v := range cookies {
		req2.AddCookie(&http.Cookie{Name: k, Value: v})
	}
	cl := &http.Client{
		Timeout: 30 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := cl.Do(req2)
	if err != nil {
		respondErr(w, 502, err.Error())
		return
	}
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 256<<10))
	resp.Body.Close()
	status2, body := resp.StatusCode, string(raw)
	hint := ""
	switch {
	case status2 >= 400 && len(cookies) == 0:
		hint = "重放返回异常状态码，且项目无已存登录会话（先跑一次 web_login 或人工录入凭据）"
	case status2 >= 400:
		hint = "重放带会话 Cookie 仍返回异常，会话可能已过期（重新触发 web_login）"
	case len(cookies) > 0:
		hint = "已附加登录会话（用户 " + sessUser + "）"
	}
	// repeater 留痕（来源=replay，可回溯）
	_, _ = a.DB.Exec(`INSERT INTO repeater_logs(project_id,method,url,request_body,status,response_snippet,source,origin_traffic_id)
		VALUES(?,?,?,?,?,?,?,?)`,
		t.ProjectID, method, t.URL, t.ReqBody, status2, truncateStr(body, 6000), "replay", id)

	respondJSON(w, 200, map[string]any{
		"ok": true, "url": t.URL, "method": method,
		"original": map[string]any{"status": t.Status, "snippet": truncateStr(t.Snippet, 400)},
		"replayed": map[string]any{"status": status2, "snippet": truncateStr(body, 400)},
		"hint":     hint, "session_cookies": len(cookies),
	})
}

// latestSession 项目最近一次登录会话（assets 表 type='session'，web_login 回传）。
func (a *API) latestSession(projectID int64) (map[string]string, string) {
	var detail sql.NullString
	if err := a.DB.QueryRow(
		`SELECT detail FROM assets WHERE project_id=? AND type='session' ORDER BY id DESC LIMIT 1`,
		projectID).Scan(&detail); err != nil {
		return nil, ""
	}
	var s struct {
		User    string            `json:"user"`
		Cookies map[string]string `json:"cookies"`
	}
	if json.Unmarshal([]byte(detail.String), &s) != nil {
		return nil, ""
	}
	return s.Cookies, s.User
}

// ================= Findings 补充端点（蓝本 assets.py read/evidence/steps/DELETE） =================

// MarkFindingRead POST /api/findings/{id}/read — 标记单条已读。
func (a *API) MarkFindingRead(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		respondErr(w, 422, err.Error())
		return
	}
	res, err := a.DB.Exec(`UPDATE findings SET read_at=? WHERE id=? AND read_at IS NULL`, store.Now(), id)
	if err != nil {
		respondErr(w, 500, err.Error())
		return
	}
	if rowsAffectedInt(res) == 0 {
		// 已读或不存在都算幂等成功（蓝本行为：不存在才 404）
		var one int
		if a.DB.QueryRow(`SELECT 1 FROM findings WHERE id=?`, id).Scan(&one) != nil {
			respondErr(w, 404, "漏洞不存在")
			return
		}
	}
	respondJSON(w, 200, map[string]bool{"ok": true})
}

// MarkAllFindingsRead POST /api/findings/read-all — 全部标记已读。
func (a *API) MarkAllFindingsRead(w http.ResponseWriter, r *http.Request) {
	res, err := a.DB.Exec(`UPDATE findings SET read_at=? WHERE read_at IS NULL`, store.Now())
	if err != nil {
		respondErr(w, 500, err.Error())
		return
	}
	respondJSON(w, 200, map[string]any{"ok": true, "marked": rowsAffectedInt(res)})
}

// FindingEvidence GET /api/findings/{id}/evidence — 证据包：详情 + 利用链 + 关联流量。
func (a *API) FindingEvidence(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		respondErr(w, 422, err.Error())
		return
	}
	var f struct {
		Name, Detail, Evidence, Target string
	}
	if err := a.DB.QueryRow(
		`SELECT name,detail,evidence,target FROM findings WHERE id=?`, id).
		Scan(&f.Name, &f.Detail, &f.Evidence, &f.Target); err != nil {
		if err == sql.ErrNoRows {
			respondErr(w, 404, "漏洞不存在")
			return
		}
		respondErr(w, 500, err.Error())
		return
	}
	// 利用链步骤
	steps := a.findingStepsList(id)
	// 关联流量（同 target 前缀的请求报文）
	base := strings.SplitN(f.Target, "?", 2)[0]
	trows, _ := a.DB.Query(
		`SELECT method,url,request_body,status,response_snippet FROM traffic_logs
		 WHERE url LIKE ? ORDER BY id DESC LIMIT 20`, base+"%")
	traffic := []map[string]any{}
	for trows.Next() {
		var method, u, reqBody, snippet string
		var st int
		if trows.Scan(&method, &u, &reqBody, &st, &snippet) == nil {
			traffic = append(traffic, map[string]any{
				"method": method, "url": u, "request_body": reqBody,
				"status": st, "response_snippet": snippet})
		}
	}
	trows.Close()
	respondJSON(w, 200, map[string]any{
		"finding": map[string]any{
			"name": f.Name, "detail": f.Detail, "evidence": f.Evidence, "target": f.Target},
		"steps": steps, "traffic": traffic,
	})
}

// FindingSteps GET /api/findings/{id}/steps — 利用链步骤（复现路径）。
func (a *API) FindingSteps(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		respondErr(w, 422, err.Error())
		return
	}
	respondJSON(w, 200, a.findingStepsList(id))
}

func (a *API) findingStepsList(findingID int64) []map[string]any {
	rows, err := a.DB.Query(
		`SELECT seq,note,request,response,conclusion,created_at FROM finding_steps
		 WHERE finding_id=? ORDER BY seq`, findingID)
	if err != nil {
		return []map[string]any{}
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var seq int
		var note, req, resp, conclusion string
		var createdAt sql.NullString
		if rows.Scan(&seq, &note, &req, &resp, &conclusion, &createdAt) == nil {
			out = append(out, map[string]any{
				"seq": seq, "note": note, "request": req, "response": resp,
				"conclusion": conclusion, "created_at": nilOrStr(createdAt),
			})
		}
	}
	return out
}

// DeleteFinding DELETE /api/findings/{id} — 删除漏洞（连同利用链步骤）。
func (a *API) DeleteFinding(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		respondErr(w, 422, err.Error())
		return
	}
	res, err := a.DB.Exec(`DELETE FROM findings WHERE id=?`, id)
	if err != nil {
		respondErr(w, 500, err.Error())
		return
	}
	if rowsAffectedInt(res) == 0 {
		respondErr(w, 404, "漏洞不存在")
		return
	}
	_, _ = a.DB.Exec(`DELETE FROM finding_steps WHERE finding_id=?`, id)
	respondJSON(w, 200, map[string]bool{"ok": true})
}

// ================= 辅助 =================

func rowsAffectedInt(res sql.Result) int64 {
	n, _ := res.RowsAffected()
	return n
}

func nilOrStr(ns sql.NullString) any {
	if ns.Valid {
		return ns.String
	}
	return nil
}

func truncateStr(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
