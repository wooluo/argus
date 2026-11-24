package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/wooluo/argus/internal/llm"
	"github.com/wooluo/argus/internal/pipeline"
	"github.com/wooluo/argus/internal/scope"
	"github.com/wooluo/argus/internal/store"
	"github.com/wooluo/argus/internal/tools"
)

// ============ Retest 域（蓝本 api/retest.py） ============

// parseRetestRequest 解析 "GET/POST URL[... DATA: {...}|k=v&k2=v2]" 形式的步骤请求。
func parseRetestRequest(raw string) (method, rawURL string, data map[string]string) {
	method, rawURL, data = "GET", "", map[string]string{}
	s := strings.TrimSpace(raw)
	if s == "" {
		return
	}
	if strings.HasPrefix(strings.ToUpper(s), "POST ") {
		method = "POST"
		s = strings.TrimSpace(s[5:])
	} else if strings.HasPrefix(strings.ToUpper(s), "GET ") {
		s = strings.TrimSpace(s[4:])
	}
	if i := strings.Index(s, " DATA:"); i > 0 {
		data = parseKVForm(s[i+6:])
		s = strings.TrimSpace(s[:i])
	} else if i := strings.Index(s, "..."); i > 0 {
		s = strings.TrimSpace(s[:i])
	}
	rawURL = strings.TrimSpace(s)
	return
}

// parseKVForm 解析 k=v&k2=v2 或 JSON 对象为参数表。
func parseKVForm(s string) map[string]string {
	s = strings.TrimSpace(s)
	out := map[string]string{}
	if s == "" {
		return out
	}
	if strings.HasPrefix(s, "{") {
		var m map[string]any
		if json.Unmarshal([]byte(s), &m) == nil {
			for k, v := range m {
				out[k] = fmt.Sprint(v)
			}
		}
		return out
	}
	for _, kv := range strings.Split(s, "&") {
		if k, v, ok := strings.Cut(kv, "="); ok {
			if dk, err := url.QueryUnescape(k); err == nil {
				k = dk
			}
			if dv, err := url.QueryUnescape(v); err == nil {
				v = dv
			}
			out[k] = v
		}
	}
	return out
}

// retestReporter 最小 Reporter：重放流量留痕进 traffic_logs（与 pipeline memReporter 同构的最小实现）。
type retestReporter struct {
	db      *sql.DB
	project int64
}

func (r *retestReporter) SaveEvidence(ctx context.Context, typ, content string, meta map[string]any) {
	if typ != "traffic" {
		return
	}
	body, _ := meta["body"].(string)
	_, _ = r.db.ExecContext(ctx,
		"INSERT INTO traffic_logs (project_id, task_id, method, url, request_body, status, response_snippet, source_tool) VALUES (?,?,0,?,?,?,?,?)",
		r.project, "GET", content, "", 0, tools.Truncate(body, 600), "retest")
}

func (r *retestReporter) SaveAsset(context.Context, string, string, map[string]any)      {}
func (r *retestReporter) SaveSession(context.Context, string, string, map[string]string) {}

// SaveTraffic 复测也走结构化流量录制（重放报文留痕）。
func (r *retestReporter) SaveTraffic(ctx context.Context, method, rawURL, reqBody string,
	status int, snippet, sourceTool string) {
	_, _ = r.db.ExecContext(ctx,
		"INSERT INTO traffic_logs (project_id, task_id, method, url, request_body, status, response_snippet, source_tool) VALUES (?,?,0,?,?,?,?,?)",
		r.project, method, rawURL, reqBody, status, tools.Truncate(snippet, 600), sourceTool)
}
func (r *retestReporter) SaveFinding(context.Context, tools.Finding) (int64, error)     { return 0, nil }
func (r *retestReporter) UpdateFinding(context.Context, int64, map[string]any) error    { return nil }
func (r *retestReporter) SaveKnowledge(context.Context, tools.Knowledge) error          { return nil }
func (r *retestReporter) SearchKnowledge(context.Context, string, int) []map[string]any { return nil }
func (r *retestReporter) Log(context.Context, string, string, string)                   {}
func (r *retestReporter) LLMDesc() string                                               { return "retest" }

// RetestFinding POST /api/findings/{id}/retest — 按原利用链步骤范围内重放，LLM 三选一判定并追加进 detail。
func (a *API) RetestFinding(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		respondErr(w, http.StatusNotFound, "finding 不存在")
		return
	}
	var f store.Finding
	err = a.DB.QueryRow(
		"SELECT id, project_id, name, severity, target, detail, evidence, poc, status, source, created_at FROM findings WHERE id=?", id,
	).Scan(&f.ID, &f.ProjectID, &f.Name, &f.Severity, &f.Target, &f.Detail, &f.Evidence, &f.PoC, &f.Status, &f.Source, &f.CreatedAt)
	if err == sql.ErrNoRows {
		respondErr(w, http.StatusNotFound, "finding 不存在")
		return
	}
	if err != nil {
		respondErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	// 利用链步骤按 seq 升序
	type stepRow struct {
		Seq      int
		Request  string
		Response string
	}
	var steps []stepRow
	rows, err := a.DB.Query("SELECT seq, request, response FROM finding_steps WHERE finding_id=? ORDER BY seq", id)
	if err != nil {
		respondErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	defer rows.Close()
	for rows.Next() {
		var s stepRow
		if rows.Scan(&s.Seq, &s.Request, &s.Response) != nil {
			continue
		}
		steps = append(steps, s)
	}

	// 范围护栏 + 会话复用重放（HttpFetchTool 自带 projectSessions 复用）
	var proj store.Project
	var allowHosts []string
	if err := a.DB.QueryRow("SELECT scope, allow_hosts FROM projects WHERE id=?", f.ProjectID).
		Scan(&proj.Scope, &proj.AllowHosts); err == nil {
		if len(proj.AllowHosts) > 0 {
			if err := json.Unmarshal(proj.AllowHosts, &allowHosts); err != nil {
				allowHosts = nil
			}
		}
	}
	var rules []scope.Rule
	_ = json.Unmarshal(proj.Scope, &rules)
	guard := scope.New(int64(f.ProjectID), rules, allowHosts)

	tc := &tools.Context{
		ProjectID: int64(f.ProjectID),
		Reporter:  &retestReporter{db: a.DB, project: int64(f.ProjectID)},
	}
	fetch := &tools.HttpFetchTool{}
	replays := []map[string]any{}
	for _, s := range steps {
		method, rawURL, data := parseRetestRequest(s.Request)
		if rawURL == "" {
			replays = append(replays, map[string]any{"seq": s.Seq, "skipped": "步骤请求不可解析，人工复核"})
			continue
		}
		if guard.EnsureURL(rawURL) != nil {
			replays = append(replays, map[string]any{"seq": s.Seq, "skipped": "URL 不在授权范围"})
			continue
		}
		args := map[string]any{"url": rawURL, "method": method}
		if len(data) > 0 {
			args["data"] = data
		}
		outJSON, err := fetch.Execute(r.Context(), args, tc)
		if err != nil {
			replays = append(replays, map[string]any{"seq": s.Seq, "error": tools.Truncate(err.Error(), 150)})
			continue
		}
		var out map[string]any
		_ = json.Unmarshal([]byte(outJSON), &out)
		status, _ := out["status"].(int)
		if status == 0 {
			if f64, ok := out["status"].(float64); ok {
				status = int(f64)
			}
		}
		body, _ := out["body"].(string)
		note, _ := out["note"].(string)
		replays = append(replays, map[string]any{
			"seq": s.Seq, "note": note, "status": status,
			"body_snippet": tools.Truncate(body, 500),
			"original":     tools.Truncate(s.Response, 300),
		})
	}

	// LLM 三选一判定（内置=实战验证的复测方法论；Agent 管理页 retester 可覆盖）
	system := pipeline.RETESTER_SYSTEM_PROMPT
	if custom := agentPromptSetting(a.DB, "retester"); custom != "" {
		system = custom
	}
	if custom := strings.TrimSpace(a.retesterPrompt()); custom != "" {
		system = custom
	}
	var rb strings.Builder
	for _, rep := range replays {
		b, _ := json.Marshal(rep)
		rb.WriteString(string(b))
		rb.WriteString("\n")
	}
	prompt := fmt.Sprintf(
		"漏洞：%s @ %s\n原始结论：%s\n\n以下是按原利用链步骤重放的结果（含原始记录对比）：\n%s\n\n"+
			"判定结论，三选一：still（仍可复现，响应与原始证据一致或仍含漏洞特征）/ "+
			"fixed（已修复，响应不再出现原始证据特征）/ unknown（无法确认，如全被跳过或证据不足）。"+
			"第一行只输出 still/fixed/unknown，随后不超过 100 字说明。",
		f.Name, f.Target, tools.Truncate(f.Detail, 300), rb.String())
	client := llm.NewClient(llm.DefaultProvider(llmConfigForRole(a.DB, "review"))) // 复测判定：分工了用「审查与核验」的模型
	verdict, err := client.ChatText(r.Context(), system, prompt, 0.1)
	if err != nil {
		respondErr(w, http.StatusInternalServerError, "判定失败（LLM）: "+err.Error())
		return
	}

	key := ""
	for _, line := range strings.Split(strings.TrimSpace(verdict), "\n") {
		if line = strings.TrimSpace(line); line != "" {
			key = strings.ToLower(line)
			break
		}
	}
	conclusion := "unknown"
	if strings.Contains(key, "still") {
		conclusion = "still"
	} else if strings.Contains(key, "fixed") {
		conclusion = "fixed"
	}
	note := ""
	if i := strings.Index(strings.TrimSpace(verdict), "\n"); i > 0 {
		note = tools.Truncate(strings.TrimSpace(strings.TrimSpace(verdict)[i+1:]), 500)
	}
	cn := map[string]string{"still": "仍可复现", "fixed": "已修复", "unknown": "无法确认"}[conclusion]

	stamp := time.Now().UTC().Format("01-02 15:04")
	if _, err := a.DB.Exec("UPDATE findings SET detail=detail||? WHERE id=?",
		fmt.Sprintf("\n\n[复测 %s] 结论：%s。%s", stamp, cn, note), id); err != nil {
		respondErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	respondJSON(w, http.StatusOK, map[string]any{
		"ok": true, "conclusion": conclusion, "conclusion_cn": cn, "note": note, "replays": replays,
	})
}

// retesterPrompt 从 settings 读取 retester 角色自定义提示词（agents 列表存 settings["agents"]）。
func (a *API) retesterPrompt() string {
	raw := store.GetSetting(a.DB, "agents")
	var agents []map[string]any
	if json.Unmarshal([]byte(raw), &agents) != nil {
		return ""
	}
	for _, ag := range agents {
		if fmt.Sprint(ag["id"]) == "retester" {
			p, _ := ag["prompt"].(string)
			return p
		}
	}
	return ""
}

// agentPromptSetting settings.agents 中指定角色的自定义 prompt（空=用内置）。
func agentPromptSetting(db *sql.DB, role string) string {
	var saved []map[string]any
	_ = json.Unmarshal([]byte(store.GetSetting(db, "agents")), &saved)
	for _, s := range saved {
		if id, _ := s["id"].(string); id == role {
			if p, _ := s["prompt"].(string); strings.TrimSpace(p) != "" {
				return p
			}
		}
	}
	return ""
}
