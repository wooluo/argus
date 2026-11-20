package api

// Extension 域（对应蓝本 api/extension.py）：agents 预置角色 / MCP 服务器 /
// Skill 库 / 通知 webhook / Repeater / POC 库。
// 存储约定：配置走 settings 表键值，skill 正文走 DataDir/skills/*.md。

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/wooluo/argus/internal/config"
	"github.com/wooluo/argus/internal/pipeline"
	"github.com/wooluo/argus/internal/scope"
	"github.com/wooluo/argus/internal/store"
	"github.com/wooluo/argus/internal/tools"
)

// ---------- Agent 管理 ----------

func extDefaultAgents() []map[string]any {
	return []map[string]any{
		{"id": "hunt", "name": "自主渗透 Agent", "role": "自主模式全程执行（连续会话）", "prompt": "", "max_steps": 120, "enabled": true},
		{"id": "staged", "name": "阶段流水线 Agent", "role": "阶段模式各阶段执行", "prompt": "", "max_steps": 25, "enabled": true},
		{"id": "retester", "name": "复测 Agent", "role": "漏洞复测判定", "prompt": "", "max_steps": 10, "enabled": true},
	}
}

// extAgentList 读 settings.agents（已保存的自定义项，含 id）。
func extAgentList(db *sql.DB) []map[string]any {
	var saved []map[string]any
	_ = json.Unmarshal([]byte(store.GetSetting(db, "agents")), &saved)
	return saved
}

// ListAgents GET /api/agents —— 默认角色 + 已保存项覆盖。
func (a *API) ListAgents(w http.ResponseWriter, r *http.Request) {
	saved := map[string]map[string]any{}
	for _, s := range extAgentList(a.DB) {
		if id, _ := s["id"].(string); id != "" {
			saved[id] = s
		}
	}
	out := []map[string]any{}
	for _, d := range extDefaultAgents() {
		m := map[string]any{}
		for k, v := range d {
			m[k] = v
		}
		if o, ok := saved[d["id"].(string)]; ok {
			for k, v := range o {
				m[k] = v
			}
		}
		out = append(out, m)
	}
	respondJSON(w, 200, out)
}

// BuiltinAgentPrompt GET /api/agents/builtin-prompt?agent_id=
func (a *API) BuiltinAgentPrompt(w http.ResponseWriter, r *http.Request) {
	agentID := r.URL.Query().Get("agent_id")
	if agentID == "" {
		agentID = "hunt"
	}
	var prompt, note string
	switch agentID {
	case "hunt":
		prompt = pipeline.AUTONOMOUS_SYSTEM_PROMPT
		note = "自定义保存后**替换**内置角色设定（安全红线强制追加）"
	case "staged":
		prompt = pipeline.STAGED_SYSTEM_PROMPT
		note = "自定义保存后**前置附加**到内置阶段规则之前（操作纪律保留），安全红线强制追加；{stage} 为阶段名占位符，运行时自动替换"
	case "retester":
		prompt = "你是漏洞复测判定专家。"
		note = "自定义保存后**替换**角色设定；判定输出格式指令不受影响"
	default:
		respondErr(w, 404, "未知角色")
		return
	}
	respondJSON(w, 200, map[string]any{
		"agent_id": agentID, "prompt": prompt,
		"safety_rules": pipeline.SAFETY_RULES, "note": note,
	})
}

// PutAgent PUT /api/agents/{agent_id} —— 保存 prompt/max_steps/enabled。
func (a *API) PutAgent(w http.ResponseWriter, r *http.Request) {
	agentID := chi.URLParam(r, "agent_id")
	known := map[string]bool{"hunt": true, "staged": true, "retester": true}
	if !known[agentID] {
		respondErr(w, 404, "未知 Agent")
		return
	}
	var in struct {
		Prompt   string `json:"prompt"`
		MaxSteps int    `json:"max_steps"`
		Enabled  bool   `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		respondErr(w, 400, err.Error())
		return
	}
	if len(in.Prompt) > 20000 {
		in.Prompt = in.Prompt[:20000]
	}
	if in.MaxSteps < 5 {
		in.MaxSteps = 5
	}
	if in.MaxSteps > 300 {
		in.MaxSteps = 300
	}
	out := []map[string]any{}
	for _, s := range extAgentList(a.DB) {
		if id, _ := s["id"].(string); id != agentID {
			out = append(out, s)
		}
	}
	out = append(out, map[string]any{
		"id": agentID, "prompt": in.Prompt,
		"max_steps": in.MaxSteps, "enabled": in.Enabled,
	})
	if err := saveSettingKey(a.DB, "agents", out); err != nil {
		respondErr(w, 500, err.Error())
		return
	}
	respondJSON(w, 200, map[string]any{"ok": true})
}

// ---------- MCP ----------

func extMCPList(db *sql.DB) []map[string]any {
	var saved []map[string]any
	_ = json.Unmarshal([]byte(store.GetSetting(db, "mcp")), &saved)
	return saved
}

// ListMCP GET /api/mcp —— token 掩码。
func (a *API) ListMCP(w http.ResponseWriter, r *http.Request) {
	out := []map[string]any{}
	for _, s := range extMCPList(a.DB) {
		m := map[string]any{}
		for k, v := range s {
			m[k] = v
		}
		tok, _ := m["token"].(string)
		m["token"] = maskKey(tok)
		m["has_token"] = tok != ""
		if _, ok := m["tools_count"]; !ok {
			m["tools_count"] = 0
		}
		out = append(out, m)
	}
	respondJSON(w, 200, out)
}

// PutMCP PUT /api/mcp —— 整组保存；掩码 token 保留旧值。
func (a *API) PutMCP(w http.ResponseWriter, r *http.Request) {
	var in []struct {
		ID      string `json:"id"`
		Name    string `json:"name"`
		URL     string `json:"url"`
		Token   string `json:"token"`
		Enabled bool   `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		respondErr(w, 400, err.Error())
		return
	}
	cur := map[string]map[string]any{}
	for _, s := range extMCPList(a.DB) {
		if id, _ := s["id"].(string); id != "" {
			cur[id] = s
		}
	}
	cleaned := []map[string]any{}
	for i, s := range in {
		tok := s.Token
		if tok == "" || isMasked(tok) {
			if old, ok := cur[s.ID]; ok {
				tok, _ = old["token"].(string)
			}
		}
		id := strings.TrimSpace(s.ID)
		if id == "" {
			id = fmt.Sprintf("mcp-%d-%d", time.Now().Unix(), i)
		}
		cleaned = append(cleaned, map[string]any{
			"id": id, "name": s.Name, "url": s.URL,
			"token": tok, "enabled": s.Enabled,
		})
	}
	if err := saveSettingKey(a.DB, "mcp", cleaned); err != nil {
		respondErr(w, 500, err.Error())
		return
	}
	respondJSON(w, 200, map[string]any{"ok": true})
}

// DeleteMCP DELETE /api/mcp/{server_id}
func (a *API) DeleteMCP(w http.ResponseWriter, r *http.Request) {
	sid := chi.URLParam(r, "server_id")
	out := []map[string]any{}
	for _, s := range extMCPList(a.DB) {
		if id, _ := s["id"].(string); id != sid {
			out = append(out, s)
		}
	}
	if err := saveSettingKey(a.DB, "mcp", out); err != nil {
		respondErr(w, 500, err.Error())
		return
	}
	respondJSON(w, 200, map[string]any{"ok": true})
}

// TestMCP POST /api/mcp/{server_id}/test —— Streamable HTTP initialize+tools/list。
func (a *API) TestMCP(w http.ResponseWriter, r *http.Request) {
	sid := chi.URLParam(r, "server_id")
	var srv map[string]any
	for _, s := range extMCPList(a.DB) {
		if id, _ := s["id"].(string); id == sid {
			srv = s
			break
		}
	}
	if srv == nil {
		respondErr(w, 404, "服务器不存在")
		return
	}
	u, _ := srv["url"].(string)
	tok, _ := srv["token"].(string)
	timeout := 15
	if v, ok := srv["timeout"].(float64); ok && v > 0 {
		timeout = int(v)
	}
	ctx, cancel := context.WithTimeout(r.Context(), time.Duration(timeout)*time.Second)
	defer cancel()

	initBody, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": "initialize",
		"params": map[string]any{
			"protocolVersion": "2024-11-05",
			"capabilities":    map[string]any{},
			"clientInfo":      map[string]any{"name": "argus", "version": "1.0"},
		},
	})
	resp, err := extHTTPPost(ctx, u, tok, initBody)
	if err != nil {
		respondJSON(w, 200, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 {
		respondJSON(w, 200, map[string]any{"ok": false, "error": fmt.Sprintf("initialize HTTP %d", resp.StatusCode)})
		return
	}

	listBody, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
	resp2, err := extHTTPPost(ctx, u, tok, listBody)
	if err != nil {
		respondJSON(w, 200, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	defer resp2.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp2.Body, 1<<20))
	var parsed struct {
		Result struct {
			Tools []struct {
				Name        string `json:"name"`
				Description string `json:"description"`
			} `json:"tools"`
		} `json:"result"`
	}
	_ = json.Unmarshal(raw, &parsed)
	// SSE 响应体兜底：取 data: 行
	if len(parsed.Result.Tools) == 0 {
		for _, line := range strings.Split(string(raw), "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "data:") {
				_ = json.Unmarshal([]byte(strings.TrimPrefix(line, "data:")), &parsed)
				break
			}
		}
	}
	names := []string{}
	for _, t := range parsed.Result.Tools {
		names = append(names, t.Name)
	}
	list := extMCPList(a.DB)
	for _, s := range list {
		if id, _ := s["id"].(string); id == sid {
			s["tools_count"] = len(names)
		}
	}
	_ = saveSettingKey(a.DB, "mcp", list)
	respondJSON(w, 200, map[string]any{"ok": true, "tools": len(names), "names": names})
}

// extHTTPPost MCP/JSON-RPC POST。
func extHTTPPost(ctx context.Context, u, token string, body []byte) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, "POST", u, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	cl := &http.Client{Timeout: 20 * time.Second}
	return cl.Do(req)
}

// ---------- Skill 库 ----------

var extSkillSafeRe = regexp.MustCompile(`[^a-zA-Z0-9_\-]`)

func extSkillsDir() string { return filepath.Join(config.Load().DataDir, "skills") }

func extSkillPath(sid string) string {
	safe := extSkillSafeRe.ReplaceAllString(sid, "_")
	if len(safe) > 60 {
		safe = safe[:60]
	}
	return filepath.Join(extSkillsDir(), safe+".md")
}

func extSkillMeta(db *sql.DB) []map[string]any {
	var saved []map[string]any
	_ = json.Unmarshal([]byte(store.GetSetting(db, "skills")), &saved)
	return saved
}

// ListSkills GET /api/skills
func (a *API) ListSkills(w http.ResponseWriter, r *http.Request) {
	saved := map[string]map[string]any{}
	for _, s := range extSkillMeta(a.DB) {
		if id, _ := s["id"].(string); id != "" {
			saved[id] = s
		}
	}
	out := []map[string]any{}
	entries, _ := os.ReadDir(extSkillsDir())
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".md") {
			continue
		}
		stem := strings.TrimSuffix(e.Name(), ".md")
		name := stem
		enabled := false
		if m := saved[stem]; m != nil {
			if v, ok := m["name"].(string); ok && v != "" {
				name = v
			}
			if v, ok := m["enabled"].(bool); ok {
				enabled = v
			}
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		out = append(out, map[string]any{
			"id": stem, "name": name, "enabled": enabled,
			"chars": info.Size(), "updated": info.ModTime().Format("2006-01-02 15:04"),
		})
	}
	respondJSON(w, 200, out)
}

// CreateSkill POST /api/skills —— {name,content,enabled}。
func (a *API) CreateSkill(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name    string `json:"name"`
		Content string `json:"content"`
		Enabled bool   `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		respondErr(w, 400, err.Error())
		return
	}
	if strings.TrimSpace(in.Name) == "" {
		respondErr(w, 400, "name 不能为空")
		return
	}
	_ = os.MkdirAll(extSkillsDir(), 0o755)
	sid := extSkillSafeRe.ReplaceAllString(in.Name, "_")
	if len(sid) > 60 {
		sid = sid[:60]
	}
	if sid == "" {
		sid = fmt.Sprintf("skill-%d", time.Now().Unix())
	}
	path := extSkillPath(sid)
	if _, err := os.Stat(path); err == nil {
		respondErr(w, 400, fmt.Sprintf("Skill「%s」已存在", sid))
		return
	}
	content := tools.Truncate(in.Content, 50000)
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		respondErr(w, 500, err.Error())
		return
	}
	meta := extSkillMeta(a.DB)
	meta = append(meta, map[string]any{
		"id": sid, "name": tools.Truncate(in.Name, 80), "enabled": in.Enabled,
	})
	if err := saveSettingKey(a.DB, "skills", meta); err != nil {
		respondErr(w, 500, err.Error())
		return
	}
	respondJSON(w, 200, map[string]any{"ok": true, "id": sid})
}

// UpdateSkill PUT /api/skills/{skill_id} —— {name,content,enabled}。
func (a *API) UpdateSkill(w http.ResponseWriter, r *http.Request) {
	sid := chi.URLParam(r, "skill_id")
	path := extSkillPath(sid)
	if _, err := os.Stat(path); err != nil {
		respondErr(w, 404, "Skill 不存在")
		return
	}
	var in struct {
		Name    string `json:"name"`
		Content string `json:"content"`
		Enabled bool   `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		respondErr(w, 400, err.Error())
		return
	}
	if err := os.WriteFile(path, []byte(tools.Truncate(in.Content, 50000)), 0o644); err != nil {
		respondErr(w, 500, err.Error())
		return
	}
	meta := extSkillMeta(a.DB)
	found := false
	for _, s := range meta {
		if id, _ := s["id"].(string); id == sid {
			s["name"] = tools.Truncate(in.Name, 80)
			s["enabled"] = in.Enabled
			found = true
		}
	}
	if !found {
		meta = append(meta, map[string]any{"id": sid, "name": in.Name, "enabled": in.Enabled})
	}
	if err := saveSettingKey(a.DB, "skills", meta); err != nil {
		respondErr(w, 500, err.Error())
		return
	}
	respondJSON(w, 200, map[string]any{"ok": true})
}

// SkillContent GET /api/skills/{skill_id}/content
func (a *API) SkillContent(w http.ResponseWriter, r *http.Request) {
	sid := chi.URLParam(r, "skill_id")
	b, err := os.ReadFile(extSkillPath(sid))
	if err != nil {
		respondErr(w, 404, "Skill 不存在")
		return
	}
	respondJSON(w, 200, map[string]any{"id": sid, "content": string(b)})
}

// DeleteSkill DELETE /api/skills/{skill_id}
func (a *API) DeleteSkill(w http.ResponseWriter, r *http.Request) {
	sid := chi.URLParam(r, "skill_id")
	_ = os.Remove(extSkillPath(sid))
	meta := extSkillMeta(a.DB)
	out := []map[string]any{}
	for _, s := range meta {
		if id, _ := s["id"].(string); id != sid {
			out = append(out, s)
		}
	}
	if err := saveSettingKey(a.DB, "skills", out); err != nil {
		respondErr(w, 500, err.Error())
		return
	}
	respondJSON(w, 200, map[string]any{"ok": true})
}

// ---------- 通知推送 ----------

// GetNotifyConfig GET /api/notify/config —— webhook_url 掩码。
func (a *API) GetNotifyConfig(w http.ResponseWriter, r *http.Request) {
	m := settingJSON(a.DB, "notify")
	if u, ok := m["webhook_url"].(string); ok {
		m["webhook_url"] = maskKey(u)
	}
	respondJSON(w, 200, m)
}

// PutNotifyConfig PUT /api/notify/config —— 掩码回传保留旧值。
func (a *API) PutNotifyConfig(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Enabled    bool     `json:"enabled"`
		WebhookURL string   `json:"webhook_url"`
		Events     []string `json:"events"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		respondErr(w, 400, err.Error())
		return
	}
	if isMasked(in.WebhookURL) {
		old := settingJSON(a.DB, "notify")
		if u, ok := old["webhook_url"].(string); ok {
			in.WebhookURL = u
		}
	}
	events := in.Events
	if events == nil {
		events = []string{"task_done", "finding_confirmed"}
	}
	cfg := map[string]any{"enabled": in.Enabled, "webhook_url": in.WebhookURL, "events": events}
	if err := saveSettingKey(a.DB, "notify", cfg); err != nil {
		respondErr(w, 500, err.Error())
		return
	}
	respondJSON(w, 200, map[string]any{"ok": true})
}

// TestNotify POST /api/notify/test
func (a *API) TestNotify(w http.ResponseWriter, r *http.Request) {
	m := settingJSON(a.DB, "notify")
	u, _ := m["webhook_url"].(string)
	if u == "" {
		respondJSON(w, 200, map[string]any{"ok": false, "error": "未配置 webhook_url"})
		return
	}
	payload, _ := json.Marshal(map[string]any{
		"msgtype": "markdown",
		"markdown": map[string]any{
			"content": "argus 通知测试：webhook 连通 OK ✅",
		},
	})
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "POST", u, bytes.NewReader(payload))
	if err != nil {
		respondJSON(w, 200, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		respondJSON(w, 200, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	respondJSON(w, 200, map[string]any{"ok": resp.StatusCode == 200, "status": resp.StatusCode})
}

// ---------- Repeater ----------

// RepeaterLogs GET /api/repeater/logs?project_id=&limit=
func (a *API) RepeaterLogs(w http.ResponseWriter, r *http.Request) {
	q := `SELECT id,project_id,method,url,request_body,headers,cookies,status,
		response_snippet,source,origin_traffic_id,created_at FROM repeater_logs`
	args := []any{}
	if pid := r.URL.Query().Get("project_id"); pid != "" && pid != "0" {
		q += " WHERE project_id=?"
		args = append(args, extAtoi(pid, 0))
	}
	limit := extAtoi(r.URL.Query().Get("limit"), 100)
	if limit > 500 {
		limit = 500
	}
	if limit < 1 {
		limit = 1
	}
	q += " ORDER BY id DESC LIMIT ?"
	args = append(args, limit)
	rows, err := a.DB.Query(q, args...)
	if err != nil {
		respondErr(w, 500, err.Error())
		return
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var id, pid, status, origin int64
		var method, urlV, reqBody, headers, cookies, snippet, source, created string
		if err := rows.Scan(&id, &pid, &method, &urlV, &reqBody, &headers, &cookies,
			&status, &snippet, &source, &origin, &created); err != nil {
			continue
		}
		out = append(out, map[string]any{
			"id": id, "project_id": pid, "method": method, "url": urlV,
			"request_body": reqBody, "headers": headers, "cookies": cookies,
			"status": status, "response_snippet": snippet, "source": source,
			"origin_traffic_id": origin, "created_at": created,
		})
	}
	respondJSON(w, 200, out)
}

// RepeaterSend POST /api/repeater/send —— 手动重发（范围护栏 + 落库 repeater_logs）。
func (a *API) RepeaterSend(w http.ResponseWriter, r *http.Request) {
	var in struct {
		ProjectID int64          `json:"project_id"`
		Method    string         `json:"method"`
		URL       string         `json:"url"`
		Data      map[string]any `json:"data"`
		Headers   map[string]any `json:"headers"`
		Cookies   map[string]any `json:"cookies"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		respondErr(w, 400, err.Error())
		return
	}
	if !strings.HasPrefix(in.URL, "http://") && !strings.HasPrefix(in.URL, "https://") {
		respondErr(w, 400, "URL 必须以 http(s):// 开头")
		return
	}
	var scopeRaw, allowRaw []byte
	err := a.DB.QueryRow(`SELECT scope,allow_hosts FROM projects WHERE id=?`, in.ProjectID).
		Scan(&scopeRaw, &allowRaw)
	if err == sql.ErrNoRows {
		respondErr(w, 404, "项目不存在")
		return
	}
	if err != nil {
		respondErr(w, 500, err.Error())
		return
	}
	var rules []scope.Rule
	var allowHosts []string
	_ = json.Unmarshal(scopeRaw, &rules)
	_ = json.Unmarshal(allowRaw, &allowHosts)
	guard := scope.New(in.ProjectID, rules, allowHosts)
	if err := guard.EnsureURL(in.URL); err != nil {
		respondErr(w, 400, "范围护栏拦截: "+err.Error())
		return
	}

	method := strings.ToUpper(strings.TrimSpace(in.Method))
	if method == "" {
		method = "GET"
	}
	var bodyReader io.Reader
	reqBody := ""
	if method == "POST" && len(in.Data) > 0 {
		form := url.Values{}
		for k, v := range in.Data {
			form.Set(k, fmt.Sprint(v))
		}
		reqBody = form.Encode()
		bodyReader = strings.NewReader(reqBody)
	} else if len(in.Data) > 0 {
		b, _ := json.Marshal(in.Data)
		reqBody = string(b)
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, method, in.URL, bodyReader)
	if err != nil {
		respondErr(w, 400, err.Error())
		return
	}
	if method == "POST" && reqBody != "" {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	for k, v := range in.Headers {
		req.Header.Set(k, fmt.Sprint(v))
	}
	for k, v := range in.Cookies {
		req.AddCookie(&http.Cookie{Name: k, Value: fmt.Sprint(v)})
	}
	cl := &http.Client{
		Timeout: 30 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := cl.Do(req)
	if err != nil {
		respondErr(w, 502, err.Error())
		return
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 256<<10))
	body := tools.Truncate(string(raw), 8000)
	headerOut := map[string]string{}
	for k := range resp.Header {
		headerOut[k] = resp.Header.Get(k)
	}
	headersJSON, _ := json.Marshal(in.Headers)
	cookiesJSON, _ := json.Marshal(in.Cookies)
	_, _ = a.DB.Exec(`INSERT INTO repeater_logs
		(project_id,method,url,request_body,headers,cookies,status,response_snippet,source,origin_traffic_id)
		VALUES(?,?,?,?,?,?,?,?,?,0)`,
		in.ProjectID, method, in.URL, reqBody, string(headersJSON), string(cookiesJSON),
		resp.StatusCode, tools.Truncate(string(raw), 6000), "manual")
	respondJSON(w, 200, map[string]any{
		"ok": true, "status": resp.StatusCode,
		"headers": headerOut, "body": body, "body_length": len(raw),
		"request_body": reqBody,
	})
}

// ---------- POC 库 ----------

func extPoclibDir() string { return filepath.Join(config.Load().DataDir, "poclib") }

// PoclibStats GET /api/poclib —— 各仓库统计。
func (a *API) PoclibStats(w http.ResponseWriter, r *http.Request) {
	m := settingJSON(a.DB, "poclib_repos")
	reposAny, _ := m["repos"].([]any)
	repos := []map[string]any{}
	for _, ra := range reposAny {
		rm, _ := ra.(map[string]any)
		name, _ := rm["name"].(string)
		u, _ := rm["url"].(string)
		templates, pocs := extCountPoc(filepath.Join(extPoclibDir(), name))
		repos = append(repos, map[string]any{
			"name": name, "url": u,
			"templates": templates, "pocs": pocs,
			"synced": extDirExists(filepath.Join(extPoclibDir(), name)),
		})
	}
	respondJSON(w, 200, map[string]any{"repos": repos})
}

// PutPocRepos PUT /api/poclib/repos —— [{name,url}]。
func (a *API) PutPocRepos(w http.ResponseWriter, r *http.Request) {
	var in []struct {
		Name string `json:"name"`
		URL  string `json:"url"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		respondErr(w, 400, err.Error())
		return
	}
	repos := []map[string]any{}
	for _, s := range in {
		repos = append(repos, map[string]any{"name": s.Name, "url": s.URL})
	}
	if err := saveSettingKey(a.DB, "poclib_repos", map[string]any{"repos": repos}); err != nil {
		respondErr(w, 500, err.Error())
		return
	}
	respondJSON(w, 200, map[string]any{"ok": true})
}

// PoclibSync POST /api/poclib/sync —— git clone/pull 规则库。
func (a *API) PoclibSync(w http.ResponseWriter, r *http.Request) {
	m := settingJSON(a.DB, "poclib_repos")
	reposAny, _ := m["repos"].([]any)
	if len(reposAny) == 0 {
		respondErr(w, 400, "需要先配置规则库仓库")
		return
	}
	_ = os.MkdirAll(extPoclibDir(), 0o755)
	stats := map[string]any{}
	allOK := true
	for _, ra := range reposAny {
		rm, _ := ra.(map[string]any)
		name, _ := rm["name"].(string)
		u, _ := rm["url"].(string)
		if name == "" || u == "" {
			continue
		}
		dest := filepath.Join(extPoclibDir(), name)
		var out []byte
		var err error
		if extDirExists(filepath.Join(dest, ".git")) {
			out, err = extGitRun(r.Context(), 180, "git", "-C", dest, "pull", "--ff-only")
		} else {
			out, err = extGitRun(r.Context(), 300, "git", "clone", "--depth", "1", u, dest)
		}
		ok := err == nil && !strings.Contains(string(out), "fatal")
		if !ok {
			allOK = false
		}
		stats[name] = map[string]any{
			"ok": ok, "output": tools.Truncate(string(out)+extErrText(err), 500),
		}
	}
	respondJSON(w, 200, map[string]any{"ok": allOK, "repos": stats})
}

// ---------- 小工具 ----------

func extAtoi(s string, def int) int {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil {
		return def
	}
	return n
}

func extDirExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && st.IsDir()
}

// extCountPoc 统计目录下 yaml/yml（nuclei 模板）与 py/sh/go/php（POC 脚本）数量。
func extCountPoc(dir string) (templates, pocs int) {
	if !extDirExists(dir) {
		return 0, 0
	}
	_ = filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		switch strings.ToLower(filepath.Ext(path)) {
		case ".yaml", ".yml":
			templates++
		case ".py", ".sh", ".go", ".php":
			pocs++
		}
		return nil
	})
	return templates, pocs
}

func extGitRun(ctx context.Context, timeoutSec int, name string, args ...string) ([]byte, error) {
	cctx, cancel := context.WithTimeout(ctx, time.Duration(timeoutSec)*time.Second)
	defer cancel()
	cmd := exec.CommandContext(cctx, name, args...)
	out, err := cmd.CombinedOutput()
	return out, err
}

func extErrText(err error) string {
	if err == nil {
		return ""
	}
	return " | " + err.Error()
}
