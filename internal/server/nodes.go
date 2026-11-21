package server

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/wooluo/argus/internal/auth"
	"github.com/wooluo/argus/internal/config"
	"github.com/wooluo/argus/internal/deploy"
	"github.com/wooluo/argus/internal/intel"
	"github.com/wooluo/argus/internal/store"
)

// NodeAPI: 执行面 API（argus-node 调用）。
// 模型： 节点注册（管理 token 开启）→ 心跳 → 轮询领取 → 执行 → 回传结果。
type NodeAPI struct {
	DB       *sql.DB
	Bus      eventsBus
	NodeAuth *auth.NodeAuth
	Admin    *auth.Middleware // 管理鉴权（SSH 部署时下发的注册凭证 = 当前管理 token）
}

// eventsBus: server 包内事件发布接口（events.Bus 实现）。
type eventsBus interface {
	Publish(event string, data any)
}

func jout(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func jerr(w http.ResponseWriter, code int, msg string) {
	jout(w, code, map[string]string{"detail": msg})
}

var nodeTokenChars = []byte("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")

func genNodeToken() string {
	b := make([]byte, 32)
	for i := range b {
		b[i] = nodeTokenChars[rand.Intn(len(nodeTokenChars))]
	}
	return string(b)
}

// ListNodes: GET /api/nodes/ （管理面，UI 用）
func (n *NodeAPI) ListNodes(w http.ResponseWriter, r *http.Request) {
	rows, err := n.DB.Query(`SELECT id,name,platform,hostname,version,status,last_seen,created_at FROM nodes ORDER BY id`)
	if err != nil {
		jerr(w, 500, err.Error())
		return
	}
	defer rows.Close()
	type nodeRow struct {
		ID        int    `json:"id"`
		Name      string `json:"name"`
		Platform  string `json:"platform"`
		Hostname  string `json:"hostname"`
		Version   string `json:"version"`
		Status    string `json:"status"`
		LastSeen  string `json:"last_seen"`
		CreatedAt string `json:"created_at"`
	}
	out := []nodeRow{}
	for rows.Next() {
		var v nodeRow
		if err := rows.Scan(&v.ID, &v.Name, &v.Platform, &v.Hostname, &v.Version, &v.Status, &v.LastSeen, &v.CreatedAt); err != nil {
			jerr(w, 500, err.Error())
			return
		}
		out = append(out, v)
	}
	jout(w, 200, out)
}

// Register: POST /api/nodes/register {"name":"kali-1","capabilities":["nmap","httpx"]}
func (n *NodeAPI) Register(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name         string   `json:"name"`
		Capabilities []string `json:"capabilities"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Name == "" {
		jerr(w, 422, "name required")
		return
	}
	tok := genNodeToken()
	caps, _ := json.Marshal(req.Capabilities)
	res, err := n.DB.Exec(`INSERT INTO nodes(name,token,capabilities,status,last_seen) VALUES(?,?,?,?,?)`,
		req.Name, tok, string(caps), "online", store.Now())
	if err != nil {
		jerr(w, 500, err.Error())
		return
	}
	id, _ := res.LastInsertId()
	if n.NodeAuth != nil {
		n.NodeAuth.Set(tok, id)
	}
	n.Bus.Publish("node_registered", map[string]any{"id": id, "name": req.Name})
	jout(w, 201, map[string]any{"node_id": id, "token": tok})
}

// Heartbeat: POST /api/nodes/heartbeat {"node_id":1} — 更新 last_seen。
func (n *NodeAPI) Heartbeat(w http.ResponseWriter, r *http.Request) {
	var req struct {
		NodeID int64 `json:"node_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.NodeID == 0 {
		jerr(w, 422, "node_id required")
		return
	}
	if _, err := n.DB.Exec(`UPDATE nodes SET last_seen=?,status='online' WHERE id=?`, store.Now(), req.NodeID); err != nil {
		jerr(w, 500, err.Error())
		return
	}
	n.Bus.Publish("node_heartbeat", map[string]any{"node_id": req.NodeID})
	jout(w, 200, map[string]any{"ok": true})
}

// Poll: GET /api/nodes/poll?node_id=1 — 领取一条待执行任务（原子抢占）。
func (n *NodeAPI) Poll(w http.ResponseWriter, r *http.Request) {
	nodeID := r.URL.Query().Get("node_id")
	var node store.Node
	err := n.DB.QueryRow(`SELECT id,name,token,capabilities,status,last_seen FROM nodes WHERE id=?`, nodeID).
		Scan(&node.ID, &node.Name, &node.Token, &node.Capabilities, &node.Status, &node.LastSeen)
	if err != nil {
		jerr(w, 404, "node not found")
		return
	}

	row := n.DB.QueryRow(`
		SELECT t.id FROM tasks t
		JOIN projects p ON p.id=t.project_id
		WHERE t.status IN ('pending','running') AND p.authorized=1
		ORDER BY t.id LIMIT 1`)
	var taskID int64
	if err := row.Scan(&taskID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			jout(w, 200, map[string]any{"task": nil})
			return
		}
		jerr(w, 500, err.Error())
		return
	}
	res, err := n.DB.Exec(`UPDATE tasks SET status='assigned',node_id=?,assigned_at=? WHERE id=? AND status IN ('pending','running')`,
		node.ID, store.Now(), taskID)
	if err != nil || rowsAffected(res) == 0 {
		jout(w, 200, map[string]any{"task": nil})
		return
	}
	var t store.Task
	var finishedAt, assignedAt sql.NullString
	err = n.DB.QueryRow(`SELECT id,project_id,name,status,mode,current_stage,tokens,message,node_id,created_at,finished_at,assigned_at FROM tasks WHERE id=?`, taskID).
		Scan(&t.ID, &t.ProjectID, &t.Name, &t.Status, &t.Mode, &t.CurrentStage, &t.Tokens, &t.Message, &t.NodeID, &t.CreatedAt, &finishedAt, &assignedAt)
	if err != nil {
		jerr(w, 500, err.Error())
		return
	}
	t.FinishedAt = nilOrString(finishedAt)
	t.AssignedAt = nilOrString(assignedAt)

	// 附带项目概要与 LLM 配置：节点构建任务书必需（scope/description/llm key）。
	var p store.Project
	var llmCfg store.RawJSON
	_ = n.DB.QueryRow(`SELECT id,name,description,scope,authorized,allow_hosts,created_at FROM projects WHERE id=?`, t.ProjectID).
		Scan(&p.ID, &p.Name, &p.Description, &p.Scope, &p.Authorized, &p.AllowHosts, &p.CreatedAt)
	_ = n.DB.QueryRow(`SELECT value FROM settings WHERE key='llm'`).Scan(&llmCfg)

	// 知识注入：项目已有知识库条目随任务下发（node 侧拼入任务书，跨任务经验复用）
	knowledgeBlock := n.buildKnowledgeBlock()

	// HITL 审批名单下发（节点 agent 执行前拦截；空数组=无审批）
	var approvalsRequire []string
	_ = json.Unmarshal([]byte(store.GetSetting(n.DB, "approvals_require")), &approvalsRequire)
	if approvalsRequire == nil {
		approvalsRequire = []string{}
	}

	// 项目情报（跨任务持久，任务书携带；蓝本 ProjectIntel）
	intel := []string{}
	irows, _ := n.DB.Query(
		`SELECT content FROM project_intel WHERE project_id=? ORDER BY id DESC LIMIT 20`, t.ProjectID)
	for irows.Next() {
		var s string
		if irows.Scan(&s) == nil && strings.TrimSpace(s) != "" {
			intel = append([]string{s}, intel...) // 逆序回正（旧→新）
		}
	}
	irows.Close()

	// Skill 领域知识块（启用的 skills 拼接）
	skillsBlock := n.buildSkillBlock()

	// MCP 动态工具：启用的服务器下发（节点 initialize + tools/list 后注册）
	mcpServers := []mcpServer{}
	for _, s := range extMCPEnabled(n.DB) {
		mcpServers = append(mcpServers, s)
	}

	// 自定义 Agent（hunt 角色覆盖：prompt + 步数）
	agentPrompt, agentMaxSteps := huntAgentOverride(n.DB)

	// FOFA 凭据（设置页配置；未配置时空串，节点回落环境变量）
	fofaEmail, fofaKey := store.GetSetting(n.DB, "fofa_email"), store.GetSetting(n.DB, "fofa_key")

	// 断点续测：continue_from 指定任务的历史成果摘要
	continueSummary := ""
	var contFrom int64
	_ = n.DB.QueryRow(`SELECT continue_from FROM tasks WHERE id=?`, taskID).Scan(&contFrom)
	if contFrom > 0 {
		continueSummary = n.buildContinueSummary(contFrom)
	}

	jout(w, 200, map[string]any{"task": t, "project": p, "llm": json.RawMessage(llmCfg),
		"knowledge": knowledgeBlock, "approvals_require": approvalsRequire,
		"intel": intel, "skills": skillsBlock, "mcp": mcpServers,
		"agent":            map[string]any{"prompt": agentPrompt, "max_steps": agentMaxSteps},
		"fofa":             map[string]any{"email": fofaEmail, "key": fofaKey},
		"continue_summary": continueSummary})
}

// mcpServer Poll 下发给节点的 MCP 服务器配置（节点侧 mcp.go 反序列化）。
type mcpServer struct {
	ID      string `json:"id"`
	URL     string `json:"url"`
	Token   string `json:"token"`
	Timeout int    `json:"timeout"`
}

// extMCPEnabled settings.mcp 中 enabled 的服务器（token 明文仅走节点面）。
func extMCPEnabled(db *sql.DB) []mcpServer {
	var saved []map[string]any
	_ = json.Unmarshal([]byte(store.GetSetting(db, "mcp")), &saved)
	out := []mcpServer{}
	for _, s := range saved {
		on, _ := s["enabled"].(bool)
		if !on {
			continue
		}
		id, _ := s["id"].(string)
		u, _ := s["url"].(string)
		if id == "" || u == "" {
			continue
		}
		tok, _ := s["token"].(string)
		if strings.Contains(tok, "*") { // 掩码值不下发
			tok = ""
		}
		srv := mcpServer{ID: id, URL: u, Token: tok, Timeout: 30}
		if v, ok := s["timeout"].(float64); ok && v > 0 {
			srv.Timeout = int(v)
		}
		out = append(out, srv)
	}
	return out
}

// huntAgentOverride settings.agents 中 hunt 角色的自定义 prompt / 步数覆盖。
func huntAgentOverride(db *sql.DB) (string, int) {
	var saved []map[string]any
	_ = json.Unmarshal([]byte(store.GetSetting(db, "agents")), &saved)
	for _, s := range saved {
		if id, _ := s["id"].(string); id != "hunt" {
			continue
		}
		prompt, _ := s["prompt"].(string)
		steps := 0
		if v, ok := s["max_steps"].(float64); ok {
			steps = int(v)
		}
		return prompt, steps
	}
	return "", 0
}

// buildSkillBlock 启用的 skills 正文拼接（蓝本 skills 注入任务书）。
func (n *NodeAPI) buildSkillBlock() string {
	dir := filepath.Join(config.Load().DataDir, "skills")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return ""
	}
	var meta []map[string]any
	_ = json.Unmarshal([]byte(store.GetSetting(n.DB, "skills")), &meta)
	enabled := map[string]bool{}
	for _, m := range meta {
		id, _ := m["id"].(string)
		if on, ok := m["enabled"].(bool); !ok || on {
			enabled[id] = true
		}
	}
	var parts []string
	for _, e := range entries {
		id := strings.TrimSuffix(e.Name(), ".md")
		if !strings.HasSuffix(e.Name(), ".md") || !enabled[id] || len(parts) >= 5 {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			continue
		}
		content := string(b)
		if len(content) > 2000 {
			content = content[:2000]
		}
		parts = append(parts, content)
	}
	if len(parts) == 0 {
		return ""
	}
	return "## Skill 领域知识（已启用，按需应用）\n\n" + strings.Join(parts, "\n\n") + "\n"
}

// buildContinueSummary 断点续测摘要：指定任务起止窗口内的漏洞 + 资产（蓝本 continue_from）。
// findings/assets 无 task_id 关联，按 [created_at, COALESCE(finished_at, ∞)] 时间窗归属。
func (n *NodeAPI) buildContinueSummary(taskID int64) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "### 上轮任务 #%d 成果\n", taskID)
	const q = `SELECT %s FROM %s WHERE project_id=
		 (SELECT project_id FROM tasks WHERE id=?) AND created_at>=
		 (SELECT created_at FROM tasks WHERE id=?) AND created_at<=
		 COALESCE((SELECT finished_at FROM tasks WHERE id=?), '9999-12-31') %s`
	frows, _ := n.DB.Query(fmt.Sprintf(q, "name,severity,target,status", "findings", "LIMIT 50"),
		taskID, taskID, taskID)
	nf := 0
	for frows.Next() {
		var name, sev, target, status string
		if frows.Scan(&name, &sev, &target, &status) == nil {
			fmt.Fprintf(&sb, "- 漏洞: [%s] %s @ %s（%s）\n", sev, name, target, status)
			nf++
		}
	}
	frows.Close()
	arows, _ := n.DB.Query(fmt.Sprintf(q, "type,value", "assets", "LIMIT 80"),
		taskID, taskID, taskID)
	na := 0
	for arows.Next() {
		var typ, val string
		if arows.Scan(&typ, &val) == nil {
			fmt.Fprintf(&sb, "- 资产: %s %s\n", typ, val)
			na++
		}
	}
	arows.Close()
	if nf == 0 && na == 0 {
		return ""
	}
	return sb.String()
}

// NodeIntel: GET /api/nodes/intel?task_id= — 节点拉取运行中情报（Drain 语义）。
func (n *NodeAPI) NodeIntel(w http.ResponseWriter, r *http.Request) {
	taskID, _ := strconv.ParseInt(r.URL.Query().Get("task_id"), 10, 64)
	if taskID == 0 {
		jerr(w, 422, "task_id required")
		return
	}
	jout(w, 200, intel.Drain(taskID))
}

// buildKnowledgeBlock 启用状态的知识条目（≤5 条 × 截断），注入任务书（蓝本 _knowledge_block）。
func (n *NodeAPI) buildKnowledgeBlock() string {
	dir := filepath.Join(config.Load().DataDir, "knowledge")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return ""
	}
	var meta []map[string]any
	_ = json.Unmarshal([]byte(store.GetSetting(n.DB, "knowledge")), &meta)
	enabled := map[string]bool{}
	titles := map[string]string{}
	for _, m := range meta {
		id, _ := m["id"].(string)
		title, _ := m["title"].(string)
		if id != "" {
			titles[id] = title
			if on, ok := m["enabled"].(bool); !ok || on {
				enabled[id] = true
			}
		}
	}
	var parts []string
	count := 0
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".md") || count >= 5 {
			continue
		}
		id := strings.TrimSuffix(e.Name(), ".md")
		if !enabled[id] {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			continue
		}
		title := titles[id]
		if title == "" {
			title = id
		}
		content := string(b)
		if len(content) > 1500 {
			content = content[:1500]
		}
		parts = append(parts, fmt.Sprintf("### %s\n%s", title, content))
		count++
	}
	if len(parts) == 0 {
		return ""
	}
	return "## 知识库（历史任务沉淀，按需应用）\n\n" + strings.Join(parts, "\n\n") + "\n"
}

// approvalWait 审批等待上限；超过即自动拒绝（与节点端 cmd/argus-node/approval.go 一致）。
const approvalWait = 600 * time.Second

// CreateApproval: POST /api/nodes/approvals — 节点侧 HITL 审批请求
// （写 pending + SSE 通知操作员；管理面 /api/approvals 列表可见、可决策）。
func (n *NodeAPI) CreateApproval(w http.ResponseWriter, r *http.Request) {
	var req struct {
		TaskID    int64          `json:"task_id"`
		ProjectID int64          `json:"project_id"`
		Tool      string         `json:"tool"`
		Args      map[string]any `json:"args"`
		Reason    string         `json:"reason"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Tool == "" || req.TaskID == 0 {
		jerr(w, 422, "task_id/tool 必填")
		return
	}
	argsJSON, _ := json.Marshal(req.Args)
	if req.Args == nil {
		argsJSON = []byte("{}")
	}
	if len(req.Reason) > 2000 {
		req.Reason = req.Reason[:2000]
	}
	res, err := n.DB.Exec(`INSERT INTO approvals(task_id,project_id,tool,args,reason,status,created_at)
		VALUES(?,?,?,?,?,'pending',?)`,
		req.TaskID, req.ProjectID, req.Tool, string(argsJSON), req.Reason, store.Now())
	if err != nil {
		jerr(w, 500, err.Error())
		return
	}
	id, _ := res.LastInsertId()
	n.Bus.Publish("approval_pending", map[string]any{
		"id": id, "task_id": req.TaskID, "tool": req.Tool,
		"content": fmt.Sprintf("⛔ 调用 %s 需人工审批（等待中，%.0fs 超时自动拒绝）",
			req.Tool, approvalWait.Seconds()),
	})
	jout(w, 200, map[string]any{"id": id})
}

// GetApproval: GET /api/nodes/approvals/{id} — 节点轮询决定；
// 超时未决的自动落库为 denied(timeout)（兜底：节点侧有自己的超时）。
func (n *NodeAPI) GetApproval(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	var status, createdAt string
	if err := n.DB.QueryRow(`SELECT status,created_at FROM approvals WHERE id=?`, id).
		Scan(&status, &createdAt); err != nil {
		jerr(w, 404, "approval not found")
		return
	}
	if status == "pending" {
		if t, err := time.Parse("2006-01-02T15:04:05.000Z", createdAt); err == nil &&
			time.Since(t) > approvalWait {
			if res, err := n.DB.Exec(
				`UPDATE approvals SET status='denied',decided_by='timeout',decided_at=?
				 WHERE id=? AND status='pending'`, store.Now(), id); err == nil && rowsAffected(res) > 0 {
				status = "denied"
				n.Bus.Publish("approval_done", map[string]any{"id": id, "status": "denied(timeout)"})
			}
		}
	}
	jout(w, 200, map[string]any{"status": status})
}

// ReportResult: POST /api/nodes/result — 节点执行完毕回传 findings/assets/logs/traffic。
func (n *NodeAPI) ReportResult(w http.ResponseWriter, r *http.Request) {
	var req struct {
		TaskID   int64  `json:"task_id"`
		Status   string `json:"status"` // done | failed | partial
		Message  string `json:"message"`
		Findings []struct {
			Name     string `json:"name"`
			Severity string `json:"severity"`
			Target   string `json:"target"`
			Detail   string `json:"detail"`
			Evidence string `json:"evidence"`
			PoC      string `json:"poc"`
		} `json:"findings"`
		Assets []struct {
			Type   string `json:"type"`
			Value  string `json:"value"`
			Detail string `json:"detail"`
		} `json:"assets"`
		Logs []struct {
			Stage   string `json:"stage"`
			Tool    string `json:"tool"`
			Content string `json:"content"`
		} `json:"logs"`
		Traffic []struct {
			Method          string `json:"method"`
			URL             string `json:"url"`
			RequestBody     string `json:"request_body"`
			Status          int    `json:"status"`
			ResponseSnippet string `json:"response_snippet"`
			SourceTool      string `json:"source_tool"`
		} `json:"traffic"`
		Report string `json:"report"` // 任务最终 Markdown 报告（落 reports 表）
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.TaskID == 0 {
		jerr(w, 422, "task_id required")
		return
	}
	if err := n.persistNodeBatch(req.TaskID, req.Findings, req.Assets, req.Logs, req.Traffic); err != nil {
		jerr(w, 500, err.Error())
		return
	}
	status := req.Status
	if status == "" {
		status = "done"
	}
	if req.Report != "" {
		if _, err := n.DB.Exec(`INSERT INTO reports(project_id,task_id,markdown)
			SELECT project_id,?,? FROM tasks WHERE id=?`, req.TaskID, req.Report, req.TaskID); err != nil {
			jerr(w, 500, err.Error())
			return
		}
	}
	if _, err := n.DB.Exec(`UPDATE tasks SET status=?,finished_at=?,message=? WHERE id=?`,
		status, store.Now(), req.Message, req.TaskID); err != nil {
		jerr(w, 500, err.Error())
		return
	}
	intel.Discard(req.TaskID) // 任务结束丢弃未消费的运行中情报
	n.Bus.Publish("task_done", map[string]any{"task_id": req.TaskID, "status": status})
	jout(w, 200, map[string]any{"ok": true})
}

// NodeBatch: Progress / ReportResult 共用的批量落库。
func (n *NodeAPI) persistNodeBatch(taskID int64, findings, assets, logs, traffic any) error {
	// findings / assets / logs / traffic 为匿名结构切片，走 JSON 重编码最省事
	buf, _ := json.Marshal(map[string]any{
		"findings": findings, "assets": assets, "logs": logs, "traffic": traffic,
	})
	var req struct {
		Findings []struct {
			Name     string `json:"name"`
			Severity string `json:"severity"`
			Target   string `json:"target"`
			Detail   string `json:"detail"`
			Evidence string `json:"evidence"`
			PoC      string `json:"poc"`
			Steps    []struct {
				Note       string `json:"note"`
				Request    string `json:"request"`
				Response   string `json:"response"`
				Conclusion string `json:"conclusion"`
			} `json:"steps"`
		} `json:"findings"`
		Assets []struct {
			Type   string `json:"type"`
			Value  string `json:"value"`
			Detail string `json:"detail"`
		} `json:"assets"`
		Logs []struct {
			Stage   string `json:"stage"`
			Tool    string `json:"tool"`
			Content string `json:"content"`
		} `json:"logs"`
		Traffic []struct {
			Method          string `json:"method"`
			URL             string `json:"url"`
			RequestBody     string `json:"request_body"`
			Status          int    `json:"status"`
			ResponseSnippet string `json:"response_snippet"`
			SourceTool      string `json:"source_tool"`
		} `json:"traffic"`
	}
	_ = json.Unmarshal(buf, &req)
	for _, f := range req.Findings {
		sev := f.Severity
		if sev == "" {
			sev = "info"
		}
		res, err := n.DB.Exec(`INSERT INTO findings(project_id,name,severity,target,detail,evidence,poc,source)
			SELECT project_id,?,?,?,?,?,?,'node' FROM tasks WHERE id=?`,
			f.Name, sev, f.Target, f.Detail, f.Evidence, f.PoC, taskID)
		if err != nil {
			return err
		}
		// 利用链步骤随 finding 落 finding_steps（蓝本 FindingStep）
		fid, _ := res.LastInsertId()
		for seq, st := range f.Steps {
			_, _ = n.DB.Exec(`INSERT INTO finding_steps(finding_id,project_id,seq,note,request,response,conclusion)
				SELECT ?,project_id,?,?,?,?,? FROM tasks WHERE id=?`,
				fid, seq+1, st.Note, st.Request, st.Response, st.Conclusion, taskID)
		}
	}
	for _, s := range req.Assets {
		if _, err := n.DB.Exec(`INSERT INTO assets(project_id,type,value,detail,source)
			SELECT project_id,?,?,?,?,'node' FROM tasks WHERE id=?`,
			s.Type, s.Value, s.Detail, taskID); err != nil {
			return err
		}
	}
	for _, l := range req.Logs {
		_, _ = n.DB.Exec(`INSERT INTO agent_logs(task_id,stage,type,tool,content) SELECT ?,?,?,?,? WHERE EXISTS(SELECT 1 FROM tasks WHERE id=?)`,
			taskID, l.Stage, l.Tool, l.Tool, l.Content, taskID)
	}
	for _, t := range req.Traffic {
		_, _ = n.DB.Exec(`INSERT INTO traffic_logs(project_id,task_id,method,url,request_body,status,response_snippet,source_tool)
			SELECT project_id,?,?,?,?,?,?,? FROM tasks WHERE id=?`,
			taskID, t.Method, t.URL, t.RequestBody, t.Status, t.ResponseSnippet, t.SourceTool, taskID)
	}
	return nil
}

// Progress: POST /api/nodes/progress — 节点执行中增量上报（长任务进度可见）。
func (n *NodeAPI) Progress(w http.ResponseWriter, r *http.Request) {
	var req struct {
		TaskID   int64 `json:"task_id"`
		Findings []struct {
			Name     string `json:"name"`
			Severity string `json:"severity"`
			Target   string `json:"target"`
			Detail   string `json:"detail"`
			Evidence string `json:"evidence"`
			PoC      string `json:"poc"`
		} `json:"findings"`
		Assets []struct {
			Type   string `json:"type"`
			Value  string `json:"value"`
			Detail string `json:"detail"`
		} `json:"assets"`
		Logs []struct {
			Stage   string `json:"stage"`
			Tool    string `json:"tool"`
			Content string `json:"content"`
		} `json:"logs"`
		Traffic []struct {
			Method          string `json:"method"`
			URL             string `json:"url"`
			RequestBody     string `json:"request_body"`
			Status          int    `json:"status"`
			ResponseSnippet string `json:"response_snippet"`
			SourceTool      string `json:"source_tool"`
		} `json:"traffic"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.TaskID == 0 {
		jerr(w, 422, "task_id required")
		return
	}
	if err := n.persistNodeBatch(req.TaskID, req.Findings, req.Assets, req.Logs, req.Traffic); err != nil {
		jerr(w, 500, err.Error())
		return
	}
	jout(w, 200, map[string]any{"ok": true})
}

func rowsAffected(res sql.Result) int64 {
	n, _ := res.RowsAffected()
	return n
}

func nilOrString(ns sql.NullString) any {
	if ns.Valid {
		return ns.String
	}
	return nil
}

// pushNotify 任务完成/失败时向配置的 webhook 推送 JSON（蓝本 _finish → push_event）。
func (n *NodeAPI) pushNotify(taskID int64, status, message string) {
	cfg := store.GetSetting(n.DB, "notify")
	if cfg == "" {
		return
	}
	var c struct {
		Enabled    bool   `json:"enabled"`
		WebhookURL string `json:"webhook_url"`
	}
	_ = json.Unmarshal([]byte(cfg), &c)
	if !c.Enabled || c.WebhookURL == "" {
		return
	}
	body, _ := json.Marshal(map[string]any{
		"event": "task_" + status, "title": fmt.Sprintf("任务 #%d %s", taskID, status),
		"body": message, "time": time.Now().UTC().Format(time.RFC3339)})
	go func() {
		client := &http.Client{Timeout: 10 * time.Second}
		req, _ := http.NewRequest(http.MethodPost, c.WebhookURL,
			strings.NewReader(string(body)))
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		if err == nil {
			_ = resp.Body.Close()
		}
	}()
}

// DeployNode: POST /api/nodes/deploy — SSH 引导式节点部署。
// UI 填 VPS 连接信息 → server SSH 上去装 argus-node → 节点自行回连注册。
func (n *NodeAPI) DeployNode(w http.ResponseWriter, r *http.Request) {
	var req deploy.SSHConfig
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jerr(w, 422, "参数解析失败: "+err.Error())
		return
	}
	if req.Host == "" || req.Username == "" || req.NodeName == "" {
		jerr(w, 422, "host/username/node_name 必填")
		return
	}
	// 默认值
	if req.Port == 0 {
		req.Port = 22
	}
	if req.AuthType == "" {
		req.AuthType = "password"
	}
	if req.ServerURL == "" {
		req.ServerURL = "http://" + localIP() + ":7887"
	}
	if req.NodeToken == "" {
		// 注册端点要求管理 token（防开放注册）——部署下发的凭证必须与之匹配：
		// 优先专用部署 token（settings.node_deploy_token），否则直接用当前管理
		// token；本地模式（无 token）时注册放行，占位值即可。
		req.NodeToken = store.GetSetting(n.DB, "node_deploy_token")
		if req.NodeToken == "" && n.Admin != nil {
			req.NodeToken = n.Admin.Token()
		}
		if req.NodeToken == "" {
			req.NodeToken = "argus-node-auto"
		}
	}
	// BinaryPath 留空——Deploy 内部会检测远端架构自动选择

	// 异步部署（SSH 可能 10-30 秒）
	go func() {
		result := deploy.Deploy(req)
		n.Bus.Publish("node_deploy", map[string]any{
			"node_name": req.NodeName, "host": req.Host, "result": result,
		})
	}()
	jout(w, 200, map[string]any{
		"ok": true, "message": "部署已启动（异步），结果将实时推送到节点列表",
		"node_name": req.NodeName,
	})
}

// localIP 获取本机非回环 IP（节点回连地址用）。
func localIP() string {
	conn, err := net.Dial("udp", "8.8.8.8:53")
	if err != nil {
		return "127.0.0.1"
	}
	defer conn.Close()
	return conn.LocalAddr().(*net.UDPAddr).IP.String()
}
