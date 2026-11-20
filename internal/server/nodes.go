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
	"strings"
	"time"

	"github.com/wooluo/argus/internal/config"
	"github.com/wooluo/argus/internal/deploy"
	"github.com/wooluo/argus/internal/auth"
	"github.com/wooluo/argus/internal/store"
)

// NodeAPI: 执行面 API（argus-node 调用）。
// 模型： 节点注册（管理 token 开启）→ 心跳 → 轮询领取 → 执行 → 回传结果。
type NodeAPI struct {
	DB       *sql.DB
	Bus      eventsBus
	NodeAuth *auth.NodeAuth
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

	jout(w, 200, map[string]any{"task": t, "project": p, "llm": json.RawMessage(llmCfg),
		"knowledge": knowledgeBlock})
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

// ReportResult: POST /api/nodes/result — 节点执行完毕回传 findings/assets/logs。
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
		Report string `json:"report"` // 任务最终 Markdown 报告（落 reports 表）
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.TaskID == 0 {
		jerr(w, 422, "task_id required")
		return
	}
	for _, f := range req.Findings {
		sev := f.Severity
		if sev == "" {
			sev = "info"
		}
		if _, err := n.DB.Exec(`INSERT INTO findings(project_id,name,severity,target,detail,evidence,poc,source)
			SELECT project_id,?,?,?,?,?,?,'node' FROM tasks WHERE id=?`,
			f.Name, sev, f.Target, f.Detail, f.Evidence, f.PoC, req.TaskID); err != nil {
			jerr(w, 500, err.Error())
			return
		}
	}
	for _, s := range req.Assets {
		if _, err := n.DB.Exec(`INSERT INTO assets(project_id,type,value,detail,source)
			SELECT project_id,?,?,?,?,'node' FROM tasks WHERE id=?`,
			s.Type, s.Value, s.Detail, req.TaskID); err != nil {
			jerr(w, 500, err.Error())
			return
		}
	}
	for _, l := range req.Logs {
		_, _ = n.DB.Exec(`INSERT INTO agent_logs(task_id,stage,type,tool,content) SELECT ?,?,?,?,? WHERE EXISTS(SELECT 1 FROM tasks WHERE id=?)`,
			req.TaskID, l.Stage, l.Tool, l.Tool, l.Content, req.TaskID)
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
	n.Bus.Publish("task_done", map[string]any{"task_id": req.TaskID, "status": status})
	jout(w, 200, map[string]any{"ok": true})
}

// NodeBatch: Progress / ReportResult 共用的批量落库。
func (n *NodeAPI) storeNodeBatch(w http.ResponseWriter, taskID int64,
	findings, assets, logs any) {
	// findings / assets / logs 为匿名结构切片，走 JSON 重编码最省事
	buf, _ := json.Marshal(map[string]any{
		"findings": findings, "assets": assets, "logs": logs,
	})
	var req struct {
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
	}
	_ = json.Unmarshal(buf, &req)
	for _, f := range req.Findings {
		sev := f.Severity
		if sev == "" {
			sev = "info"
		}
		if _, err := n.DB.Exec(`INSERT INTO findings(project_id,name,severity,target,detail,evidence,poc,source)
			SELECT project_id,?,?,?,?,?,?,'node' FROM tasks WHERE id=?`,
			f.Name, sev, f.Target, f.Detail, f.Evidence, f.PoC, taskID); err != nil {
			jerr(w, 500, err.Error())
			return
		}
	}
	for _, s := range req.Assets {
		if _, err := n.DB.Exec(`INSERT INTO assets(project_id,type,value,detail,source)
			SELECT project_id,?,?,?,?,'node' FROM tasks WHERE id=?`,
			s.Type, s.Value, s.Detail, taskID); err != nil {
			jerr(w, 500, err.Error())
			return
		}
	}
	for _, l := range req.Logs {
		_, _ = n.DB.Exec(`INSERT INTO agent_logs(task_id,stage,type,tool,content) SELECT ?,?,?,?,? WHERE EXISTS(SELECT 1 FROM tasks WHERE id=?)`,
			taskID, l.Stage, l.Tool, l.Tool, l.Content, taskID)
	}
	jout(w, 200, map[string]any{"ok": true})
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
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.TaskID == 0 {
		jerr(w, 422, "task_id required")
		return
	}
	n.storeNodeBatch(w, req.TaskID, req.Findings, req.Assets, req.Logs)
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
		req.NodeToken = store.GetSetting(n.DB, "node_deploy_token")
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

