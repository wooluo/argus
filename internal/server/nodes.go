package server

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math/rand"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/wooluo/argus/internal/api"
	"github.com/wooluo/argus/internal/auth"
	"github.com/wooluo/argus/internal/config"
	"github.com/wooluo/argus/internal/deploy"
	"github.com/wooluo/argus/internal/intel"
	"github.com/wooluo/argus/internal/store"
	"github.com/wooluo/argus/internal/tools"
)

// NodeAPI: 执行面 API（argus-node 调用）。
// 模型： 节点注册（管理 token 开启）→ 心跳 → 轮询领取 → 执行 → 回传结果。
type NodeAPI struct {
	DB       *sql.DB
	Bus      eventsBus
	NodeAuth *auth.NodeAuth
	Admin    *auth.Middleware // 管理鉴权（SSH 部署时下发的注册凭证 = 当前管理 token）
	Tunnels  *TunnelManager   // SSH 隧道回连管理（NAT/内网 server 的节点回连通道）
	Watchdog *Watchdog        // 任务看门狗（执行心跳在 NodeIntel 采集；nil=不启用）
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
	rows, err := n.DB.Query(`SELECT id,name,platform,hostname,version,status,last_seen,created_at,host,last_deploy,ssh_conf FROM nodes ORDER BY id`)
	if err != nil {
		jerr(w, 500, err.Error())
		return
	}
	defer rows.Close()
	type nodeRow struct {
		ID         int    `json:"id"`
		Name       string `json:"name"`
		Platform   string `json:"platform"`
		Hostname   string `json:"hostname"`
		Version    string `json:"version"`
		Status     string `json:"status"`
		LastSeen   string `json:"last_seen"`
		CreatedAt  string `json:"created_at"`
		Host       string `json:"host"`
		LastDeploy string `json:"last_deploy"` // 最近一次部署结果 JSON（ok/message/steps）
		Tunnel     bool   `json:"tunnel"`      // SSH 隧道回连是否托管中
		HasSSH     bool   `json:"has_ssh"`     // SSH 观测凭据（部署写入或详情配置）
		// 已保存的连接参数（「编辑 → 重新部署」和「SSH 观测」弹窗带出用）；
		// 密码 / 私钥不出接口
		SSHPort int    `json:"ssh_port"`
		SSHUser string `json:"ssh_user"`
		SSHAuth string `json:"ssh_auth"`
		sshConf string
	}
	out := []nodeRow{}
	for rows.Next() {
		var v nodeRow
		if err := rows.Scan(&v.ID, &v.Name, &v.Platform, &v.Hostname, &v.Version,
			&v.Status, &v.LastSeen, &v.CreatedAt, &v.Host, &v.LastDeploy, &v.sshConf); err != nil {
			jerr(w, 500, err.Error())
			return
		}
		v.HasSSH = v.sshConf != ""
		var saved struct {
			Port     int    `json:"port"`
			Username string `json:"username"`
			AuthType string `json:"auth_type"`
		}
		_ = json.Unmarshal([]byte(v.sshConf), &saved)
		v.SSHPort, v.SSHUser, v.SSHAuth = saved.Port, saved.Username, saved.AuthType
		// 状态动态化：deploying/deploy_failed 原样；其余按心跳新鲜度判
		// （心跳周期 15s，45s 容忍）
		if v.Status != "deploying" && v.Status != "deploy_failed" {
			v.Status = "offline"
			if v.LastSeen != "" {
				if t, err := time.Parse("2006-01-02T15:04:05.000Z", v.LastSeen); err == nil &&
					time.Since(t) < 45*time.Second {
					v.Status = "online"
				}
			}
		}
		if n.Tunnels != nil {
			v.Tunnel = n.Tunnels.Status(v.Name)
		}
		out = append(out, v)
	}
	jout(w, 200, out)
}

// UpdateExecNode: PUT /api/nodes/exec/{id} — 编辑执行节点（名称/地址标注）。
// 注意：改名后节点自身携带旧名，重新注册会按旧名 UPSERT 出新行——重命名
// 仅用于显示标注场景。
// DeleteExecNode: DELETE /api/nodes/exec/{id} — 删除执行节点
// （deploying/deploy_failed 残留行清理、下线节点移除；凭证立即失效）。
func (n *NodeAPI) DeleteExecNode(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil || id <= 0 {
		jerr(w, 422, "invalid id")
		return
	}
	// 有在跑任务的节点不允许删（避免任务悬空）；节点已失联（>10min 无
	// 心跳）则任务是僵尸——代停放行，别让死任务卡死节点管理。
	var running int
	_ = n.DB.QueryRow(`SELECT COUNT(*) FROM tasks WHERE node_id=? AND status IN ('pending','running','assigned')`, id).Scan(&running)
	stoppedZombies := 0
	if running > 0 {
		var lastSeen string
		_ = n.DB.QueryRow(`SELECT last_seen FROM nodes WHERE id=?`, id).Scan(&lastSeen)
		if t, err := time.Parse(time.RFC3339, lastSeen); err == nil && time.Since(t) < 10*time.Minute {
			// 节点活着 → 照旧拦，但列出任务号——「先停任务」得让人知道停哪条
			var ids string
			_ = n.DB.QueryRow(`SELECT GROUP_CONCAT(id) FROM tasks WHERE node_id=? AND status IN ('pending','running','assigned')`, id).Scan(&ids)
			jerr(w, 400, fmt.Sprintf("该节点有 %d 条待执行/执行中任务（#%s），先停任务再删", running, ids))
			return
		}
		_, _ = n.DB.Exec(`UPDATE tasks SET status='stopped', finished_at=? WHERE node_id=? AND status IN ('pending','running','assigned')`,
			store.Now(), id)
		stoppedZombies = running
	}
	var nodeName string
	_ = n.DB.QueryRow(`SELECT name FROM nodes WHERE id=?`, id).Scan(&nodeName)
	if n.Tunnels != nil && nodeName != "" {
		n.Tunnels.Remove(nodeName) // 撤隧道（远端监听随连接关闭释放）
	}
	res, err := n.DB.Exec(`DELETE FROM nodes WHERE id=?`, id)
	if err != nil {
		jerr(w, 500, err.Error())
		return
	}
	if rowsAffected(res) == 0 {
		jerr(w, 404, "节点不存在")
		return
	}
	if n.NodeAuth != nil {
		n.NodeAuth.RemoveByNode(id) // 节点 token 立即失效
	}
	if stoppedZombies > 0 {
		jout(w, 200, map[string]any{"ok": true,
			"message": fmt.Sprintf("节点已删除；失联期间的 %d 条僵尸任务已代停", stoppedZombies)})
		return
	}
	jout(w, 200, map[string]any{"ok": true})
}

// Register: POST /api/nodes/register {"name":"kali-1","capabilities":["nmap","httpx"]}
func (n *NodeAPI) Register(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name         string   `json:"name"`
		Platform     string   `json:"platform"`
		Capabilities []string `json:"capabilities"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Name == "" {
		jerr(w, 422, "name required")
		return
	}
	tok := genNodeToken()
	caps, _ := json.Marshal(req.Capabilities)
	// UPSERT：SSH 部署会预插 deploying 行——注册即激活（换 token 上线），
	// 重复注册（节点重装/重试）也是换 token 续用同一行。
	res, err := n.DB.Exec(`
		INSERT INTO nodes(name,token,capabilities,platform,status,last_seen) VALUES(?,?,?,?, 'online', ?)
		ON CONFLICT(name) DO UPDATE SET token=excluded.token, capabilities=excluded.capabilities,
			platform=excluded.platform, status='online', last_seen=excluded.last_seen`,
		req.Name, tok, string(caps), req.Platform, store.Now())
	if err != nil {
		jerr(w, 500, err.Error())
		return
	}
	id, _ := res.LastInsertId()
	if id == 0 { // UPSERT 命中已有行时 LastInsertId 无意义——查回
		_ = n.DB.QueryRow(`SELECT id FROM nodes WHERE name=?`, req.Name).Scan(&id)
	}
	if n.NodeAuth != nil {
		n.NodeAuth.Set(tok, id)
	}
	n.Bus.Publish("node_registered", map[string]any{"id": id, "name": req.Name})
	jout(w, 201, map[string]any{"node_id": id, "token": tok})
}

// Heartbeat: POST /api/nodes/heartbeat {"node_id":1,"tools":[…]} — 更新 last_seen；
// tools 是节点上报的工具状态（有变化才落库，设置页按节点查看用）。
func (n *NodeAPI) Heartbeat(w http.ResponseWriter, r *http.Request) {
	var req struct {
		NodeID int64           `json:"node_id"`
		Tools  json.RawMessage `json:"tools"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.NodeID == 0 {
		jerr(w, 422, "node_id required")
		return
	}
	if _, err := n.DB.Exec(`UPDATE nodes SET last_seen=?,status='online' WHERE id=?`, store.Now(), req.NodeID); err != nil {
		jerr(w, 500, err.Error())
		return
	}
	if len(req.Tools) > 0 && json.Valid(req.Tools) {
		var cur string
		_ = n.DB.QueryRow(`SELECT tools FROM nodes WHERE id=?`, req.NodeID).Scan(&cur)
		if cur != string(req.Tools) {
			_, _ = n.DB.Exec(`UPDATE nodes SET tools=?, tools_at=? WHERE id=?`,
				string(req.Tools), store.Now(), req.NodeID)
		}
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
	// started_at 记首次领取时刻（重排/重跑不改写，耗时统计按首次起算）
	res, err := n.DB.Exec(`UPDATE tasks SET status='assigned',node_id=?,assigned_at=?,
		started_at=COALESCE(started_at,?) WHERE id=? AND status IN ('pending','running')`,
		node.ID, store.Now(), store.Now(), taskID)
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

	// 知识索引（推索引、拉全文）：本项目专属条目优先，其后是与「项目名 / 授权
	// 范围 / 项目说明」最相关的通用条目；全文由节点经 knowledge_get 按需拉取。
	//（原先按文件名顺序取前 5 条整篇塞进任务书：与目标无关、条目一多就撑爆）
	knowledgeBlock := api.KnowledgeIndexMarkdown(n.DB, int64(t.ProjectID), knowledgeQuery(p), 10)

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

	// 自定义 Agent 覆盖（按任务模式取角色：autonomous→hunt / staged→staged）
	agentRole := "hunt"
	if t.Mode == "staged" {
		agentRole = "staged"
	}
	agentPrompt, agentMaxSteps := agentOverride(n.DB, agentRole)

	// FOFA 凭据（设置页配置；未配置时空串，节点回落环境变量）
	fofaEmail, fofaKey := store.GetSetting(n.DB, "fofa_email"), store.GetSetting(n.DB, "fofa_key")

	// 断点续测：continue_from 指定任务的历史成果摘要
	continueSummary := ""
	var contFrom int64
	_ = n.DB.QueryRow(`SELECT continue_from FROM tasks WHERE id=?`, taskID).Scan(&contFrom)
	if contFrom > 0 {
		continueSummary = n.buildContinueSummary(contFrom)
	}

	// 时间预算：剩余时长自首次领取起算（重排 / 重跑不重置），节点据此在任务书里
	// 写明并临近结束时提醒收敛；到点由看门狗代停（同一个上限，两处读同一份设置）
	remaining, limit := int64(0), int64(0)
	if max := taskTimeLimit(n.DB); max > 0 {
		var started string
		_ = n.DB.QueryRow(`SELECT COALESCE(started_at, assigned_at, '') FROM tasks WHERE id=?`, taskID).
			Scan(&started)
		limit = int64(max.Seconds())
		if t, err := time.Parse("2006-01-02T15:04:05.000Z", started); err == nil {
			if left := time.Until(t.Add(max)); left > 0 {
				remaining = int64(left.Seconds())
			}
		}
	}

	// 分层用脑：按角色下发模型配置（主循环 / 审查核验 / 报告复盘）。没分工的
	// 角色不下发，节点沿用主配置。
	models := map[string]any{}
	for _, def := range api.ModelRoles {
		if cfg := api.ResolveModel(n.DB, def.ID); cfg != nil {
			models[def.ID] = *cfg
		}
	}

	jout(w, 200, map[string]any{"task": t, "project": p, "llm": json.RawMessage(llmCfg),
		"knowledge": knowledgeBlock, "approvals_require": approvalsRequire,
		"intel": intel, "skills": skillsBlock, "mcp": mcpServers,
		"agent":            map[string]any{"prompt": agentPrompt, "max_steps": agentMaxSteps},
		"fofa":             map[string]any{"email": fofaEmail, "key": fofaKey},
		"github_token":     store.GetSetting(n.DB, "github_token"),
		"continue_summary": continueSummary,
		"verify_findings":  limitBool(n.DB, "autonomous_verify", true), // 收工后独立核验
		"limits":           pollLimits(n.DB),                           // 限速参数：request_rate / max_concurrency
		"time_budget": map[string]any{
			"remaining_seconds": remaining, "limit_seconds": limit},
		"models": models,
	})
}

// limitBool 读 settings.limits 里的布尔项（缺省取 def）。
func limitBool(db *sql.DB, key string, def bool) bool {
	var limits map[string]any
	_ = json.Unmarshal([]byte(store.GetSetting(db, "limits")), &limits)
	if v, ok := limits[key].(bool); ok {
		return v
	}
	return def
}

// pollLimits 读 settings.limits 里的数值限速项。没有配置时返回 nil，
// 节点收到 nil 即不限速，沿用原有的工具内建退避。
func pollLimits(db *sql.DB) *tools.Limits {
	var raw map[string]any
	_ = json.Unmarshal([]byte(store.GetSetting(db, "limits")), &raw)
	if raw == nil {
		return nil
	}
	l := &tools.Limits{}
	if v, ok := raw["request_rate"].(float64); ok && v > 0 {
		l.RequestRate = v
	}
	if v, ok := raw["max_concurrency"].(float64); ok && v > 0 {
		l.MaxConcurrency = int(v)
	}
	if l.RequestRate <= 0 && l.MaxConcurrency <= 0 {
		return nil
	}
	return l
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

// agentOverride settings.agents 中指定角色的自定义 prompt / 步数覆盖
// （hunt=自主模式 / staged=阶段模式；retester 在 retest.go 直接读）。
func agentOverride(db *sql.DB, role string) (string, int) {
	var saved []map[string]any
	_ = json.Unmarshal([]byte(store.GetSetting(db, "agents")), &saved)
	for _, s := range saved {
		if id, _ := s["id"].(string); id != role {
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
	// 响应带任务停止标志——节点 5s 轮询发现即中断执行（真正的停止）
	stopped := false
	var st string
	if n.DB.QueryRow(`SELECT status FROM tasks WHERE id=?`, taskID).Scan(&st) == nil {
		stopped = st == "stopped"
	}
	if n.Watchdog != nil {
		n.Watchdog.Touch(taskID, time.Now()) // 执行心跳：看门狗据此区分「节点在线但任务没人跑」
	}
	jout(w, 200, map[string]any{"intel": intel.Drain(taskID), "stopped": stopped})
}

// knowledgeQuery 知识索引的相关性查询：项目名 + 授权范围 + 项目说明。
func knowledgeQuery(p store.Project) string {
	var rules []struct {
		Value string `json:"value"`
	}
	_ = json.Unmarshal(p.Scope, &rules)
	values := make([]string, len(rules))
	for i, r := range rules {
		values[i] = r.Value
	}
	return p.Name + " " + strings.Join(values, " ") + " " + p.Description
}

// NodeKnowledge: GET /api/nodes/knowledge/{kid}?task_id= — 节点按需拉取知识条目
// 全文（任务书只带索引）。只放行对该任务所属项目可见且启用的条目。
func (n *NodeAPI) NodeKnowledge(w http.ResponseWriter, r *http.Request) {
	kid := chi.URLParam(r, "kid")
	taskID, _ := strconv.ParseInt(r.URL.Query().Get("task_id"), 10, 64)
	var projectID int64
	if taskID > 0 {
		_ = n.DB.QueryRow(`SELECT project_id FROM tasks WHERE id=?`, taskID).Scan(&projectID)
	}
	title, content, ok := api.KnowledgeBody(n.DB, kid, projectID)
	if !ok {
		jerr(w, 404, "knowledge not found")
		return
	}
	jout(w, 200, map[string]any{"id": kid, "title": title, "content": content})
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
		TaskID  int64  `json:"task_id"`
		Status  string `json:"status"` // done | failed | partial
		Message string `json:"message"`
		// 原样透传：persistNodeBatch 统一解码（含 status 与 steps——接口自己的
		// 匿名结构曾缺这两个字段，转发时被丢掉）
		Findings json.RawMessage `json:"findings"`
		Assets   []struct {
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
		Report string           `json:"report"` // 任务最终 Markdown 报告（落 reports 表）
		Tokens map[string]int64 `json:"tokens"` // 任务级 token 用量 {prompt,completion,calls}（落 tasks.tokens）
		// 分模型用量 {模型 ID: {prompt,completion,calls}}——分层用脑后各角色可能是
		// 不同模型，合计看不出谁花了多少
		TokensByModel map[string]map[string]int64 `json:"tokens_by_model"`
		Knowledge     []api.KnowledgeIn           `json:"knowledge"` // 本任务沉淀的经验（落知识库）
		// 发现的三种形态：新增 / 运行中的状态更新 / 最终结果的全量对账（见 upsertFinding）
		FindingUpdates json.RawMessage `json:"finding_updates"`
		FindingUpserts json.RawMessage `json:"finding_upserts"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.TaskID == 0 {
		jerr(w, 422, "task_id required")
		return
	}
	if err := n.persistNodeBatch(req.TaskID, req.Findings, req.Assets, req.Logs, req.Traffic,
		req.Knowledge, req.FindingUpdates, req.FindingUpserts); err != nil {
		jerr(w, 500, err.Error())
		return
	}
	if len(req.Tokens) > 0 {
		// 合计与分模型用量存进同一个 JSON：合计键保持原样（仪表盘按它汇总），
		// 分模型的放在 "models" 下
		tokens := map[string]any{}
		for k, v := range req.Tokens {
			tokens[k] = v
		}
		if len(req.TokensByModel) > 0 {
			tokens["models"] = req.TokensByModel
		}
		if b, err := json.Marshal(tokens); err == nil {
			_, _ = n.DB.Exec(`UPDATE tasks SET tokens=? WHERE id=?`, string(b), req.TaskID)
		}
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
	// 已停止的任务不覆盖状态（操作员/看门狗停止优先于执行结果），数据照常入库；
	// 看门狗写下的代停原因保留，节点侧的收尾说明接在其后
	msg := req.Message
	var curStatus, curMsg string
	_ = n.DB.QueryRow(`SELECT status, message FROM tasks WHERE id=?`, req.TaskID).Scan(&curStatus, &curMsg)
	if curStatus == "stopped" && strings.HasPrefix(curMsg, watchdogMark) {
		msg = curMsg + "；节点侧：" + req.Message
	}
	if _, err := n.DB.Exec(`UPDATE tasks SET status=CASE WHEN status='stopped' THEN status ELSE ? END,
		finished_at=?, message=? WHERE id=?`,
		status, store.Now(), msg, req.TaskID); err != nil {
		jerr(w, 500, err.Error())
		return
	}
	intel.Discard(req.TaskID) // 任务结束丢弃未消费的运行中情报
	if n.Watchdog != nil {
		n.Watchdog.Forget(req.TaskID) // 执行心跳表不留已完成任务
	}
	n.Bus.Publish("task_done", map[string]any{"task_id": req.TaskID, "status": status})
	jout(w, 200, map[string]any{"ok": true})
}

// NodeBatch: Progress / ReportResult 共用的批量落库。
func (n *NodeAPI) persistNodeBatch(taskID int64, findings, assets, logs, traffic, knowledge,
	findingUpdates, findingUpserts any) error {
	// 各参数为匿名结构切片，走 JSON 重编码最省事
	buf, _ := json.Marshal(map[string]any{
		"findings": findings, "assets": assets, "logs": logs, "traffic": traffic,
		"knowledge": knowledge, "finding_updates": findingUpdates, "finding_upserts": findingUpserts,
	})
	var req struct {
		Findings       []nodeFinding `json:"findings"`
		FindingUpdates []nodeFinding `json:"finding_updates"`
		FindingUpserts []nodeFinding `json:"finding_upserts"`
		Assets         []struct {
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
		Knowledge []api.KnowledgeIn `json:"knowledge"`
	}
	_ = json.Unmarshal(buf, &req)
	var projectID int64
	_ = n.DB.QueryRow(`SELECT project_id FROM tasks WHERE id=?`, taskID).Scan(&projectID)
	// 经验入库（任务后复盘 / knowledge_save / 验证过的凭据）。单条失败不影响
	// 其余落库——发现与日志比知识条目要紧。
	for _, k := range req.Knowledge {
		if _, _, err := api.SaveKnowledgeAuto(n.DB, k, projectID, taskID); err != nil {
			log.Printf("[knowledge] task %d「%s」入库失败: %v", taskID, k.Title, err)
		}
	}
	// 发现：按（项目、名称、目标）插入或更新。三路合流——新增（findings）、运行中
	// 的状态更新（finding_updates）、最终结果的全量对账（finding_upserts）。
	for _, group := range [][]nodeFinding{req.Findings, req.FindingUpdates, req.FindingUpserts} {
		for _, f := range group {
			if err := n.upsertFinding(projectID, f); err != nil {
				return err
			}
		}
	}
	for _, s := range req.Assets {
		// 去重：同项目同类型同值已存在则更新 detail（资产回流合并而非堆行）。
		// detail 收拾成合法 JSON：空串会让整个资产列表转 JSON 失败。
		if _, err := n.DB.Exec(`INSERT INTO assets(project_id,type,value,detail,source)
			SELECT project_id,?,?,?,'node' FROM tasks WHERE id=?
			AND NOT EXISTS(SELECT 1 FROM assets a WHERE a.project_id=tasks.project_id AND a.type=? AND a.value=?)`,
			s.Type, s.Value, store.NormalizeJSON(s.Detail), taskID, s.Type, s.Value); err != nil {
			return err
		}
	}
	for _, l := range req.Logs {
		_, _ = n.DB.Exec(`INSERT INTO agent_logs(task_id,stage,type,tool,content) SELECT ?,?,?,?,? WHERE EXISTS(SELECT 1 FROM tasks WHERE id=?)`,
			taskID, l.Stage, l.Tool, l.Tool, l.Content, taskID)
		// 实时推送（蓝本 audit.emit：任务流无名事件，前端 onmessage 增量渲染）
		n.Bus.Publish("task_log", map[string]any{
			"task_id": taskID, "type": func() string {
				if l.Tool != "" {
					return l.Tool
				}
				return "log"
			}(),
			"data": map[string]any{"stage": l.Stage, "tool": l.Tool, "content": l.Content},
			"time": store.Now(),
		})
	}
	for _, t := range req.Traffic {
		_, _ = n.DB.Exec(`INSERT INTO traffic_logs(project_id,task_id,method,url,request_body,status,response_snippet,source_tool)
			SELECT project_id,?,?,?,?,?,?,? FROM tasks WHERE id=?`,
			taskID, t.Method, t.URL, t.RequestBody, t.Status, t.ResponseSnippet, t.SourceTool, taskID)
	}
	stages := make([]string, len(req.Logs))
	for i, l := range req.Logs {
		stages[i] = l.Stage
	}
	n.advanceStage(taskID, stages)
	return nil
}

// nodeFinding 节点回传的一条发现（含利用链步骤；与 pipeline.Finding 同形）。
type nodeFinding struct {
	Name     string `json:"name"`
	Severity string `json:"severity"`
	Target   string `json:"target"`
	Detail   string `json:"detail"`
	Evidence string `json:"evidence"`
	PoC      string `json:"poc"`
	Status   string `json:"status"`
	Steps    []struct {
		Note       string `json:"note"`
		Request    string `json:"request"`
		Response   string `json:"response"`
		Conclusion string `json:"conclusion"`
	} `json:"steps"`
}

// upsertFinding 按（项目、名称、目标）落一条发现：不存在则插入（严重度、状态
// 取节点上报值）；已存在则以后来的为准更新严重度/详情/证据/PoC/状态（空值
// 不覆盖），并整体替换其利用链步骤。
//
// 原先只有「不存在才插入」一条路：节点随后标记的「确认 / 误报」与补充的步骤
// 永远到不了 server（阶段模式的「AI 验证」阶段因此形同虚设），插入时也没写
// status；且发现已存在时照样取 LastInsertId——单连接下拿到的是这条连接上一次
// 成功插入的任意行，步骤被挂到了错误的发现上。
func (n *NodeAPI) upsertFinding(projectID int64, f nodeFinding) error {
	var id int64
	err := n.DB.QueryRow(`SELECT id FROM findings WHERE project_id=? AND name=? AND target=?`,
		projectID, f.Name, f.Target).Scan(&id)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		sev, status := f.Severity, f.Status
		if sev == "" {
			sev = "info"
		}
		if status == "" {
			status = "pending"
		}
		res, err := n.DB.Exec(`INSERT INTO findings(project_id,name,severity,target,detail,evidence,poc,status,source)
			VALUES(?,?,?,?,?,?,?,?,'node')`,
			projectID, f.Name, sev, f.Target, f.Detail, f.Evidence, f.PoC, status)
		if err != nil {
			return err
		}
		id, _ = res.LastInsertId() // 真实插入，这个 id 才可信
	case err != nil:
		return err
	default:
		if _, err := n.DB.Exec(`UPDATE findings SET
			severity=COALESCE(NULLIF(?,''),severity), detail=COALESCE(NULLIF(?,''),detail),
			evidence=COALESCE(NULLIF(?,''),evidence), poc=COALESCE(NULLIF(?,''),poc),
			status=COALESCE(NULLIF(?,''),status) WHERE id=?`,
			f.Severity, f.Detail, f.Evidence, f.PoC, f.Status, id); err != nil {
			return err
		}
		if _, err := n.DB.Exec(`DELETE FROM finding_steps WHERE finding_id=?`, id); err != nil {
			return err
		}
	}
	for seq, st := range f.Steps {
		if _, err := n.DB.Exec(`INSERT INTO finding_steps(finding_id,project_id,seq,note,request,response,conclusion)
			VALUES(?,?,?,?,?,?,?)`,
			id, projectID, seq+1, st.Note, st.Request, st.Response, st.Conclusion); err != nil {
			return err
		}
	}
	return nil
}

// stagedOrder 阶段模式流水线顺序（与 pipeline.STAGES 一致，看板进度条同序）。
var stagedOrder = []string{"recon", "mapping", "vulnscan", "verify", "report"}

func stageIndex(stage string) int {
	for i, s := range stagedOrder {
		if s == stage {
			return i
		}
	}
	return -1
}

// advanceStage 阶段模式的进度投影：节点日志条目自带结构化 stage 字段，按
// 流水线顺序推进 tasks.current_stage / stages_done——看板顶部五阶段进度条
// 读它（原先无写入点，进度条永远停在第 0 步）。只前进不后退：progress 批次
// 并发到达时乱序不致回退；自主模式与未知 stage 不适用。
func (n *NodeAPI) advanceStage(taskID int64, stages []string) {
	next := ""
	for _, s := range stages {
		if stageIndex(s) > stageIndex(next) {
			next = s
		}
	}
	if stageIndex(next) < 0 {
		return
	}
	var mode, current string
	if err := n.DB.QueryRow(`SELECT mode,current_stage FROM tasks WHERE id=?`, taskID).
		Scan(&mode, &current); err != nil || mode != "staged" || stageIndex(next) <= stageIndex(current) {
		return
	}
	done := []string{}
	for _, s := range stagedOrder[:stageIndex(next)] {
		done = append(done, s)
	}
	doneJSON, _ := json.Marshal(done)
	// 以读到的当前值作条件：并发批次里只有「推进」的那次生效
	_, _ = n.DB.Exec(`UPDATE tasks SET current_stage=?, stages_done=? WHERE id=? AND current_stage=?`,
		next, string(doneJSON), taskID, current)
}

// Progress: POST /api/nodes/progress — 节点执行中增量上报（长任务进度可见）。
func (n *NodeAPI) Progress(w http.ResponseWriter, r *http.Request) {
	var req struct {
		TaskID int64 `json:"task_id"`
		// 原样透传：persistNodeBatch 统一解码（含 status 与 steps——接口自己的
		// 匿名结构曾缺这两个字段，转发时被丢掉）
		Findings json.RawMessage `json:"findings"`
		Assets   []struct {
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
		Knowledge      []api.KnowledgeIn `json:"knowledge"`
		FindingUpdates json.RawMessage   `json:"finding_updates"` // 运行中被更新过的发现
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.TaskID == 0 {
		jerr(w, 422, "task_id required")
		return
	}
	// 进度上报不做全量对账：finding_upserts 留空（仅最终结果携带）
	if err := n.persistNodeBatch(req.TaskID, req.Findings, req.Assets, req.Logs, req.Traffic,
		req.Knowledge, req.FindingUpdates, nil); err != nil {
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

// reuseSavedSecret 部署表单里留空的密码 / 私钥，沿用该节点上次保存的——
// 「编辑 → 重新部署」不必每次重敲。只在主机和用户名都没变时沿用：换了
// 目标还拿旧密码去试，轻则认证失败，重则把对方账号试锁。
func reuseSavedSecret(db *sql.DB, req *deploy.SSHConfig) {
	if req.Password != "" && req.PrivateKey != "" {
		return
	}
	var raw string
	_ = db.QueryRow(`SELECT ssh_conf FROM nodes WHERE name=?`, req.NodeName).Scan(&raw)
	var saved deploy.SSHConfig
	if json.Unmarshal([]byte(raw), &saved) != nil ||
		!strings.EqualFold(strings.TrimSpace(saved.Host), strings.TrimSpace(req.Host)) ||
		saved.Username != req.Username ||
		(saved.AuthType != "" && saved.AuthType != req.AuthType) {
		return
	}
	if req.Password == "" {
		req.Password = saved.Password
	}
	if req.PrivateKey == "" {
		req.PrivateKey = saved.PrivateKey
	}
}

// DeployNode: POST /api/nodes/deploy — SSH 引导部署执行节点（异步，进度经 SSE 推送）。
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
	// host 清洗：内嵌端口/全角/零宽字符入口归一——SSH 拨号、nodes 表展示、
	// 隧道凭据恢复共用一份干净数据（"1.2.3.4:22" 拆出端口直达 SSH，
	// 而非被 JoinHostPort 拼成 "[1.2.3.4:22]:22" 当域名 lookup 超时）
	if h, hp, herr := deploy.CleanHostPort(req.Host); herr != nil {
		jerr(w, 422, herr.Error())
		return
	} else {
		req.Host = h
		if hp > 0 {
			req.Port = hp
		}
	}
	// 默认值
	if req.Port == 0 {
		req.Port = 22
	}
	if req.AuthType == "" {
		req.AuthType = "password"
	}
	reuseSavedSecret(n.DB, &req)
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
	// 节点程序来源：平台推送（默认，上传 server 本机二进制）/ GitHub 下载
	//（远端机器直接从 Release 下载）。GitHub 来源的私有仓库鉴权在 server
	// 侧完成——换取签名下载地址下发，token 不落远端；凭据取设置页的
	// GitHub Token，未配置时回落环境变量 GITHUB_TOKEN。
	switch req.Source {
	case "", deploy.SourceServer:
		req.Source = deploy.SourceServer
	case deploy.SourceGitHub:
		// 仓库/版本格式入口预检——免得 SSH 连上远端才报格式错
		if err := deploy.CheckReleaseRef(req.ReleaseRepo, req.ReleaseTag); err != nil {
			jerr(w, 422, err.Error())
			return
		}
		req.GitHubToken = store.GetSetting(n.DB, "github_token")
		if req.GitHubToken == "" {
			req.GitHubToken = os.Getenv("GITHUB_TOKEN")
		}
	default:
		jerr(w, 422, "source must be server|github")
		return
	}
	// BinaryPath 留空——Deploy 内部会检测远端架构自动选择

	// 部署即上屏：预插 deploying 行（注册 UPSERT 激活），Web 界面立即可见；
	// 隧道模式同步落 SSH 凭据（server 重启后 TunnelManager.Restore 恢复通道）
	if req.Tunnel {
		if b, err := json.Marshal(req); err == nil {
			_, _ = n.DB.Exec(`
				INSERT INTO nodes(name,token,platform,status,last_seen,host,tunnel_ssh)
				VALUES(?, '', '', 'deploying', '', ?, ?)
				ON CONFLICT(name) DO UPDATE SET status='deploying', last_seen='', host=excluded.host, tunnel_ssh=excluded.tunnel_ssh`,
				req.NodeName, req.Host, string(b))
		}
	} else {
		_, _ = n.DB.Exec(`
			INSERT INTO nodes(name,token,platform,status,last_seen,host)
			VALUES(?, '', '', 'deploying', '', ?)
			ON CONFLICT(name) DO UPDATE SET status='deploying', last_seen='', host=excluded.host, tunnel_ssh=''`,
			req.NodeName, req.Host)
	}

	// SSH 观测凭据落库：部署表单的连接信息兼作 ssh_conf（成败都写——部署
	// 失败凭据依然有效，节点详情页的监控/测试照常可用）
	if sc, merr := json.Marshal(api.SSHConf{Host: req.Host, Port: req.Port,
		Username: req.Username, AuthType: req.AuthType,
		Password: req.Password, PrivateKey: req.PrivateKey}); merr == nil {
		_, _ = n.DB.Exec(`UPDATE nodes SET ssh_conf=? WHERE name=?`, string(sc), req.NodeName)
	}

	// 异步部署（分步推送进度；panic/整体超时兜底——goroutine 卡死会让
	// 状态永远「部署中」，实测踩过）
	go func() {
		result := deploy.Result{OK: false, Message: "部署 goroutine 异常退出"}
		defer func() {
			if p := recover(); p != nil {
				result = deploy.Result{OK: false, Message: fmt.Sprintf("部署内部错误: %v", p)}
			}
			if !result.OK {
				_, _ = n.DB.Exec(
					`UPDATE nodes SET status='deploy_failed' WHERE name=? AND status='deploying'`,
					req.NodeName)
			} else {
				// 部署成功但节点尚未回连注册——deploying 转 offline
				//（「已装好、等回连」；注册 UPSERT 转 online。ServerURL 不可达
				// 时停在 offline 而非误导性的「部署中」）
				_, _ = n.DB.Exec(
					`UPDATE nodes SET status='offline' WHERE name=? AND status='deploying'`,
					req.NodeName)
			}
			// 部署结果落库（SSE 即发即焚，落库后可回查/排障）
			if b, err := json.Marshal(result); err == nil {
				_, _ = n.DB.Exec(`UPDATE nodes SET last_deploy=? WHERE name=?`,
					string(b), req.NodeName)
			}
			// 隧道模式：接管部署连接建 remote forward（节点连 VPS 本机
			// 17887 经隧道回 server；看门狗自动重拨，重启后凭据恢复）
			if result.OK && req.Tunnel && result.KeepClient != nil && n.Tunnels != nil {
				if err := n.Tunnels.Attach(req.NodeName, req, result.KeepClient); err != nil {
					n.Bus.Publish("node_deploy", map[string]any{
						"node_name": req.NodeName, "partial": true,
						"step": "⚠ 隧道建立失败: " + err.Error() + "（节点暂时无法回连，可重新部署）",
					})
				} else {
					n.Bus.Publish("node_deploy", map[string]any{
						"node_name": req.NodeName, "partial": true,
						"step": "🔗 SSH 隧道已建立并托管（断线自动重连）: VPS " +
							deploy.TunnelRemoteAddr + " → 本机 " + deploy.TunnelServerAddr,
					})
				}
			}
			n.Bus.Publish("node_deploy", map[string]any{
				"node_name": req.NodeName, "host": req.Host, "result": result,
			})
		}()
		done := make(chan deploy.Result, 1)
		go func() {
			done <- deploy.DeployWithProgress(req, func(step string) {
				n.Bus.Publish("node_deploy", map[string]any{
					"node_name": req.NodeName, "host": req.Host,
					"partial": true, "step": step,
				})
			})
		}()
		select {
		case result = <-done:
		case <-time.After(5 * time.Minute):
			result = deploy.Result{OK: false,
				Message: "部署整体超时（>5min）：SSH 链路过慢或远端无响应"}
		}
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
