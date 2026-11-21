package api

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/wooluo/argus/internal/pipeline"
)

// 探索链路 + 决策树（对齐原 core/exploration.py 与 api/tasks.py 的 /exploration /tree）：
// 从 agent_logs 确定性推导 起点→目标→意图→事实→漏洞 的血缘 DAG。

var expStageNames = map[string]string{
	"recon": "侦察", "mapping": "资产测绘", "vulnscan": "漏洞扫描",
	"verify": "AI 验证", "report": "报告生成", "hunt": "自主推进",
}

// 思考里"有行动价值"的行：提到工具名或动作动词。
var actionRE = regexp.MustCompile(`(?i)(尝试|验证|测试|探测|扫描|调用|执行|绕过|登录|检查|利用|获取|确认|上传|爆破|枚举|nuclei|nmap|subfinder|httpx|http_fetch|dir_brute|sqlmap|katana|kali_exec|web_login|msf|dnslog)`)

var (
	mdHeadingRE = regexp.MustCompile(`^#{1,6}\s*`)
	findingIDRE = regexp.MustCompile(`finding_id["']?:?\s*(\d+)`)
)

// runesPrefix: 按字符截断（中文安全，等价 Python 切片）。
func runesPrefix(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n])
}

func cleanLine(s string) string {
	s = mdHeadingRE.ReplaceAllString(s, "")
	s = strings.ReplaceAll(s, "**", "")
	s = strings.ReplaceAll(s, "`", "")
	s = strings.ReplaceAll(s, "*", "")
	return strings.TrimSpace(s)
}

// firstLine: 第一个非空行（清洗后），无则截断原文。
func firstLine(text string, n int) string {
	for _, line := range strings.Split(text, "\n") {
		if l := cleanLine(strings.TrimSpace(line)); l != "" {
			return runesPrefix(l, n)
		}
	}
	s := strings.TrimSpace(text)
	if s == "" {
		return "（空）"
	}
	return runesPrefix(s, n)
}

// intentTitle: 从思考文本提取有信息量的意图行（优先含动作词的行）。
func intentTitle(content string, n int) string {
	var lines []string
	for _, l := range strings.Split(content, "\n") {
		if c := cleanLine(l); c != "" {
			lines = append(lines, c)
		}
	}
	if len(lines) == 0 {
		return "（空）"
	}
	pick := lines[0]
	for _, l := range lines {
		if actionRE.MatchString(l) {
			pick = l
			break
		}
	}
	return runesPrefix(pick, n)
}

func shortenURL(u string, n int) string {
	u = strings.ReplaceAll(u, "https://", "")
	u = strings.ReplaceAll(u, "http://", "")
	r := []rune(u)
	if len(r) > n {
		return string(r[:n]) + "…"
	}
	return u
}

func fieldRE(key string) *regexp.Regexp {
	return regexp.MustCompile(`"` + regexp.QuoteMeta(key) + `"\s*:\s*("?[^,"}]*?"?)\s*[,}]`)
}

// fStr: 字段提取：完整解析的 dict 优先，截断 JSON 用正则兜底，值转字符串。
func fStr(d map[string]any, raw, key string) string {
	switch v := d[key].(type) {
	case string:
		return v
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(v)
	}
	m := fieldRE(key).FindStringSubmatch(raw)
	if m == nil {
		return ""
	}
	return strings.Trim(m[1], `"`)
}

// fNum: 数字字段（int(float(v))；失败回 default）。
func fNum(d map[string]any, raw, key, def string) string {
	if f, err := strconv.ParseFloat(fStr(d, raw, key), 64); err == nil {
		return strconv.Itoa(int(f))
	}
	return def
}

// factTitle: 工具结果 → 人话摘要（按工具提取关键数字/结论，而不是贴 JSON 头）。
// 结果串可能被截断（JSON 残缺），字段用正则兜底而非依赖完整解析。
func factTitle(tool, content string) string {
	ok := strings.HasPrefix(content, "✅")
	raw := strings.TrimSpace(strings.TrimLeft(content, "✅❌⚠ "))
	d := map[string]any{}
	if strings.HasPrefix(raw, "{") {
		_ = json.Unmarshal([]byte(raw), &d)
	}
	mark := "❌"
	if ok {
		mark = "✅"
	}
	fs := func(key string) string { return fStr(d, raw, key) }
	fn := func(key, def string) string { return fNum(d, raw, key, def) }
	switch tool {
	case "http_alive", "httpx_probe", "httpx":
		return mark + " 存活 " + fn("alive", "?") + "/" + fn("input", "?")
	case "port_scan":
		var ports []string
		if results, ok := d["results"].([]any); ok {
			for i, rr := range results {
				if i >= 8 {
					break
				}
				if m, _ := rr.(map[string]any); m != nil {
					if p, ok := m["port"].(float64); ok {
						ports = append(ports, strconv.Itoa(int(p)))
					}
				}
			}
		}
		ps := strings.Join(ports, ",")
		if ps == "" {
			ps = "…"
		}
		return mark + " 开放 " + fn("open_ports", "?") + " 端口: " + ps
	case "nuclei_scan":
		return mark + " 扫描 " + fn("scanned", "?") + " 目标，发现 " + fn("found", "0") + " 条"
	case "dir_brute":
		s := mark + " 命中 " + fn("hits", "?") + "/" + fn("probed", "?")
		if _, has := d["wildcard_warning"]; has || strings.Contains(raw, "wildcard_warning") {
			s += "（⚠ 疑似通配响应）"
		}
		return s
	case "subfinder":
		return mark + " 子域名 " + fn("found", "?") + " 个"
	case "osint_lookup":
		if _, has := d["error"]; has || strings.Contains(runesPrefix(raw, 200), "error") {
			msg := fs("error")
			if msg == "" {
				msg = "crt.sh 限流/查询失败"
			}
			return "⚠ " + runesPrefix(msg, 50)
		}
		return mark + " CT日志 " + fn("found", "?") + " 条"
	case "http_fetch":
		method := fs("method")
		if method == "" {
			method = "GET"
		}
		return mark + " " + method + " " + shortenURL(fs("url"), 52) +
			" → " + fn("status", "?") + " (" + fn("body_length", "0") + "B)"
	case "web_login":
		login := "失败"
		if strings.Contains(raw, `"ok": true`) || strings.Contains(raw, `"ok":true`) {
			login = "成功"
		}
		return mark + " 登录" + login + " " + shortenURL(fs("action"), 40)
	case "kali_exec":
		if purpose := strings.TrimSpace(fs("purpose")); purpose != "" {
			return mark + " " + runesPrefix(purpose, 56)
		}
		out := raw
		if i := strings.Index(out, "output"); i >= 0 {
			out = out[:i]
		}
		return mark + " " + firstLine(out, 52)
	case "report_finding", "update_finding", "finding_step":
		fid := "?"
		if m := findingIDRE.FindStringSubmatch(raw); m != nil {
			fid = m[1]
		}
		return mark + " 漏洞 #" + fid + " 已记录/更新"
	case "knowledge_search":
		return mark + " 知识检索: 命中 " + fn("found", "0") + " 条"
	case "github_search", "exploitdb_search", "msf_search":
		return mark + " 检索到 " + fn("count", "0") + " 条"
	}
	return mark + " " + tool + " → " + firstLine(raw, 40)
}

// ---- 探索图 ----

type expNode struct {
	ID       string  `json:"id"`
	Type     string  `json:"type"`
	Title    string  `json:"title"`
	Status   string  `json:"status"`
	Detail   string  `json:"detail"`
	Priority *string `json:"priority"`
	Ref      *int    `json:"ref"`
}

type expEdge struct {
	Source string `json:"source"`
	Target string `json:"target"`
	EType  string `json:"etype"`
}

type expBuilder struct {
	nodes []expNode
	edges []expEdge
	seq   int
}

func (b *expBuilder) add(typ, title, status, detail string, priority *string, ref *int, detailCap int) string {
	b.seq++
	nid := "n" + strconv.Itoa(b.seq)
	b.nodes = append(b.nodes, expNode{ID: nid, Type: typ, Title: title, Status: status,
		Detail: runesPrefix(detail, detailCap), Priority: priority, Ref: ref})
	return nid
}

func (b *expBuilder) edge(src, dst, etype string) {
	b.edges = append(b.edges, expEdge{Source: src, Target: dst, EType: etype})
}

func sp(s string) *string { return &s }
func intPtr(i int) *int   { return &i }

type agentLogRow struct {
	ID      int
	Stage   string
	Type    string
	Tool    string
	Args    string
	Content string
	Summary string
}

func (a *API) queryAgentLogs(taskID int64) ([]agentLogRow, error) {
	rows, err := a.DB.Query(`SELECT id,stage,type,tool,args,content,result_summary
		FROM agent_logs WHERE task_id=? ORDER BY id`, taskID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []agentLogRow
	for rows.Next() {
		var l agentLogRow
		if err := rows.Scan(&l.ID, &l.Stage, &l.Type, &l.Tool, &l.Args, &l.Content, &l.Summary); err != nil {
			return nil, err
		}
		out = append(out, l)
	}
	return out, rows.Err()
}

// findingIDFromContent: report_finding 成功结果里抽 finding_id。
func findingIDFromContent(content string) int {
	body := strings.TrimSpace(strings.TrimLeft(content, "✅ "))
	if body == "" {
		return 0
	}
	var res map[string]any
	if err := json.Unmarshal([]byte(body), &res); err != nil {
		return 0
	}
	if v, ok := res["finding_id"].(float64); ok {
		return int(v)
	}
	return 0
}

// ExplorationGraph: GET /api/tasks/{id}/exploration —
// 探索链路血缘 DAG（起点/目标/意图/事实/漏洞/提示，ARTEX 双图架构的探索图）。
func (a *API) ExplorationGraph(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		respondErr(w, 422, err.Error())
		return
	}
	var status string
	if err := a.DB.QueryRow(`SELECT status FROM tasks WHERE id=?`, id).Scan(&status); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			respondErr(w, 404, "任务不存在")
			return
		}
		respondErr(w, 500, err.Error())
		return
	}
	logs, err := a.queryAgentLogs(id)
	if err != nil {
		respondErr(w, 500, err.Error())
		return
	}

	b := &expBuilder{}
	root := b.add("start", "任务起点", "done", "授权范围内的自主渗透测试", nil, nil, 800)
	cur := root
	curIntent := "" // 最近意图节点 id；空 = 无
	findingNodes := map[int]string{}
	stageGoal := map[string]string{}
	prevStage := ""
	prevIntentTitle := ""

	for _, l := range logs {
		content := l.Content
		stage := l.Stage
		if stage == "" {
			stage = "hunt"
		}

		// 阶段变化 → 目标节点（同阶段复用既有目标，避免震荡产生重复）
		if stage != prevStage {
			if name, known := expStageNames[stage]; known {
				if g, seen := stageGoal[stage]; seen {
					cur, curIntent, prevStage = g, "", stage
					continue
				}
				g := b.add("goal", name, "done", "阶段目标："+name, sp("P9"), nil, 800)
				stageGoal[stage] = g
				if curIntent != "" {
					b.edge(curIntent, g, "chain") // 上个意图派生新阶段目标
				} else {
					b.edge(root, g, "spawn")
				}
				cur, curIntent, prevStage = g, "", stage
				continue
			}
		}
		if l.Type == "system" && (strings.Contains(content, "任务启动") ||
			strings.Contains(content, "阶段完成") || strings.Contains(content, "步数预算")) {
			continue
		}

		// 操作员情报 → 提示节点
		if l.Type == "intel" {
			h := b.add("hint", runesPrefix(content, 46), "done", runesPrefix(content, 400), nil, nil, 800)
			b.edge(cur, h, "spawn")
			continue
		}

		// 思考 → 意图节点（连续相同意图去重）
		if l.Type == "thought" {
			t := intentTitle(content, 60)
			if t == prevIntentTitle {
				continue
			}
			prevIntentTitle = t
			n := b.add("intent", t, "done", runesPrefix(content, 600), sp("P8"), nil, 800)
			if curIntent != "" {
				b.edge(curIntent, n, "chain") // 意图链
			} else {
				b.edge(cur, n, "spawn")
			}
			curIntent, cur = n, n
			continue
		}

		// 工具调用行本身不产节点，信息由对应 tool_result 承载
		if l.Type == "tool_call" {
			continue
		}

		if l.Type == "tool_result" {
			ok := strings.HasPrefix(content, "✅")
			blocked := strings.HasPrefix(content, "❌") && strings.Contains(content, "BLOCKED")
			st := "err"
			if ok {
				st = "ok"
			} else if blocked {
				st = "blocked"
			}
			detail := runesPrefix(content, 400)
			if l.Summary != "" {
				detail += "\n[result] " + runesPrefix(l.Summary, 300)
			}
			f := b.add("fact", factTitle(l.Tool, content), st, detail, nil, nil, 800)
			src := cur
			if curIntent != "" {
				src = curIntent
			}
			b.edge(src, f, "yield")

			// report_finding → 漏洞节点（证明边；详情用完整漏洞档案而非返回 JSON）
			if l.Tool == "report_finding" && ok {
				if fid := findingIDFromContent(content); fid > 0 {
					var name, severity, target, fstatus, fdetail, evidence, poc string
					qerr := a.DB.QueryRow(`SELECT name,severity,target,status,detail,evidence,poc
						FROM findings WHERE id=?`, fid).
						Scan(&name, &severity, &target, &fstatus, &fdetail, &evidence, &poc)
					ftitle := fmt.Sprintf("漏洞 #%d", fid)
					sev := "P8"
					var parts []string
					if qerr == nil {
						ftitle = name
						if severity == "critical" || severity == "high" {
							sev = "P9"
						}
						parts = []string{"名称: " + name, "严重度: " + severity,
							"目标: " + target, "状态: " + fstatus}
						if fdetail != "" {
							parts = append(parts, "描述: "+runesPrefix(fdetail, 600))
						}
						if evidence != "" {
							parts = append(parts, "证据: "+runesPrefix(evidence, 400))
						}
						if poc != "" {
							parts = append(parts, "PoC: "+runesPrefix(poc, 300))
						}
						if srows, serr := a.DB.Query(`SELECT seq,note,request,response,conclusion
							FROM finding_steps WHERE finding_id=? ORDER BY seq LIMIT 6`, fid); serr == nil {
							for srows.Next() {
								var seq int
								var note, req, resp, concl string
								if srows.Scan(&seq, &note, &req, &resp, &concl) == nil {
									parts = append(parts, fmt.Sprintf("第%d步 %s\n  请求: %s\n  结论: %s",
										seq, runesPrefix(note, 80), runesPrefix(req, 150), runesPrefix(concl, 100)))
								}
							}
							srows.Close()
						}
					} else {
						parts = []string{runesPrefix(content, 400)}
					}
					fd := b.add("finding", ftitle, "已入库", strings.Join(parts, "\n"), sp(sev), intPtr(fid), 4000)
					findingNodes[fid] = fd
					b.edge(f, fd, "prove")
					cur = fd
					continue
				}
			}
			cur = f
			continue
		}

		// 审计/错误
		if l.Type == "error" {
			e := b.add("fact", "⚠ "+firstLine(content, 46), "err", runesPrefix(content, 400), nil, nil, 800)
			b.edge(cur, e, "yield")
		}
	}

	// update_finding 的确认状态回填（second pass）
	for _, l := range logs {
		if l.Type == "tool_result" && l.Tool == "update_finding" && strings.Contains(l.Summary, "confirmed") {
			m := findingIDRE.FindStringSubmatch(l.Summary)
			if m == nil {
				continue
			}
			fid, _ := strconv.Atoi(m[1])
			if nid, ok := findingNodes[fid]; ok {
				for i := range b.nodes {
					if b.nodes[i].ID == nid {
						b.nodes[i].Status = "已确认"
					}
				}
			}
		}
	}

	// 运行中的任务：最后一个节点标进行中
	if status == "running" && len(b.nodes) > 0 {
		b.nodes[len(b.nodes)-1].Status = "进行中"
	}
	if b.nodes == nil {
		b.nodes = []expNode{}
	}
	if b.edges == nil {
		b.edges = []expEdge{}
	}
	respondJSON(w, 200, map[string]any{"nodes": b.nodes, "edges": b.edges, "task_status": status})
}

// ---- 决策树 ----

type treeNode struct {
	ID       string      `json:"id"`
	Type     string      `json:"type"`
	Label    string      `json:"label"`
	Status   string      `json:"status"`
	Detail   string      `json:"detail"`
	Children []*treeNode `json:"children"`
}

// argsLabel: k=v 串（键排序保证确定性；每值截 40 字符）。
func argsLabel(args string) string {
	var m map[string]any
	if err := json.Unmarshal([]byte(args), &m); err != nil || len(m) == 0 {
		return ""
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, k+"="+runesPrefix(fmt.Sprintf("%v", m[k]), 40))
	}
	return strings.Join(parts, ", ")
}

// DecisionTree: GET /api/tasks/{id}/tree — 决策树：阶段 → 思考 → 工具调用（含结果状态）。
func (a *API) DecisionTree(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		respondErr(w, 422, err.Error())
		return
	}
	var status, currentStage string
	var stagesDoneRaw []byte
	if err := a.DB.QueryRow(`SELECT status,current_stage,stages_done FROM tasks WHERE id=?`, id).
		Scan(&status, &currentStage, &stagesDoneRaw); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			respondErr(w, 404, "任务不存在")
			return
		}
		respondErr(w, 500, err.Error())
		return
	}
	var stagesDone []string
	_ = json.Unmarshal(stagesDoneRaw, &stagesDone)
	done := map[string]bool{}
	for _, s := range stagesDone {
		done[s] = true
	}

	logs, err := a.queryAgentLogs(id)
	if err != nil {
		respondErr(w, 500, err.Error())
		return
	}

	tree := []*treeNode{}
	stageNodes := map[string]*treeNode{}
	stageNode := func(stage string) *treeNode {
		if n, ok := stageNodes[stage]; ok {
			return n
		}
		label := stage
		if n, ok := pipeline.STAGE_NAMES[stage]; ok {
			label = n
		} else if stage == "" {
			label = "准备"
		}
		st := "pending"
		if stage == currentStage && status == "running" {
			st = "active"
		} else if done[stage] {
			st = "done"
		}
		n := &treeNode{ID: fmt.Sprintf("s-%s-%d", stage, len(stageNodes)), Type: "stage",
			Label: label, Status: st, Children: []*treeNode{}}
		stageNodes[stage] = n
		tree = append(tree, n)
		return n
	}

	var currentThought *treeNode
	var pendingTools []*treeNode
	for _, l := range logs {
		parent := stageNode(l.Stage)
		switch l.Type {
		case "thought":
			currentThought = &treeNode{ID: "n-" + strconv.Itoa(l.ID), Type: "thought",
				Label: runesPrefix(l.Content, 90), Status: "ok", Detail: l.Content, Children: []*treeNode{}}
			parent.Children = append(parent.Children, currentThought)
			pendingTools = nil // 新思考开启，旧工具节点保持当前状态
		case "tool_call":
			node := &treeNode{ID: "n-" + strconv.Itoa(l.ID), Type: "tool",
				Label:  "⚙ " + l.Tool + "(" + runesPrefix(argsLabel(l.Args), 80) + ")",
				Status: "running", Detail: l.Content, Children: []*treeNode{}}
			target := parent
			if currentThought != nil {
				target = currentThought
			}
			target.Children = append(target.Children, node)
			pendingTools = append(pendingTools, node)
		case "tool_result":
			if len(pendingTools) > 0 {
				node := pendingTools[0]
				pendingTools = pendingTools[1:]
				st := "ok"
				if strings.HasPrefix(l.Content, "BLOCKED") {
					st = "blocked"
				} else if strings.HasPrefix(l.Content, "ERROR") || strings.HasPrefix(l.Content, "❌") {
					st = "err"
				}
				node.Status = st
				node.Children = append(node.Children, &treeNode{ID: "n-" + strconv.Itoa(l.ID),
					Type: "result", Label: runesPrefix(l.Content, 120), Status: st,
					Detail: l.Content, Children: []*treeNode{}})
			}
		case "intel":
			parent.Children = append([]*treeNode{{ID: "n-" + strconv.Itoa(l.ID), Type: "intel",
				Label: "📨 " + runesPrefix(l.Content, 80), Status: "ok", Detail: l.Content,
				Children: []*treeNode{}}}, parent.Children...)
		case "system", "error", "audit":
			st := "ok"
			if l.Type == "error" {
				st = "err"
			}
			parent.Children = append(parent.Children, &treeNode{ID: "n-" + strconv.Itoa(l.ID),
				Type: l.Type, Label: runesPrefix(l.Content, 90), Status: st,
				Detail: l.Content, Children: []*treeNode{}})
		}
	}
	respondJSON(w, 200, map[string]any{"task_id": id, "status": status,
		"current_stage": currentStage, "tree": tree})
}
