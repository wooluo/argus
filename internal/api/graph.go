package api

// graph.go: 资产覆盖图（蓝本 api/dashboard.py asset_graph）。
// ARTEX 风格层级化（主机→服务→端点）+ 已测/未测三态 + 覆盖度。
// 已测判定：traffic_logs 命中该 URL/服务（平台工具真实请求过）。

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// GetGraph GET /api/projects/{id}/graph — 资产覆盖图数据。
func (a *API) GetGraph(w http.ResponseWriter, r *http.Request) {
	pid, err := pathID(r)
	if err != nil {
		respondErr(w, 422, err.Error())
		return
	}

	// 流量命中表：url 去参数 → (count, last_status)
	trafficMap := map[string][2]int{}
	trows, _ := a.DB.Query(`SELECT url,status FROM traffic_logs WHERE project_id=? LIMIT 2000`, pid)
	for trows.Next() {
		var u string
		var st int
		if trows.Scan(&u, &st) == nil {
			base := strings.SplitN(u, "?", 2)[0]
			e := trafficMap[base]
			trafficMap[base] = [2]int{e[0] + 1, st}
		}
	}
	trows.Close()

	// 漏洞命中表：target 去参数 → severity
	findingMap := map[string]string{}
	frows, _ := a.DB.Query(`SELECT target,severity FROM findings WHERE project_id=? LIMIT 1000`, pid)
	for frows.Next() {
		var t, sev string
		if frows.Scan(&t, &sev) == nil && t != "" {
			findingMap[strings.SplitN(t, "?", 2)[0]] = sev
		}
	}
	frows.Close()

	hostOf := func(v string) string {
		if strings.HasPrefix(v, "http") {
			if pr, err := url.Parse(v); err == nil {
				return pr.Hostname()
			}
		}
		return strings.SplitN(v, ":", 2)[0]
	}

	type hostMeta struct {
		tested   bool
		traffic  int
		findings int
	}
	hosts := map[string]*hostMeta{}
	type svcMeta struct {
		id, host, port, service string
		tested                  bool
	}
	services := map[[2]string]*svcMeta{}
	type endpointMeta struct {
		id, host, port, path string
		query, tested        bool
	}
	endpoints := []endpointMeta{}

	arows, _ := a.DB.Query(`SELECT type,value,detail FROM assets WHERE project_id=? LIMIT 800`, pid)
	for arows.Next() {
		var typ, val, detailStr string
		if arows.Scan(&typ, &val, &detailStr) != nil || val == "" {
			continue
		}
		var detail map[string]any
		_ = json.Unmarshal([]byte(detailStr), &detail)
		switch typ {
		case "ip", "domain":
			if hosts[val] == nil {
				hosts[val] = &hostMeta{}
			}
		case "port":
			host := hostOf(val)
			port := ""
			if parts := strings.Split(val, ":"); len(parts) > 1 {
				port = parts[1]
			}
			if port == "" {
				if v, ok := detail["port"].(string); ok {
					port = v
				} else if v, ok := detail["port"].(float64); ok {
					port = strconv.Itoa(int(v))
				}
			}
			svc, _ := detail["service"].(string)
			key := [2]string{host, port}
			if services[key] == nil {
				services[key] = &svcMeta{id: val, host: host, port: port, service: svc}
			}
			if e, ok := trafficMap[host+":"+port]; ok {
				services[key].tested = true
				_ = e
			}
		case "url":
			pr, err := url.Parse(val)
			if err != nil {
				continue
			}
			host := pr.Hostname()
			port := ""
			if pr.Port() != "" {
				port = pr.Port()
			} else if pr.Scheme == "https" {
				port = "443"
			} else {
				port = "80"
			}
			base := strings.SplitN(val, "?", 2)[0]
			e, hit := trafficMap[base]
			endpoints = append(endpoints, endpointMeta{
				id: val, host: host, port: port, path: orDefault(pr.Path, "/"),
				query: pr.RawQuery != "", tested: hit,
			})
			if hit && hosts[host] != nil {
				hosts[host].tested = true
				hosts[host].traffic = e[0]
			}
			if sev, ok := findingMap[base]; ok && hosts[host] != nil {
				hosts[host].findings++
				_ = sev
			}
		}
	}
	arows.Close()

	// ---- 节点/边 ----
	type node struct {
		ID         string `json:"id"`
		Kind       string `json:"kind"`
		Label      string `json:"label"`
		Sub        string `json:"sub"`
		Tested     bool   `json:"tested"`
		SymbolSize int    `json:"symbolSize"`
	}
	type edge struct {
		Source string `json:"source"`
		Target string `json:"target"`
	}
	nodes := []node{}
	edges := []edge{}
	addNode := func(id, kind, label, sub string, tested bool, size int) {
		if len(label) > 46 {
			label = label[:46]
		}
		nodes = append(nodes, node{id, kind, label, sub, tested, size})
	}

	for h, m := range hosts {
		addNode(h, "host", h, "主机", m.tested, 34)
	}
	for _, svc := range services {
		nid := svc.host + ":" + svc.port
		sub := ":" + svc.port
		if svc.service != "" {
			sub += " · " + svc.service
		}
		addNode(nid, "service", sub, sub, svc.tested, 26)
		if _, ok := hosts[svc.host]; ok {
			edges = append(edges, edge{svc.host, nid})
		}
	}
	nodeIDs := map[string]bool{}
	for _, n := range nodes {
		nodeIDs[n.ID] = true
	}
	for _, e := range endpoints {
		sub := ":" + e.port + " · 端点"
		addNode(e.id, "endpoint", e.id, sub, e.tested, 18)
		attach := ""
		if svc, ok := services[[2]string{e.host, e.port}]; ok {
			attach = svc.host + ":" + svc.port
		} else if _, ok := hosts[e.host]; ok {
			attach = e.host
		}
		if attach != "" && attach != e.id && nodeIDs[attach] {
			edges = append(edges, edge{attach, e.id})
		}
	}

	// ---- 覆盖度 ----
	testable, testedN := 0, 0
	for _, n := range nodes {
		if n.Kind == "service" || n.Kind == "endpoint" {
			testable++
			if n.Tested {
				testedN++
			}
		}
	}
	percent := 0.0
	if testable > 0 {
		percent = float64(testedN) / float64(testable) * 100
	}
	respondJSON(w, 200, map[string]any{
		"nodes": nodes, "edges": edges,
		"categories": []map[string]string{
			{"name": "主机/IP"}, {"name": "服务"}, {"name": "端点"}, {"name": "技术"}},
		"coverage": map[string]any{
			"in_scope": testable, "tested": testedN,
			"percent": float64(int(percent*10)) / 10,
			"hosts":   len(hosts), "findings_total": len(findingMap), "out_of_scope": 0,
		},
	})
}
