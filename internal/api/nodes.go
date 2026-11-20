package api

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/wooluo/argus/internal/store"
)

// ============ 节点管理域（蓝本 api/nodes.py）：DNSLog 等渗透节点 CRUD / 测试 ============
// 存 settings["nodes"]；token 掩码回传（前4...后2），空/掩码时 PUT 保留旧值。

const nodesKey = "nodes"

// nodesLoad 读 settings["nodes"]（蓝本 store.NodeStore.list_all(masked=False)）。
func (a *API) nodesLoad() []map[string]any {
	var nodes []map[string]any
	_ = json.Unmarshal([]byte(store.GetSetting(a.DB, nodesKey)), &nodes)
	return nodes
}

// nodesSave 落 settings["nodes"]。
func (a *API) nodesSave(nodes []map[string]any) error {
	b, err := json.Marshal(nodes)
	if err != nil {
		return err
	}
	return store.SetSetting(a.DB, nodesKey, string(b))
}

// nodesMasked 掩码列表（token 只回掩码 + has_token，绝不回明文）。
func nodesMasked(nodes []map[string]any) []map[string]any {
	out := make([]map[string]any, 0, len(nodes))
	for _, n := range nodes {
		m := map[string]any{}
		for k, v := range n {
			m[k] = v
		}
		tok, _ := n["token"].(string)
		m["token"] = kaliMask(tok) // 复用 kali 域 _mask 同款掩码
		m["has_token"] = tok != ""
		out = append(out, m)
	}
	return out
}

// nodesIsMasked 空 / 含 "..." / 全 * —— 视为掩码回传（蓝本 save 判空+"..."，test 同）。
func nodesIsMasked(v string) bool {
	return v == "" || strings.Contains(v, "...") || strings.Trim(v, "*") == ""
}

// ListNodes GET /api/nodes — 列表（token 掩码）。
func (a *API) ListNodes(w http.ResponseWriter, r *http.Request) {
	respondJSON(w, http.StatusOK, nodesMasked(a.nodesLoad()))
}

// PutNodes PUT /api/nodes — 整表保存；token 空/掩码回传时按 id 保留旧值。
func (a *API) PutNodes(w http.ResponseWriter, r *http.Request) {
	var in []map[string]any
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		respondErr(w, http.StatusBadRequest, "参数错误")
		return
	}
	old := map[string]map[string]any{}
	for _, n := range a.nodesLoad() {
		if id, ok := n["id"].(string); ok {
			old[id] = n
		}
	}
	for _, n := range in {
		id, _ := n["id"].(string)
		if id == "" {
			id = fmt.Sprintf("n%d", time.Now().UnixNano()) // 新节点补 id
			n["id"] = id
		}
		tok, _ := n["token"].(string)
		if nodesIsMasked(tok) {
			if o := old[id]; o != nil {
				n["token"] = o["token"] // 掩码回传 → 保留旧值
			} else {
				n["token"] = ""
			}
		}
	}
	if err := a.nodesSave(in); err != nil {
		respondErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	respondJSON(w, http.StatusOK, map[string]any{"ok": true, "nodes": nodesMasked(in)})
}

// TestNode POST /api/nodes/test — dnslog 平台连通（无需先保存；掩码 token 自动取已存值）。
// 蓝本调 provider 的查询接口验证 token（如 ceye /ceye/{token}）；Go 侧 GET base_url 探活 + 状态码回报。
func (a *API) TestNode(w http.ResponseWriter, r *http.Request) {
	var in map[string]any
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		respondErr(w, http.StatusBadRequest, "参数错误")
		return
	}
	id, _ := in["id"].(string)
	if tok, _ := in["token"].(string); nodesIsMasked(tok) {
		for _, n := range a.nodesLoad() {
			if nid, _ := n["id"].(string); nid == id && id != "" {
				in["token"] = n["token"]
				break
			}
		}
	}
	base, _ := in["base_url"].(string)
	if base == "" {
		respondErr(w, http.StatusBadRequest, "base_url 必填")
		return
	}
	client := &http.Client{Timeout: 10 * time.Second}
	var url string
	if idf, _ := in["identifier"].(string); idf != "" && strings.Contains(base, "ceye") {
		// ceye-api：探活页 http://api.ceye.io/ceye/{token}（与蓝本一致）
		tok, _ := in["token"].(string)
		url = fmt.Sprintf("%s/ceye/%s", strings.TrimSuffix(base, "/"), tok)
	} else {
		url = base
	}
	resp, err := client.Get(url)
	if err != nil {
		respondJSON(w, http.StatusOK, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 200))
	respondJSON(w, http.StatusOK, map[string]any{
		"ok":   resp.StatusCode == http.StatusOK,
		"info": fmt.Sprintf("HTTP %d: %s", resp.StatusCode, string(body)),
	})
}
