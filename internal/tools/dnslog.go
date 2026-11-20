package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// ===== dnslog 工具（对应 builtin/dnslog.py：dnslog_payload / dnslog_check） =====

type dnslogNode struct {
	Name       string `json:"name"`
	Type       string `json:"type"` // dnslog
	Provider   string `json:"provider"`
	Identifier string `json:"identifier"` // 泛解析域名
	BaseURL    string `json:"base_url"`
	Token      string `json:"token"`
	Enabled    bool   `json:"enabled"`
}

// firstDnslogNode 第一个启用的 dnslog 节点：server 下发 Extra 优先，回落本地 ~/.argus/nodes.json。
func firstDnslogNode(tc *Context) *dnslogNode {
	if tc.Extra != nil {
		if raw, ok := tc.Extra["dnslog_node"]; ok {
			if b, err := json.Marshal(raw); err == nil {
				var n dnslogNode
				if json.Unmarshal(b, &n) == nil && n.Type == "dnslog" && n.Enabled {
					return &n
				}
			}
		}
	}
	home, _ := os.UserHomeDir()
	b, err := os.ReadFile(filepath.Join(home, ".argus", "nodes.json"))
	if err != nil {
		return nil
	}
	var nodes []dnslogNode
	if json.Unmarshal(b, &nodes) != nil {
		return nil
	}
	for i := range nodes {
		if nodes[i].Type == "dnslog" && nodes[i].Enabled {
			return &nodes[i]
		}
	}
	return nil
}

// genSubdomain 随机子域名（对应 nodes.gen_subdomain）。
func genSubdomain(n int) string {
	const hex = "0123456789abcdef"
	b := make([]byte, n)
	for i := range b {
		b[i] = hex[rand.Intn(16)]
	}
	return string(b)
}

// ceyeRecords 查询 ceye 兼容 API 最近记录（对应 nodes.ceye_records）。
func ceyeRecords(baseURL, token string) ([]map[string]any, error) {
	u := strings.TrimRight(baseURL, "/") + "/v1/records?token=" + token
	cl := &http.Client{Timeout: 15 * time.Second}
	resp, err := cl.Get(u)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var data struct {
		Data []map[string]any `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, err
	}
	return data.Data, nil
}

// checkPayload 检查 payload 子域名是否带外命中（对应 nodes.check_payload）。
func checkPayload(node *dnslogNode, payload string) map[string]any {
	sub := strings.Split(payload, ".")[0]
	if node.Provider == "manual" {
		return map[string]any{"mode": "manual", "hit": nil,
			"note": "手动模式：请在对应 dnslog 面板人工查看记录"}
	}
	base := node.BaseURL
	if base == "" {
		base = "http://api.ceye.io"
	}
	records, err := ceyeRecords(base, node.Token)
	if err != nil {
		return map[string]any{"mode": "api", "hit": nil, "error": err.Error()}
	}
	var hits []map[string]any
	for _, r := range records {
		if strings.Contains(fmt.Sprint(r["name"]), sub) {
			hits = append(hits, r)
		}
	}
	out := map[string]any{"mode": "api", "hit": len(hits) > 0, "total": len(hits)}
	var dnsHits, httpHits []map[string]any
	for _, r := range hits {
		switch r["type"] {
		case "dns":
			dnsHits = append(dnsHits, map[string]any{"name": r["name"], "src": r["remote_addr"]})
		case "http":
			url := r["name"]
			if u, ok := r["url"]; ok {
				url = u
			}
			httpHits = append(httpHits, map[string]any{"name": r["name"], "src": r["remote_addr"], "url": url})
		}
	}
	out["dns"] = dnsHits
	out["http"] = httpHits
	return out
}

// DnslogPayloadTool dnslog_payload：生成带外检测子域名。
type DnslogPayloadTool struct{}

func (DnslogPayloadTool) Name() string { return "dnslog_payload" }
func (DnslogPayloadTool) Description() string {
	return "生成 DNSLog 带外检测 payload 子域名。把返回的域名拼入探测点（如 SSRF url 参数、" +
		"盲注语句的 load_file/con(http) 等），目标若发起解析/请求即证明漏洞存在。" +
		"生成后稍等数秒再用 dnslog_check 查询。"
}
func (DnslogPayloadTool) Parameters() map[string]any {
	return Schema(map[string]any{
		"count": Prop("integer", "生成数量 1-5，默认 1"),
		"label": Prop("string", "用途标记（如 ssrf-test），会编入子域名前缀，便于区分"),
	})
}
func (DnslogPayloadTool) Execute(ctx context.Context, args map[string]any, tc *Context) (string, error) {
	node := firstDnslogNode(tc)
	if node == nil {
		return "", Errorf("未配置可用的 DNSLog 节点，请到「节点管理」页配置")
	}
	if node.Identifier == "" {
		return "", Errorf("DNSLog 节点缺少域名（identifier）")
	}
	count := ArgInt(args, "count", 1)
	if count < 1 {
		count = 1
	}
	if count > 5 {
		count = 5
	}
	label := strings.ReplaceAll(strings.TrimSpace(ArgString(args, "label", "")), " ", "-")
	if label == "" {
		label = "t"
	}
	if len(label) > 12 {
		label = label[:12]
	}
	payloads := []string{}
	for i := 0; i < count; i++ {
		payloads = append(payloads, fmt.Sprintf("%s-%s.%s", label, genSubdomain(10), node.Identifier))
	}
	note := "等待 5-30 秒后用 dnslog_check 查询"
	if node.Provider == "manual" {
		note = "手动模式：命中记录请在节点面板人工查看"
	}
	return MustJSON(map[string]any{
		"tool": "dnslog_payload", "node": node.Name, "mode": node.Provider,
		"payloads": payloads, "note": note,
	}), nil
}

func init() { Register(DnslogPayloadTool{}) }

// DnslogCheckTool dnslog_check：查询 payload 命中。
type DnslogCheckTool struct{}

func (DnslogCheckTool) Name() string { return "dnslog_check" }
func (DnslogCheckTool) Description() string {
	return "查询 DNSLog payload 是否命中（目标发起过 DNS 解析或 HTTP 请求）。" +
		"输入 dnslog_payload 生成的完整域名。命中即证明带外回连（SSRF/盲注/RCE 等）。"
}
func (DnslogCheckTool) Parameters() map[string]any {
	return Schema(map[string]any{
		"payload": Prop("string", "dnslog_payload 生成的完整子域名"),
	}, "payload")
}
func (DnslogCheckTool) Execute(ctx context.Context, args map[string]any, tc *Context) (string, error) {
	node := firstDnslogNode(tc)
	if node == nil {
		return "", Errorf("未配置可用的 DNSLog 节点")
	}
	payload := strings.TrimSpace(ArgString(args, "payload", ""))
	if payload == "" {
		return "", Errorf("payload 为空")
	}
	result := checkPayload(node, payload)
	if hit, _ := result["hit"].(bool); hit {
		_, _ = tc.Reporter.SaveFinding(ctx, Finding{
			Name:     "带外回连确认（DNSLog）",
			Severity: "high",
			Target:   payload,
			Detail:   fmt.Sprintf("payload %s 命中 %v 条记录", payload, result["total"]),
			Evidence: MustJSON(result),
			PoC:      "payload: " + payload,
			Source:   "dnslog",
			Status:   "confirmed",
		})
	}
	out := map[string]any{"tool": "dnslog_check", "payload": payload}
	for k, v := range result {
		out[k] = v
	}
	return MustJSON(out), nil
}

func init() { Register(DnslogCheckTool{}) }
