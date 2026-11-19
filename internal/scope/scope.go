// Package scope 移植自 AutoPentest core/scope.py —— ScopeGuard 范围护栏。
// 所有对目标发起的请求必须先过这里；越界即 Violation。
//
// 规则格式（与 Project.scope 一致）：
//
//	[{"type":"domain","value":"example.com"},   // 含所有子域名
//	 {"type":"ip","value":"10.0.0.5"},
//	 {"type":"cidr","value":"192.168.1.0/24"}]
package scope

import (
	"fmt"
	"net/netip"
	"net/url"
	"strings"
)

// Rule 单条授权范围规则。
type Rule struct {
	Type  string `json:"type"`  // domain | ip | cidr
	Value string `json:"value"` // 域名 / IP / CIDR
}

// Violation 范围违规错误。
type Violation struct {
	Target string
	Reason string
}

func (v *Violation) Error() string {
	if v.Reason != "" {
		return fmt.Sprintf("目标 %s 不在授权范围内 · %s", v.Target, v.Reason)
	}
	return fmt.Sprintf("目标 %s 不在授权范围内", v.Target)
}

// Guard 授权范围护栏。New 时预解析规则，Check* O(1)/O(n) 判定。
type Guard struct {
	ProjectID int64
	Rules     []Rule

	allow   map[string]struct{} // 证明/回调白名单（允许访问但不属于测试范围）
	domains map[string]struct{} // 精确域名（子域名自动包含）
	ips     map[string]struct{} // 精确 IP（字符串规范化后）
	nets    []netip.Prefix      // CIDR 网段
}

// New 构建护栏。容错逻辑与原版一致：
// IP 误加成 domain 按 IP 匹配；cidr 填纯 IP 按单 IP。
func New(projectID int64, rules []Rule, allowHosts []string) *Guard {
	g := &Guard{
		ProjectID: projectID,
		Rules:     rules,
		allow:     map[string]struct{}{},
		domains:   map[string]struct{}{},
		ips:       map[string]struct{}{},
	}
	for _, h := range allowHosts {
		h = strings.ToLower(strings.Trim(strings.TrimSpace(h), "."))
		if h != "" {
			g.allow[h] = struct{}{}
		}
	}
	for _, r := range rules {
		v := strings.TrimSpace(r.Value)
		switch r.Type {
		case "domain":
			if addr, err := netip.ParseAddr(v); err == nil {
				g.ips[addr.String()] = struct{}{} // 容错：IP 误标域名
				continue
			}
			g.domains[strings.ToLower(strings.Trim(v, "."))] = struct{}{}
		case "ip":
			if addr, err := netip.ParseAddr(v); err == nil {
				g.ips[addr.String()] = struct{}{}
			}
		case "cidr":
			if p, err := netip.ParsePrefix(v); err == nil {
				g.nets = append(g.nets, p.Masked())
			} else if addr, err := netip.ParseAddr(v); err == nil {
				g.ips[addr.String()] = struct{}{} // 容错：cidr 填纯 IP
			}
		}
	}
	return g
}

// CheckHost 判定 host（域名或 IP 字面量）是否在授权范围内。
func (g *Guard) CheckHost(host string) bool {
	host = strings.ToLower(strings.Trim(strings.TrimSpace(host), "."))
	if host == "" {
		return false
	}
	// IPv4/IPv6 字面量
	if addr, err := netip.ParseAddr(host); err == nil {
		key := addr.String()
		if _, ok := g.ips[key]; ok {
			return true
		}
		for _, n := range g.nets {
			if n.Contains(addr) {
				return true
			}
		}
		return false
	}
	// 证明/回调白名单（精确或其子域名）
	if _, ok := g.allow[host]; ok {
		return true
	}
	for a := range g.allow {
		if strings.HasSuffix(host, "."+a) {
			return true
		}
	}
	// 域名：精确匹配或为范围内域名的子域名
	if _, ok := g.domains[host]; ok {
		return true
	}
	for d := range g.domains {
		if strings.HasSuffix(host, "."+d) {
			return true
		}
	}
	return false
}

// CheckURL 判定 URL（自动补 scheme）的 host 是否在范围内。
func (g *Guard) CheckURL(rawURL string) bool {
	u := rawURL
	if !strings.Contains(u, "://") {
		u = "http://" + u
	}
	parsed, err := url.Parse(u)
	if err != nil {
		return false
	}
	return g.CheckHost(parsed.Hostname())
}

// EnsureHost host 不在范围内时返回 *Violation。
func (g *Guard) EnsureHost(host string) error {
	if !g.CheckHost(host) {
		return &Violation{Target: host}
	}
	return nil
}

// EnsureURL URL 不在范围内时返回 *Violation。
func (g *Guard) EnsureURL(rawURL string) error {
	if !g.CheckURL(rawURL) {
		return &Violation{Target: rawURL}
	}
	return nil
}

// Describe 人类可读的范围摘要（domain 加 /* 后缀，与原版一致）。
func (g *Guard) Describe() string {
	var parts []string
	for _, r := range g.Rules {
		isDomain := r.Type == "domain"
		if isDomain {
			if _, err := netip.ParseAddr(r.Value); err == nil {
				isDomain = false // IP 误标为域名时按 IP 展示
			}
		}
		v := r.Value
		if isDomain {
			v += "/*"
		}
		parts = append(parts, v)
	}
	if len(parts) == 0 {
		return "(空)"
	}
	return strings.Join(parts, ", ")
}
