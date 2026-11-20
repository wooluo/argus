package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"
)

// ===== osint_lookup（对应 builtin/osint.py：whois / crt.sh 证书透明） =====

var osintDomainRe = regexp.MustCompile(
	`^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?)+$`)

// OsintTool osint_lookup：被动情报查询（whois / ct_logs）。
type OsintTool struct{}

func (OsintTool) Name() string { return "osint_lookup" }
func (OsintTool) Description() string {
	return "开源情报（OSINT，被动查询第三方数据源，不直接触碰目标）：\n" +
		"- whois：域名注册人/机构/NS/到期时间（资产归属与关联线索）\n" +
		"- ct_logs：crt.sh 证书透明日志子域名枚举（历史签发证书里的子域，比主动枚举更全）\n" +
		"输入必须是授权范围内的域名。"
}
func (OsintTool) Parameters() map[string]any {
	return Schema(map[string]any{
		"query_type": PropEnum("查询类型", "whois", "ct_logs"),
		"domain":     Prop("string", "主域名（须在授权范围内）"),
	}, "query_type", "domain")
}
func (OsintTool) Execute(ctx context.Context, args map[string]any, tc *Context) (string, error) {
	qtype := ArgString(args, "query_type", "")
	domain := strings.ToLower(strings.TrimSpace(ArgString(args, "domain", "")))
	if !osintDomainRe.MatchString(domain) {
		return "", Errorf("非法域名: %s", domain)
	}
	if err := tc.Scope.EnsureHost(domain); err != nil {
		return "", err
	}
	switch qtype {
	case "whois":
		out, err := runTool(ctx, 30*time.Second, "", "/bin/sh", "-c",
			"whois "+domain+" 2>&1 | head -60")
		if err != nil && out == "" {
			return "", Errorf("whois 执行失败（本机需安装 whois）: %v", err)
		}
		var keep []string
		for _, l := range strings.Split(out, "\n") {
			low := strings.ToLower(l)
			for _, k := range []string{"registrant", "org", "name server", "nserver",
				"created", "expiry", "updated", "status", "email"} {
				if strings.Contains(low, k) {
					keep = append(keep, l)
					break
				}
			}
		}
		if len(keep) > 25 {
			keep = keep[:25]
		}
		return MustJSON(map[string]any{
			"tool": "osint_lookup", "type": "whois", "domain": domain,
			"summary": strings.Join(keep, "\n"), "raw_length": len(out),
		}), nil
	case "ct_logs":
		u := "https://crt.sh/?q=%." + domain + "&output=json"
		cl := &http.Client{Timeout: 40 * time.Second}
		req, _ := http.NewRequestWithContext(ctx, "GET", u, nil)
		req.Header.Set("User-Agent", "Mozilla/5.0")
		resp, err := cl.Do(req)
		if err != nil {
			return MustJSON(map[string]any{"tool": "osint_lookup", "type": "ct_logs",
				"domain": domain, "error": fmt.Sprint(err)}), nil
		}
		defer resp.Body.Close()
		if resp.StatusCode == 429 {
			return MustJSON(map[string]any{"tool": "osint_lookup", "type": "ct_logs",
				"domain": domain,
				"error":  "crt.sh 限流（HTTP 429）——请改用 subfinder 枚举子域名，或数分钟后重试"}), nil
		}
		if resp.StatusCode != 200 {
			return MustJSON(map[string]any{"tool": "osint_lookup", "type": "ct_logs",
				"domain": domain, "error": fmt.Sprintf("crt.sh HTTP %d", resp.StatusCode)}), nil
		}
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
		var items []struct {
			NameValue string `json:"name_value"`
		}
		if err := json.Unmarshal(b, &items); err != nil {
			return "", Errorf("crt.sh JSON 解析失败: %v", err)
		}
		subs := map[string]bool{}
		for _, it := range items {
			for _, name := range strings.Split(it.NameValue, "\n") {
				name = strings.ToLower(strings.TrimPrefix(strings.TrimSpace(name), "*."))
				if strings.HasSuffix(name, "."+domain) && name != domain {
					subs[name] = true
				}
			}
		}
		subList := make([]string, 0, len(subs))
		for s := range subs {
			subList = append(subList, s)
		}
		sort.Strings(subList)
		// 泛解析过滤
		real, wildCount, _, isWild := filterWildcard(domain, subList)
		keepSet := map[string]bool{}
		for _, s := range subList {
			keepSet[s] = true
		}
		if isWild {
			keepSet = map[string]bool{}
			for _, s := range real {
				keepSet[s] = true
			}
		}
		for _, sub := range subList {
			if keepSet[sub] {
				tc.Reporter.SaveAsset(ctx, "domain", sub, map[string]any{"via": "crt.sh"})
			}
		}
		// 信息熵裁剪：高价值关键词优先 + 分层抽样
		hvKeys := []string{"admin", "api", "test", "dev", "uat", "staging", "stage",
			"internal", "oa", "vpn", "jenkins", "grafana", "git", "sso", "auth",
			"manage", "console", "portal", "backup", "config", "mail", "erp", "crm"}
		all := subList
		if isWild {
			all = real
		}
		var hv, rest []string
		hvSet := map[string]bool{}
		for _, s := range all {
			isHv := false
			for _, k := range hvKeys {
				if strings.Contains(s, k) {
					isHv = true
					break
				}
			}
			if isHv {
				hv = append(hv, s)
				hvSet[s] = true
			}
		}
		for _, s := range all {
			if !hvSet[s] {
				rest = append(rest, s)
			}
		}
		if len(hv) > 30 {
			hv = hv[:30]
		}
		step := len(rest) / 30
		if step < 1 {
			step = 1
		}
		for i := 0; i < len(rest) && len(hv) < 60; i += step {
			hv = append(hv, rest[i])
		}
		out := map[string]any{
			"tool": "osint_lookup", "type": "ct_logs", "domain": domain,
			"found": len(keepSet), "high_value": len(hv), "subdomains": hv,
			"note": fmt.Sprintf("共 %d 个证书透明子域名已全部入库资产表；以上为高价值+分层抽样。", len(subList)),
		}
		if isWild {
			out["wildcard"] = true
			out["wild_count"] = wildCount
		}
		return MustJSON(out), nil
	default:
		return "", Errorf("query_type 必须是 whois 或 ct_logs")
	}
}

func init() { Register(OsintTool{}) }
