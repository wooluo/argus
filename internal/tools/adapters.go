package tools

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strings"
	"time"
)

// PropEnumArray 字符串数组字段 schema。
func PropEnumArray(desc string) map[string]any {
	return map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": desc}
}

// ensurePdTool 确保工具可执行；缺失时 go install（对应蓝本 kernels ensure 逻辑）。
// GOTOOLCHAIN 未钉 local 时 go 会自动下载所需工具链，新版 nuclei 可装。
func ensurePdTool(name, importPath string) (string, error) {
	if p := toolPath(name); toolAvailable(p) {
		return p, nil
	}
	out, err := runTool(context.Background(), 10*time.Minute, "", "go", "install", importPath+"@latest")
	if err != nil {
		return "", fmt.Errorf("go install %s 失败: %v\n%s（可手动安装后重试；GOTOOLCHAIN=local 时新版内核可能装不上）", importPath, err, Truncate(out, 300))
	}
	gp, _ := exec.Command("go", "env", "GOPATH").Output()
	bin := strings.TrimSpace(string(gp)) + "/bin/" + name
	if _, err := os.Stat(bin); err != nil {
		return "", fmt.Errorf("安装完成但未找到二进制: %s", bin)
	}
	return bin, nil
}

// ========== httpx（对应 adapters/httpx_tool.py：httpx_probe） ==========

type HttpxProbeTool struct{}

func (HttpxProbeTool) Name() string { return "httpx_probe" }
func (HttpxProbeTool) Description() string {
	return "HTTP 存活探测：输入域名或 URL 列表，返回存活站点（状态码/标题/Web服务器/技术栈），结果存入资产库。"
}
func (HttpxProbeTool) Parameters() map[string]any {
	return Schema(map[string]any{
		"targets": PropEnumArray("域名或 URL 列表（最多 200 个）"),
	}, "targets")
}

var cidrRe = regexp.MustCompile(`^\d{1,3}(?:\.\d{1,3}){3}/\d{1,2}$`)
var httpURLRe = regexp.MustCompile(`^https?://`)

func hostOf(t string) string {
	if u, err := url.Parse(t); err == nil && u.Hostname() != "" {
		return u.Hostname()
	}
	if !strings.Contains(t, "://") {
		if u2, err2 := url.Parse("http://" + t); err2 == nil && u2.Hostname() != "" {
			return u2.Hostname()
		}
	}
	return t
}

func (HttpxProbeTool) Execute(ctx context.Context, args map[string]any, tc *Context) (string, error) {
	targets := ArgStrings(args, "targets")
	var cleaned []string
	for _, t := range targets {
		t = strings.TrimSpace(t)
		if t == "" {
			continue
		}
		if cidrRe.MatchString(t) {
			return "", Errorf("「%s」是网段：请先用 host_discovery 发现存活主机，再探测单台", t)
		}
		cleaned = append(cleaned, t)
	}
	if len(cleaned) == 0 {
		return "", Errorf("targets 为空")
	}
	if len(cleaned) > 200 {
		cleaned = cleaned[:200]
	}
	for _, t := range cleaned {
		if err := tc.Scope.EnsureHost(hostOf(t)); err != nil {
			return "", err
		}
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	bin, err := ensurePdTool("httpx", "github.com/projectdiscovery/httpx/cmd/httpx@latest")
	if err != nil {
		return "", Errorf("%v", err)
	}
	if err := ensurePdHTTPX(bin); err != nil {
		return "", Errorf("%v", err)
	}
	out, err := runTool(ctx, toolTimeout, strings.Join(cleaned, "\n")+"\n",
		bin, "-json", "-silent", "-title", "-tech-detect", "-status-code",
		"-web-server", "-timeout", "15")
	var alive []map[string]any
	for _, j := range jsonLines(out) {
		u, _ := j["url"].(string)
		if u == "" {
			continue
		}
		var techs []string
		switch tv := j["tech"].(type) {
		case []any:
			for _, x := range tv {
				techs = append(techs, fmt.Sprintf("%v", x))
			}
		case string:
			for _, p := range strings.Split(tv, ",") {
				if p = strings.TrimSpace(p); p != "" {
					techs = append(techs, p)
				}
			}
		}
		m := map[string]any{
			"url": u, "status_code": j["status_code"], "title": j["title"],
			"webserver": j["webserver"], "tech": strings.Join(techs, ","),
			"content_length": j["content_length"],
		}
		alive = append(alive, m)
		tc.Reporter.SaveAsset(ctx, "url", u, m)
		for _, tech := range techs {
			tc.Reporter.SaveAsset(ctx, "tech", tech, map[string]any{"url": u})
		}
	}
	if err := toolFailed("httpx", out, err, len(alive) > 0); err != nil {
		return "", Errorf("%v", err)
	}
	res := map[string]any{
		"tool": "httpx", "input": len(cleaned), "alive": len(alive), "results": alive,
	}
	if note := InterruptedNote("httpx", out, err, len(alive) > 0); note != "" {
		res["note"] = note
	}
	return MustJSON(res), nil
}

// ========== katana（对应 adapters/katana_tool.py：katana_crawl） ==========

type KatanaCrawlTool struct{}

func (KatanaCrawlTool) Name() string { return "katana_crawl" }
func (KatanaCrawlTool) Description() string {
	return "URL 爬取。输入起始 URL，爬取站内链接与端点（可指定深度），结果存入资产库供漏洞扫描用。"
}
func (KatanaCrawlTool) Parameters() map[string]any {
	return Schema(map[string]any{
		"url":   Prop("string", "起始 URL，如 http://target.com"),
		"depth": Prop("integer", "爬取深度 1-3，默认 2"),
	}, "url")
}

func (KatanaCrawlTool) Execute(ctx context.Context, args map[string]any, tc *Context) (string, error) {
	u := strings.TrimSpace(ArgString(args, "url", ""))
	if !httpURLRe.MatchString(u) {
		return "", Errorf("URL 必须以 http(s):// 开头: %s", u)
	}
	depth := ArgInt(args, "depth", 2)
	if depth < 1 {
		depth = 1
	}
	if depth > 3 {
		depth = 3
	}
	if err := tc.Scope.EnsureURL(u); err != nil {
		return "", err
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	bin, err := ensurePdTool("katana", "github.com/projectdiscovery/katana/cmd/katana@latest")
	if err != nil {
		return "", Errorf("%v", err)
	}
	// 单请求 10s + 总 300s：内网目标响应快，避免长尾拖满 10 分钟
	out, err := runTool(ctx, 300*time.Second, "",
		bin, "-u", u, "-d", fmt.Sprintf("%d", depth), "-silent",
		"-timeout", "10", "-js-crawl", "-concurrency", "10", "-rate-limit", "150")
	var urls []string
	seen := map[string]bool{}
	for _, line := range strings.Split(out, "\n") {
		s := strings.TrimSpace(line)
		if strings.HasPrefix(s, "http") && !seen[s] {
			seen[s] = true
			urls = append(urls, s)
			tc.Reporter.SaveAsset(ctx, "url", s, map[string]any{"via": "katana"})
		}
	}
	if len(urls) > 500 {
		urls = urls[:500]
	}
	if err := toolFailed("katana", out, err, len(urls) > 0); err != nil {
		return "", Errorf("%v", err)
	}
	res := map[string]any{
		"tool": "katana", "start": u, "depth": depth, "found": len(urls), "urls": urls,
	}
	if note := InterruptedNote("katana", out, err, len(urls) > 0); note != "" {
		res["note"] = note
	}
	return MustJSON(res), nil
}

// ========== sqlmap（对应 adapters/sqlmap_tool.py：sqlmap_detect，仅检测不提取） ==========

type SqlmapDetectTool struct{}

func (SqlmapDetectTool) Name() string { return "sqlmap_detect" }
func (SqlmapDetectTool) Description() string {
	return "SQL 注入检测（仅检测、不提取数据）。输入带参数的 URL，布尔/时间盲注检测，确认即入漏洞库。"
}
func (SqlmapDetectTool) Parameters() map[string]any {
	return Schema(map[string]any{
		"url": Prop("string", "带参数的目标 URL，如 http://t.com/a?id=1"),
	}, "url")
}

// 硬编码检测模式参数；任何数据提取/OS 交互参数都不允许出现
var sqlmapDetectArgs = []string{"--batch", "--level=1", "--risk=1", "--timeout=10",
	"--retries=2", "--threads=3", "--technique=BT", "--flush-session"}

func (SqlmapDetectTool) Execute(ctx context.Context, args map[string]any, tc *Context) (string, error) {
	u := strings.TrimSpace(ArgString(args, "url", ""))
	if !regexp.MustCompile(`^https?://\S+\?\S+=`).MatchString(u) {
		return "", Errorf("URL 必须是带查询参数的 http(s) 链接，如 http://t.com/a?id=1")
	}
	if err := tc.Scope.EnsureURL(u); err != nil {
		return "", err
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if !toolAvailable(toolPath("sqlmap")) {
		return "", Errorf("sqlmap 未安装（需 apt/pip 安装），无法执行")
	}
	argv := append([]string{toolPath("sqlmap"), "-u", u}, sqlmapDetectArgs...)
	out, err := runTool(ctx, 900*time.Second, "", argv...)
	// sqlmap 的 banner 一定含自己的名字：有 banner 才说明它真跑起来了
	started := strings.Contains(out, "sqlmap")
	if err := toolFailed("sqlmap", out, err, started); err != nil {
		return "", Errorf("%v", err)
	}
	vulnerable := strings.Contains(out, "is vulnerable") || strings.Contains(out, "might be injectable")
	var params []string
	for _, m := range regexp.MustCompile(`Parameter: (\S+)`).FindAllStringSubmatch(out, -1) {
		params = append(params, m[1])
	}
	dbms := ""
	if m := regexp.MustCompile(`back-end DBMS: (.+)`).FindStringSubmatch(out); m != nil {
		dbms = strings.TrimSpace(m[1])
	}
	if vulnerable {
		detail := fmt.Sprintf("注入参数: %s；后端: %s", orUnknown(strings.Join(params, ", ")), orUnknown(dbms))
		_, _ = tc.Reporter.SaveFinding(ctx, Finding{
			Name: "SQL 注入", Severity: "critical", Target: u,
			Detail: detail, Evidence: Truncate(out, 3000),
			PoC:    fmt.Sprintf("sqlmap -u '%s' --batch（已确认可注入）", u),
			Source: "sqlmap",
		})
	}
	res := map[string]any{
		"tool": "sqlmap", "url": u, "vulnerable": vulnerable,
		"params": params, "dbms": dbms, "tail": Truncate(out, 800),
	}
	if note := InterruptedNote("sqlmap", out, err, started); note != "" {
		res["note"] = note
	}
	return MustJSON(res), nil
}

func orUnknown(s string) string {
	if s == "" {
		return "未知"
	}
	return s
}

// ========== subfinder（对应 adapters/subfinder.py：子域枚举+泛解析过滤+熵裁剪） ==========

type SubfinderTool struct{}

func (SubfinderTool) Name() string { return "subfinder" }
func (SubfinderTool) Description() string {
	return "子域名枚举。输入主域名，返回发现的子域名列表（经泛解析过滤与高价值裁剪）并存入资产库。"
}
func (SubfinderTool) Parameters() map[string]any {
	return Schema(map[string]any{
		"domain": Prop("string", "主域名，如 example.com"),
	}, "domain")
}

var domainRe = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?)+$`)

func (SubfinderTool) Execute(ctx context.Context, args map[string]any, tc *Context) (string, error) {
	domain := strings.ToLower(strings.TrimSpace(ArgString(args, "domain", "")))
	if net.ParseIP(domain) != nil {
		return "", Errorf("「%s」是 IP 地址，subfinder 仅用于域名子域枚举；IP 请用 httpx_probe/nmap_scan", domain)
	}
	if !domainRe.MatchString(domain) {
		return "", Errorf("非法域名: %s", domain)
	}
	if err := tc.Scope.EnsureHost(domain); err != nil {
		return "", err
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	bin, err := ensurePdTool("subfinder", "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest")
	if err != nil {
		return "", Errorf("%v", err)
	}
	out, err := runTool(ctx, toolTimeout, "", bin, "-d", domain, "-json", "-silent", "-timeout", "120")
	suffix := "." + domain
	var subdomains []string
	for _, j := range jsonLines(out) {
		host, _ := j["host"].(string)
		if host != "" && strings.HasSuffix(strings.ToLower(host), suffix) {
			subdomains = append(subdomains, host)
		}
	}
	// 泛解析检测与过滤（core/dns_utils.py 对应实现见 exec_util.go）
	real, wildCount, unresolved, wildcard := filterWildcard(domain, subdomains)
	for _, s := range real {
		tc.Reporter.SaveAsset(ctx, "domain", s, map[string]any{"root": domain})
	}
	// 信息熵裁剪：高价值关键词全保留 + 其余分层抽样（防 context 爆炸）
	var hv []string
	for _, s := range real {
		low := strings.ToLower(s)
		for _, k := range hvKeywords {
			if strings.Contains(low, k) {
				hv = append(hv, s)
				break
			}
		}
	}
	if len(hv) > 60 {
		hv = hv[:60]
	}
	others := difference(real, hv)
	if len(others) > 40 {
		step := len(others) / 40
		var sampled []string
		for i := 0; i < len(others); i += step {
			sampled = append(sampled, others[i])
		}
		others = sampled
	}
	ret := append(hv, others...)
	sort.Strings(ret)
	if err := toolFailed("subfinder", out, err, len(subdomains) > 0); err != nil {
		return "", Errorf("%v", err)
	}
	res := map[string]any{
		"tool": "subfinder", "domain": domain,
		"total": len(subdomains), "wildcard": wildcard, "wild_count": wildCount,
		"unresolved": unresolved, "returned": len(ret), "subdomains": ret,
	}
	if note := InterruptedNote("subfinder", out, err, len(subdomains) > 0); note != "" {
		res["note"] = note
	}
	return MustJSON(res), nil
}

var hvKeywords = []string{"admin", "api", "test", "dev", "uat", "staging", "stage", "internal",
	"oa", "vpn", "jenkins", "grafana", "git", "sso", "auth", "manage",
	"console", "portal", "backup", "config", "map", "erp", "crm"}

func difference(a, b []string) []string {
	bs := map[string]bool{}
	for _, x := range b {
		bs[x] = true
	}
	var out []string
	for _, x := range a {
		if !bs[x] {
			out = append(out, x)
		}
	}
	return out
}

// ========== nmap（对应 adapters/nmap_tool.py：nmap_scan） ==========

type NmapScanTool struct{}

func (NmapScanTool) Name() string { return "nmap_scan" }
func (NmapScanTool) Description() string {
	return "端口扫描。输入 IP 或域名，返回开放端口与服务识别（nmap -sV）。"
}
func (NmapScanTool) Parameters() map[string]any {
	return Schema(map[string]any{
		"target": Prop("string", "IP 或域名"),
	}, "target")
}

func (NmapScanTool) Execute(ctx context.Context, args map[string]any, tc *Context) (string, error) {
	target := strings.TrimSpace(ArgString(args, "target", ""))
	if target == "" {
		return "", Errorf("target 为空")
	}
	if cidrRe.MatchString(target) {
		return "", Errorf("「%s」是网段：请先 host_discovery 发现存活主机", target)
	}
	if err := tc.Scope.EnsureHost(target); err != nil {
		return "", err
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if !toolAvailable(toolPath("nmap")) {
		return "", Errorf("nmap 未安装（apt install nmap），无法执行")
	}
	out, err := runTool(ctx, toolTimeout, "",
		toolPath("nmap"), "-sV", "-T4", "--version-intensity", "5", "-Pn", target)
	// -sV 文本输出解析（保真原版行为）
	var ports []map[string]any
	portLine := regexp.MustCompile(`^(\d+)/(tcp|udp)\s+open\s+(\S+)\s*(.*)$`)
	for _, line := range strings.Split(out, "\n") {
		m := portLine.FindStringSubmatch(strings.TrimSpace(line))
		if m == nil {
			continue
		}
		ports = append(ports, map[string]any{
			"port": m[1], "proto": m[2], "service": m[3], "version": strings.TrimSpace(m[4]),
		})
	}
	for _, p := range ports {
		port, _ := p["port"].(string)
		proto, _ := p["proto"].(string)
		tc.Reporter.SaveAsset(ctx, "port", net.JoinHostPort(target, port),
			map[string]any{"proto": proto, "service": p["service"], "version": p["version"]})
	}
	if err := toolFailed("nmap", out, err, len(ports) > 0); err != nil {
		return "", Errorf("%v", err)
	}
	res := map[string]any{
		"tool": "nmap", "target": target, "ports": ports, "raw": Truncate(out, 2000),
	}
	if note := InterruptedNote("nmap", out, err, len(ports) > 0); note != "" {
		res["note"] = note
	}
	return MustJSON(res), nil
}

// ========== nuclei（对应 adapters/nuclei_tool.py：nuclei_scan 模板漏洞扫描） ==========

type NucleiScanTool struct{}

func (NucleiScanTool) Name() string { return "nuclei_scan" }
func (NucleiScanTool) Description() string {
	return "nuclei 漏洞扫描。输入 URL 列表，用官方模板库跑已知漏洞扫描（cves/misconfig/exposures 等目录可指定），命中即入漏洞库。"
}
func (NucleiScanTool) Parameters() map[string]any {
	return Schema(map[string]any{
		"targets":   PropEnumArray("URL 列表"),
		"templates": Prop("string", "nuclei 模板目录，如 cves/ 或 misconfig/，默认 -t 自动全模板"),
	}, "targets")
}

var nucleiSeverity = map[string]string{
	"critical": "critical", "high": "high", "medium": "medium", "low": "low", "info": "info",
}

func (NucleiScanTool) Execute(ctx context.Context, args map[string]any, tc *Context) (string, error) {
	targets := ArgStrings(args, "targets")
	var cleaned []string
	for _, t := range targets {
		if t = strings.TrimSpace(t); t != "" {
			cleaned = append(cleaned, t)
		}
	}
	if len(cleaned) == 0 {
		return "", Errorf("targets 为空")
	}
	if len(cleaned) > 50 {
		cleaned = cleaned[:50]
	}
	for _, t := range cleaned {
		if err := tc.Scope.EnsureURL(t); err != nil {
			return "", err
		}
	}
	tmpl := strings.TrimSpace(ArgString(args, "templates", ""))
	if err := ctx.Err(); err != nil {
		return "", err
	}
	bin, err := ensurePdTool("nuclei", "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest")
	if err != nil {
		return "", Errorf("%v", err)
	}
	if err := ensureNucleiTemplates(ctx, bin); err != nil {
		return "", Errorf("%v", err)
	}
	argv := []string{bin, "-jsonl", "-silent", "-timeout", "15",
		"-target-file", "-", "-concurrency", "25", "-bulk-size", "25", "-headless"}
	if tmpl != "" {
		argv = append(argv, "-t", tmpl)
	}
	out, err := runTool(ctx, toolTimeout, strings.Join(cleaned, "\n")+"\n", argv...)
	var findings []map[string]any
	for _, j := range jsonLines(out) {
		tid, _ := j["template-id"].(string)
		matched, _ := j["matched-at"].(string)
		if tid == "" || matched == "" {
			continue
		}
		sev, _ := j["info"].(map[string]any)
		severity := "info"
		if s, ok := sev["severity"].(string); ok {
			severity = nucleiSeverity[s]
			if severity == "" {
				severity = "info"
			}
		}
		name := tid
		if n, ok := sev["name"].(string); ok && n != "" {
			name = n
		}
		f := map[string]any{
			"template_id": tid, "name": name, "severity": severity,
			"matched_at": matched, "type": j["type"], "host": j["host"],
		}
		if d, ok := sev["description"].(string); ok {
			f["description"] = d
		}
		if curl, ok := j["curl-command"].(string); ok {
			f["curl"] = curl
		}
		findings = append(findings, f)
		_, _ = tc.Reporter.SaveFinding(ctx, Finding{
			Name: name, Severity: severity, Target: matched,
			Detail:   fmt.Sprintf("nuclei 模板 %s 命中（%s）", tid, orUnknown(fmt.Sprintf("%v", j["type"]))),
			PoC:      fmt.Sprintf("nuclei -t %s -u %s", orUnknown(tmpl), matched),
			Evidence: Truncate(MustJSON(j), 2000),
			Source:   "nuclei",
		})
	}
	if err := toolFailed("nuclei", out, err, len(findings) > 0); err != nil {
		return "", Errorf("%v", err)
	}
	res := map[string]any{
		"tool": "nuclei", "input": len(cleaned), "templates": tmpl,
		"findings": len(findings), "results": findings,
	}
	if note := InterruptedNote("nuclei", out, err, len(findings) > 0); note != "" {
		res["note"] = note
	}
	return MustJSON(res), nil
}

func init() {
	Register(HttpxProbeTool{})
	Register(KatanaCrawlTool{})
	Register(SqlmapDetectTool{})
	Register(SubfinderTool{})
	Register(NmapScanTool{})
	Register(NucleiScanTool{})
}
