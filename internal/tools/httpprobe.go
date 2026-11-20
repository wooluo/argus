package tools

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
)

// ===== http_alive（对应 builtin/http_probe.py：自研 HTTP 存活探测） =====

var techHints = [][2]string{
	{"nginx", "Nginx"}, {"apache", "Apache"}, {"tomcat", "Tomcat"},
	{"iis", "IIS"}, {"jetty", "Jetty"}, {"litespeed", "LiteSpeed"},
}
var titleRe = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)
var probeCidrRe = regexp.MustCompile(`^\d{1,3}(?:\.\d{1,3}){3}/\d{1,2}$`)

// HttpProbeTool http_alive：域名/URL 列表存活探测。
type HttpProbeTool struct{}

func (HttpProbeTool) Name() string { return "http_alive" }
func (HttpProbeTool) Description() string {
	return "HTTP 存活探测（自研）。输入域名/URL 列表，返回状态码/标题/Web服务器等基础信息，存活者存入资产库。"
}
func (HttpProbeTool) Parameters() map[string]any {
	return Schema(map[string]any{
		"targets": map[string]any{
			"type": "array", "items": map[string]any{"type": "string"},
			"description": "域名或 URL 列表（最多 200 个）",
		},
	}, "targets")
}
func (HttpProbeTool) Execute(ctx context.Context, args map[string]any, tc *Context) (string, error) {
	targets := ArgStrings(args, "targets")
	var cleaned []string
	for _, t := range targets {
		t = strings.TrimSpace(t)
		if t == "" {
			continue
		}
		if probeCidrRe.MatchString(t) {
			return "", Errorf("「%s」是网段：请先用 host_discovery 发现存活主机，再对单个 IP 做存活探测", t)
		}
		cleaned = append(cleaned, t)
	}
	if len(cleaned) > 200 {
		cleaned = cleaned[:200]
	}
	if len(cleaned) == 0 {
		return "", Errorf("targets 为空")
	}
	for _, t := range cleaned {
		u := t
		if !strings.Contains(u, "://") {
			u = "http://" + u
		}
		h := t
		if parsed, err := url.Parse(u); err == nil && parsed.Hostname() != "" {
			h = parsed.Hostname()
		}
		if err := tc.Scope.EnsureHost(h); err != nil {
			return "", err
		}
	}
	var mu sync.Mutex
	var alive []map[string]any
	var wg sync.WaitGroup
	sem := make(chan struct{}, 64)
	cl := &http.Client{
		Timeout:   12 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
	for _, t := range cleaned {
		wg.Add(1)
		go func(target string) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				return
			}
			defer func() { <-sem }()
			u := target
			if !strings.HasPrefix(u, "http") {
				u = "http://" + u
			}
			req, err := http.NewRequestWithContext(ctx, "GET", u, nil)
			if err != nil {
				return
			}
			req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; Argus/0.1)")
			resp, err := cl.Do(req)
			if err != nil {
				return
			}
			defer resp.Body.Close()
			b, _ := io.ReadAll(io.LimitReader(resp.Body, 20000))
			text := string(b)
			title := ""
			if m := titleRe.FindStringSubmatch(text); m != nil {
				title = strings.TrimSpace(m[1])
				if len(title) > 120 {
					title = title[:120]
				}
			}
			server := resp.Header.Get("Server")
			head := strings.ToLower(server + " " + text[:min(4000, len(text))])
			var techs []string
			for _, h := range techHints {
				if strings.Contains(head, h[0]) {
					techs = append(techs, h[1])
				}
			}
			item := map[string]any{
				"url": resp.Request.URL.String(), "status_code": resp.StatusCode,
				"title": title, "webserver": server, "tech": strings.Join(techs, ","),
			}
			mu.Lock()
			alive = append(alive, item)
			mu.Unlock()
			tc.Reporter.SaveAsset(ctx, "url", fmt.Sprint(item["url"]), item)
			host := ""
			if parsed, err := url.Parse(u); err == nil {
				host = parsed.Hostname()
			}
			for _, t2 := range techs {
				tc.Reporter.SaveAsset(ctx, "tech", t2, map[string]any{"url": u})
			}
			if host != "" {
				tc.Reporter.SaveAsset(ctx, "domain", host, map[string]any{
					"title": title, "status_code": resp.StatusCode, "webserver": server,
				})
			}
			if server != "" && len(server) <= 60 {
				tc.Reporter.SaveAsset(ctx, "tech", server, map[string]any{"host": host})
			}
		}(t)
	}
	wg.Wait()
	// 相同结果折叠
	seen := map[string]int{}
	dedup := []map[string]any{}
	for _, r := range alive {
		key := fmt.Sprint(r["url"], "|", r["title"])
		if _, ok := seen[key]; ok {
			seen[key]++
			continue
		}
		seen[key] = 0
		dedup = append(dedup, r)
	}
	dupN := 0
	for _, v := range seen {
		dupN += v
	}
	out := map[string]any{
		"tool": "http_alive", "input": len(cleaned), "alive": len(alive),
		"duplicates_collapsed": dupN, "results": dedup,
	}
	if dupN > 0 {
		out["note"] = fmt.Sprintf("已折叠 %d 条完全相同的重复结果（多为目标统一跳转到同一错误页，无独立测试价值）。", dupN)
	}
	return MustJSON(out), nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func init() { Register(HttpProbeTool{}) }
