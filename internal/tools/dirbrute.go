package tools

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// ===== dir_brute（对应 builtin/dir_brute.py：字典并发探测） =====

var interestingStatuses = map[int]bool{200: true, 204: true, 301: true, 302: true, 401: true, 403: true}

// DirBruteTool dir_brute：目录与敏感文件探测。
type DirBruteTool struct{}

func (DirBruteTool) Name() string { return "dir_brute" }
func (DirBruteTool) Description() string {
	return "目录与敏感文件探测（自研）。对目标 URL 按内置字典并发探测，返回状态码非 404 的路径" +
		"（后台/备份/配置泄露等），存入资产库。"
}
func (DirBruteTool) Parameters() map[string]any {
	return Schema(map[string]any{
		"url":           Prop("string", "目标站点根 URL，如 http://target.com"),
		"wordlist_size": PropEnum("small=前50条快速探测，full=完整字典，默认 small", "small", "full"),
	}, "url")
}
func (DirBruteTool) Execute(ctx context.Context, args map[string]any, tc *Context) (string, error) {
	base := strings.TrimRight(strings.TrimSpace(ArgString(args, "url", "")), "/")
	if !strings.HasPrefix(base, "http://") && !strings.HasPrefix(base, "https://") {
		return "", Errorf("URL 必须以 http(s):// 开头: %s", base)
	}
	if err := tc.Scope.EnsureURL(base); err != nil {
		return "", err
	}
	words := builtinWordlist()
	if ArgString(args, "wordlist_size", "small") != "full" {
		if len(words) > 50 {
			words = words[:50]
		}
	}
	cl := &http.Client{
		Timeout:   10 * time.Second,
		Transport: ProxyTransport(TargetProxy()), // 测试流量代理（WAF 规避，显式即全量）
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // 不跟随
		},
	}
	pacer := NewPacer() // AIMD：拦截响应自动退避
	var mu sync.Mutex
	type hit struct {
		URL    string `json:"url"`
		Status int    `json:"status"`
		Length int    `json:"length"`
	}
	var hits []hit
	var wg sync.WaitGroup
	sem := make(chan struct{}, 64)
	for _, w := range words {
		wg.Add(1)
		go func(word string) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				return
			}
			defer func() { <-sem }()
			target := base + "/" + strings.TrimLeft(word, "/")
			req, err := http.NewRequestWithContext(ctx, "GET", target, nil)
			if err != nil {
				return
			}
			req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; Argus/0.1)")
			pacer.Wait()
			resp, err := cl.Do(req)
			if err != nil {
				return
			}
			pacer.Feedback(resp.StatusCode)
			b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
			_ = resp.Body.Close()
			if interestingStatuses[resp.StatusCode] {
				length := len(b)
				mu.Lock()
				hits = append(hits, hit{target, resp.StatusCode, length})
				mu.Unlock()
				tc.Reporter.SaveAsset(ctx, "url", target, map[string]any{
					"status": resp.StatusCode, "length": length, "type": "dir-brute",
				})
			}
		}(w)
	}
	wg.Wait()
	// 排序：200 优先，再按长度降序
	for i := 0; i < len(hits); i++ {
		for j := i + 1; j < len(hits); j++ {
			a, b := hits[i], hits[j]
			if (a.Status != 200 && b.Status == 200) || (a.Status == b.Status && a.Length < b.Length) {
				hits[i], hits[j] = hits[j], hits[i]
			}
		}
	}
	if len(hits) > 100 {
		hits = hits[:100]
	}
	out := map[string]any{
		"tool": "dir_brute", "base": base, "probed": len(words),
		"hits": len(hits), "results": hits,
	}
	// 通配响应识别
	if len(hits) >= 10 {
		cnt := map[int]int{}
		for _, h := range hits {
			cnt[h.Length]++
		}
		commonLen, commonN := 0, 0
		for l, c := range cnt {
			if c > commonN {
				commonLen, commonN = l, c
			}
		}
		if float64(commonN)/float64(len(hits)) >= 0.8 {
			out["wildcard_warning"] = fmt.Sprintf(
				"⚠ %d/%d 个命中响应长度完全一致（%dB）——疑似通配响应（网关对任意路径返回统一页面），"+
					"这些大概率是伪命中。请先用 http_fetch 抽查 1-2 条确认，再决定是否值得深入。",
				commonN, len(hits), commonLen)
		}
	}
	return MustJSON(out), nil
}

// builtinWordlist 内置目录字典（对应 ensure_wordlist 的内置集）。
func builtinWordlist() []string {
	w := `robots.txt .env .git .svn .htaccess README.md readme.txt
admin login index.bak backup www.zip site.tar.gz db.sql dump.sql
api swagger swagger.json api-docs phpinfo.php info.php test
console manage manager admin
config configuration.ini config.php.bak wp-config.php.bak
uploads upload static assets js css images img
docs doc changelog CHANGELOG.md LICENSE
actuator metrics health status
graphql graphiql
shell.php cmd.php
administrator phpmyadmin pma mysql
data temp tmp cache logs log debug
old dev test1 uat
server-status server-info .DS_Store
WEB-INF web.config crossdomain.xml
sso cas oauth token jwt
export backup.zip backup.tar backup7z
`
	return strings.Fields(w)
}

func init() { Register(DirBruteTool{}) }
