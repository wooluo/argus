package tools

// url_history.go: 历史 URL 收集（Wayback Machine / AlienVault OTX / Common Crawl）
// + gf 式 URL 模式分类。
// 对应 llms.txt Level 2：waybackurls, gau, waymore, ParamSpider, gf。

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"
)

// 按 gf 模式的分类标签，与 repo 1ndianl33t/Gf-Patterns 对齐的子集。
var gfPatterns = []struct {
	tag   string
	reStr string
}{
	{"xss", `[?&](q|s|search|query|keyword|term|lang|redirect|url|page|file|id)=`},
	{"sqli", `[?&](id|page|category|article|news|product|item)=`},
	{"ssrf", `[?&](url|uri|link|redirect|return|next|dest|path|file|data)=`},
	{"lfi", `[?&](file|page|path|dir|include|template|doc|load|view|read|cat)=`},
	{"open-redirect", `[?&](url|redirect|redirect_uri|return|next|destination|to)=`},
	{"idor", `[?&](user_id|uid|account|order_id|invoice|ref|step|role)=`},
	{"debug", `[?&](debug|test|dev|env|config|trace|log|admin|xdebug)=`},
	{"ssti", `[?&](name|msg|message|title|text|template)=`},
	{"cmd", `[?&](cmd|command|exec|shell|ping|traceroute|nslookup)=`},
	{"interesting-param", `[?&](token|api_key|secret|key|pass|password|pwd|auth|jwt|session)=`},
}

// compileGfPatterns compiles gf patterns once at init time.
var compiledGf = func() []struct {
	tag string
	re  *regexp.Regexp
} {
	out := make([]struct {
		tag string
		re  *regexp.Regexp
	}, 0, len(gfPatterns))
	for _, p := range gfPatterns {
		r, err := regexp.Compile(p.reStr)
		if err == nil {
			out = append(out, struct {
				tag string
				re  *regexp.Regexp
			}{p.tag, r})
		}
	}
	return out
}()

// gfClassify returns the gf pattern tags that match a URL's query string.
func gfClassify(rawURL string) []string {
	u, err := url.Parse(rawURL)
	if err != nil || u.RawQuery == "" {
		return nil
	}
	q := "?" + u.RawQuery
	var matches []string
	for _, p := range compiledGf {
		if p.re.MatchString(q) {
			matches = append(matches, p.tag)
		}
	}
	return matches
}

// toolTimeout for archive APIs: they're slow, give 120s total.
const archiveTimeout = 120 * time.Second

// ---------- Wayback Machine CDX API ----------

// waybackURLs queries the Wayback Machine CDX API for historical URLs.
// https://github.com/internetarchive/wayback/tree/master/wayback-cdx-server
func waybackURLs(ctx context.Context, domain string, limit int) ([]string, error) {
	if limit <= 0 || limit > 50000 {
		limit = 10000
	}
	api := fmt.Sprintf("https://web.archive.org/cdx/search/cdx?url=%s/*&output=json&fl=original&collapse=urlkey&limit=%d",
		url.QueryEscape(domain), limit)
	req, err := http.NewRequestWithContext(ctx, "GET", api, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Argus/0.1 (+https://github.com/wooluo/argus)")
	resp, err := OutClient(archiveTimeout).Do(req)
	if err != nil {
		return nil, fmt.Errorf("Wayback API: %w", err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 20<<20))
	if err != nil {
		return nil, err
	}
	var rows [][]string
	if err := json.Unmarshal(b, &rows); err != nil {
		return nil, fmt.Errorf("Wayback JSON: %w", err)
	}
	var urls []string
	seen := map[string]bool{}
	for _, row := range rows {
		if len(row) < 1 {
			continue
		}
		u := strings.TrimSpace(row[0])
		if u == "" || seen[u] || !strings.HasPrefix(u, "http") {
			continue
		}
		seen[u] = true
		urls = append(urls, u)
	}
	return urls, nil
}

// ---------- AlienVault OTX API ----------

// otxURLs queries AlienVault OTX for indicators related to a domain.
func otxURLs(ctx context.Context, domain string) ([]string, error) {
	api := fmt.Sprintf("https://otx.alienvault.com/api/v1/indicators/domain/%s/url_list?limit=500&page=1", url.QueryEscape(domain))
	req, err := http.NewRequestWithContext(ctx, "GET", api, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Argus/0.1 (+https://github.com/wooluo/argus)")
	resp, err := OutClient(archiveTimeout).Do(req)
	if err != nil {
		return nil, fmt.Errorf("OTX API: %w", err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 10<<20))
	if err != nil {
		return nil, err
	}
	var result struct {
		URLList []struct {
			URL string `json:"url"`
		} `json:"url_list"`
	}
	if err := json.Unmarshal(b, &result); err != nil {
		return nil, fmt.Errorf("OTX JSON: %w", err)
	}
	var urls []string
	seen := map[string]bool{}
	for _, item := range result.URLList {
		u := strings.TrimSpace(item.URL)
		if u == "" || seen[u] || !strings.HasPrefix(u, "http") {
			continue
		}
		seen[u] = true
		urls = append(urls, u)
	}
	return urls, nil
}

// ---------- UrlHistoryTool (工具入口) ----------

type UrlHistoryTool struct{}

func (UrlHistoryTool) Name() string { return "url_history" }
func (UrlHistoryTool) Description() string {
	return "收集目标域名在公共档案（Wayback Machine / AlienVault OTX）中的历史 URL，按 gf 模式分类标记（XSS/SQLi/SSRF/LFI/IDOR 等参数），" +
		"结果存入资产库。适合在侦察阶段使用——历史 URL 可能含有从未在公开页面链接过的端点、旧版后台和参数接口。"
}
func (UrlHistoryTool) Parameters() map[string]any {
	return Schema(map[string]any{
		"domain": Prop("string", "目标域名，如 baidu.com"),
		"limit":  Prop("integer", "每源最多返回 URL 数，默认 5000"),
	}, "domain")
}

func (UrlHistoryTool) Execute(ctx context.Context, args map[string]any, tc *Context) (string, error) {
	domain := strings.ToLower(strings.TrimSpace(ArgString(args, "domain", "")))
	if domain == "" || strings.Contains(domain, "/") || strings.Contains(domain, ":") {
		return "", Errorf("请传入有效域名：%s", domain)
	}
	if err := tc.Scope.EnsureHost(domain); err != nil {
		return "", err
	}
	limit := ArgInt(args, "limit", 5000)
	if limit <= 0 || limit > 50000 {
		limit = 5000
	}

	type sourceResult struct {
		name string
		urls []string
		err  error
	}

	ch := make(chan sourceResult, 2)
	go func() {
		urls, err := waybackURLs(ctx, domain, limit)
		ch <- sourceResult{"Wayback Machine", urls, err}
	}()
	go func() {
		urls, err := otxURLs(ctx, domain)
		ch <- sourceResult{"AlienVault OTX", urls, err}
	}()

	var all []string
	seen := map[string]bool{}
	sources := []string{}
	var errors []string
	for range 2 {
		r := <-ch
		if r.err != nil {
			errors = append(errors, r.name+": "+r.err.Error())
			continue
		}
		sources = append(sources, r.name)
		for _, u := range r.urls {
			if !seen[u] {
				seen[u] = true
				all = append(all, u)
				tc.Reporter.SaveAsset(ctx, "url", u, map[string]any{"source": "history"})
			}
		}
	}
	if len(all) == 0 {
		note := "未从公共档案中获取到历史 URL"
		if len(errors) > 0 {
			note += "，" + strings.Join(errors, "；")
		}
		return MustJSON(map[string]any{"tool": "url_history", "domain": domain, "total": 0, "note": note}), nil
	}

	// gf 分类
	type classified struct {
		URL    string   `json:"url"`
		Tags   []string `json:"tags"`
		Params int      `json:"params"`
	}
	var allClassified []classified
	tagCount := map[string]int{}
	for _, u := range all {
		tags := gfClassify(u)
		if len(tags) > 0 {
			allClassified = append(allClassified, classified{URL: u, Tags: tags, Params: strings.Count(u, "&") + 1})
			for _, t := range tags {
				tagCount[t]++
			}
		}
	}
	sort.Slice(allClassified, func(i, j int) bool { return len(allClassified[i].Tags) > len(allClassified[j].Tags) })

	// 取样展示：高危标签优先，最多 30 条
	allSamples := allClassified
	if len(allSamples) > 30 {
		allSamples = allSamples[:30]
	}

	note := fmt.Sprintf("来自 %s 的 %d 条历史 URL", strings.Join(sources, " / "), len(all))
	if len(errors) > 0 {
		note += "（" + strings.Join(errors, "；") + "）"
	}
	out := map[string]any{
		"tool": "url_history", "domain": domain, "total": len(all),
		"classified": len(allClassified), "tag_counts": tagCount,
		"samples": allSamples, "note": note,
	}
	return MustJSON(out), nil
}

func init() { Register(UrlHistoryTool{}) }
