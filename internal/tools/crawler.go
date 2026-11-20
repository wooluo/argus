package tools

import (
	"context"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
)

// ===== web_crawl（对应 builtin/crawler.py：BFS 同站爬取，复用登录会话） =====

var linkRe = regexp.MustCompile(`(?i)href=["']([^"'#]+)["']`)
var formActionRe = regexp.MustCompile(`(?is)<form[^>]*action=["']([^"']+)["'][^>]*>(.*?)</form>`)
var inputNameRe = regexp.MustCompile(`(?i)<input[^>]*name=["']([^"']+)["']`)

// CrawlerTool web_crawl：BFS 爬取同站链接与表单。
type CrawlerTool struct{}

func (CrawlerTool) Name() string { return "web_crawl" }
func (CrawlerTool) Description() string {
	return "站点爬虫（自研，**自动复用 web_login 的登录会话**——登录后调用可爬取认证后的功能页面与表单）。" +
		"BFS 爬取同站链接与表单（含带参数 URL），结果存入资产库。已登录站点优先用本工具而非 katana（katana 不带会话）。"
}
func (CrawlerTool) Parameters() map[string]any {
	return Schema(map[string]any{
		"url":       Prop("string", "起始 URL"),
		"max_pages": Prop("integer", "最多爬取页数 1-100，默认 30"),
	}, "url")
}
func (CrawlerTool) Execute(ctx context.Context, args map[string]any, tc *Context) (string, error) {
	rawURL := strings.TrimSpace(ArgString(args, "url", ""))
	if !strings.HasPrefix(rawURL, "http://") && !strings.HasPrefix(rawURL, "https://") {
		return "", Errorf("URL 必须以 http(s):// 开头: %s", rawURL)
	}
	if err := tc.Scope.EnsureURL(rawURL); err != nil {
		return "", err
	}
	loadSession(tc)
	maxPages := ArgInt(args, "max_pages", 30)
	if maxPages < 1 {
		maxPages = 1
	}
	if maxPages > 100 {
		maxPages = 100
	}
	originHost := ""
	if p, err := url.Parse(rawURL); err == nil {
		originHost = p.Hostname()
	}
	visited := map[string]bool{}
	foundURLs := map[string]bool{}
	var forms []map[string]any
	queue := []string{rawURL}

	for len(queue) > 0 && len(visited) < maxPages {
		batch := queue
		if len(batch) > 10 {
			batch = batch[:10]
			queue = queue[10:]
		} else {
			queue = nil
		}
		var mu sync.Mutex
		var wg sync.WaitGroup
		type page struct {
			u    string
			html string
		}
		var pages []page
		for _, pu := range batch {
			if visited[pu] {
				continue
			}
			wg.Add(1)
			go func(pageURL string) {
				defer wg.Done()
				status, body, err := fetchWithSession(ctx, tc, "GET", pageURL, nil, "", nil)
				if err != nil || status != 200 {
					return
				}
				mu.Lock()
				pages = append(pages, page{pageURL, Truncate(body, 100000)})
				mu.Unlock()
			}(pu)
		}
		wg.Wait()
		for _, pg := range pages {
			visited[pg.u] = true
			for _, link := range linkRe.FindAllStringSubmatch(pg.html, -1) {
				absu := resolveURL(pg.u, link[1])
				parsed, err := url.Parse(absu)
				if err != nil || parsed.Hostname() != originHost {
					continue
				}
				if parsed.Scheme != "http" && parsed.Scheme != "https" {
					continue
				}
				clean := strings.SplitN(absu, "#", 2)[0]
				if !foundURLs[clean] {
					foundURLs[clean] = true
					tc.Reporter.SaveAsset(ctx, "url", clean, map[string]any{"via": "crawl"})
					if len(queue) < 200 && parsed.RawQuery == "" &&
						(strings.HasSuffix(clean, "/") || strings.HasSuffix(clean, ".html") ||
							strings.HasSuffix(clean, ".htm") || strings.HasSuffix(clean, ".jsp") ||
							strings.HasSuffix(clean, ".php") || strings.HasSuffix(clean, ".asp") ||
							strings.HasSuffix(clean, ".aspx")) {
						queue = append(queue, clean)
					}
				}
			}
			for _, fm := range formActionRe.FindAllStringSubmatch(pg.html, -1) {
				actionURL := resolveURL(pg.u, fm[1])
				var fields []string
				for _, im := range inputNameRe.FindAllStringSubmatch(fm[2], -1) {
					if len(fields) >= 10 {
						break
					}
					fields = append(fields, im[1])
				}
				forms = append(forms, map[string]any{"action": actionURL, "fields": fields})
				tc.Reporter.SaveAsset(ctx, "url", actionURL, map[string]any{
					"type": "form", "fields": fields,
				})
			}
		}
	}
	var urlList []string
	for u := range foundURLs {
		urlList = append(urlList, u)
	}
	sort.Strings(urlList)
	if len(urlList) > 300 {
		urlList = urlList[:300]
	}
	if len(forms) > 50 {
		forms = forms[:50]
	}
	return MustJSON(map[string]any{
		"tool": "web_crawl", "start": rawURL, "pages": len(visited),
		"urls": len(foundURLs), "url_list": urlList, "forms": forms,
	}), nil
}

func init() { Register(CrawlerTool{}) }
