package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// ===== github_search / github_fetch（对应 builtin/github_search.py） =====

// GithubSearchTool github_search：公开安全研究检索（repos/code）。
type GithubSearchTool struct{}

func (GithubSearchTool) Name() string { return "github_search" }
func (GithubSearchTool) Description() string {
	return "搜索 GitHub 公开安全研究（AI 自我迭代的检索环节）：按组件/版本/CVE 检索 POC 仓库与利用代码。" +
		"search_type=repos 搜仓库（无需登录）；code 搜代码内容（需配置 GitHub Token）。" +
		"返回仓库/文件清单与链接；找到目标后用 github_fetch 下载 POC 文件。"
}
func (GithubSearchTool) Parameters() map[string]any {
	return Schema(map[string]any{
		"query":       Prop("string", "检索词，如 'DVWA 1.10 exploit'、'Apache 2.4.10 CVE poc'"),
		"search_type": PropEnum("默认 repos；code 需已配置 GitHub Token", "repos", "code"),
		"limit":       Prop("integer", "结果数 1-10，默认 5"),
	}, "query")
}
func (GithubSearchTool) Execute(ctx context.Context, args map[string]any, tc *Context) (string, error) {
	query := cleanQuery(ArgString(args, "query", ""))
	if query == "" {
		return "", Errorf("query 为空")
	}
	limit := ArgInt(args, "limit", 5)
	if limit < 1 {
		limit = 1
	}
	if limit > 10 {
		limit = 10
	}
	stype := ArgString(args, "search_type", "repos")
	if stype != "repos" && stype != "code" {
		stype = "repos"
	}
	token := os.Getenv("GITHUB_TOKEN")
	if stype == "code" && token == "" {
		return "", Errorf("code 搜索需要 GitHub Token（环境变量 GITHUB_TOKEN）；repos 搜索无需登录")
	}
	path := "repositories"
	if stype == "code" {
		path = "code"
	}
	u := "https://api.github.com/search/" + path + "?q=" + url.QueryEscape(query) + fmt.Sprintf("&per_page=%d", limit)
	cl := &http.Client{Timeout: 20 * time.Second}
	req, _ := http.NewRequestWithContext(ctx, "GET", u, nil)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "Argus")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := cl.Do(req)
	if err != nil {
		return "", Errorf("GitHub 请求失败: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == 403 {
		return "", Errorf("GitHub 速率限制（未配置 Token 时 repos 搜索 10 次/分钟，稍后再试或配置 GITHUB_TOKEN）")
	}
	if resp.StatusCode != 200 {
		return "", Errorf("GitHub 搜索失败 HTTP %d", resp.StatusCode)
	}
	var data struct {
		Items []struct {
			FullName    string `json:"full_name"`
			Stars       int    `json:"stargazers_count"`
			Description string `json:"description"`
			HTMLURL     string `json:"html_url"`
			CloneURL    string `json:"clone_url"`
			Repository  struct {
				FullName string `json:"full_name"`
			} `json:"repository"`
			Path  string  `json:"path"`
			Score float64 `json:"score"`
		} `json:"items"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return "", Errorf("JSON 解析失败: %v", err)
	}
	results := []map[string]any{}
	for i, it := range data.Items {
		if i >= limit {
			break
		}
		if stype == "repos" {
			results = append(results, map[string]any{
				"repo": it.FullName, "stars": it.Stars,
				"desc": Truncate(it.Description, 150), "url": it.HTMLURL,
				"clone_hint": "git clone --depth 1 " + it.CloneURL,
			})
		} else {
			results = append(results, map[string]any{
				"repo": it.Repository.FullName, "path": it.Path,
				"raw_url": strings.ReplaceAll(it.HTMLURL, "/blob/", "/raw/"),
				"score":   it.Score,
			})
		}
	}
	return MustJSON(map[string]any{
		"tool": "github_search", "query": query, "type": stype,
		"count": len(results), "results": results,
		"note": "选中的仓库/文件用 github_fetch 下载后可 run_script 适配执行",
	}), nil
}

func init() { Register(GithubSearchTool{}) }

// GithubFetchTool github_fetch：下载 GitHub raw 文件到脚本目录。
type GithubFetchTool struct{}

func (GithubFetchTool) Name() string { return "github_fetch" }
func (GithubFetchTool) Description() string {
	return "下载 GitHub 公开文件（raw）到脚本目录，供 run_script 或直接执行。" +
		"输入 raw 文件 URL（github_search code 结果里的 raw_url，或仓库内文件页地址把 /blob/ 换成 /raw/）。" +
		"大仓库请勿整仓下载。下载的 POC 仍受安全红线约束：只做良性验证。"
}
func (GithubFetchTool) Parameters() map[string]any {
	return Schema(map[string]any{
		"raw_url":  Prop("string", "GitHub raw 文件地址"),
		"filename": Prop("string", "保存文件名（默认取 URL 尾段）"),
	}, "raw_url")
}
func (GithubFetchTool) Execute(ctx context.Context, args map[string]any, tc *Context) (string, error) {
	rawURL := strings.TrimSpace(ArgString(args, "raw_url", ""))
	if !strings.HasPrefix(rawURL, "https://raw.githubusercontent.com/") &&
		!strings.HasPrefix(rawURL, "https://github.com/") {
		return "", Errorf("仅支持 github.com / raw.githubusercontent.com 地址")
	}
	rawURL = strings.ReplaceAll(rawURL, "/blob/", "/raw/")
	fname := ArgString(args, "filename", "")
	if fname == "" {
		parts := strings.Split(strings.TrimRight(rawURL, "/"), "/")
		fname = "poc.py"
		if len(parts) > 0 && parts[len(parts)-1] != "" {
			fname = parts[len(parts)-1]
		}
	}
	fname = regexp.MustCompile(`[^a-zA-Z0-9._\-]`).ReplaceAllString(fname, "_")
	if len(fname) > 60 {
		fname = fname[:60]
	}
	dir := tc.Workdir
	if dir == "" {
		dir = "/tmp/argus/scripts"
	}
	_ = os.MkdirAll(dir, 0o755)
	cl := &http.Client{Timeout: 60 * time.Second}
	req, _ := http.NewRequestWithContext(ctx, "GET", rawURL, nil)
	req.Header.Set("User-Agent", "Argus")
	resp, err := cl.Do(req)
	if err != nil {
		return "", Errorf("下载失败: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", Errorf("下载失败 HTTP %d", resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return "", Errorf("下载失败: %v", err)
	}
	saved := filepath.Join(dir, fname)
	if err := os.WriteFile(saved, b, 0o644); err != nil {
		return "", err
	}
	head := Truncate(string(b), 300)
	return MustJSON(map[string]any{
		"tool": "github_fetch", "saved": saved, "size": len(b), "head": head,
		"note": "下载完成；先阅读代码理解逻辑，再用 run_script/bash 适配执行（良性验证）",
	}), nil
}

func init() { Register(GithubFetchTool{}) }
