package tools

// js_extract.go: JS 端点/路径/SourceMap/密钥提取（对应 llms.txt LinkFinder / gf 在 JS 上的应用）。
//
// 输入一条 JS URL 或 JS 文件内容，返回：端点 URL、疑似路径前缀、SourceMap 引用、
// 和疑似密钥/令牌（token/secret/API key）。katana 抓到的 JS 文件可以喂给这个工具。

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// 端点提取正则（覆盖完整 URL、根路径 URL）
var jsEndpointRe = regexp.MustCompile(`['"](https?://[^'"\s,)]{4,200})['"]`)
var concatURLRe = regexp.MustCompile(`['"]([^'"\s,)]{8,200})['"]`)

// SourceMap 引用（不含反引号）
var sourceMapRe = regexp.MustCompile(`(?i)//[#@]\s*sourceMappingURL\s*=\s*(\S+)`)
var sourceMapJSON = regexp.MustCompile(`(?i)sourceMappingURL["']?\s*[:=]\s*["'](\S+?)["'\s]`)

// 疑似密钥（JSON 风格：{"key": "value"} 或 key = "value"）
var secretRe = regexp.MustCompile(`(?i)["']((?:api[_-]?key|secret|token|password|passwd|auth|bearer|jwt|access[_-]key)["']\s*[:=]\s*["'])([^"'\s]{4,120})["']`)

// JS 变量赋值中的密钥（var/let/const name = "value"）
var jsAssignSecretRe = regexp.MustCompile(`(?i)(?:var|let|const)\s+(token|secret|apiKey|api_key|password|passwd|auth|bearer|jwt|accessKey|access_key)\s*=\s*["']([^"'\s]{6,120})["']`)

type JsExtractTool struct{}

func (JsExtractTool) Name() string { return "js_extract" }
func (JsExtractTool) Description() string {
	return "从 JavaScript 文件中提取端点 URL、路径、SourceMap 引用和疑似密钥。" +
		"输入 JS 文件的 URL 或文件内容，返回所有 HTTP 端点、路径前缀、SourceMap 引用位置和疑似密钥（token/secret/API key）。" +
		"适合在 katana 或 web_crawl 抓到 JS 后，把 JS 文件拿来提取隐藏的 API 端点。"
}
func (JsExtractTool) Parameters() map[string]any {
	return Schema(map[string]any{
		"source": Prop("string", "JS 文件 URL 或 JS 文件内容（至少包含 http/https 或 .js 扩展名，或 100 字符以上内容的视为内容）"),
	}, "source")
}

func (JsExtractTool) Execute(ctx context.Context, args map[string]any, tc *Context) (string, error) {
	source := strings.TrimSpace(ArgString(args, "source", ""))
	if source == "" {
		return "", Errorf("source 不能为空")
	}
	// 判断是 URL 还是内容
	isURL := strings.HasPrefix(strings.ToLower(source), "http")
	endpoints := map[string]bool{}
	secrets := []string{}
	var sourceMaps []string
	var content string

	if isURL {
		if err := tc.Scope.EnsureURL(source); err != nil {
			return "", err
		}
		status, body, _, _, err := tc.DoRequest(ctx, "GET", source, "", nil, false)
		if err != nil {
			return "", Errorf("获取 JS 失败: %v", err)
		}
		if status < 200 || status >= 400 {
			return "", Errorf("获取 JS 返回状态码 %d", status)
		}
		content = body
		// 以 js 文件名形式记录资产
		tc.Reporter.SaveAsset(ctx, "url", source, map[string]any{"type": "js", "source": "js_extract"})
	} else {
		content = source
	}

	if len(content) < 10 {
		return "", Errorf("JS 内容太短（%d 字节）", len(content))
	}

	// 1. 提取完整 HTTP 端点
	for _, m := range jsEndpointRe.FindAllStringSubmatch(content, -1) {
		if len(m) > 1 {
			u := strings.TrimSpace(m[1])
			if strings.HasPrefix(u, "http") || strings.HasPrefix(u, "//") {
				endpoints[u] = true
			}
		}
	}
	// 2. 提取拼接 URL（涵盖 path/filename 片段）
	for _, m := range concatURLRe.FindAllStringSubmatch(content, -1) {
		if len(m) > 1 {
			u := strings.TrimSpace(m[1])
			if !endpoints[u] && (strings.HasPrefix(u, "http") ||
				strings.HasPrefix(u, "//") ||
				strings.HasPrefix(u, "/")) {
				endpoints[u] = true
			}
		}
	}
	// 3. SourceMap 引用
	for _, m := range sourceMapRe.FindAllStringSubmatch(content, -1) {
		if len(m) > 1 {
			sourceMaps = append(sourceMaps, strings.TrimSpace(m[1]))
		}
	}
	for _, m := range sourceMapJSON.FindAllStringSubmatch(content, -1) {
		if len(m) > 1 {
			s := strings.TrimSpace(m[1])
			found := false
			for _, sm := range sourceMaps {
				if sm == s {
					found = true
					break
				}
			}
			if !found {
				sourceMaps = append(sourceMaps, s)
			}
		}
	}
	// 4. 疑似密钥
	for _, m := range secretRe.FindAllStringSubmatch(content, -1) {
		if len(m) >= 3 {
			secrets = append(secrets, fmt.Sprintf("%s = %s", strings.TrimSpace(m[1]), strings.TrimSpace(m[2])))
		}
	}
	for _, m := range jsAssignSecretRe.FindAllStringSubmatch(content, -1) {
		if len(m) >= 3 {
			secrets = append(secrets, fmt.Sprintf("%s = %s", strings.TrimSpace(m[1]), strings.TrimSpace(m[2])))
		}
	}

	// 排序输出
	var epList []string
	for e := range endpoints {
		epList = append(epList, e)
	}
	sort.Strings(epList)

	var out strings.Builder
	out.WriteString(fmt.Sprintf("JS 端点提取完成（%s）：\n", map[bool]string{true: "URL " + source, false: "原始内容"}[isURL]))
	out.WriteString(fmt.Sprintf("- 提取 HTTP 端点/路径: %d 个\n", len(epList)))
	if len(epList) > 50 {
		epList = epList[:50]
	}
	if len(epList) > 0 {
		out.WriteString("  已列出 " + fmt.Sprintf("%d", len(epList)) + " 条（共 " + fmt.Sprintf("%d", len(endpoints)) + " 条）：\n")
		for _, e := range epList {
			gf := gfClassify(e)
			tag := ""
			if len(gf) > 0 {
				tag = " [" + strings.Join(gf, " ") + "]"
			}
			tc.Reporter.SaveAsset(ctx, "url", e, map[string]any{"source": "js_extract", "tags": gf})
			u := e
			if len(u) > 90 {
				u = u[:90] + "..."
			}
			out.WriteString(fmt.Sprintf("  - %s%s\n", u, tag))
		}
	}
	if len(sourceMaps) > 0 {
		out.WriteString(fmt.Sprintf("- SourceMap: %d 个\n", len(sourceMaps)))
		for _, sm := range sourceMaps {
			out.WriteString(fmt.Sprintf("  - %s\n", sm))
		}
	}
	if len(secrets) > 0 {
		out.WriteString(fmt.Sprintf("\n⚠ 发现疑似密钥/凭据：%d 个\n", len(secrets)))
		for i, s := range secrets {
			if i >= 5 {
				out.WriteString(fmt.Sprintf("  ... 还有 %d 条\n", len(secrets)-i))
				break
			}
			out.WriteString(fmt.Sprintf("  - %s\n", s))
		}
	}
	return out.String(), nil
}

func init() { Register(JsExtractTool{}) }
