package tools

// fofa.go: FOFA 空间测绘检索（移植自 AutoPentest builtin/fofa.py）。
// 被动情报（查测绘库，零目标请求），结果按授权范围分流标注并上报资产。
// 配置：ARGUS_FOFA_EMAIL / ARGUS_FOFA_KEY 环境变量（server 设置页可注入）。

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"
)

var fofaPortRe = regexp.MustCompile(`\D`)

// FofaTool fofa_search：FOFA 网络空间测绘检索。
type FofaTool struct{}

func (FofaTool) Name() string { return "fofa_search" }
func (FofaTool) Description() string {
	return "FOFA 网络空间测绘检索（被动情报，零目标请求）：按语法查询目标的公网暴露资产，" +
		"如 domain=\"xx.com\"、cert=\"xx.com\"、title=\"后台\"。" +
		"返回 host/ip/port/标题并自动入库资产，标注授权范围内外（范围外仅情报参考，禁止主动请求）。" +
		"侦察阶段优先用它摸清暴露面。需配置 ARGUS_FOFA_EMAIL/ARGUS_FOFA_KEY。"
}
func (FofaTool) Parameters() map[string]any {
	return Schema(map[string]any{
		"query": Prop("string", `FOFA 查询语法，如 domain="example.com" 或 cert="example.com"`),
		"size":  Prop("integer", "返回条数 1-100，默认 20"),
	}, "query")
}

func (FofaTool) Execute(ctx context.Context, args map[string]any, tc *Context) (string, error) {
	query := strings.TrimSpace(ArgString(args, "query", ""))
	if query == "" {
		return "", Errorf("query 为空")
	}
	size := ArgInt(args, "size", 20)
	if size < 1 {
		size = 1
	} else if size > 100 {
		size = 100
	}
	// 配置来源：server 经 Poll 下发（Extra["fofa_email"]/["fofa_key"]，设置页可配）
	// 优先于环境变量；掩码值（****）视为未配置回落 env。
	email := strings.TrimSpace(os.Getenv("ARGUS_FOFA_EMAIL"))
	key := strings.TrimSpace(os.Getenv("ARGUS_FOFA_KEY"))
	if tc != nil && tc.Extra != nil {
		if v, _ := tc.Extra["fofa_email"].(string); strings.TrimSpace(v) != "" && !strings.Contains(v, "*") {
			email = strings.TrimSpace(v)
		}
		if v, _ := tc.Extra["fofa_key"].(string); strings.TrimSpace(v) != "" && !strings.Contains(v, "*") {
			key = strings.TrimSpace(v)
		}
	}
	if email == "" || key == "" || strings.Trim(key, "*") == "" {
		return "", Errorf("FOFA 未配置：在设置页配置 FOFA Email/Key，或设置 ARGUS_FOFA_EMAIL 与 ARGUS_FOFA_KEY 环境变量")
	}

	qb := base64.StdEncoding.EncodeToString([]byte(query))
	u := fmt.Sprintf("https://fofa.info/api/v1/search/all?email=%s&key=%s&qbase64=%s&fields=host,ip,port,title&size=%d",
		url.QueryEscape(email), url.QueryEscape(key), url.QueryEscape(qb), size)

	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	client := &http.Client{Timeout: 30 * time.Second,
		Transport: ProxyTransport(OutProxyFor("https://fofa.info"))}
	resp, err := client.Do(req)
	if err != nil {
		return "", Errorf("FOFA 请求失败: %v", err)
	}
	defer resp.Body.Close()
	var data struct {
		Error   bool       `json:"error"`
		Errmsg  string     `json:"errmsg"`
		Size    int        `json:"size"`
		Results [][]string `json:"results"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return "", Errorf("FOFA 响应解析失败: %v", err)
	}
	if data.Error {
		return "", Errorf("FOFA API 错误: %s", data.Errmsg)
	}

	type entry struct {
		Host    string `json:"host"`
		IP      string `json:"ip"`
		Port    string `json:"port"`
		Title   string `json:"title"`
		InScope bool   `json:"in_scope"`
	}
	var inScope, intel []entry
	for _, item := range data.Results {
		var host, ip, port, title string
		for i, v := range item {
			switch i {
			case 0:
				host = v
			case 1:
				ip = v
			case 2:
				port = v
			case 3:
				title = v
			}
		}
		port = fofaPortRe.ReplaceAllString(port, "")
		if len(title) > 80 {
			title = title[:80]
		}
		ok := tc.Scope.CheckHost(host) || (ip != "" && tc.Scope.CheckHost(ip))
		e := entry{host, ip, port, title, ok}
		if ok {
			inScope = append(inScope, e)
		} else {
			intel = append(intel, e)
		}
		// 资产回流（测绘情报全量入库）
		if host != "" {
			tc.Reporter.SaveAsset(ctx, "domain", host, map[string]any{
				"title": title, "via": "fofa", "in_scope": ok})
		} else if ip != "" {
			tc.Reporter.SaveAsset(ctx, "ip", ip, map[string]any{
				"port": port, "title": title, "in_scope": ok})
		}
	}

	var b strings.Builder
	fmt.Fprintf(&b, "FOFA %q：命中 %d，返回 %d（范围内 %d / 情报 %d）\n",
		query, data.Size, len(data.Results), len(inScope), len(intel))
	list := append(append([]entry(nil), inScope...), intel...)
	sort.SliceStable(list, func(i, j int) bool { return list[i].InScope && !list[j].InScope })
	for _, e := range list {
		tag := "情报"
		if e.InScope {
			tag = "范围内"
		}
		fmt.Fprintf(&b, "  [%s] %s:%s | %s\n", tag, e.Host, e.Port, e.Title)
	}
	if len(list) == 0 {
		b.WriteString("无结果，尝试调整查询语法。\n")
	} else {
		b.WriteString("说明：范围内条目可直接测试；范围外仅作测绘情报，禁止主动请求。\n")
	}
	return b.String(), nil
}

func init() { Register(FofaTool{}) }
