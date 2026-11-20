package tools

import (
	"context"
	"crypto/md5"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// ===== web_login / http_fetch（对应 builtin/auth_session.py） =====
//
// 会话：tc.Session（Cookie 桶+基址），持久化到 ~/.argus/sessions/<project_id>.json。
// 流量录制：Reporter.SaveEvidence（对应 record_traffic 落 TrafficLog）。

var loginFailHints = []string{"login failed", "登录失败", "incorrect", "wrong password", "invalid password", "try again"}

// projectSessions 进程内会话缓存（project_id -> cookies）。
var projectSessions sync.Map

// sessionCookieCount 项目会话 Cookie 数。
func sessionCookieCount(tc *Context) int {
	if s := loadSession(tc); s != nil && len(s.Cookies) > 0 {
		return len(s.Cookies)
	}
	return 0
}

// loadSession 取项目会话：Context 内嵌优先，回落磁盘恢复（重启不丢登录态）。
func loadSession(tc *Context) *Session {
	if tc.Session != nil && len(tc.Session.Cookies) > 0 {
		return tc.Session
	}
	if s, ok := projectSessions.Load(tc.ProjectID); ok {
		if sess := s.(*Session); len(sess.Cookies) > 0 {
			tc.Session = sess
			return sess
		}
	}
	home, _ := os.UserHomeDir()
	b, err := os.ReadFile(filepath.Join(home, ".argus", "sessions", fmt.Sprint(tc.ProjectID)+".json"))
	if err != nil {
		return nil
	}
	var sess Session
	if json.Unmarshal(b, &sess) != nil || len(sess.Cookies) == 0 {
		return nil
	}
	projectSessions.Store(tc.ProjectID, &sess)
	tc.Session = &sess
	return &sess
}

// persistSession 登录成功后落盘。
func persistSession(tc *Context, sess *Session) {
	home, _ := os.UserHomeDir()
	dir := filepath.Join(home, ".argus", "sessions")
	_ = os.MkdirAll(dir, 0o755)
	b, _ := json.Marshal(sess)
	_ = os.WriteFile(filepath.Join(dir, fmt.Sprint(tc.ProjectID)+".json"), b, 0o600)
}

// cookieHeader 会话 Cookie 拼请求头（可叠加一次性覆盖）。
func cookieHeader(sess *Session, override map[string]string) string {
	merged := map[string]string{}
	if sess != nil {
		for k, v := range sess.Cookies {
			merged[k] = v
		}
	}
	for k, v := range override {
		merged[k] = v
	}
	keys := make([]string, 0, len(merged))
	for k := range merged {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, k+"="+merged[k])
	}
	return strings.Join(parts, "; ")
}

var bodyFps sync.Map // project_id -> *map[string]int 响应指纹记忆

// sessionHint 响应像被踢回登录页/WAF 拦截 → 可操作提示（对应 _session_hint）。
func sessionHint(status int, body, location string) string {
	loc := strings.ToLower(location)
	if (status == 301 || status == 302 || status == 303 || status == 307 || status == 308) &&
		strings.Contains(loc+" "+loc+" "+loc, "login") {
		return "重定向到登录页：该项目会话缺失或已过期，请先对项目执行 web_login（或补充 Cookie 请求头）。"
	}
	if strings.Contains(loc, "signin") || strings.Contains(loc, "sign-in") ||
		strings.Contains(loc, "auth") || strings.Contains(loc, "sso") {
		if status >= 301 && status <= 308 {
			return "重定向到登录页：该项目会话缺失或已过期，请先对项目执行 web_login（或补充 Cookie 请求头）。"
		}
	}
	head := strings.ToLower(body)
	if len(head) > 3000 {
		head = head[:3000]
	}
	if status == 403 || status == 406 || status == 429 || status == 444 || status == 501 {
		for _, k := range []string{"waf", "firewall", "501page", "blocked", "forbidden by"} {
			if strings.Contains(head, k) {
				return "WAF 拦截页：该目标部署了 Web 应用防火墙，当前 payload 已被拦截。" +
					"继续换花样硬试注入/XSS 只会浪费步数——建议转向目录探测、业务逻辑测试、信息收集类测试。"
			}
		}
	}
	if status == 200 && strings.Contains(head, "<form") &&
		regexp.MustCompile(`type=["']?password`).MatchString(head) {
		return "响应体是登录表单：该项目会话缺失或已过期，请先对项目执行 web_login（或补充 Cookie 请求头）。"
	}
	return ""
}

// parseLoginForm 解析第一个含 password 输入的表单（对应 _parse_form）。
func parseLoginForm(html, baseURL string) (action, method string, fields map[string]string, userField, passField string, ok bool) {
	formRe := regexp.MustCompile(`(?is)<form[^>]*>(.*?)</form>`)
	for _, m := range formRe.FindAllStringSubmatch(html, -1) {
		tagBody := m[1]
		tag := m[0]
		am := regexp.MustCompile(`(?i)action=["']([^"']*)["']`).FindStringSubmatch(tag)
		mm := regexp.MustCompile(`(?i)method=["']?(\w+)`).FindStringSubmatch(tag)
		fields = map[string]string{}
		userField, passField = "", ""
		inpRe := regexp.MustCompile(`(?is)<(input|select|textarea)[^>]*>`)
		for _, inp := range inpRe.FindAllString(tagBody, -1) {
			nm := regexp.MustCompile(`(?i)name=["']([^"']+)["']`).FindStringSubmatch(inp)
			if nm == nil {
				continue
			}
			name := nm[1]
			vm := regexp.MustCompile(`(?i)value=["']([^"']*)["']`).FindStringSubmatch(inp)
			if vm != nil {
				fields[name] = vm[1]
			} else {
				fields[name] = ""
			}
			if regexp.MustCompile(`(?i)type=["']?password`).MatchString(inp) {
				passField = name
			} else if regexp.MustCompile(`(?i)type=["']?(text|email)`).MatchString(inp) && userField == "" {
				userField = name
			}
		}
		if passField != "" {
			if userField == "" {
				for _, cand := range []string{"username", "user", "login", "email", "account"} {
					if _, okc := fields[cand]; okc {
						userField = cand
						break
					}
				}
			}
			if userField == "" {
				userField = "username"
			}
			action = ""
			if am != nil {
				action = resolveURL(baseURL, am[1])
			} else {
				action = baseURL
			}
			method = "POST"
			if mm != nil {
				method = strings.ToUpper(mm[1])
			}
			return action, method, fields, userField, passField, true
		}
	}
	return "", "", nil, "", "", false
}

// resolveURL 相对/绝对 URL 合并（urljoin 等效）。
func resolveURL(base, ref string) string {
	b, err := url.Parse(base)
	if err != nil {
		return ref
	}
	r, err := url.Parse(ref)
	if err != nil {
		return ref
	}
	return b.ResolveReference(r).String()
}

// WebLoginTool web_login：自动解析登录表单并建立会话。
type WebLoginTool struct{}

func (WebLoginTool) Name() string { return "web_login" }
func (WebLoginTool) Description() string {
	return "登录目标 Web 站点并建立会话（自动解析登录表单字段与 CSRF token，按项目保存 Cookie）。" +
		"输入登录页 URL 与用户名/密码。登录成功后用 http_fetch 访问登录后的功能页面。" +
		"适用于表单类登录（GET 登录页→POST 凭据）。"
}
func (WebLoginTool) Parameters() map[string]any {
	return Schema(map[string]any{
		"url":            Prop("string", "登录页 URL（如 http://t/login.php）"),
		"username":       Prop("string", "用户名"),
		"password":       Prop("string", "密码"),
		"username_field": Prop("string", "用户名字段名（默认自动识别）"),
		"password_field": Prop("string", "密码字段名（默认自动识别）"),
	}, "url", "username", "password")
}
func (WebLoginTool) Execute(ctx context.Context, args map[string]any, tc *Context) (string, error) {
	rawURL := strings.TrimSpace(ArgString(args, "url", ""))
	username := ArgString(args, "username", "")
	password := ArgString(args, "password", "")
	if !strings.HasPrefix(rawURL, "http://") && !strings.HasPrefix(rawURL, "https://") {
		return "", Errorf("URL 必须以 http(s):// 开头: %s", rawURL)
	}
	if err := tc.Scope.EnsureURL(rawURL); err != nil {
		return "", err
	}
	sess := loadSession(tc)
	if sess == nil {
		sess = &Session{Cookies: map[string]string{}, BaseURL: rawURL}
		tc.Session = sess
		projectSessions.Store(tc.ProjectID, sess)
	}
	// 1) GET 登录页
	status1, html, err := fetchWithSession(ctx, tc, "GET", rawURL, nil, "", nil)
	if err != nil {
		return "", Errorf("登录页获取失败: %v", err)
	}
	_ = status1
	action, method, fields, uf, pf, ok := parseLoginForm(html, rawURL)
	if !ok {
		return "", Errorf("未在 %s 解析到含密码输入的登录表单；若是 JS 弹窗认证或 API 登录，请用 http_fetch 手动 POST", rawURL)
	}
	if v := ArgString(args, "username_field", ""); v != "" {
		uf = v
	}
	if v := ArgString(args, "password_field", ""); v != "" {
		pf = v
	}
	fields[uf] = username
	fields[pf] = password
	// 2) POST 凭据（表单编码）
	form := url.Values{}
	for k, v := range fields {
		form.Set(k, v)
	}
	reqBody := form.Encode()
	if method == "GET" {
		action += "?" + reqBody
		reqBody = ""
	}
	status, body, finalURL := postWithSession(ctx, tc, method, action, reqBody, nil)
	low := strings.ToLower(body)
	failed := false
	for _, h := range loginFailHints {
		if strings.Contains(low, h) {
			failed = true
			break
		}
	}
	stillLogin := false
	if status == 200 {
		_, _, _, _, _, stillLogin = parseLoginForm(body, finalURL)
	}
	okLogin := !failed && !stillLogin && (status == 200 || status == 302)
	// 流量录制
	tc.Reporter.SaveEvidence(ctx, "traffic", fmt.Sprintf("POST %s %s → %d login_ok=%v → %s",
		action, uf, status, okLogin, finalURL), map[string]any{"source_tool": "web_login"})
	var hidden []string
	for k, v := range fields {
		if v != "" && k != uf && k != pf {
			hidden = append(hidden, k)
		}
	}
	title := ""
	if m := regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`).FindStringSubmatch(body); m != nil {
		title = strings.TrimSpace(m[1])
		if len(title) > 80 {
			title = title[:80]
		}
	}
	if okLogin {
		sess.User = username
		persistSession(tc, sess)
		tc.Reporter.SaveAsset(ctx, "url", finalURL, map[string]any{
			"type": "authenticated", "as": username, "source": "web_login",
		})
		// 凭据自动情报化：登录成功的凭据入库，后续任务开局即可用
		tc.Reporter.SaveKnowledge(ctx, "已验证凭据 "+rawURL,
			fmt.Sprintf("[已验证凭据] %s 用户名 %s 密码 %s（web_login 实测成功，可直接登录测试认证后功能）",
				rawURL, username, password))
	}
	return MustJSON(map[string]any{
		"tool": "web_login", "ok": okLogin, "status": status,
		"action": action, "user_field": uf, "pass_field": pf,
		"hidden_fields": hidden, "final_url": finalURL,
		"title_hint": title, "body_snippet": Truncate(body, 400),
	}), nil
}

func init() { Register(WebLoginTool{}) }

// fetchWithSession 带会话 GET（登录页获取等）。
func fetchWithSession(ctx context.Context, tc *Context, method, u string, headers map[string]string, body string, cookieOverride map[string]string) (int, string, error) {
	sess := tc.Session
	hdrs := map[string]string{}
	for k, v := range headers {
		hdrs[k] = v
	}
	if c := cookieHeader(sess, cookieOverride); c != "" {
		hdrs["Cookie"] = c
	}
	return fetchRawFollow(ctx, method, u, hdrs, body)
}

// postWithSession 带会话请求+Set-Cookie 回写（返回状态/响应体/最终URL）。
func postWithSession(ctx context.Context, tc *Context, method, u, body string, cookieOverride map[string]string) (int, string, string) {
	hdrs := map[string]string{"Content-Type": "application/x-www-form-urlencoded"}
	if c := cookieHeader(tc.Session, cookieOverride); c != "" {
		hdrs["Cookie"] = c
	}
	return fetchFollowCapture(ctx, method, u, hdrs, body, tc.Session)
}

// HttpFetchTool http_fetch：带会话的任意 GET/POST。
type HttpFetchTool struct{}

func (HttpFetchTool) Name() string { return "http_fetch" }
func (HttpFetchTool) Description() string {
	return "带会话的 HTTP 请求（复用 web_login 建立的 Cookie 会话）。GET/POST 任意 URL，可带表单数据，" +
		"返回状态码/响应头/响应体片段。用于访问登录后的功能页面、构造参数验证行为差异（如 ?id=1 与 ?id=1' 对比）。" +
		"注意只做良性验证。"
}
func (HttpFetchTool) Parameters() map[string]any {
	return Schema(map[string]any{
		"url":     Prop("string", "目标 URL（可带查询参数）"),
		"method":  PropEnum("默认 GET", "GET", "POST"),
		"data":    Prop("object", "POST 表单数据（键值对），可选"),
		"headers": Prop("object", "额外请求头（键值对），可选"),
		"cookies": Prop("object", "一次性 Cookie 覆盖（键值对），优先于项目会话，可选"),
	}, "url")
}
func (HttpFetchTool) Execute(ctx context.Context, args map[string]any, tc *Context) (string, error) {
	rawURL := strings.TrimSpace(ArgString(args, "url", ""))
	if !strings.HasPrefix(rawURL, "http://") && !strings.HasPrefix(rawURL, "https://") {
		return "", Errorf("URL 必须以 http(s):// 开头: %s", rawURL)
	}
	if err := tc.Scope.EnsureURL(rawURL); err != nil {
		return "", err
	}
	loadSession(tc)
	method := strings.ToUpper(ArgString(args, "method", "GET"))
	data := map[string]string{}
	if d, ok := args["data"].(map[string]any); ok {
		for k, v := range d {
			data[k] = fmt.Sprint(v)
		}
	}
	headers := map[string]string{}
	if h, ok := args["headers"].(map[string]any); ok {
		for k, v := range h {
			headers[k] = fmt.Sprint(v)
		}
	}
	cookies := map[string]string{}
	if c, ok := args["cookies"].(map[string]any); ok {
		for k, v := range c {
			cookies[k] = fmt.Sprint(v)
		}
	}
	reqBody := ""
	if method == "POST" && len(data) > 0 {
		form := url.Values{}
		for k, v := range data {
			form.Set(k, v)
		}
		reqBody = form.Encode()
	}
	status, body, finalURL := postWithSession(ctx, tc, method, rawURL, reqBody, cookies)
	for k, v := range headers {
		_ = k
		_ = v
	}
	hint := sessionHint(status, body, "")
	tc.Reporter.SaveEvidence(ctx, "traffic", fmt.Sprintf("%s %s → %d", method, rawURL, status),
		map[string]any{"body": Truncate(body, 600), "source_tool": "http_fetch"})
	// 资产回流
	host := ""
	if parsed, err := url.Parse(rawURL); err == nil {
		host = parsed.Hostname()
	}
	if status < 400 {
		title := ""
		if m := titleRe.FindStringSubmatch(body); m != nil {
			title = strings.TrimSpace(m[1])
		}
		tc.Reporter.SaveAsset(ctx, "url", strings.SplitN(finalURL, "?", 2)[0], map[string]any{
			"title": title, "status_code": status, "source": "http_fetch",
		})
		if host != "" {
			tc.Reporter.SaveAsset(ctx, "domain", host, map[string]any{"status_code": status})
		}
	}
	// 响应指纹折叠（SPA/统一错误页）
	norm := regexp.MustCompile(`\d+`).ReplaceAllString(Truncate(body, 1500), "N")
	norm = regexp.MustCompile(`\s+`).ReplaceAllString(norm, " ")
	fp := fmt.Sprintf("%x", md5.Sum([]byte(norm)))
	fpsAny, _ := bodyFps.LoadOrStore(tc.ProjectID, &map[string]int{})
	fps := fpsAny.(*map[string]int)
	seenN := (*fps)[fp] + 1
	(*fps)[fp] = seenN
	bodyOut := Truncate(body, 4000)
	extra := ""
	if seenN >= 2 {
		bodyOut = ""
		extra = fmt.Sprintf("【响应折叠】该响应体与此前 %d 次完全一致（SPA fallback/统一错误页/模板响应），已省略。", seenN-1)
		if seenN >= 3 {
			extra += "该主机对不同路径返回相同响应——路径枚举/目录爆破对此站点无效，请转向参数化接口测试或其它目标。"
		}
	}
	out := map[string]any{
		"tool": "http_fetch", "url": rawURL, "method": method,
		"status": status, "final_url": finalURL,
		"has_session":     sessionCookieCount(tc) > 0,
		"session_cookies": sessionCookieCount(tc),
		"hint":            hint, "body_length": len(body), "body": bodyOut,
		"repeat_count": seenN,
	}
	if extra != "" {
		out["note"] = extra
	}
	return MustJSON(out), nil
}

func init() { Register(HttpFetchTool{}) }

// fetchRawFollow 跟随重定向的抓取（最多 10 跳），返回 (状态, 体, err)。
func fetchRawFollow(ctx context.Context, method, u string, headers map[string]string, body string) (int, string, error) {
	cl := &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{
		Proxy:     proxyFunc(TargetProxy()),
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}}
	req, err := http.NewRequestWithContext(ctx, method, u, strings.NewReader(body))
	if err != nil {
		return 0, "", err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; Argus/0.1)")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := cl.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return resp.StatusCode, "", err
	}
	return resp.StatusCode, string(b), nil
}

// fetchFollowCapture 跟随重定向 + 捕获 Set-Cookie 写回会话 + 返回最终 URL。
func fetchFollowCapture(ctx context.Context, method, u string, headers map[string]string, body string, sess *Session) (int, string, string) {
	cl := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			Proxy:     proxyFunc(TargetProxy()),
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
	req, err := http.NewRequestWithContext(ctx, method, u, strings.NewReader(body))
	if err != nil {
		return 0, "", u
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; Argus/0.1)")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := cl.Do(req)
	if err != nil {
		return 0, "", u
	}
	defer resp.Body.Close()
	// Set-Cookie 回写会话
	if sess != nil && sess.Cookies != nil {
		for _, c := range resp.Cookies() {
			if c.Value != "" {
				sess.Cookies[c.Name] = c.Value
			}
		}
	}
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	return resp.StatusCode, string(b), resp.Request.URL.String()
}
