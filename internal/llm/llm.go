// Package llm 移植自 AutoPentest core/llm.py —— OpenAI 兼容 LLM 客户端。
// 支持 GLM / OpenAI / Ollama 等；内网地址自动绕过系统代理；指数退避重试。
package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

// ErrorKind LLM 失败类别——失败分层处理：瞬时错误退避重试，永久错误立即
// 失败并给出可操作提示。（原先 429 限流与 401 鉴权失败一视同仁：1s/2s 退避
// 重试两次就放弃，无人值守时碰到一次限流即整任务失败。）
type ErrorKind int

const (
	ErrUnknown    ErrorKind = iota // 未归类：不重试
	ErrTransient                   // 网络 / 限流 / 服务端抖动：退避重试
	ErrAuth                        // 鉴权失败、额度耗尽：重试无意义
	ErrBadRequest                  // 请求本身有问题（模型名 / 参数 / 上下文超长）
)

// Error LLM 调用失败。
type Error struct {
	Msg  string
	Kind ErrorKind

	retryAfter time.Duration // 服务端 Retry-After（仅瞬时错误）
}

func (e *Error) Error() string { return e.Msg }

// RetryPolicy 瞬时错误的退避重试策略。
type RetryPolicy struct {
	MaxAttempts int           // 总尝试次数（含首次）
	BaseDelay   time.Duration // 首次退避，逐次翻倍
	MaxDelay    time.Duration // 单次等待上限
	Budget      time.Duration // 重试总时长上限（含等待）
}

// DefaultRetryPolicy 限流通常以分钟为窗口、服务端抖动多为秒级：约 3 分钟的
// 退避序列（2s 起翻倍、封顶 60s）足以熬过一次限流，5 分钟总预算防止拖死任务。
func DefaultRetryPolicy() RetryPolicy {
	return RetryPolicy{MaxAttempts: 8, BaseDelay: 2 * time.Second, MaxDelay: time.Minute, Budget: 5 * time.Minute}
}

var retryPolicy atomic.Pointer[RetryPolicy]

func init() { p := DefaultRetryPolicy(); retryPolicy.Store(&p) }

// SetRetryPolicy 覆盖全局默认重试策略（主要供测试提速）。
func SetRetryPolicy(p RetryPolicy) { retryPolicy.Store(&p) }

// Config 每次调用前刷新（支持热更新），字段与设置页对齐。
type Config struct {
	BaseURL string `json:"base_url"`
	APIKey  string `json:"api_key"`
	Model   string `json:"model"`
	Proxy   string `json:"proxy"` // 可选：外网端点显式代理（http://host:port）
}

// Provider 负责提供当前配置；nil 时用 DefaultProvider。
type Provider interface {
	LLMConfig() Config
}

type defaultProvider struct{ cfg Config }

func (d *defaultProvider) LLMConfig() Config { return d.cfg }

// DefaultProvider 固定配置（测试/无热更新场景）。
func DefaultProvider(cfg Config) Provider { return &defaultProvider{cfg: cfg} }

// Client OpenAI 兼容 chat/completions 客户端。
type Client struct {
	provider Provider
	http     *http.Client

	// 任务级 token 用量累计（Run 收尾回传 tasks.tokens）。记在客户端口径：
	// 阶段模式的多个会话、报告生成都走同一个 Client，不会漏计。
	tokPrompt     atomic.Int64
	tokCompletion atomic.Int64
	tokCalls      atomic.Int64

	retry *RetryPolicy // 本客户端的重试策略覆盖（nil=全局默认）
}

// SetRetryPolicy 本客户端覆盖重试策略（如设置页「测试连接」不重试——
// 否则端点故障时要等满退避序列才报错）。
func (c *Client) SetRetryPolicy(p RetryPolicy) { c.retry = &p }

func (c *Client) policy() RetryPolicy {
	if c.retry != nil {
		return *c.retry
	}
	if p := retryPolicy.Load(); p != nil {
		return *p
	}
	return DefaultRetryPolicy()
}

// Tokens 累计 token 用量（prompt / completion / 成功响应次数）。
func (c *Client) Tokens() (prompt, completion, calls int64) {
	return c.tokPrompt.Load(), c.tokCompletion.Load(), c.tokCalls.Load()
}

// Config 当前生效的模型配置（分层用脑后各客户端不同）。
func (c *Client) Config() Config { return c.provider.LLMConfig() }

// ModelName 当前模型 ID（分模型用量统计用）。
func (c *Client) ModelName() string { return c.provider.LLMConfig().Model }

// NewClient 每次请求按配置构建 transport（内网直连/外网代理/默认）。
func NewClient(p Provider) *Client {
	return &Client{provider: p, http: &http.Client{Timeout: 600 * time.Second}}
}

var localHostRe = regexp.MustCompile(`^(localhost|127\.0\.0\.1|::1|10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.)`)

func isLocalBase(baseURL string) bool {
	m := regexp.MustCompile(`://([^/:]+)`).FindStringSubmatch(baseURL)
	if m == nil {
		return false
	}
	return localHostRe.MatchString(strings.ToLower(m[1]))
}

// Message 一条消息（system/user/assistant/tool）。
type Message struct {
	Role       string     `json:"role"`
	Content    string     `json:"content"`
	ToolCalls  []ToolCall `json:"tool_calls,omitempty"`
	ToolCallID string     `json:"tool_call_id,omitempty"`
	Name       string     `json:"name,omitempty"`
}

// ToolCall 模型发起的工具调用请求。
type ToolCall struct {
	ID       string `json:"id"`
	Type     string `json:"type"`
	Function struct {
		Name      string `json:"name"`
		Arguments string `json:"arguments"`
	} `json:"function"`
}

// ToolSpec 工具 schema（OpenAI function 格式）。
type ToolSpec struct {
	Type     string `json:"type"`
	Function struct {
		Name        string         `json:"name"`
		Description string         `json:"description"`
		Parameters  map[string]any `json:"parameters"`
	} `json:"function"`
}

// NewToolSpec 构建单个工具 schema。
func NewToolSpec(name, description string, params map[string]any) ToolSpec {
	t := ToolSpec{Type: "function"}
	t.Function.Name = name
	t.Function.Description = description
	t.Function.Parameters = params
	return t
}

// ToolSpecsFrom 把工具列表转成请求 schema。
func ToolSpecsFrom(tools []any) []ToolSpec {
	var specs []ToolSpec
	for _, t := range tools {
		if s, ok := t.(interface {
			Spec() ToolSpec
		}); ok {
			specs = append(specs, s.Spec())
		}
	}
	return specs
}

type chatRequest struct {
	Model       string     `json:"model"`
	Messages    []Message  `json:"messages"`
	Tools       []ToolSpec `json:"tools,omitempty"`
	ToolChoice  any        `json:"tool_choice,omitempty"`
	Temperature float64    `json:"temperature"`
	MaxTokens   int        `json:"max_tokens,omitempty"`
}

type Usage struct {
	PromptTokens     int `json:"prompt_tokens"`
	CompletionTokens int `json:"completion_tokens"`
	TotalTokens      int `json:"total_tokens"`
}

type ChatResp struct {
	Usage   *Usage `json:"usage,omitempty"`
	Choices []struct {
		Message struct {
			Role      string     `json:"role"`
			Content   string     `json:"content"`
			ToolCalls []ToolCall `json:"tool_calls"`
		} `json:"message"`
		FinishReason string `json:"finish_reason"`
	} `json:"choices"`
	Error *struct {
		Message string `json:"message"`
		Type    string `json:"type"`
	} `json:"error"`
}

// Chat 调用 chat/completions。失败分层：瞬时错误（网络/限流/5xx）按
// RetryPolicy 退避重试并尊重 Retry-After；鉴权/额度/请求错误立即失败。
func (c *Client) Chat(ctx context.Context, messages []Message, tools []ToolSpec, temperature float64) (*ChatResp, error) {
	cfg := c.provider.LLMConfig()
	if cfg.BaseURL == "" {
		return nil, &Error{Msg: "LLM 未配置 base_url", Kind: ErrBadRequest}
	}
	body := chatRequest{
		Model:       cfg.Model,
		Messages:    messages,
		Tools:       tools,
		Temperature: temperature,
		MaxTokens:   4000,
	}
	if tools != nil {
		body.ToolChoice = "auto"
	}
	payload, err := json.Marshal(body)
	if err != nil {
		return nil, &Error{Msg: err.Error(), Kind: ErrBadRequest}
	}
	endpoint := strings.TrimRight(cfg.BaseURL, "/") + "/chat/completions"

	policy := c.policy()
	start := time.Now()
	var last *Error
	for attempt := 1; ; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
		if err != nil {
			return nil, &Error{Msg: err.Error(), Kind: ErrBadRequest}
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+cfg.APIKey)

		resp, err := c.transportFor(cfg).Do(req)
		if err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err() // 任务被停：不重试
			}
			last = &Error{Kind: ErrTransient, Msg: err.Error()}
		} else {
			data, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				var out ChatResp
				if err := json.Unmarshal(data, &out); err != nil {
					return nil, &Error{Msg: "响应解析失败: " + err.Error(), Kind: ErrUnknown}
				}
				if out.Error != nil {
					kind := ErrUnknown
					if quotaRe.MatchString(strings.ToLower(out.Error.Message)) {
						kind = ErrAuth
					}
					return nil, &Error{Kind: kind,
						Msg: fmt.Sprintf("LLM 错误[%s]: %s", out.Error.Type, out.Error.Message)}
				}
				c.tokCalls.Add(1)
				if out.Usage != nil {
					c.tokPrompt.Add(int64(out.Usage.PromptTokens))
					c.tokCompletion.Add(int64(out.Usage.CompletionTokens))
				}
				return &out, nil
			}
			last = &Error{Kind: classify(resp.StatusCode, string(data)),
				Msg:        fmt.Sprintf("HTTP %d: %s", resp.StatusCode, truncate(string(data), 300)),
				retryAfter: parseRetryAfter(resp.Header.Get("Retry-After"), time.Now())}
		}
		wait := backoff(policy, attempt, last.retryAfter)
		if last.Kind != ErrTransient || attempt >= policy.MaxAttempts ||
			time.Since(start)+wait > policy.Budget {
			return nil, wrapFinal(last, attempt, time.Since(start))
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(wait):
		}
	}
}

// quotaRe 额度/余额耗尽的特征——限流与欠费都可能回 429/403，只看状态码
// 会把「每分钟限流」误判成「key 没额度」（sapper-v2 实战踩过的风暴根源）。
var quotaRe = regexp.MustCompile(
	`insufficient[_ ]quota|exceed\w* (your |the )?(current )?quota|quota (is )?exhausted|` +
		`billing|out of credit|欠费|余额|额度(不足|用尽|耗尽|已用完)`)

// classify 非 200 响应的失败类别。
func classify(status int, body string) ErrorKind {
	switch status {
	case http.StatusRequestTimeout:
		return ErrTransient
	case http.StatusTooManyRequests:
		if quotaRe.MatchString(strings.ToLower(body)) {
			return ErrAuth
		}
		return ErrTransient
	case http.StatusBadRequest, http.StatusNotFound, http.StatusRequestEntityTooLarge,
		http.StatusUnprocessableEntity:
		return ErrBadRequest
	case http.StatusUnauthorized, http.StatusPaymentRequired, http.StatusForbidden:
		return ErrAuth
	}
	if status >= 500 {
		return ErrTransient
	}
	return ErrUnknown
}

// backoff 第 attempt 次失败后的等待：指数退避；服务端给了 Retry-After 则取
// 较大者（限流窗口由服务端说了算），一律封顶 MaxDelay。
func backoff(p RetryPolicy, attempt int, retryAfter time.Duration) time.Duration {
	d := p.BaseDelay << (attempt - 1)
	if d <= 0 || d > p.MaxDelay {
		d = p.MaxDelay
	}
	if ra := min(retryAfter, p.MaxDelay); ra > d {
		d = ra
	}
	return d
}

// parseRetryAfter 解析 Retry-After（秒数或 HTTP 日期）；无法解析返回 0。
func parseRetryAfter(v string, now time.Time) time.Duration {
	v = strings.TrimSpace(v)
	if n, err := strconv.Atoi(v); err == nil && n > 0 {
		return time.Duration(n) * time.Second
	}
	if t, err := http.ParseTime(v); err == nil && t.After(now) {
		return t.Sub(now)
	}
	return 0
}

// wrapFinal 重试耗尽 / 不可重试错误的统一措辞：带上类别对应的处置提示。
func wrapFinal(e *Error, attempts int, elapsed time.Duration) error {
	switch e.Kind {
	case ErrAuth:
		return &Error{Kind: ErrAuth, Msg: "LLM 鉴权或额度失败（不重试）: " + e.Msg +
			"——检查设置页的 API Key 与账户余额"}
	case ErrBadRequest:
		return &Error{Kind: ErrBadRequest, Msg: "LLM 请求被拒（不重试）: " + e.Msg +
			"——检查模型名、上下文长度与请求参数"}
	case ErrTransient:
		return &Error{Kind: ErrTransient, Msg: fmt.Sprintf(
			"LLM 服务不可用（已重试 %d 次、历时 %.0fs）: %s——稍后重跑或更换模型端点",
			attempts-1, elapsed.Seconds(), e.Msg)}
	}
	return &Error{Kind: e.Kind, Msg: "LLM 调用失败（不重试）: " + e.Msg}
}

// transportFor 内网直连（绕系统代理）；外网按需显式代理。
func (c *Client) transportFor(cfg Config) *http.Client {
	if isLocalBase(cfg.BaseURL) || cfg.Proxy == "" {
		return c.http // 默认 transport，含系统代理支持
	}
	pu, err := url.Parse(cfg.Proxy)
	if err != nil {
		return c.http
	}
	return &http.Client{
		Timeout:   600 * time.Second,
		Transport: &http.Transport{Proxy: http.ProxyURL(pu)},
	}
}

// ChatText 纯文本对话（报告生成/验证等场景）。
func (c *Client) ChatText(ctx context.Context, system, prompt string, temperature float64) (string, error) {
	var msgs []Message
	if system != "" {
		msgs = append(msgs, Message{Role: "system", Content: system})
	}
	msgs = append(msgs, Message{Role: "user", Content: prompt})
	resp, err := c.Chat(ctx, msgs, nil, temperature)
	if err != nil {
		return "", err
	}
	if len(resp.Choices) == 0 {
		return "", &Error{Msg: "LLM 返回空 choices"}
	}
	return strings.TrimSpace(resp.Choices[0].Message.Content), nil
}

// TestConnection 设置页“测试连接”用：模型回一句“正常”即通。
func (c *Client) TestConnection(ctx context.Context) map[string]any {
	cfg := c.provider.LLMConfig()
	text, err := c.ChatText(ctx, "", "回复两个字：正常", 0.3)
	if err != nil {
		return map[string]any{"ok": false, "model": cfg.Model, "error": err.Error()}
	}
	if len(text) > 100 {
		text = text[:100]
	}
	return map[string]any{"ok": true, "model": cfg.Model, "reply": text}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
