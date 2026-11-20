// Package llm 移植自 AutoPentest core/llm.py —— OpenAI 兼容 LLM 客户端。
// 支持 GLM / OpenAI / Ollama 等；内网地址自动绕过系统代理；指数退避重试。
package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// Error LLM 调用失败。
type Error struct{ Msg string }

func (e *Error) Error() string { return e.Msg }

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
}

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
		Usage *Usage `json:"usage,omitempty"`
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

// Chat 调用 chat/completions（带指数退避重试）。
func (c *Client) Chat(ctx context.Context, messages []Message, tools []ToolSpec, temperature float64) (*ChatResp, error) {
	cfg := c.provider.LLMConfig()
	if cfg.BaseURL == "" {
		return nil, &Error{Msg: "LLM 未配置 base_url"}
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
		return nil, &Error{Msg: err.Error()}
	}
	endpoint := strings.TrimRight(cfg.BaseURL, "/") + "/chat/completions"

	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		req, err := http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewReader(payload))
		if err != nil {
			return nil, &Error{Msg: err.Error()}
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+cfg.APIKey)

		resp, err := c.transportFor(cfg).Do(req)
		if err != nil {
			lastErr = err
		} else {
			data, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if resp.StatusCode == 200 {
				var out ChatResp
				if err := json.Unmarshal(data, &out); err != nil {
					return nil, &Error{Msg: "响应解析失败: " + err.Error()}
				}
				if out.Error != nil {
					return nil, &Error{Msg: fmt.Sprintf("LLM 错误[%s]: %s", out.Error.Type, out.Error.Message)}
				}
				return &out, nil
			}
			lastErr = fmt.Errorf("HTTP %d: %s", resp.StatusCode, truncate(string(data), 300))
		}
		if attempt < 2 {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(time.Duration(math.Pow(2, float64(attempt))) * time.Second):
			}
		}
	}
	return nil, &Error{Msg: "LLM 调用失败: " + lastErr.Error()}
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
