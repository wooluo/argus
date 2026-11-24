package llm

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// 失败分层回归：限流/5xx/网络错误退避重试（尊重 Retry-After）；鉴权失败、
// 额度耗尽、请求被拒立即失败并给出处置提示。限流与欠费都可能回 429——
// 只看状态码会把「每分钟限流」误判成「key 没额度」。

func fastPolicy() RetryPolicy {
	return RetryPolicy{MaxAttempts: 4, BaseDelay: time.Millisecond, MaxDelay: 3 * time.Millisecond, Budget: time.Second}
}

func clientFor(baseURL string) *Client {
	c := NewClient(DefaultProvider(Config{BaseURL: baseURL, APIKey: "k", Model: "m"}))
	c.SetRetryPolicy(fastPolicy())
	return c
}

const okBody = `{"choices":[{"message":{"role":"assistant","content":"ok"}}],` +
	`"usage":{"prompt_tokens":10,"completion_tokens":5}}`

// serve 起一个按序返回指定响应的假端点，返回客户端与命中计数。
func serve(t *testing.T, policy RetryPolicy, replies ...func(w http.ResponseWriter)) (*Client, *atomic.Int64) {
	t.Helper()
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		replies[min(int(hits.Load()), len(replies)-1)](w) // 最后一种响应一直重复
		hits.Add(1)
	}))
	t.Cleanup(srv.Close)
	c := NewClient(DefaultProvider(Config{BaseURL: srv.URL, APIKey: "k", Model: "m"}))
	c.SetRetryPolicy(policy)
	return c, &hits
}

func statusReply(code int, body string, header map[string]string) func(http.ResponseWriter) {
	return func(w http.ResponseWriter) {
		for k, v := range header {
			w.Header().Set(k, v)
		}
		w.WriteHeader(code)
		_, _ = w.Write([]byte(body))
	}
}

func kindOf(t *testing.T, err error) ErrorKind {
	t.Helper()
	var e *Error
	if !errors.As(err, &e) {
		t.Fatalf("期望 *llm.Error，得到 %T: %v", err, err)
	}
	return e.Kind
}

func chat(t *testing.T, c *Client) error {
	t.Helper()
	_, err := c.Chat(context.Background(), []Message{{Role: "user", Content: "hi"}}, nil, 0.2)
	return err
}

func TestRetryOnRateLimitThenOK(t *testing.T) {
	c, hits := serve(t, fastPolicy(),
		statusReply(http.StatusTooManyRequests, `{"error":{"message":"Rate limit reached for requests"}}`, nil),
		statusReply(http.StatusBadGateway, "bad gateway", nil),
		func(w http.ResponseWriter) { _, _ = w.Write([]byte(okBody)) })
	if err := chat(t, c); err != nil {
		t.Fatalf("限流后应恢复: %v", err)
	}
	if n := hits.Load(); n != 3 {
		t.Errorf("期望 3 次命中（429、502、200），得到 %d", n)
	}
	if p, c2, calls := c.Tokens(); calls != 1 || p != 10 || c2 != 5 {
		t.Errorf("token 只应计入成功的那次: prompt=%d completion=%d calls=%d", p, c2, calls)
	}
}

func TestFailFastOnAuthAndBadRequest(t *testing.T) {
	for _, tc := range []struct {
		name  string
		reply func(http.ResponseWriter)
		kind  ErrorKind
		hint  string
	}{
		{"401 鉴权失败", statusReply(http.StatusUnauthorized, `{"error":{"message":"Invalid API key"}}`, nil),
			ErrAuth, "API Key"},
		{"429 额度耗尽（非限流）", statusReply(http.StatusTooManyRequests,
			`{"error":{"code":"insufficient_quota","message":"You exceeded your current quota, please check your plan and billing details."}}`, nil),
			ErrAuth, "余额"},
		{"404 模型不存在", statusReply(http.StatusNotFound, `{"error":{"message":"The model 'x' does not exist"}}`, nil),
			ErrBadRequest, "模型名"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, hits := serve(t, fastPolicy(), tc.reply)
			err := chat(t, c)
			if err == nil || kindOf(t, err) != tc.kind {
				t.Fatalf("期望 %v 类失败，得到 %v", tc.kind, err)
			}
			if hits.Load() != 1 {
				t.Errorf("不可重试的错误应只请求 1 次，实际 %d 次", hits.Load())
			}
			var e *Error
			_ = errors.As(err, &e)
			if !strings.Contains(e.Msg, tc.hint) {
				t.Errorf("失败信息应带处置提示 %q: %s", tc.hint, e.Msg)
			}
		})
	}
}

func TestTransientExhaustsRetries(t *testing.T) {
	c, hits := serve(t, fastPolicy(), statusReply(http.StatusServiceUnavailable, "overloaded", nil))
	err := chat(t, c)
	if kindOf(t, err) != ErrTransient {
		t.Fatalf("期望瞬时错误，得到 %v", err)
	}
	if hits.Load() != 4 || !strings.Contains(err.Error(), "已重试 3 次") {
		t.Errorf("应重试到上限: hits=%d err=%v", hits.Load(), err)
	}

	// 网络错误同属瞬时：端点直接不可达
	dead := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	dead.Close()
	c = clientFor(dead.URL)
	if kindOf(t, chat(t, c)) != ErrTransient {
		t.Errorf("网络错误应归为瞬时")
	}
}

func TestRetryAfterCappedByMaxDelay(t *testing.T) {
	// 服务端让等 3600s：不能真等，按 MaxDelay 封顶后继续重试
	c, _ := serve(t, fastPolicy(),
		statusReply(http.StatusTooManyRequests, "slow down", map[string]string{"Retry-After": "3600"}),
		func(w http.ResponseWriter) { _, _ = w.Write([]byte(okBody)) })
	start := time.Now()
	if err := chat(t, c); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if time.Since(start) > 500*time.Millisecond {
		t.Errorf("Retry-After 未被封顶，耗时 %v", time.Since(start))
	}
}

func TestBudgetAndCancelStopRetrying(t *testing.T) {
	// 下一次等待会超出总预算 → 不再重试
	p := RetryPolicy{MaxAttempts: 9, BaseDelay: 20 * time.Millisecond, MaxDelay: 20 * time.Millisecond, Budget: 10 * time.Millisecond}
	c, hits := serve(t, p, statusReply(http.StatusInternalServerError, "boom", nil))
	_ = chat(t, c)
	if hits.Load() != 1 {
		t.Errorf("超出预算应只请求 1 次，实际 %d", hits.Load())
	}

	// 等待期间任务被取消（ctx Done）→ 立即返回，不再重试
	p = RetryPolicy{MaxAttempts: 9, BaseDelay: 400 * time.Millisecond, MaxDelay: 400 * time.Millisecond, Budget: time.Minute}
	c, hits = serve(t, p, statusReply(http.StatusInternalServerError, "boom", nil))
	ctx, cancel := context.WithCancel(context.Background())
	start := time.Now()
	go func() { time.Sleep(20 * time.Millisecond); cancel() }()
	_, err := c.Chat(ctx, []Message{{Role: "user", Content: "hi"}}, nil, 0.2)
	if !errors.Is(err, context.Canceled) || time.Since(start) > 300*time.Millisecond || hits.Load() != 1 {
		t.Errorf("取消应立即中断重试: err=%v elapsed=%v hits=%d", err, time.Since(start), hits.Load())
	}
}

func TestClassifyAndRetryAfter(t *testing.T) {
	for _, tc := range []struct {
		status int
		body   string
		want   ErrorKind
	}{
		{429, "Rate limit reached", ErrTransient},
		{429, "insufficient_quota", ErrAuth},
		{500, "internal error", ErrTransient},
		{503, "overloaded", ErrTransient},
		{408, "timeout", ErrTransient},
		{401, "unauthorized", ErrAuth},
		{403, "余额不足", ErrAuth},
		{400, "context_length_exceeded", ErrBadRequest},
		{422, "unprocessable", ErrBadRequest},
		{418, "teapot", ErrUnknown},
	} {
		if got := classify(tc.status, tc.body); got != tc.want {
			t.Errorf("classify(%d, %q) = %v, 期望 %v", tc.status, tc.body, got, tc.want)
		}
	}

	now := time.Date(2026, 11, 24, 0, 0, 0, 0, time.UTC)
	if d := parseRetryAfter("30", now); d != 30*time.Second {
		t.Errorf("秒数形式: %v", d)
	}
	if d := parseRetryAfter(now.Add(90*time.Second).Format(http.TimeFormat), now); d != 90*time.Second {
		t.Errorf("HTTP 日期形式: %v", d)
	}
	for _, bad := range []string{"", "soon", "-5", now.Add(-time.Hour).Format(http.TimeFormat)} {
		if d := parseRetryAfter(bad, now); d != 0 {
			t.Errorf("Retry-After %q 应解析为 0，得到 %v", bad, d)
		}
	}
	// 退避：指数翻倍、封顶、Retry-After 取较大者
	p := RetryPolicy{MaxAttempts: 8, BaseDelay: time.Second, MaxDelay: 3 * time.Second, Budget: time.Minute}
	for attempt, want := range map[int]time.Duration{1: time.Second, 2: 2 * time.Second, 3: 3 * time.Second, 7: 3 * time.Second} {
		if d := backoff(p, attempt, 0); d != want {
			t.Errorf("backoff(attempt=%d) = %v, 期望 %v", attempt, d, want)
		}
	}
	if d := backoff(p, 1, 2*time.Second); d != 2*time.Second {
		t.Errorf("Retry-After 更长时应取 Retry-After: %v", d)
	}
	if d := backoff(p, 1, time.Hour); d != 3*time.Second {
		t.Errorf("Retry-After 应被封顶: %v", d)
	}
}
