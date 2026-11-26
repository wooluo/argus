package tools

// throttle.go: 自研 HTTP 工具的任务级限速 + 拦截识别。
//
// 以前设置页的 request_rate / max_concurrency 只是展示，没有任何代码读它；
// 退避只存在于 dir_brute 一个工具里（Pacer），WAF 提示只在 http_fetch 里有
// 一段关键词匹配。这里并成一层：所有自研 HTTP 工具都经 Context.DoRequest
// 发请求——限速 → 识别拦截 → 记账降速，工具结果和 agent 提醒都从这里取。

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Limits 任务级限速参数（server 按设置页 limits 下发）。
type Limits struct {
	RequestRate    float64 `json:"request_rate"`    // 每秒请求数；<=0 取默认
	MaxConcurrency int     `json:"max_concurrency"` // 同时在途的请求数；<=0 取默认
}

// 缺省值与设置页 limits 的默认值一致。
const (
	DefaultRequestRate    = 20.0
	DefaultMaxConcurrency = 10
)

func (l Limits) withDefaults() Limits {
	if l.RequestRate <= 0 {
		l.RequestRate = DefaultRequestRate
	}
	if l.MaxConcurrency <= 0 {
		l.MaxConcurrency = DefaultMaxConcurrency
	}
	return l
}

// Throttle 任务级限速器：并发上限 + 令牌间隔，外加 AIMD——收到拦截信号速率
// 减半（最低 1/8），连续 20 次正常请求后加倍恢复（借 TCP 拥塞控制）。
type Throttle struct {
	sem      chan struct{}
	interval time.Duration

	mu       sync.Mutex
	next     time.Time // 下一个可发送时刻
	factor   float64   // 当前速率系数，1 = 全速
	okStreak int
}

func NewThrottle(l Limits) *Throttle {
	l = l.withDefaults()
	return &Throttle{
		sem:      make(chan struct{}, l.MaxConcurrency),
		interval: time.Duration(float64(time.Second) / l.RequestRate),
		factor:   1,
	}
}

// Acquire 取一个发送名额：先限并发，再限速率。返回的释放函数在响应体关闭时
// 由 DoRequest 调用；请求失败时 DoRequest 自己释放。
func (t *Throttle) Acquire(ctx context.Context) (func(), error) {
	select {
	case t.sem <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	release := func() { <-t.sem }
	t.mu.Lock()
	now := time.Now()
	if t.next.Before(now) {
		t.next = now
	}
	at := t.next
	t.next = at.Add(time.Duration(float64(t.interval) / t.factor))
	t.mu.Unlock()
	if d := time.Until(at); d > 0 {
		timer := time.NewTimer(d)
		defer timer.Stop()
		select {
		case <-timer.C:
		case <-ctx.Done():
			release()
			return nil, ctx.Err()
		}
	}
	return release, nil
}

// Penalize 收到拦截信号：速率减半。
func (t *Throttle) Penalize() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.factor /= 2
	if t.factor < 0.125 {
		t.factor = 0.125
	}
	t.okStreak = 0
}

// okRequest 一次正常响应；连续 20 次后速率加倍恢复。
func (t *Throttle) okRequest() {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.factor >= 1 {
		return
	}
	t.okStreak++
	if t.okStreak >= 20 {
		t.factor *= 2
		if t.factor > 1 {
			t.factor = 1
		}
		t.okStreak = 0
	}
}

// Factor 当前速率系数（日志 / 提醒用）。
func (t *Throttle) Factor() float64 {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.factor
}

// ---------- 拦截识别 ----------

// BlockInfo 一次拦截信号。Kind：rate_limited（限流）/ waf（WAF 拦截页）/
// challenge（JS 挑战或验证码页）。
type BlockInfo struct {
	Kind   string `json:"kind"`
	Detail string `json:"detail"`
}

// 厂商特征：响应头或响应体命中即认定。头名小写、体已小写。
var wafSigns = []struct{ vendor, header, body string }{
	{"Cloudflare", "cf-ray", "cf-chl"},
	{"Cloudflare", "cf-mitigated", "challenge-platform"},
	{"Akamai", "akamai", ""},
	{"Imperva", "x-iinfo", "_incapsula_resource"},
	{"Sucuri", "x-sucuri", "sucuri firewall"},
	{"雷池 SafeLine", "safeline", "雷池"},
	{"宝塔防火墙", "", "宝塔网站防火墙"},
	{"腾讯云 WAF", "waf.tencent", "腾讯云 waf"},
	{"阿里云 WAF", "aliyun-waf", "阿里云 waf"},
}

// 挑战页特征：命中即视为 challenge（这类页面对正常内容不会出现）。
var challengeSigns = []string{
	"just a moment", "checking if the site connection is secure",
	"please enable javascript and cookies", "g-recaptcha", "h-captcha", "hcaptcha.com",
	"人机验证", "滑动验证", "安全验证",
}

// 泛化的拦截文案：只有状态码也像拦截时才算，免得页面里一句「WAF」就被误判。
var blockPhrases = []string{
	"web application firewall", "request blocked", "blocked by", "request rejected",
	"firewall has blocked", "请求过于频繁", "访问过于频繁", "访问太频繁", "操作频繁",
	"安全拦截", "拦截页面", "网站防火墙",
}

// blockStatuses 状态码本身就像拦截的集合。
// netpolicy.go 的 isBlockStatus 也定义了它（含 403/406/429/444/450/501/503），
// 这里直接用同一个条件，不重复声明。

// DetectBlock 从一次响应判断是不是被拦截。429 直接算限流；其它状态码要有
// WAF 响应头、厂商特征或挑战页特征才算。普通的 403（比如 /admin 禁止访问）
// 是一条有价值的结果，不能当成拦截。
func DetectBlock(status int, hdr http.Header, body string) *BlockInfo {
	head := strings.ToLower(body)
	if len(head) > 4096 {
		head = head[:4096]
	}
	var vendor string
	for k, vs := range hdr {
		lk := strings.ToLower(k)
		for _, w := range wafSigns {
			if w.header != "" && strings.Contains(lk, w.header) {
				vendor = w.vendor
			}
		}
		_ = vs
	}
	if vendor == "" {
		for _, w := range wafSigns {
			if w.body != "" && strings.Contains(head, w.body) {
				vendor = w.vendor
				break
			}
		}
	}
	if status == 429 {
		return &BlockInfo{Kind: "rate_limited", Detail: "HTTP 429 限流" + vendorSuffix(vendor)}
	}
	if !isBlockStatus(status) {
		return nil
	}
	for _, s := range challengeSigns {
		if strings.Contains(head, s) {
			return &BlockInfo{Kind: "challenge", Detail: "JS 挑战 / 验证码页" + vendorSuffix(vendor)}
		}
	}
	if vendor == "" {
		for _, p := range blockPhrases {
			if strings.Contains(head, p) {
				vendor = "WAF"
				break
			}
		}
	}
	if vendor == "" {
		return nil
	}
	return &BlockInfo{Kind: "waf", Detail: "WAF 拦截页" + vendorSuffix(vendor)}
}

func vendorSuffix(vendor string) string {
	if vendor == "" {
		return ""
	}
	return "（" + vendor + "）"
}
