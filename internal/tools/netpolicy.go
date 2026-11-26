package tools

// netpolicy.go: 出站网络策略统一层（移植自 AutoPentest config.py 的
// proxy_for_url / target_proxy + base.py 的 AdaptivePacer AIMD）。
// 出站代理（GitHub/OSINT/FOFA 等平台自身请求）：ARGUS_OUT_PROXY，
// 内网地址自动绕过。测试流量代理（对目标）：ARGUS_TARGET_PROXY，
// 显式开启即全量生效不绕过。AIMD：拦截响应乘性退避、连续正常加性恢复。

import (
	"crypto/tls"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

// ---------- 出站/测试代理 ----------

var intranetCIDRs = []string{
	"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "::1/128",
}

// OutProxyFor 平台出站请求（GitHub/FOFA/crt.sh/webhook）的代理：
// ARGUS_OUT_PROXY 开启且目标为公网时返回代理 URL，内网/本机自动绕过。
func OutProxyFor(rawurl string) string {
	p := strings.TrimSpace(os.Getenv("ARGUS_OUT_PROXY"))
	if p == "" {
		return ""
	}
	u, err := url.Parse(rawurl)
	if err != nil {
		return ""
	}
	if isPrivateHost(u.Hostname()) {
		return ""
	}
	return p
}

// TargetProxy 测试流量代理：ARGUS_TARGET_PROXY 显式配置即全量生效
// （不绕过——规避 WAF 封 IP 是操作者的主动决策）。空=直连。
func TargetProxy() string {
	return strings.TrimSpace(os.Getenv("ARGUS_TARGET_PROXY"))
}

// ProxyTransport 按用途构造 http.Transport（TLS 不校验，与工具侧惯例一致）。
func ProxyTransport(proxyURL string) *http.Transport {
	t := &http.Transport{
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
		MaxIdleConnsPerHost: 8,
	}
	if proxyURL != "" {
		if pu, err := url.Parse(proxyURL); err == nil {
			t.Proxy = http.ProxyURL(pu)
		}
	}
	return t
}

// OutClient 平台出站 HTTP 客户端（对内网自动直连、公网走出站代理）。
func OutClient(timeout time.Duration) *http.Client {
	return &http.Client{Timeout: timeout, Transport: ProxyTransport(OutProxyFor(""))}
}

func isPrivateHost(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	if ip == nil { // 域名：按公网处理（DNS 私域判定成本高，出站场景域名即公网）
		return false
	}
	for _, c := range intranetCIDRs {
		if _, n, err := net.ParseCIDR(c); err == nil && n.Contains(ip) {
			return true
		}
	}
	return ip.IsLoopback()
}

// ---------- AIMD 自适应限速（借 TCP 拥塞控制） ----------

// Pacer 拦截率反馈调节请求节奏：拦截（403/429/501/444）→ 延迟乘性退避
// ×2（上限 ×8）；连续 20 次正常 → 加性恢复减半。并发安全。
type Pacer struct {
	mu       sync.Mutex
	base     time.Duration
	mult     float64
	okStreak int
}

// NewPacer 构造（base 为单次退避基数，0.25s 起步）。
func NewPacer() *Pacer { return &Pacer{base: 250 * time.Millisecond, mult: 1} }

// blockCodes 视为拦截的状态码（与 AutoPentent AdaptivePacer 一致）。
func isBlockStatus(code int) bool {
	switch code {
	case 403, 406, 429, 444, 450, 501, 503:
		return true
	}
	return false
}

// Feedback 每次响应后反馈状态码（0=无状态/错误不反馈）。
func (p *Pacer) Feedback(status int) {
	if status <= 0 {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if isBlockStatus(status) {
		p.mult *= 2
		if p.mult > 8 {
			p.mult = 8
		}
		if p.mult < 2 {
			p.mult = 2
		}
		p.okStreak = 0
	} else {
		p.okStreak++
		if p.okStreak >= 20 && p.mult > 1 {
			p.mult /= 2
			if p.mult < 1 {
				p.mult = 1
			}
			p.okStreak = 0
		}
	}
}

// Wait 当前应等待的时长（退避中则阻塞，直连态为 0）。
func (p *Pacer) Wait() {
	p.mu.Lock()
	d := time.Duration(float64(p.base) * (p.mult - 1))
	p.mu.Unlock()
	if d > 0 {
		time.Sleep(d)
	}
}

// Multiplier 当前倍率（日志/调试用）。
func (p *Pacer) Multiplier() float64 {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.mult
}

// proxyFunc 供 http.Transport.Proxy 使用的函数值（空代理返回 nil=直连）。
func proxyFunc(proxyURL string) func(*http.Request) (*url.URL, error) {
	if proxyURL == "" {
		return nil
	}
	pu, err := url.Parse(proxyURL)
	if err != nil {
		return nil
	}
	return http.ProxyURL(pu)
}
