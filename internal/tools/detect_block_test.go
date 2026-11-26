package tools

import (
	"net/http"
	"strings"
	"testing"
)

func TestDetectBlock429(t *testing.T) {
	status, hdr, body := 429, http.Header{}, "too many requests"
	info := DetectBlock(status, hdr, body)
	if info == nil || info.Kind != "rate_limited" {
		t.Fatalf("429 应识别为 rate_limited：%+v", info)
	}
	if !strings.Contains(info.Detail, "429") {
		t.Fatalf("Detail 应含 429：%s", info.Detail)
	}
}

// 419 不是拦截状态码，不应误判。
func TestDetectBlockSkipsNonBlockCodes(t *testing.T) {
	for _, code := range []int{200, 302, 401, 404, 500} {
		if info := DetectBlock(code, http.Header{}, "anything"); info != nil {
			t.Errorf("%d 不应判为拦截：%+v", code, info)
		}
	}
}

// 无 WAF 特征的普通 403（如 /admin 禁止访问）不应算拦截。
func TestDetectBlock403WithoutWAFSign(t *testing.T) {
	info := DetectBlock(403, http.Header{}, `<html><body><h1>Forbidden</h1><p>Access denied</p></body></html>`)
	if info != nil {
		t.Fatalf("无特征的 403 不应算拦截：%+v", info)
	}
}

func TestDetectBlock403WAF(t *testing.T) {
	info := DetectBlock(403, http.Header{"cf-ray": []string{"xyz"}}, "blocked by firewall")
	if info == nil || info.Kind != "waf" || !strings.Contains(info.Detail, "Cloudflare") {
		t.Fatalf("Cloudflare WAF 拦截应识别为 waf：%+v", info)
	}
}

func TestDetectBlockChallenge(t *testing.T) {
	for _, body := range []string{"Just a moment, checking your browser", "g-recaptcha", "人机验证"} {
		info := DetectBlock(403, http.Header{}, body)
		if info == nil || info.Kind != "challenge" {
			t.Fatalf("挑战页应识别为 challenge（%q）：%+v", body, info)
		}
	}
}

// 响应头也可以识别厂商
func TestDetectBlockVendorByHeader(t *testing.T) {
	info := DetectBlock(503, http.Header{"x-sucuri-cache": []string{"blocked"}}, "service unavailable")
	if info == nil || info.Kind != "waf" || !strings.Contains(info.Detail, "Sucuri") {
		t.Fatalf("Sucuri 响应头应识别：%+v", info)
	}
}

// 503 有拦截特征 → 算 challenge；无特征不算
func TestDetectBlock503(t *testing.T) {
	if info := DetectBlock(503, http.Header{}, "upstream connection timeout"); info != nil {
		t.Fatalf("无特征的 503 不应算拦截：%+v", info)
	}
	info := DetectBlock(503, http.Header{"X-Aliyun-Waf": []string{"blocked"}}, "service unavailable")
	if info == nil || !strings.Contains(info.Detail, "阿里云 WAF") {
		t.Fatalf("阿里云 WAF 503 应识别：%+v", info)
	}
}
