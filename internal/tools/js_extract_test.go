package tools

import (
	"context"
	"strings"
	"testing"
)

// js_extract 从 JS 内容中提取端点、SourceMap 和密钥。
func TestJsExtractEndpoints(t *testing.T) {
	js := `
		var api = "https://api.example.com/v1/users"
		var cdn = "//cdn.example.com/asset"
		var path = "/admin/panel"
		var token = "sk-test12345"
		//# sourceMappingURL=/dist/app.js.map
		const SECRET = "secret-my-key"
		fetch("https://internal-api.example.com/data?key=abc")
	`
	result, err := JsExtractTool{}.Execute(context.Background(), map[string]any{"source": js}, &Context{
		Scope: anyScope{}, Reporter: &captureReporter{},
	})
	if err != nil {
		t.Fatalf("js_extract 不应失败: %v", err)
	}
	if !strings.Contains(result, "api.example.com") {
		t.Errorf("应提取出 api.example.com: %s", truncStr(result, 300))
	}
	if !strings.Contains(result, "cdn.example.com") {
		t.Errorf("应提取出 cdn.example.com: %s", truncStr(result, 300))
	}
	if !strings.Contains(result, "sourceMappingURL") && !strings.Contains(result, "/dist/app.js.map") {
		t.Errorf("应提取出 sourcemap 引用: %s", truncStr(result, 400))
	}
	if !strings.Contains(result, "疑似密钥") && !strings.Contains(result, "sk-test") {
		t.Errorf("应报告疑似密钥: %s", truncStr(result, 400))
	}
}

func truncStr(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// 空 JS 不应做端点误判
func TestJsExtractEmpty(t *testing.T) {
	_, err := JsExtractTool{}.Execute(context.Background(), map[string]any{"source": "var x = 1"}, &Context{
		Scope: anyScope{}, Reporter: &captureReporter{},
	})
	if err == nil {
		t.Fatal("内容太短时应返回错误")
	}
}
