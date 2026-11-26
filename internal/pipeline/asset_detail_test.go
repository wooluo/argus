package pipeline

import (
	"encoding/json"
	"testing"
)

// 资产明细要带着 meta 入库。以前只认 meta["detail"] 这一个字符串，其余字段
// 全丢：httpx 探到的状态码、标题、技术栈都没进库，存下去的是空串。
func TestAssetDetailKeepsMeta(t *testing.T) {
	got := assetDetail(map[string]any{"url": "https://x.test", "status_code": 200, "title": "X", "tech": "nginx"})
	var m map[string]any
	if err := json.Unmarshal([]byte(got), &m); err != nil {
		t.Fatalf("不是 JSON: %q %v", got, err)
	}
	for k, want := range map[string]any{"status_code": float64(200), "title": "X", "tech": "nginx"} {
		if m[k] != want {
			t.Errorf("detail.%s = %v，应为 %v（%s）", k, m[k], want, got)
		}
	}
	if d := assetDetail(nil); d != "{}" {
		t.Errorf("nil meta → %q", d)
	}
	// web_login 的会话：detail 是现成的 JSON 串，原样保留
	session := `{"user":"admin","cookies":{"a":"b"}}`
	if d := assetDetail(map[string]any{"detail": session, "source": "web_login"}); d != session {
		t.Errorf("会话 detail → %q", d)
	}
	// detail 是串但不是 JSON：包一层，保证入库的是合法 JSON
	d := assetDetail(map[string]any{"detail": "cookies: a=b", "source": "web_login"})
	if !json.Valid([]byte(d)) {
		t.Errorf("应包成合法 JSON: %q", d)
	}
}
