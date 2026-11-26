package tools

import (
	"sort"
	"testing"
)

func TestGFClassify(t *testing.T) {
	cases := []struct {
		url  string
		tags []string
	}{
		{"https://example.com/search?q=hello", []string{"xss"}},
		{"https://example.com/item?id=123", []string{"sqli", "xss"}},
		{"https://example.com/proxy?url=http://evil.com", []string{"ssrf", "open-redirect", "xss"}},
		{"https://example.com/read?file=../../etc/passwd", []string{"lfi", "ssrf", "xss"}},
		{"https://example.com/login?redirect=/admin", []string{"open-redirect", "ssrf", "xss"}},
		{"https://example.com/order?user_id=123", []string{"idor"}},
		{"https://example.com/debug?debug=true", []string{"debug"}},
		{"https://example.com/", []string{}},                 // no query params
		{"https://example.com/static/style.css", []string{}}, // no query params
		{"https://example.com/auth?token=abc123", []string{"interesting-param"}},
	}
	for _, c := range cases {
		got := gfClassify(c.url)
		sort.Strings(got)
		sort.Strings(c.tags)
		if len(got) != len(c.tags) {
			t.Errorf("gfClassify(%q) = %v，应为 %v", c.url, got, c.tags)
			continue
		}
		for i := range got {
			if got[i] != c.tags[i] {
				t.Errorf("gfClassify(%q) = %v，应为 %v", c.url, got, c.tags)
			}
		}
	}
}

// gf 不应对无参 URL 做任何分类
func TestGFClassifyNoFalsePositive(t *testing.T) {
	urls := []string{
		"https://example.com/",
		"https://example.com/index.html",
		"https://example.com/admin?",
		"https://example.com/api/v1/users",
	}
	for _, u := range urls {
		if tags := gfClassify(u); len(tags) > 0 {
			t.Errorf("gfClassify(%q) 应为空，得到 %v", u, tags)
		}
	}
}
