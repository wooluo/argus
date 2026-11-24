package rank

import (
	"strings"
	"testing"
)

func TestTokens(t *testing.T) {
	got := strings.Join(Tokens("DVWA v1.10 盲注 与 CSRF-token 处理"), " ")
	want := "dvwa v1 10 csrf token 盲注 处理" // 英数词（点号、连字符均分隔）+ 相邻汉字 bigram
	if got != want {
		t.Errorf("Tokens = %q, 期望 %q", got, want)
	}
}

func TestSearchRanksTitleHitAboveBodyHit(t *testing.T) {
	// 三条文档都提到「登录」，只有一条标题里是「弱口令」
	ix := New([]Doc{
		{"body", Weighted("会话保持", "", "", "登录后要保存 cookie，登录态失效时重连")},
		{"title", Weighted("后台弱口令登录", "", "", "admin/admin 可直接登录")},
		{"other", Weighted("端口扫描", "", "", "nmap 全端口")},
	})
	got := ix.Search("弱口令", 5)
	if len(got) != 1 || got[0].ID != "title" {
		t.Fatalf("期望只命中标题含弱口令的文档: %+v", got)
	}

	got = ix.Search("登录", 5)
	if len(got) != 2 || got[0].ID != "title" {
		t.Fatalf("标题命中应排在正文命中之前: %+v", got)
	}
}

func TestSearchIgnoresUnknownTermsAndKeepsInputOrder(t *testing.T) {
	ix := New([]Doc{
		{"b", "sql 注入"},
		{"a", "sql 注入"},
		{"c", "xss 跨站"},
	})
	got := ix.Search("完全不相关的词", 5)
	if got != nil {
		t.Errorf("无命中应返回空: %+v", got)
	}
	got = ix.Search("sql 注入", 5)
	if len(got) != 2 || got[0].ID != "b" || got[0].Score != got[1].Score {
		t.Errorf("同分应保持录入顺序: %+v", got)
	}
	if got = ix.Search("sql 注入 xss", 1); len(got) != 1 {
		t.Errorf("limit 应生效: %+v", got)
	}
	if got = (*Index)(nil).Search("x", 1); got != nil {
		t.Errorf("nil 索引不应 panic")
	}
}
