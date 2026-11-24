package deploy

import "testing"

// CleanHostPort 回归：真实踩过的坑——host 带内嵌端口被 JoinHostPort 拼成
// "[1.2.3.4:22]:22" 整串当域名 lookup 超时；零宽/全角同理。
func TestCleanHostPort(t *testing.T) {
	cases := []struct {
		in    string
		host  string
		port  int
		fails bool
	}{
		{"10.211.55.4", "10.211.55.4", 0, false},         // 干净 IP
		{"10.211.55.4:22", "10.211.55.4", 22, false},     // 内嵌端口（本次线上坑）
		{"10.211.55.4:2222", "10.211.55.4", 2222, false}, // 非默认端口
		{"10.211.55.4:", "10.211.55.4", 0, false},        // 尾随冒号
		{" 10.211.55.4 ", "10.211.55.4", 0, false},       // 首尾空格（TrimSpace 已覆盖）
		{"10.211.55.4​", "10.211.55.4", 0, false},        // 尾随零宽 U+200B（TrimSpace 去不掉）
		{"​10.211.55.4", "10.211.55.4", 0, false},        // 前置零宽
		{"10.211.55.4", "10.211.55.4", 0, false},        // BOM U+FEFF
		{"１0.211.55.4", "10.211.55.4", 0, false},         // 全角数字
		{"10。211.55.4", "10.211.55.4", 0, false},         // 中文句点
		{"10．211．55．4", "10.211.55.4", 0, false},         // 全角句点
		{"example.com", "example.com", 0, false},         // 域名
		{"example.com:2222", "example.com", 2222, false}, // 域名+端口
		{"fe80::1", "fe80::1", 0, false},                 // 裸 IPv6（多冒号不拆）
		{"[::1]:2222", "::1", 2222, false},               // 括号 IPv6+端口
		{"[::1]", "::1", 0, false},                       // 括号 IPv6
		{"  ", "", 0, true},                              // 全空白
		{"10.211.55.4：22", "10.211.55.4", 22, false},     // 全角冒号内嵌端口
		{"10.211.55.４", "10.211.55.4", 0, false},         // 全角末位数字
		{"１０.２１１.５５.４:22", "10.211.55.4", 22, false},     // 整段全角+端口
		{"bad host", "badhost", 0, false},                // 中间空格剥掉（域名不含空格）
		{"10.211.55.4:abc", "", 0, true},                 // 冒号后非数字
		{"[fe80::1", "", 0, true},                        // 括号不成对
		{"host中文", "", 0, true},                          // 残留非 ASCII
	}
	for _, c := range cases {
		host, port, err := CleanHostPort(c.in)
		if c.fails {
			if err == nil {
				t.Errorf("CleanHostPort(%q) 期望报错，得到 host=%q port=%d", c.in, host, port)
			}
			continue
		}
		if err != nil {
			t.Errorf("CleanHostPort(%q) 意外报错: %v", c.in, err)
			continue
		}
		if host != c.host || port != c.port {
			t.Errorf("CleanHostPort(%q) = (%q, %d), 期望 (%q, %d)", c.in, host, port, c.host, c.port)
		}
	}
}
