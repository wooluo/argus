package tools

import "testing"

// TestCheckBlacklist 黑名单放行/拦截语义（蓝本 (?!tmp|home|var/tmp) 的 RE2 等价实现）。
func TestCheckBlacklist(t *testing.T) {
	cases := []struct{ in, want string }{
		{"rm -rf /tmp/argus/scripts", ""},         // 放行目录
		{"rm -rf /home/wooluo/junk", ""},          // 放行目录
		{"rm -rf /", "rm -rf 根路径"},                // 根路径拦截
		{"rm -rf /etc/passwd", "rm -rf 根路径"},      // 非放行绝对路径拦截
		{"rm -rf /tmp/a; rm -rf /", "rm -rf 根路径"}, // 复合命令逐段检查
		{"mkfs.ext4 /dev/sda1", "格式化磁盘"},          // 其余黑名单仍生效
		{"ls -la /tmp", ""},                       // 无害命令
	}
	for _, c := range cases {
		if got := checkBlacklist(c.in); got != c.want {
			t.Errorf("checkBlacklist(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestRegistryCount 全部工具注册成功（init panic / 漏注册都会在此暴露）。
func TestRegistryCount(t *testing.T) {
	if n := len(Names()); n != 31 {
		t.Fatalf("registered %d tools, want 31: %v", n, Names())
	}
}
