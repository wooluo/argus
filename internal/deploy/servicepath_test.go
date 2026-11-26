package deploy

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// 节点服务的 PATH：部署用户家目录下的工具目录要带上（实测 Kali 上 subfinder
// 在 ~/bin，服务里找不到）；用户名或家目录带特殊字符时宁可不带。
func TestServicePath(t *testing.T) {
	base := "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/local/go/bin"
	cases := []struct{ name, user, home, want string }{
		{"取到家目录", "wooluo", "/home/wooluo/",
			base + ":/home/wooluo/bin:/home/wooluo/go/bin:/home/wooluo/.local/bin"},
		{"root 部署同样处理", "root", "/root",
			base + ":/root/bin:/root/go/bin:/root/.local/bin"},
		{"取不到家目录", "wooluo", "", base},
		{"用户名带特殊字符", "bad user", "/home/x", base},
		{"家目录带特殊字符", "wooluo", "/home/wooluo $x", base},
		{"家目录不是绝对路径", "wooluo", "home/wooluo", base},
		{"没有用户名", "", "/home/x", base},
	}
	for _, c := range cases {
		if got := servicePath(func(string) string { return c.home }, c.user); got != c.want {
			t.Errorf("%s：servicePath = %q，应为 %q", c.name, got, c.want)
		}
	}
}

// 取家目录先问 getent，问不到再退回 ~user 展开。
func TestRemoteHomeFallbacks(t *testing.T) {
	var asked []string
	if h := remoteHome(func(cmd string) string { asked = append(asked, cmd); return "" }, "wooluo"); h != "" {
		t.Fatalf("都取不到应为空，得到 %q", h)
	}
	if strings.Join(asked, " ; ") != "getent passwd wooluo | cut -d: -f6 ; echo ~wooluo" {
		t.Fatalf("探测顺序 = %v", asked)
	}
	if h := remoteHome(func(string) string { return "/home/wooluo\n" }, "wooluo"); h != "/home/wooluo" {
		t.Fatalf("home = %q", h)
	}
}

// 重新部署时节点服务正跑着目标文件：直接 cp 覆盖会被内核拒绝（Text file
// busy），部署悄悄落到下一个目录。装法必须是「拷成临时名再 mv 顶替」。
func TestInstallBinCmdReplacesByRename(t *testing.T) {
	cmd := installBinCmd("", "/usr/local/bin")
	want := "cp /tmp/argus-node /usr/local/bin/.argus-node.new && " +
		"chmod 755 /usr/local/bin/.argus-node.new && " +
		"mv -f /usr/local/bin/.argus-node.new /usr/local/bin/argus-node"
	if cmd != want {
		t.Fatalf("installBinCmd = %q，应为 %q", cmd, want)
	}
	// 带 sudo 前缀时三段都要提权（mv 目标在 root 才能写的目录里）
	for _, seg := range strings.Split(installBinCmd("sudo ", "/opt/argus"), " && ") {
		if !strings.HasPrefix(seg, "sudo ") {
			t.Fatalf("每一段都要经过 sudo，得到 %q", seg)
		}
	}
}

// 用测试程序自己当「正在运行的可执行文件」实测一遍：直接覆盖会失败
// （Linux 上必然），临时名 + mv 顶替能成，且本进程不受影响。
func TestInstallOverRunningBinary(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Skip("取不到自身路径:", err.Error())
	}
	dir := filepath.Dir(exe)
	sh := func(c string) error { return exec.Command("/bin/sh", "-c", c).Run() }
	if err := sh("cp " + exe + " " + exe); err == nil && runtime.GOOS == "linux" {
		t.Fatal("Linux 上直接覆盖运行中的可执行文件应当失败（Text file busy）")
	}
	if err := sh("cp " + exe + " /tmp/argus-node"); err != nil {
		t.Skip("无法准备 /tmp/argus-node:", err.Error())
	}
	defer os.Remove("/tmp/argus-node")
	if err := sh(installBinCmd("", dir)); err != nil {
		t.Skipf("本机无法做这项实测（目录可能只读）: %v", err)
	}
}
