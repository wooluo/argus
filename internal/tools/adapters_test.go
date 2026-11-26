package tools

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// anyScope 放行所有目标的范围护栏。
type anyScope struct{}

func (anyScope) CheckHost(string) bool   { return true }
func (anyScope) CheckURL(string) bool    { return true }
func (anyScope) EnsureHost(string) error { return nil }
func (anyScope) EnsureURL(string) error  { return nil }
func (anyScope) Describe() string        { return "test" }

func execCtx() *Context {
	return &Context{Scope: anyScope{}, Reporter: &captureReporter{}}
}

func oneTarget() map[string]any {
	return map[string]any{"targets": []any{"https://example.com"}}
}

// fakeTool 在临时目录放一个同名脚本顶替外部工具，并把它指给 ARGUS_TOOL_<NAME>。
func fakeTool(t *testing.T, name, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"+body), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ARGUS_TOOL_"+strings.ToUpper(name), p)
	return p
}

// 真实节点上踩到的：httpx 非零退出、把参数错误打进了输出，旧逻辑只看输出是否
// 为空，于是当成「15 个目标 0 个存活」交给了模型。
func TestHTTPXSurfacesToolFailure(t *testing.T) {
	fakeTool(t, "httpx", `
case "$1" in -version) echo "projectdiscovery httpx"; exit 0 ;; esac
echo "[err] flag provided but not defined: -title"
exit 2
`)
	_, err := HttpxProbeTool{}.Execute(context.Background(), oneTarget(), execCtx())
	if err == nil {
		t.Fatal("httpx 没跑起来，不应返回成功")
	}
	for _, want := range []string{"没有跑起来", "退出码 2", "flag provided but not defined"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("报错应包含 %q，得到: %v", want, err)
		}
	}
}

// Kali 上有同名异物的 Python 客户端 httpx，认 banner 把它拦下来。
func TestHTTPXRejectsLookalike(t *testing.T) {
	fakeTool(t, "httpx", `echo "1.0.1"`)
	_, err := HttpxProbeTool{}.Execute(context.Background(), oneTarget(), execCtx())
	if err == nil || !strings.Contains(err.Error(), "不是 ProjectDiscovery 版本") ||
		!strings.Contains(err.Error(), "ARGUS_TOOL_HTTPX") {
		t.Fatalf("应指出 httpx 不是 PD 版本并给出指定路径的办法，得到: %v", err)
	}
}

// 没跑完但已有结果：结果照给，附一句提醒。
func TestHTTPXPartialResultsCarryNote(t *testing.T) {
	fakeTool(t, "httpx", `
case "$1" in -version) echo "projectdiscovery httpx"; exit 0 ;; esac
cat >/dev/null
echo '{"url":"https://example.com","status_code":200}'
exit 1
`)
	out, err := HttpxProbeTool{}.Execute(context.Background(), oneTarget(), execCtx())
	if err != nil {
		t.Fatalf("有结果就不该判失败: %v", err)
	}
	if !strings.Contains(out, `"alive":1`) || !strings.Contains(out, "未正常结束") {
		t.Fatalf("应带出 1 个存活结果和中断提醒，得到: %s", out)
	}
}

// 服务以 root 跑时 HOME 下没有 nuclei 模板：第一次扫描先自动装，装上后正常扫。
func TestNucleiInstallsMissingTemplates(t *testing.T) {
	t.Setenv("NUCLEI_TEMPLATES_DIRECTORY", t.TempDir())
	nucleiTmpl = nucleiTemplateState{}
	marker := filepath.Join(t.TempDir(), "installed")
	fakeTool(t, "nuclei", `
case "$1" in
  -update-templates) : > "`+marker+`"; mkdir -p "$NUCLEI_TEMPLATES_DIRECTORY/cves"; exit 0 ;;
esac
cat >/dev/null
echo '{"template-id":"x","matched-at":"https://example.com","info":{"severity":"low","name":"X"}}'
`)
	out, err := NucleiScanTool{}.Execute(context.Background(), oneTarget(), execCtx())
	if err != nil {
		t.Fatalf("自动装上模板后应能扫描: %v", err)
	}
	if _, err := os.Stat(marker); err != nil {
		t.Fatal("模板缺失时没有先自动安装")
	}
	if !strings.Contains(out, `"findings":1`) {
		t.Fatalf("应报出 1 个命中，得到: %s", out)
	}
}

// 模板装不上时把安装器的报错带回去，而不是「0 个发现」。
func TestNucleiReportsMissingTemplates(t *testing.T) {
	t.Setenv("NUCLEI_TEMPLATES_DIRECTORY", t.TempDir())
	nucleiTmpl = nucleiTemplateState{}
	fakeTool(t, "nuclei", `
case "$1" in -update-templates) echo "[ERR] network unreachable"; exit 1 ;; esac
exit 0
`)
	_, err := NucleiScanTool{}.Execute(context.Background(), oneTarget(), execCtx())
	if err == nil || !strings.Contains(err.Error(), "模板库缺失") ||
		!strings.Contains(err.Error(), "network unreachable") {
		t.Fatalf("应报出模板缺失并带上安装器输出，得到: %v", err)
	}
}

func TestToolFailed(t *testing.T) {
	// 真被信号杀掉的进程：ExitError 的退出码是 -1
	killed := exec.Command("/bin/sh", "-c", "kill -9 $$").Run()
	cases := []struct {
		name    string
		err     error
		got     bool
		wantErr bool
		want    string
	}{
		{"正常退出", nil, false, false, ""},
		{"有结果就不算失败", errors.New("x"), true, false, ""},
		{"非零退出且无结果", exec.Command("/bin/sh", "-c", "exit 3").Run(), false, true, "退出码 3"},
		{"被信号终止且无结果", killed, false, true, "被信号终止"},
	}
	for _, c := range cases {
		err := toolFailed("nmap", "line\n[ERR] boom", c.err, c.got)
		if (err != nil) != c.wantErr {
			t.Errorf("%s：err = %v", c.name, err)
			continue
		}
		if err != nil && (!strings.Contains(err.Error(), "nmap") || !strings.Contains(err.Error(), "[ERR] boom") ||
			!strings.Contains(err.Error(), c.want)) {
			t.Errorf("%s：报错 = %v，应含工具名、工具输出和 %q", c.name, err, c.want)
		}
	}
}

// systemd 起的服务 PATH 里没有家目录下的工具目录（kali_install 装到 ~/bin、
// go install 装到 ~/go/bin）；补进去，且只补一次。
func TestExtendPATH(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("PATH", "/usr/bin:/bin")
	got := ExtendPATH()
	want := []string{filepath.Join(home, "bin"), filepath.Join(home, "go", "bin"),
		filepath.Join(home, ".local", "bin")}
	for _, d := range []string{"/usr/local/go/bin", "/snap/bin"} { // 系统级目录：存在才补
		if st, err := os.Stat(d); err == nil && st.IsDir() {
			want = append(want, d)
		}
	}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("补进 PATH 的目录 = %v，应为 %v（家目录下的三个，即使还不存在）", got, want)
	}
	if p := os.Getenv("PATH"); !strings.HasPrefix(p, "/usr/bin:/bin:") || !strings.Contains(p, filepath.Join(home, "go", "bin")) {
		t.Fatalf("PATH = %q", p)
	}
	if again := ExtendPATH(); len(again) != 0 {
		t.Fatalf("第二次不应重复补，得到 %v", again)
	}
}

// 旧写法 argus_TOOL_<NAME> 写在文档之外但有人可能在用，两种都认。
func TestToolPathOverride(t *testing.T) {
	t.Setenv("argus_TOOL_NMAP", "/old/path/nmap")
	if got := toolPath("nmap"); got != "/old/path/nmap" {
		t.Fatalf("旧写法 = %q", got)
	}
	t.Setenv("ARGUS_TOOL_NMAP", "/new/path/nmap")
	if got := toolPath("nmap"); got != "/new/path/nmap" {
		t.Fatalf("新写法应优先 = %q", got)
	}
}
