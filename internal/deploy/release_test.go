package deploy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// Release 解析与远端下载的回归测试。fakeGitHub 的行为按 2026-11-24 对真实
// 私有仓库（wooluo/argus v0.1.0）实测固化：
//   - 私有仓库：元数据请求不带对的 token → 404；
//   - 资产 API 带 Accept: application/octet-stream → 302 签名地址，
//     地址可无凭据裸下载，否则回资产 JSON；
//   - tag 形如 v0.1.0：不带 v 的 tag 查不到。

// fakeGitHub 最小 GitHub API 替身 + 签名地址指向的文件服务。
type fakeGitHub struct {
	token     string
	bin       []byte // Release 元数据登记的资产内容
	serve     []byte // 文件服务实际返回的内容（空=bin）
	noDigest  bool   // Release 资产不带 digest 字段
	metas     atomic.Int64
	signed    atomic.Int64
	downloads atomic.Int64
	files     *httptest.Server
}

func sha256hex(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func newFakeGitHub(t *testing.T, bin []byte) *fakeGitHub {
	t.Helper()
	f := &fakeGitHub{token: "t0k3n", bin: bin}
	f.files = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.downloads.Add(1)
		if len(f.serve) > 0 {
			_, _ = w.Write(f.serve)
			return
		}
		_, _ = w.Write(f.bin)
	}))
	release := func(w http.ResponseWriter, tag string) {
		asset := map[string]any{"id": 1, "name": "argus-node-linux-amd64", "size": len(f.bin)}
		if !f.noDigest {
			asset["digest"] = "sha256:" + sha256hex(f.bin)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"tag_name": tag,
			"assets":   []any{asset, map[string]any{"id": 2, "name": "argus-server-linux-amd64", "size": 1}},
		})
	}
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Header.Get("Authorization") {
		case "Bearer " + f.token:
		case "Bearer expired":
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"message":"Bad credentials"}`))
			return
		default: // 私有仓库：没带对的 token 一律当作不存在
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"message":"Not Found"}`))
			return
		}
		switch r.URL.Path {
		case "/repos/o/r/releases/latest", "/repos/o/r/releases/tags/v0.1.0":
			f.metas.Add(1)
			release(w, "v0.1.0")
		case "/repos/o/r/releases/assets/1":
			f.signed.Add(1)
			if r.Header.Get("Accept") != "application/octet-stream" {
				_ = json.NewEncoder(w).Encode(map[string]any{"id": 1, "name": "argus-node-linux-amd64"})
				return
			}
			// 查询串带上 shell 元字符（& = + %），顺带覆盖远端命令的引号处理
			http.Redirect(w, r, f.files.URL+"/dl/argus-node?X-Sig=a%2Bb&sp=r&x=1+2", http.StatusFound)
		default:
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"message":"Not Found"}`))
		}
	}))
	old := gitHubAPI
	gitHubAPI = api.URL
	t.Cleanup(func() { gitHubAPI = old; api.Close(); f.files.Close() })
	return f
}

func TestResolveRelease(t *testing.T) {
	bin := []byte("\x7fELFfake-node-binary")
	t.Setenv("ARGUS_RELEASE_REPO", "o/r")

	t.Run("latest：仓库留空取环境变量，资产按架构挑出", func(t *testing.T) {
		f := newFakeGitHub(t, bin)
		a, err := ResolveRelease("", "", "amd64", f.token)
		if err != nil {
			t.Fatalf("意外报错: %v", err)
		}
		if a.Repo != "o/r" || a.Tag != "v0.1.0" || a.Name != "argus-node-linux-amd64" ||
			a.Size != int64(len(bin)) || a.SHA256 != sha256hex(bin) {
			t.Errorf("资产解析不符: %+v", a)
		}
	})
	t.Run("仓库主页地址归一", func(t *testing.T) {
		f := newFakeGitHub(t, bin)
		if _, err := ResolveRelease("https://github.com/o/r/", "latest", "amd64", f.token); err != nil {
			t.Fatalf("意外报错: %v", err)
		}
	})
	t.Run("不带 v 的 tag 补 v 重试", func(t *testing.T) {
		f := newFakeGitHub(t, bin)
		a, err := ResolveRelease("o/r", "0.1.0", "amd64", f.token)
		if err != nil || a.Tag != "v0.1.0" {
			t.Fatalf("期望解析到 v0.1.0，得到 %+v, err=%v", a, err)
		}
	})
	t.Run("资产无 digest 时 SHA256 留空", func(t *testing.T) {
		f := newFakeGitHub(t, bin)
		f.noDigest = true
		a, err := ResolveRelease("o/r", "", "amd64", f.token)
		if err != nil || a.SHA256 != "" {
			t.Fatalf("期望无 digest 的资产，得到 %+v, err=%v", a, err)
		}
	})

	for _, c := range []struct {
		name, repo, tag, arch, token, want string
	}{
		{"私有仓库无 token", "o/r", "", "amd64", "", "私有"},
		{"token 过期", "o/r", "", "amd64", "expired", "无效或已过期"},
		{"tag 不存在", "o/r", "v9.9.9", "amd64", "t0k3n", "v9.9.9"},
		{"tag 含非法字符", "o/r", "v0.1.0;id", "amd64", "t0k3n", "格式无法识别"},
		{"仓库格式非法", "not a repo", "", "amd64", "t0k3n", "owner/repo"},
		{"该架构未发布", "o/r", "", "arm", "t0k3n", "argus-node-linux-arm"},
	} {
		t.Run(c.name, func(t *testing.T) {
			newFakeGitHub(t, bin)
			_, err := ResolveRelease(c.repo, c.tag, c.arch, c.token)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("期望报错含 %q，得到 %v", c.want, err)
			}
		})
	}
}

func TestCheckReleaseRef(t *testing.T) {
	if err := CheckReleaseRef("", "latest"); err != nil {
		t.Errorf("默认仓库/latest 不应报错: %v", err)
	}
	if err := CheckReleaseRef("o/r", "v0.1.0;id"); err == nil {
		t.Error("非法 tag 应被入口预检拦下")
	}
}

func TestSignedURL(t *testing.T) {
	f := newFakeGitHub(t, []byte("x"))
	a, err := ResolveRelease("o/r", "", "amd64", f.token)
	if err != nil {
		t.Fatalf("意外报错: %v", err)
	}
	loc, err := a.SignedURL(f.token)
	if err != nil {
		t.Fatalf("意外报错: %v", err)
	}
	if !strings.Contains(loc, f.files.URL+"/dl/argus-node?X-Sig=a%2Bb&sp=r&x=1+2") {
		t.Errorf("签名地址不符: %s", loc)
	}
	// 只取 302 的 Location，不跟随跳转去下载
	if n := f.downloads.Load(); n != 0 {
		t.Errorf("SignedURL 不应下载资产，实际命中文件服务 %d 次", n)
	}
	if _, err := a.SignedURL("wrong"); err == nil {
		t.Error("鉴权失败时应报错")
	}
}

// localRun 用本地 sh 充当远端执行器——fetchFromGitHub 拼出的完整命令原样
// 执行，真实 curl/wget 分支得以覆盖。path 非空时替换 PATH，用来构造
// 「只有 wget」「都没有」的远端环境。
func localRun(t *testing.T, path string) func(string, time.Duration) (string, error) {
	t.Helper()
	env := []string{}
	for _, kv := range os.Environ() {
		k := strings.ToUpper(strings.SplitN(kv, "=", 2)[0])
		if strings.HasSuffix(k, "PROXY") { // 本机代理设置不干扰 127.0.0.1
			continue
		}
		if path != "" && k == "PATH" {
			continue
		}
		env = append(env, kv)
	}
	if path != "" {
		env = append(env, "PATH="+path)
	}
	env = append(env, "no_proxy=127.0.0.1,localhost", "NO_PROXY=127.0.0.1,localhost")
	return func(cmd string, _ time.Duration) (string, error) {
		c := exec.Command("sh", "-c", cmd)
		c.Env = env
		var b strings.Builder
		c.Stdout, c.Stderr = &b, &b
		err := c.Run()
		return b.String(), err
	}
}

// localProbe 充当 probeOne：按远端命令 wc/sha256sum 的输出形态在本地算出。
func localProbe(dst string) func(string) string {
	return func(string) string {
		b, err := os.ReadFile(dst)
		if err != nil {
			return ""
		}
		return fmt.Sprintf("%d\n%s  %s\n", len(b), sha256hex(b), dst)
	}
}

func fetch(t *testing.T, f *fakeGitHub, cfg SSHConfig, dst string,
	run func(string, time.Duration) (string, error), probe func(string) string) (int64, error, string) {
	t.Helper()
	var st []string
	n, err := fetchFromGitHub(cfg, "amd64", dst, run, probe, func(s string) { st = append(st, s) })
	return n, err, strings.Join(st, "\n")
}

func TestFetchFromGitHub(t *testing.T) {
	bin := []byte("\x7fELF" + strings.Repeat("argus-node\x00", 4096))
	cfgOf := func(f *fakeGitHub) SSHConfig {
		return SSHConfig{Source: SourceGitHub, ReleaseRepo: "o/r", GitHubToken: f.token}
	}

	t.Run("curl：下载 + 字节数/sha256 校验", func(t *testing.T) {
		f := newFakeGitHub(t, bin)
		dst := filepath.Join(t.TempDir(), "argus-node")
		n, err, steps := fetch(t, f, cfgOf(f), dst, localRun(t, ""), localProbe(dst))
		if err != nil {
			t.Fatalf("意外报错: %v", err)
		}
		if got, _ := os.ReadFile(dst); n != int64(len(bin)) || string(got) != string(bin) {
			t.Fatalf("下载内容不符：size=%d bytes=%d", n, len(got))
		}
		if !strings.Contains(steps, "sha256 校验通过") || !strings.Contains(steps, "Release o/r@v0.1.0") {
			t.Errorf("步骤流水不符: %s", steps)
		}
	})

	t.Run("wget：远端只有 wget 时走兜底分支", func(t *testing.T) {
		wget, err := exec.LookPath("wget")
		if err != nil {
			t.Skip("本机无 wget")
		}
		f := newFakeGitHub(t, bin)
		dst := filepath.Join(t.TempDir(), "argus-node")
		// PATH 里只放 wget 和 rm（curl 必须找不到）
		binDir := t.TempDir()
		for _, name := range []string{"wget", "rm"} {
			p := wget
			if name == "rm" {
				if p, err = exec.LookPath("rm"); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.Symlink(p, filepath.Join(binDir, name)); err != nil {
				t.Fatal(err)
			}
		}
		n, err, _ := fetch(t, f, cfgOf(f), dst, localRun(t, binDir), localProbe(dst))
		if err != nil {
			t.Fatalf("意外报错: %v", err)
		}
		if got, _ := os.ReadFile(dst); n != int64(len(bin)) || string(got) != string(bin) {
			t.Fatalf("下载内容不符：size=%d bytes=%d", n, len(got))
		}
	})

	t.Run("远端既无 curl 也无 wget", func(t *testing.T) {
		f := newFakeGitHub(t, bin)
		dst := filepath.Join(t.TempDir(), "argus-node")
		_, err, _ := fetch(t, f, cfgOf(f), dst, localRun(t, t.TempDir()), localProbe(dst))
		if err == nil || !strings.Contains(err.Error(), "curl / wget") {
			t.Fatalf("期望提示缺少下载器，得到 %v", err)
		}
	})

	t.Run("内容与 Release 元数据不符：重下一次后报错", func(t *testing.T) {
		f := newFakeGitHub(t, bin)
		f.serve = []byte("<html>proxy error page</html>")
		dst := filepath.Join(t.TempDir(), "argus-node")
		_, err, steps := fetch(t, f, cfgOf(f), dst, localRun(t, ""), localProbe(dst))
		if err == nil || !strings.Contains(err.Error(), "校验未通过") {
			t.Fatalf("期望校验失败报错，得到 %v", err)
		}
		if f.signed.Load() != 2 || f.downloads.Load() != 2 {
			t.Errorf("期望恰好重试一次：换地址 %d 次、下载 %d 次", f.signed.Load(), f.downloads.Load())
		}
		if !strings.Contains(steps, "重新下载一次") {
			t.Errorf("重试应留步骤流水: %s", steps)
		}
	})

	t.Run("远端连不上 GitHub：报错不带签名地址", func(t *testing.T) {
		f := newFakeGitHub(t, bin)
		f.files.Close()
		dst := filepath.Join(t.TempDir(), "argus-node")
		_, err, _ := fetch(t, f, cfgOf(f), dst, localRun(t, ""), localProbe(dst))
		if err == nil || !strings.Contains(err.Error(), "远端下载失败") ||
			!strings.Contains(err.Error(), "127.0.0.1") {
			t.Fatalf("期望下载失败提示（含 CDN 主机），得到 %v", err)
		}
		// 签名地址本身即凭据，不能随报错外泄
		if strings.Contains(err.Error(), "X-Sig") {
			t.Errorf("报错泄漏了签名地址: %v", err)
		}
	})

	t.Run("远端校验输出被吞：放行并写明未校验", func(t *testing.T) {
		f := newFakeGitHub(t, bin)
		dst := filepath.Join(t.TempDir(), "argus-node")
		n, err, steps := fetch(t, f, cfgOf(f), dst, localRun(t, ""), func(string) string { return "" })
		if err != nil || n != int64(len(bin)) {
			t.Fatalf("期望放行，得到 n=%d err=%v", n, err)
		}
		if !strings.Contains(steps, "未能校验") {
			t.Errorf("放行时应写明未校验: %s", steps)
		}
	})

	t.Run("Release 解析失败不触碰远端", func(t *testing.T) {
		f := newFakeGitHub(t, bin)
		called := false
		_, err, _ := fetch(t, f, SSHConfig{Source: SourceGitHub, ReleaseRepo: "o/r"}, "unused",
			func(string, time.Duration) (string, error) { called = true; return "", nil }, localProbe("unused"))
		if err == nil || !strings.Contains(err.Error(), "私有") || called {
			t.Fatalf("期望解析阶段报错，得到 err=%v remote_called=%v", err, called)
		}
	})
}

func TestShQuote(t *testing.T) {
	for in, want := range map[string]string{
		"a=b&c?d%20e": "'a=b&c?d%20e'",
		"it's":        `'it'\''s'`,
	} {
		if got := shQuote(in); got != want {
			t.Errorf("shQuote(%q) = %s, 期望 %s", in, got, want)
		}
	}
}
