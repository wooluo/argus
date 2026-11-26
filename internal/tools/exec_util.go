package tools

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// ---------- 远程执行通道（对应原版 core/kali.py 的 exec 面，本地节点的直通实现） ----------
//
// 蓝本里 Kali 远端优先（kali.remote_which / remote_exec）；argus 节点体系下
// 本机即执行环境：execOn 就是对 exec.Cmd 的封装，保持同一调用形状以便
// 后续接远程节点时替换 transport。

// toolPath 解析工具二进制定位：环境变量 ARGUS_TOOL_<NAME>（旧写法
// argus_TOOL_<NAME> 仍认）> PATH 查找 > 名称原样。
func toolPath(name string) string {
	for _, prefix := range []string{"ARGUS_TOOL_", "argus_TOOL_"} {
		if p := os.Getenv(prefix + strings.ToUpper(name)); p != "" {
			return p
		}
	}
	if p, err := exec.LookPath(name); err == nil {
		return p
	}
	return name
}

// ExtendPATH 把节点自己会往里装工具的目录补进 PATH，返回补了哪些。
//
// systemd 起的服务只有系统默认 PATH（不读 .zshrc）：kali_install 把官方
// 二进制装到 ~/bin、go install 装到 ~/go/bin，装了也找不到；部署它的那个
// 用户放在 ~/bin 里的工具同理（部署时会把它写进服务的 PATH）。家目录下的
// 三个目录即使现在不存在也先补上——工具是运行中才装的。
func ExtendPATH() []string {
	var want []string // [目录, 是否必须已存在]
	home, _ := os.UserHomeDir()
	if home != "" {
		want = append(want,
			filepath.Join(home, "bin"), "no",
			filepath.Join(home, "go", "bin"), "no",
			filepath.Join(home, ".local", "bin"), "no")
	}
	want = append(want, "/usr/local/go/bin", "yes", "/snap/bin", "yes")

	cur := filepath.SplitList(os.Getenv("PATH"))
	have := map[string]bool{}
	for _, d := range cur {
		have[d] = true
	}
	var added []string
	for i := 0; i+1 < len(want); i += 2 {
		dir, mustExist := want[i], want[i+1] == "yes"
		if dir == "" || have[dir] {
			continue
		}
		if mustExist {
			if st, err := os.Stat(dir); err != nil || !st.IsDir() {
				continue
			}
		}
		have[dir] = true
		added = append(added, dir)
	}
	if len(added) > 0 {
		_ = os.Setenv("PATH", strings.Join(append(cur, added...), string(os.PathListSeparator)))
	}
	return added
}

// toolFailed 外部工具非零退出时的判定：没有拿到任何结果就不算「扫到 0 个」，
// 而是没跑起来，要把原因和工具自己的报错带回去。
//
// 以前只看输出是否为空——工具只要打印了用法错误、模板缺失之类的信息，非零
// 退出码就被吞掉，模型拿到的是「0 个存活 / 0 个发现」，不知道工具挂了
// （节点上 httpx 0.2 秒返回 alive:0、nuclei 0.1 秒返回空，都是这么来的）。
func toolFailed(name string, out string, err error, gotResults bool) error {
	if err == nil || gotResults {
		return nil
	}
	return fmt.Errorf("%s 没有跑起来（%v）：%s", name, exitReason(err),
		Truncate(tailLines(out, 4), 400))
}

// InterruptedNote 工具非零退出但已有部分结果时，附在结果里提醒模型。
func InterruptedNote(name string, out string, err error, gotResults bool) string {
	if err == nil || !gotResults {
		return ""
	}
	return fmt.Sprintf("%s 未正常结束（%v），以上只是中断前拿到的部分结果", name, exitReason(err))
}

func exitReason(err error) string {
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		if code := ee.ExitCode(); code >= 0 {
			return fmt.Sprintf("退出码 %d", code)
		}
		return "被信号终止（超时或内存不足）"
	}
	return err.Error()
}

// tailLines 取输出末尾 n 行非空内容（报错信息通常在最后）。
func tailLines(out string, n int) string {
	lines := []string{}
	for _, l := range strings.Split(strings.TrimSpace(out), "\n") {
		if l = strings.TrimSpace(l); l != "" {
			lines = append(lines, l)
		}
	}
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, " | ")
}

// toolAvailable 工具是否可执行。
func toolAvailable(name string) bool {
	_, err := exec.LookPath(toolPath(name))
	return err == nil
}

// runTool 执行外部工具，带超时与 stdin 注入；返回合并 stdout+stderr。
func runTool(ctx context.Context, timeout time.Duration, stdin string, argv ...string) (string, error) {
	if len(argv) == 0 {
		return "", fmt.Errorf("empty argv")
	}
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(cctx, argv[0], argv[1:]...)
	cmd.Env = os.Environ()
	var out strings.Builder
	cmd.Stdout = &out
	cmd.Stderr = &out
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	err := cmd.Run()
	return out.String(), err
}

// ---------- DNS 泛解析过滤（对应原版 core/dns_utils.py） ----------

var dnsSem = make(chan struct{}, 100)

// resolveHost 3s 超时解析 A/AAAA 记录集合；失败返回空。
func resolveHost(host string) map[string]bool {
	d := net.Resolver{}
	cctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	out := map[string]bool{}
	addrs, err := d.LookupIPAddr(cctx, host)
	if err != nil {
		return out
	}
	for _, a := range addrs {
		out[a.IP.String()] = true
	}
	return out
}

// wildcardCheck 随机编造子域名探测泛解析：resolved >= max(2, probes-1) 判泛解析。
func wildcardCheck(domain string, probes int) (bool, map[string]bool) {
	if probes < 1 {
		probes = 4
	}
	wips := map[string]bool{}
	resolved := 0
	var names []string
	seed := time.Now().UnixNano()
	for i := 0; i < probes; i++ {
		names = append(names, fmt.Sprintf("%c%c%c%c%c%c%c%c%c%c%c%c%c%c%d",
			'a'+rune(seed%26+0), 'a'+rune((seed/26)%26), 'a'+rune((seed/676)%26),
			'a'+rune((seed/17576)%26), 'a'+rune((seed/456976)%26), 'a'+rune((seed/11881376)%26),
			'b'+rune(i), 'c'+rune(i), 'd'+rune(i), 'e'+rune(i), 'f'+rune(i),
			'g'+rune(i), 'h'+rune(i), 'i'+rune(i), i))
	}
	for _, n := range names {
		if ips := resolveHost(n + "." + domain); len(ips) > 0 {
			resolved++
			for ip := range ips {
				wips[ip] = true
			}
		}
	}
	return resolved >= max(2, probes-1), wips
}

// filterWildcard 对枚举结果做泛解析过滤（假资产剔除，解析失败保守保留）。
func filterWildcard(domain string, subs []string) (real []string, wildCount, unresolved int, wildcard bool) {
	if len(subs) == 0 {
		return nil, 0, 0, false
	}
	isWild, wips := wildcardCheck(domain, 4)
	if !isWild {
		return subs, 0, 0, false
	}
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, s := range subs {
		wg.Add(1)
		go func(s string) {
			defer wg.Done()
			select {
			case dnsSem <- struct{}{}:
			case <-context.Background().Done(): // 永不触发，仅占位
				return
			}
			defer func() { <-dnsSem }()
			ips := resolveHost(s)
			mu.Lock()
			defer mu.Unlock()
			if len(ips) == 0 {
				unresolved++
				real = append(real, s) // 解析失败保守保留
			} else if subsetOf(ips, wips) {
				wildCount++ // 完全落在泛解析 IP → 假资产
			} else {
				real = append(real, s)
			}
		}(s)
	}
	wg.Wait()
	return real, wildCount, unresolved, true
}

func subsetOf(a, b map[string]bool) bool {
	for k := range a {
		if !b[k] {
			return false
		}
	}
	return true
}

// ---------- 公共 HTTP 抓取（auth_session http_fetch 与 adapters 共用） ----------

// httpClient 15s 超时、跳过 TLS 校验（内网自签证书常态），跟随重定向。
func httpClient() *http.Client {
	return &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
			DisableKeepAlives: true,
		},
	}
}

// fetchRaw 基础抓取：返回 (状态码, 响应体, 错误)。
func fetchRaw(ctx context.Context, method, rawURL string, headers map[string]string, body string) (int, string, error) {
	var rdr io.Reader
	if body != "" {
		rdr = strings.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, rawURL, rdr)
	if err != nil {
		return 0, "", err
	}
	req.Header.Set("User-Agent", "Argus/0.1 (+https://github.com/wooluo/argus)")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := httpClient().Do(req)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20)) // 8MB 上限
	if err != nil {
		return resp.StatusCode, "", err
	}
	return resp.StatusCode, string(b), nil
}

// jsonLines 从混合输出中逐行解析 JSON（httpx/nuclei JSONL 输出共用）。
func jsonLines(out string) []map[string]any {
	var list []map[string]any
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "{") {
			continue
		}
		var m map[string]any
		if json.Unmarshal([]byte(line), &m) == nil {
			list = append(list, m)
		}
	}
	return list
}

// toolTimeout 默认工具超时（对应原版 get_limits()["tool_timeout"]=600s）。
const toolTimeout = 600 * time.Second

// max Go 1.22 内建 max 已可用（1.21+），此处不重复定义。
