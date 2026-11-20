package tools

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// ---------- 远程执行通道（对应原版 core/kali.py 的 exec 面，本地节点的直通实现） ----------
//
// 蓝本里 Kali 远端优先（kali.remote_which / remote_exec）；argus 节点体系下
// 本机即执行环境：execOn 就是对 exec.Cmd 的封装，保持同一调用形状以便
// 后续接远程节点时替换 transport。

// toolPath 解析工具二进制定位：环境变量 argus_TOOL_<NAME> > PATH 查找 > 名称原样。
func toolPath(name string) string {
	env := "argus_TOOL_" + strings.ToUpper(name)
	if p := os.Getenv(env); p != "" {
		return p
	}
	if p, err := exec.LookPath(name); err == nil {
		return p
	}
	return name
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
