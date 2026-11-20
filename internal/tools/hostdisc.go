package tools

// 移植自 AutoPentest tools/builtin/host_discovery.py —— 网段存活主机发现。
// 原版 Kali 远端探测在 argus 节点模型下恒为本地探测（本机即执行环境）。

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"
)

var probePorts = []int{22, 80, 443, 445, 3389, 8080}

type HostDiscoveryTool struct{}

func (HostDiscoveryTool) Name() string { return "host_discovery" }

func (HostDiscoveryTool) Description() string {
	return "网段存活主机发现（TCP ping，无需特权）。输入 CIDR 网段（如 10.0.1.0/24）" +
		"或 IP 列表，并发探测常见端口判定存活，返回存活 IP 列表并存入资产库。" +
		"对网段做摸底的第一步；比 nmap -sn 更可靠（后者非 root 无 raw socket 不可用）。"
}

func (HostDiscoveryTool) Parameters() map[string]any {
	return Schema(map[string]any{
		"target": Prop("string", "CIDR 网段（10.0.1.0/24）或逗号分隔的 IP 列表"),
	}, "target")
}

func incIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// expandCIDR 展开 CIDR 为主机列表（对应 python ip_network.hosts()：去网络/广播地址）。
func expandCIDR(target string) ([]string, error) {
	ip, ipnet, err := net.ParseCIDR(target)
	if err != nil {
		return nil, err
	}
	var out []string
	for cur := ip.Mask(ipnet.Mask); ipnet.Contains(cur); incIP(cur) {
		out = append(out, cur.String())
	}
	if len(out) > 2 { // 去掉网络地址与广播地址（/31、/32 除外）
		out = out[1 : len(out)-1]
	}
	return out, nil
}

func (HostDiscoveryTool) Execute(ctx context.Context, args map[string]any, tc *Context) (string, error) {
	target := strings.TrimSpace(ArgString(args, "target", ""))
	if target == "" {
		return "", Errorf("target 为空")
	}
	var ips []string
	if strings.Contains(target, "/") {
		list, err := expandCIDR(target)
		if err != nil {
			return "", Errorf("非法网段: %s (%v)", target, err)
		}
		if len(list) > 1024 {
			return "", Errorf("网段过大（%d 主机），请拆分为 /24 以下", len(list))
		}
		ips = list
	} else {
		for _, part := range strings.Split(target, ",") {
			part = strings.TrimSpace(part)
			if net.ParseIP(part) == nil {
				return "", Errorf("非法 IP: %s", part)
			}
			ips = append(ips, part)
		}
	}
	for _, ip := range ips {
		if err := tc.Scope.EnsureHost(ip); err != nil {
			return "", err
		}
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}

	// 并发 TCP 探测（信号量 128，单连接 1.5s 超时，对应原版 _local_probe）
	sem := make(chan struct{}, 128)
	var mu sync.Mutex
	var alive []string
	var wg sync.WaitGroup
	for _, ip := range ips {
		wg.Add(1)
		go func(ip string) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				return
			}
			defer func() { <-sem }()
			for _, port := range probePorts {
				d := net.Dialer{Timeout: 1500 * time.Millisecond}
				conn, err := d.DialContext(ctx, "tcp",
					net.JoinHostPort(ip, fmt.Sprintf("%d", port)))
				if err == nil {
					conn.Close()
					mu.Lock()
					alive = append(alive, ip)
					mu.Unlock()
					return
				}
			}
		}(ip)
	}
	wg.Wait()
	sort.Strings(alive)

	for _, ip := range alive {
		tc.Reporter.SaveAsset(ctx, "ip", ip, map[string]any{"alive": true})
	}
	return MustJSON(map[string]any{
		"tool": "host_discovery", "target": target,
		"scanned": len(ips), "alive": len(alive),
		"alive_hosts": alive, "via": "local",
	}), nil
}

func init() { Register(HostDiscoveryTool{}) }
