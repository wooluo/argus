package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"
)

// ===== port_scan（对应 builtin/port_scan.py：自研 TCP connect 扫描，无需特权） =====

var topPorts = []int{
	21, 22, 23, 25, 53, 80, 81, 110, 135, 139, 143, 443, 445, 993, 995,
	1080, 1433, 1521, 2049, 2181, 2375, 2376, 3306, 3389, 4443, 4848,
	5000, 5432, 5601, 5900, 5984, 6379, 6443, 7001, 7002, 7070, 8000,
	8069, 8080, 8081, 8088, 8089, 8161, 8443, 8888, 9000, 9001, 9090,
	9200, 9300, 9443, 10000, 10250, 11211, 15672, 27017, 28017, 50070,
}

var serviceHints = map[int]string{
	21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
	81: "http", 110: "pop3", 135: "msrpc", 139: "netbios", 143: "imap",
	443: "https", 445: "smb", 993: "imaps", 995: "pop3s", 1080: "socks",
	1433: "mssql", 1521: "oracle", 2049: "nfs", 2181: "zookeeper", 2375: "docker",
	2376: "docker-tls", 3306: "mysql", 3389: "rdp", 4443: "http", 4848: "glassfish",
	5000: "http", 5432: "postgresql", 5601: "kibana", 5900: "vnc", 5984: "couchdb",
	6379: "redis", 6443: "kubernetes-api", 7001: "weblogic", 7002: "weblogic-tls",
	7070: "http", 8000: "http", 8069: "hadoop-yarn", 8080: "http", 8081: "http",
	8088: "http", 8089: "jenkins", 8161: "activemq", 8443: "https", 8888: "http",
	9000: "http", 9001: "http", 9090: "http", 9200: "elasticsearch", 9300: "elasticsearch",
	9443: "https", 10000: "webmin", 10250: "kubernetes", 11211: "memcached",
	15672: "rabbitmq-mgmt", 27017: "mongodb", 28017: "mongodb-web", 50070: "hadoop",
}

// PortScanTool port_scan：单主机或 CIDR 网段 TCP 扫描。
type PortScanTool struct{}

func (PortScanTool) Name() string { return "port_scan" }
func (PortScanTool) Description() string {
	return "TCP 端口扫描（自研，轻量，无需特权）。支持单主机或 CIDR 网段（如 10.0.1.0/24，" +
		"会先做存活发现再扫端口），返回开放端口与服务猜测，结果存入资产库。适合快速摸底。"
}
func (PortScanTool) Parameters() map[string]any {
	return Schema(map[string]any{
		"host": Prop("string", "目标 IP / 域名 / CIDR 网段"),
	}, "host")
}
func (PortScanTool) Execute(ctx context.Context, args map[string]any, tc *Context) (string, error) {
	host := strings.TrimSpace(ArgString(args, "host", ""))
	if host == "" {
		return "", Errorf("host 为空")
	}
	if strings.Contains(host, "/") { // CIDR：先存活发现再逐台扫
		discOut, err := (HostDiscoveryTool{}).Execute(ctx, map[string]any{"target": host}, tc)
		if err != nil {
			return "", err
		}
		var disc struct {
			AliveHosts []string `json:"alive_hosts"`
			Alive      int      `json:"alive"`
		}
		_ = json.Unmarshal([]byte(discOut), &disc)
		var all []map[string]any
		for _, ip := range disc.AliveHosts {
			rs, err := scanOneHost(ctx, ip, tc)
			if err != nil {
				return "", err
			}
			all = append(all, rs...)
		}
		return MustJSON(map[string]any{
			"tool": "port_scan", "host": host,
			"alive_hosts": disc.Alive, "open_ports": len(all), "results": all,
		}), nil
	}
	// 非法主机名拦截（与蓝本一致：IP 直接过，域名要求字母数字-点）
	if net.ParseIP(host) == nil {
		cleaned := strings.ReplaceAll(strings.ReplaceAll(host, ".", ""), "-", "")
		for _, r := range cleaned {
			if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')) {
				return "", Errorf("非法主机: %s", host)
			}
		}
	}
	if err := tc.Scope.EnsureHost(host); err != nil {
		return "", err
	}
	results, err := scanOneHost(ctx, host, tc)
	if err != nil {
		return "", err
	}
	return MustJSON(map[string]any{
		"tool": "port_scan", "host": host, "open_ports": len(results), "results": results,
	}), nil
}

// scanOneHost 并发 TCP connect 扫一台主机的 TOP 端口。
func scanOneHost(ctx context.Context, host string, tc *Context) ([]map[string]any, error) {
	if err := tc.Scope.EnsureHost(host); err != nil {
		return nil, err
	}
	var mu sync.Mutex
	var open []int
	var wg sync.WaitGroup
	sem := make(chan struct{}, 128)
	for _, p := range topPorts {
		wg.Add(1)
		go func(port int) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				return
			}
			defer func() { <-sem }()
			conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, fmt.Sprint(port)), 3*time.Second)
			if err != nil {
				return
			}
			_ = conn.Close()
			mu.Lock()
			open = append(open, port)
			mu.Unlock()
		}(p)
	}
	wg.Wait()
	sort.Ints(open)
	results := []map[string]any{}
	for _, p := range open {
		svc := "unknown"
		if s, ok := serviceHints[p]; ok {
			svc = s
		}
		r := map[string]any{"host": host, "port": p, "service": svc}
		results = append(results, r)
		tc.Reporter.SaveAsset(ctx, "port", fmt.Sprintf("%s:%d", host, p), r)
	}
	return results, nil
}

func init() { Register(PortScanTool{}) }
