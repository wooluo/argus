// Package server: tunnel.go — SSH 隧道回连的常驻管理。
// 解决"server 在 NAT/内网后，公网节点直连不可能通"：部署用过的 SSH 连接
// 上开 remote forward（VPS 127.0.0.1:17887 → 隧道 → 本机 :7887），节点连
// VPS 本机端口即回到 server。看门狗检测连接死亡自动重拨重建；server 重启
// 后按 nodes.tunnel_ssh 存的凭据恢复。
//
// 同一条连接还把 server 本机的模型服务端口带到远端（见 localModelPorts）：
// 模型接入点写的是 localhost 时，远端节点访问它自己的 127.0.0.1:<port>
// 即可——接入点不必改成 server 的局域网地址，本机服务也不用对外监听。
package server

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/wooluo/argus/internal/deploy"
	"github.com/wooluo/argus/internal/store"
)

// TunnelManager 按节点名管理的隧道集合。
type TunnelManager struct {
	mu      sync.Mutex
	tunnels map[string]*tunnel
	db      *sql.DB // 读模型接入点，决定哪些本机端口随隧道转发
}

type tunnel struct {
	name       string
	cfg        deploy.SSHConfig // 重拨凭据
	client     *ssh.Client
	localPorts []int // 随隧道转发的本机模型端口
	stop       chan struct{}
	stopped    sync.Once

	// lmu 保护下面两个监听器（watchdog 重拨、HTTP 删节点会并发碰它们）
	lmu sync.Mutex
	l   net.Listener   // 远端回连入口
	fwd []net.Listener // 远端访问本机模型的入口
}

func NewTunnelManager(db *sql.DB) *TunnelManager {
	return &TunnelManager{tunnels: map[string]*tunnel{}, db: db}
}

// Attach 建立/接管节点的隧道：client 为 nil 时拨号（重启恢复路径）。
func (m *TunnelManager) Attach(name string, cfg deploy.SSHConfig, client *ssh.Client) error {
	t := &tunnel{name: name, cfg: cfg, client: client, localPorts: m.localModelPorts(),
		stop: make(chan struct{})}
	if t.client == nil {
		c, err := deploy.DialSSH(cfg)
		if err != nil {
			return fmt.Errorf("隧道拨号失败: %w", err)
		}
		t.client = c
	}
	if err := t.serve(); err != nil {
		t.client.Close()
		return err
	}
	m.mu.Lock()
	old := m.tunnels[name]
	m.tunnels[name] = t
	m.mu.Unlock()
	if old != nil {
		old.close()
	}
	go t.watchdog()
	log.Printf("[tunnel] %s 建立成功（远端 %s → 本地 %s）", name, deploy.TunnelRemoteAddr, deploy.TunnelServerAddr)
	return nil
}

// Remove 撤除节点隧道（删节点时调用，远端监听随连接关闭自动释放）。
func (m *TunnelManager) Remove(name string) {
	m.mu.Lock()
	t := m.tunnels[name]
	delete(m.tunnels, name)
	m.mu.Unlock()
	if t != nil {
		t.close()
		log.Printf("[tunnel] %s 已撤除", name)
	}
}

// Status 节点隧道是否存活。
func (m *TunnelManager) Status(name string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, ok := m.tunnels[name]
	return ok
}

// Restore server 重启后按 nodes.tunnel_ssh 凭据恢复全部隧道（尽力而为）。
func (m *TunnelManager) Restore() {
	db := m.db
	if db == nil {
		return
	}
	rows, err := db.Query(`SELECT name,tunnel_ssh FROM nodes WHERE tunnel_ssh != ''`)
	if err != nil {
		return
	}
	type item struct {
		name string
		cfg  deploy.SSHConfig
	}
	var items []item
	for rows.Next() {
		var name, raw string
		if rows.Scan(&name, &raw) == nil && raw != "" {
			var cfg deploy.SSHConfig
			if json.Unmarshal([]byte(raw), &cfg) == nil && cfg.Host != "" {
				items = append(items, item{name, cfg})
			}
		}
	}
	rows.Close()
	for _, it := range items {
		go func(i item) {
			if err := m.Attach(i.name, i.cfg, nil); err != nil {
				log.Printf("[tunnel] %s 恢复失败: %v（看门狗稍后重试）", i.name, err)
				// 恢复失败也注册一条占位（watchdog 兜底重拨）
				m.mu.Lock()
				if _, ok := m.tunnels[i.name]; !ok {
					t := &tunnel{name: i.name, cfg: i.cfg, stop: make(chan struct{})}
					m.tunnels[i.name] = t
					go t.watchdog()
				}
				m.mu.Unlock()
			}
		}(it)
	}
}

// localModelPorts 模型接入点里落在 server 本机回环地址上的端口（去重、升序）：
// 主配置一条，模型池里启用的各一条。
func (m *TunnelManager) localModelPorts() []int {
	if m.db == nil {
		return nil
	}
	var urls []string
	if raw := store.GetSetting(m.db, "llm"); raw != "" {
		var main struct {
			BaseURL string `json:"base_url"`
		}
		_ = json.Unmarshal([]byte(raw), &main)
		urls = append(urls, main.BaseURL)
	}
	if raw := store.GetSetting(m.db, "models"); raw != "" {
		var pool []struct {
			BaseURL string `json:"base_url"`
			Enabled bool   `json:"enabled"`
		}
		_ = json.Unmarshal([]byte(raw), &pool)
		for _, e := range pool {
			if e.Enabled {
				urls = append(urls, e.BaseURL)
			}
		}
	}
	seen := map[int]bool{}
	var ports []int
	for _, u := range urls {
		p, ok := loopbackPort(u)
		if ok && !seen[p] {
			seen[p] = true
			ports = append(ports, p)
		}
	}
	sort.Ints(ports)
	return ports
}

// loopbackPort 取 http(s) 接入点在回环地址（localhost / 127.0.0.0/8 / ::1）
// 上的端口；不在回环上、没写端口或解析不了的一律返回 false。
func loopbackPort(raw string) (int, bool) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return 0, false
	}
	host := u.Hostname()
	if host != "localhost" && !net.ParseIP(host).IsLoopback() {
		return 0, false
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil || port <= 0 || port > 65535 {
		return 0, false
	}
	return port, true
}

// serve 在远端开 remote forward 并桥接到本地 server；本机模型端口一并转发。
func (t *tunnel) serve() error {
	l, err := t.client.Listen("tcp", deploy.TunnelRemoteAddr)
	if err != nil {
		// 端口被占：残留的旧隧道监听（连接已死但远端未释放/手动 ssh -R 在跑）
		return fmt.Errorf("远端监听 %s 失败（被残留隧道或手动 ssh -R 占用？）: %w",
			deploy.TunnelRemoteAddr, err)
	}
	t.lmu.Lock()
	t.l = l
	t.fwd = nil
	t.lmu.Unlock()
	go t.accept(l, deploy.TunnelServerAddr)

	// 模型端口转发失败不拖累隧道本身（远端自己占了该端口时，节点用的就是
	// 远端自己的服务），只记日志。
	var fwd []net.Listener
	var up []int
	for _, port := range t.localPorts {
		remote := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
		fl, err := t.client.Listen("tcp", remote)
		if err != nil {
			log.Printf("[tunnel] %s 模型端口 %s 在远端监听失败（被占用？），节点连不到本机的这个端口: %v",
				t.name, remote, err)
			continue
		}
		// 本机侧拨 localhost 而不是 127.0.0.1：服务只监听 ::1 时也连得上
		go t.accept(fl, net.JoinHostPort("localhost", strconv.Itoa(port)))
		fwd = append(fwd, fl)
		up = append(up, port)
	}
	t.lmu.Lock()
	t.fwd = append(t.fwd, fwd...)
	t.lmu.Unlock()
	if len(up) > 0 {
		log.Printf("[tunnel] %s 本机模型端口已随隧道下发：%v", t.name, up)
	}
	return nil
}

func (t *tunnel) accept(l net.Listener, local string) {
	for {
		conn, err := l.Accept()
		if err != nil {
			return
		}
		go t.bridge(conn, local)
	}
}

// bridge 把远端进来的连接（已过隧道）与本地 addr 对拷。
func (t *tunnel) bridge(remote net.Conn, local string) {
	lc, err := net.Dial("tcp", local)
	if err != nil {
		log.Printf("[tunnel] %s 连本机 %s 失败: %v", t.name, local, err)
		remote.Close()
		return
	}
	done := make(chan struct{}, 2)
	go func() { io.Copy(lc, remote); done <- struct{}{} }()
	go func() { io.Copy(remote, lc); done <- struct{}{} }()
	<-done
	lc.Close()
	remote.Close()
}

// closeListeners 关掉远端侧的全部监听（连接本身不动）。
func (t *tunnel) closeListeners() {
	t.lmu.Lock()
	defer t.lmu.Unlock()
	if t.l != nil {
		t.l.Close()
		t.l = nil
	}
	for _, f := range t.fwd {
		f.Close()
	}
	t.fwd = nil
}

// watchdog 20s 探活；连接死亡自动重拨重建（网络抖动/NAT 超时常态）。
func (t *tunnel) watchdog() {
	tick := time.NewTicker(20 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-t.stop:
			return
		case <-tick.C:
			if t.alive() {
				continue
			}
			log.Printf("[tunnel] %s 连接死亡，重拨…", t.name)
			t.reconnect()
		}
	}
}

func (t *tunnel) alive() bool {
	if t.client == nil {
		return false
	}
	s, err := t.client.NewSession()
	if err != nil {
		return false
	}
	defer s.Close()
	done := make(chan error, 1)
	go func() { done <- s.Run("echo 1") }()
	select {
	case <-done:
		return true
	case <-time.After(10 * time.Second):
		return false
	}
}

// reconnect 重拨 + 重建转发（退避重试，直到成功或隧道被 Remove）。
func (t *tunnel) reconnect() {
	t.closeListeners()
	if t.client != nil {
		t.client.Close()
	}
	for i := 0; ; i++ {
		select {
		case <-t.stop:
			return
		default:
		}
		c, err := deploy.DialSSH(t.cfg)
		if err == nil {
			t.client = c
			if err := t.serve(); err == nil {
				log.Printf("[tunnel] %s 重连成功", t.name)
				return
			}
			c.Close()
		}
		if i%6 == 0 { // 每约 1 分钟打一条，避免刷屏
			log.Printf("[tunnel] %s 重连中（第 %d 次）: %v", t.name, i+1, err)
		}
		time.Sleep(10 * time.Second)
	}
}

func (t *tunnel) close() {
	t.stopped.Do(func() { close(t.stop) })
	t.closeListeners()
	if t.client != nil {
		t.client.Close()
	}
}
