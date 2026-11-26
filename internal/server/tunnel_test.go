package server

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"database/sql"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/wooluo/argus/internal/deploy"
	"github.com/wooluo/argus/internal/store"
)

// fwdServer 是支持 remote forward 的进程内 SSH 服务端。为了在同一台机器上
// 把「远端的 127.0.0.1:<port>」和「本机的 <port>」区分开，它对每个转发请求
// 实际监听一个临时端口，但回给客户端的通道地址仍是请求的那个。
type fwdServer struct {
	mu    sync.Mutex
	ports map[int]int // 请求转发的端口 → 实际监听的端口
	ln    net.Listener
}

func startFwdServer(t *testing.T) *fwdServer {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &ssh.ServerConfig{
		PasswordCallback: func(ssh.ConnMetadata, []byte) (*ssh.Permissions, error) {
			return &ssh.Permissions{}, nil
		},
	}
	cfg.AddHostKey(signer)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &fwdServer{ports: map[int]int{}, ln: ln}
	t.Cleanup(func() { ln.Close() })

	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			sc, chans, reqs, err := ssh.NewServerConn(c, cfg)
			if err != nil {
				c.Close()
				continue
			}
			go func() {
				for nc := range chans {
					nc.Reject(ssh.Prohibited, "not supported")
				}
			}()
			go s.handleForwards(sc, reqs)
		}
	}()
	return s
}

func (s *fwdServer) port() int {
	return s.ln.Addr().(*net.TCPAddr).Port
}

// mapped 返回请求转发的端口在「远端」实际监听的端口，没转发过返回 0。
func (s *fwdServer) mapped(reqPort int) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ports[reqPort]
}

func (s *fwdServer) handleForwards(sc *ssh.ServerConn, reqs <-chan *ssh.Request) {
	for r := range reqs {
		if r.Type != "tcpip-forward" {
			if r.WantReply {
				r.Reply(false, nil)
			}
			continue
		}
		var req struct {
			Addr string
			Port uint32
		}
		if err := ssh.Unmarshal(r.Payload, &req); err != nil {
			r.Reply(false, nil)
			continue
		}
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			r.Reply(false, nil)
			continue
		}
		s.mu.Lock()
		s.ports[int(req.Port)] = ln.Addr().(*net.TCPAddr).Port
		s.mu.Unlock()
		r.Reply(true, ssh.Marshal(struct{ Port uint32 }{uint32(req.Port)}))
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				go s.relay(sc, c, req.Addr, req.Port)
			}
		}()
	}
}

// relay 把「远端节点」连进来的连接通过 forwarded-tcpip 通道送回客户端。
func (s *fwdServer) relay(sc *ssh.ServerConn, c net.Conn, addr string, port uint32) {
	defer c.Close()
	ch, rq, err := sc.OpenChannel("forwarded-tcpip", ssh.Marshal(struct {
		Addr       string
		Port       uint32
		OriginAddr string
		OriginPort uint32
	}{addr, port, "127.0.0.1", 40000}))
	if err != nil {
		return
	}
	defer ch.Close()
	go ssh.DiscardRequests(rq)
	done := make(chan struct{}, 2)
	go func() { io.Copy(ch, c); ch.CloseWrite(); done <- struct{}{} }()
	go func() { io.Copy(c, ch); done <- struct{}{} }()
	<-done
}

func openTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func TestLoopbackPort(t *testing.T) {
	cases := []struct {
		in   string
		port int
		ok   bool
	}{
		{"http://localhost:1234/v1", 1234, true},
		{"http://127.0.0.1:1234/v1", 1234, true},
		{"http://[::1]:1234/v1", 1234, true},
		{"  https://localhost:8443/v1  ", 8443, true},
		{"https://open.bigmodel.cn/api/coding/paas/v4", 0, false}, // 没写端口
		{"http://10.211.55.2:1234/v1", 0, false},                  // 不是回环地址
		{"http://0.0.0.0:1234/v1", 0, false},
		{"ftp://localhost:21/", 0, false},
		{"http://localhost:0/v1", 0, false},
		{"http://localhost:70000/v1", 0, false},
		{"", 0, false},
		{"not a url", 0, false},
	}
	for _, c := range cases {
		port, ok := loopbackPort(c.in)
		if ok != c.ok || port != c.port {
			t.Errorf("loopbackPort(%q) = %d,%v，应为 %d,%v", c.in, port, ok, c.port, c.ok)
		}
	}
}

func TestLocalModelPorts(t *testing.T) {
	db := openTestDB(t)
	if err := store.SetSetting(db, "llm", `{"base_url":"http://localhost:1234/v1","model":"m"}`); err != nil {
		t.Fatal(err)
	}
	if err := store.SetSetting(db, "models",
		`[{"id":"a","base_url":"https://open.bigmodel.cn/api/coding/paas/v4","enabled":true},
		  {"id":"b","base_url":"http://127.0.0.1:1234/v1","enabled":true},
		  {"id":"c","base_url":"http://localhost:8080/v1","enabled":true},
		  {"id":"d","base_url":"http://localhost:9999/v1","enabled":false},
		  {"id":"e","base_url":"http://10.0.0.5:8000/v1","enabled":true}]`); err != nil {
		t.Fatal(err)
	}
	got := NewTunnelManager(db).localModelPorts()
	if fmt.Sprint(got) != "[1234 8080]" {
		t.Fatalf("localModelPorts = %v，应为 [1234 8080]（回环端口去重升序，未启用的和外部地址不算）", got)
	}
	if p := (&TunnelManager{}).localModelPorts(); p != nil {
		t.Fatalf("没有 db 时应为空，得到 %v", p)
	}
}

// TestTunnelForwardsLocalModelPort 回归：节点跑在远端（Kali 虚拟机 / VPS），
// 模型接入点写的是 server 本机的 localhost:1234（LM Studio）——节点访问
// 它自己的 localhost 是连不上的。隧道要把这个端口带到远端。
func TestTunnelForwardsLocalModelPort(t *testing.T) {
	model := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "MODEL_OK")
	}))
	defer model.Close()
	_, portStr, _ := net.SplitHostPort(model.Listener.Addr().String())
	modelPort, _ := strconv.Atoi(portStr)

	db := openTestDB(t)
	if err := store.SetSetting(db, "llm",
		fmt.Sprintf(`{"base_url":"http://localhost:%s/v1","model":"m"}`, portStr)); err != nil {
		t.Fatal(err)
	}

	srv := startFwdServer(t)
	cfg := deploy.SSHConfig{Host: "127.0.0.1", Port: srv.port(), Username: "u",
		AuthType: "password", Password: "p"}
	client, err := deploy.DialSSH(cfg)
	if err != nil {
		t.Fatalf("连接测试服务端: %v", err)
	}
	m := NewTunnelManager(db)
	if err := m.Attach("kali", cfg, client); err != nil {
		t.Fatalf("建立隧道: %v", err)
	}
	defer m.Remove("kali")

	// 「远端节点」访问它自己的 127.0.0.1:<模型端口>
	remote := srv.mapped(modelPort)
	if remote == 0 {
		t.Fatalf("模型端口 %d 没有转发到远端", modelPort)
	}
	if srv.mapped(17887) == 0 {
		t.Fatalf("节点回连端口 17887 没有转发到远端")
	}
	conn, err := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(remote), 5*time.Second)
	if err != nil {
		t.Fatalf("远端连 127.0.0.1:%d: %v", modelPort, err)
	}
	defer conn.Close()
	fmt.Fprint(conn, "GET /v1/models HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	resp, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("读响应: %v", err)
	}
	if !strings.Contains(string(resp), "MODEL_OK") {
		t.Fatalf("经隧道没访问到本机模型服务，响应: %q", resp)
	}
}

// 撤除隧道后，远端那个端口不再有人监听。
func TestTunnelRemoveReleasesForwards(t *testing.T) {
	db := openTestDB(t)
	if err := store.SetSetting(db, "llm", `{"base_url":"http://localhost:1234/v1","model":"m"}`); err != nil {
		t.Fatal(err)
	}
	srv := startFwdServer(t)
	cfg := deploy.SSHConfig{Host: "127.0.0.1", Port: srv.port(), Username: "u",
		AuthType: "password", Password: "p"}
	client, err := deploy.DialSSH(cfg)
	if err != nil {
		t.Fatalf("连接测试服务端: %v", err)
	}
	m := NewTunnelManager(db)
	if err := m.Attach("kali", cfg, client); err != nil {
		t.Fatalf("建立隧道: %v", err)
	}
	if srv.mapped(1234) == 0 {
		t.Fatal("模型端口 1234 没有转发到远端")
	}
	m.Remove("kali")
	if m.Status("kali") {
		t.Fatal("撤除后隧道不应还在")
	}
}
