package deploy

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// testSSHServer 是进程内的 SSH 服务端。每个 exec 会话先写 stdout / stderr，
// 隔 gap 再发 exit-status 并关闭通道——真实 sshd 收尾时最常见的时序：
// 输出一到进程随即退出，EOF 同时落到两个流上。
type testSSHServer struct {
	stdout, stderr string
	gap            time.Duration
	status         uint32
	addr           string
	port           int
}

func startTestSSH(t *testing.T, srv *testSSHServer) {
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
	t.Cleanup(func() { ln.Close() })

	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			sconn, chans, reqs, err := ssh.NewServerConn(c, cfg)
			if err != nil {
				c.Close()
				continue
			}
			go ssh.DiscardRequests(reqs)
			go func() {
				for nc := range chans {
					if nc.ChannelType() != "session" {
						nc.Reject(ssh.UnknownChannelType, "unsupported")
						continue
					}
					ch, creqs, err := nc.Accept()
					if err != nil {
						continue
					}
					go srv.serve(ch, creqs)
				}
				sconn.Close()
			}()
		}
	}()

	host, port, _ := net.SplitHostPort(ln.Addr().String())
	srv.addr = host
	srv.port, _ = strconv.Atoi(port)
}

func (s *testSSHServer) serve(ch ssh.Channel, reqs <-chan *ssh.Request) {
	for r := range reqs {
		if r.Type != "exec" {
			if r.WantReply {
				r.Reply(false, nil)
			}
			continue
		}
		if r.WantReply {
			r.Reply(true, nil)
		}
		if s.stdout != "" {
			io.WriteString(ch, s.stdout)
		}
		if s.stderr != "" {
			io.WriteString(ch.Stderr(), s.stderr)
		}
		if s.gap > 0 {
			time.Sleep(s.gap)
		}
		ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{s.status}))
		ch.CloseWrite()
		ch.Close()
		return
	}
}

func dialTest(t *testing.T, srv *testSSHServer) *ssh.Client {
	t.Helper()
	client, err := sshConnect(SSHConfig{
		Host: srv.addr, Port: srv.port, Username: "u", AuthType: "password", Password: "p",
	})
	if err != nil {
		t.Fatalf("连接测试服务端: %v", err)
	}
	return client
}

// TestRunCaptureKeepsOutputOnExit 回归：部署在 Kali 上卡死在「写入 service
// 文件——输出通道异常（远端输出: ""）」。原因是 Stdout 与 Stderr 共用一个
// bytes.Buffer，Session 的两个拷贝协程并发读写它：stderr 协程在阻塞读之前
// 记下的写入位置是旧的，收到 EOF 时按旧位置重设长度，把 stdout 协程这期间
// 追加的输出截掉。命令在远端每次都完整执行了，回显却读成空串。
func TestRunCaptureKeepsOutputOnExit(t *testing.T) {
	srv := &testSSHServer{stdout: "__ARGUS_OK__\n", gap: 2 * time.Millisecond}
	startTestSSH(t, srv)
	client := dialTest(t, srv)
	defer client.Close()

	for i := range 40 {
		out, err := runCapture(client, "( true ) && echo __ARGUS_OK__", 5*time.Second)
		if err != nil {
			t.Fatalf("第 %d 次: %v", i+1, err)
		}
		if out != "__ARGUS_OK__\n" {
			t.Fatalf("第 %d 次读到 %q，应为 %q", i+1, out, "__ARGUS_OK__\n")
		}
	}
}

// 两个流都有内容时都要读到，先后不作要求。
func TestRunCaptureMergesStreams(t *testing.T) {
	srv := &testSSHServer{stdout: "out-123\n", stderr: "err-456\n", gap: 2 * time.Millisecond}
	startTestSSH(t, srv)
	client := dialTest(t, srv)
	defer client.Close()

	for i := range 20 {
		out, err := runCapture(client, "x", 5*time.Second)
		if err != nil {
			t.Fatalf("第 %d 次: %v", i+1, err)
		}
		if !strings.Contains(out, "out-123") || !strings.Contains(out, "err-456") {
			t.Fatalf("第 %d 次读到 %q，应同时含 stdout 与 stderr", i+1, out)
		}
	}
}

// 非零退出码照常以 *ssh.ExitError 返回，退出前的输出不丢。
func TestRunCaptureReportsExitStatus(t *testing.T) {
	srv := &testSSHServer{stdout: "boom\n", stderr: "denied\n", status: 3, gap: time.Millisecond}
	startTestSSH(t, srv)
	client := dialTest(t, srv)
	defer client.Close()

	out, err := runCapture(client, "false", 5*time.Second)
	var ee *ssh.ExitError
	if !errors.As(err, &ee) || ee.ExitStatus() != 3 {
		t.Fatalf("应为退出码 3 的 ExitError，得到 %v", err)
	}
	if !strings.Contains(out, "boom") || !strings.Contains(out, "denied") {
		t.Fatalf("输出 %q 不完整", out)
	}
}

// RunSSH 走完整连接层（sshConnect → runCapture），一条命令一次连接——
// kali 主机探测走的就是它。
func TestRunSSHKeepsOutput(t *testing.T) {
	srv := &testSSHServer{stdout: "SSH_OK\n", gap: 2 * time.Millisecond}
	startTestSSH(t, srv)

	for i := range 10 {
		out, err := RunSSH(srv.addr, srv.port, "u", "password", "p", "", "echo SSH_OK", 5*time.Second)
		if err != nil {
			t.Fatalf("第 %d 次: %v", i+1, err)
		}
		if !strings.Contains(out, "SSH_OK") {
			t.Fatalf("第 %d 次读到 %q", i+1, out)
		}
	}
}
