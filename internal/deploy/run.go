package deploy

// run.go: SSH 命令输出捕获 + 通用单命令执行（复用 ssh.go 的连接层；kali 主机指标采集等场景）。

import (
	"bytes"
	"fmt"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

// safeBuffer 是可并发写的输出缓冲，用来合并远端命令的 stdout + stderr。
//
// 不能让 ssh.Session 的 Stdout 和 Stderr 共用一个 bytes.Buffer：Session 给两个
// 流各起一个拷贝协程，而 bytes.Buffer.ReadFrom 在阻塞读之前记下写入位置、读完
// 再按旧位置重设长度——一个流还在等的时候另一个流写入的数据，会被它收到 EOF
// 时截掉。表现是命令退出码 0、输出却是空串（偶尔是等长的 \x00），命令本身
// 执行得好好的。部署里反复出现的「输出被幽灵吞掉」就是它，重试只是绕开。
type safeBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *safeBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *safeBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// runCapture 在连接上开会话执行 cmd，返回合并输出与退出错误；超过 timeout
// 返回当时的输出和超时错误（远端进程不保证已停）。
func runCapture(client *ssh.Client, cmd string, timeout time.Duration) (string, error) {
	session, err := client.NewSession()
	if err != nil {
		return "", err
	}
	defer session.Close()
	var out safeBuffer
	session.Stdout = &out
	session.Stderr = &out
	done := make(chan error, 1)
	go func() { done <- session.Run(cmd) }()
	select {
	case err := <-done:
		return out.String(), err
	case <-time.After(timeout):
		_ = session.Signal(ssh.SIGKILL)
		return out.String(), fmt.Errorf("command timeout after %s", timeout)
	}
}

// RunSSH 在远端执行单条命令，返回合并输出（stdout+stderr）。
// timeout 0 = 默认 20s（命令级；连接握手固定 15s）。
func RunSSH(host string, port int, username, authType, password, privateKey, command string, timeout time.Duration) (string, error) {
	if timeout <= 0 {
		timeout = 20 * time.Second
	}
	cfg := SSHConfig{
		Host: host, Port: port, Username: username,
		AuthType: authType, Password: password, PrivateKey: privateKey,
	}
	client, err := sshConnect(cfg)
	if err != nil {
		return "", err
	}
	defer client.Close()
	return runCapture(client, command, timeout)
}
