package deploy

// run.go: 通用 SSH 命令执行（复用 ssh.go 的连接层；kali 主机指标采集等场景）。

import (
	"bytes"
	"fmt"
	"time"

	"golang.org/x/crypto/ssh"
)

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
	session, err := client.NewSession()
	if err != nil {
		return "", err
	}
	defer session.Close()
	var out bytes.Buffer
	session.Stdout = &out
	session.Stderr = &out
	done := make(chan error, 1)
	go func() { done <- session.Run(command) }()
	select {
	case err := <-done:
		return out.String(), err
	case <-time.After(timeout):
		_ = session.Signal(ssh.SIGKILL)
		return out.String(), fmt.Errorf("command timeout after %s", timeout)
	}
}
