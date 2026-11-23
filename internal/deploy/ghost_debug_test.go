package deploy

// 临时排障测试：复现 kali 上 sudo -S 探测经 x/crypto SSH 输出丢失。
// 运行：KALI_HOST=10.211.55.4 KALI_USER=wooluo KALI_PW=... go test ./internal/deploy/ -run TestGhostDebug -v
import (
	"bytes"
	"fmt"
	"os"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func TestGhostDebug(t *testing.T) {
	host := os.Getenv("KALI_HOST")
	user := os.Getenv("KALI_USER")
	pw := os.Getenv("KALI_PW")
	if host == "" {
		t.Skip("KALI_HOST 未设置")
	}
	cfg := SSHConfig{Host: host, Port: 22, Username: user, AuthType: "password", Password: pw}
	client, err := DialSSH(cfg)
	if err != nil {
		t.Fatalf("连接失败: %v", err)
	}
	defer client.Close()

	run := func(cmd string) string {
		s, err := client.NewSession()
		if err != nil {
			return fmt.Sprintf("NEWW_SESSION_ERR:%v", err)
		}
		defer s.Close()
		var b bytes.Buffer
		s.Stdout = &b
		s.Stderr = &b
		done := make(chan error, 1)
		go func() { done <- s.Run(cmd) }()
		select {
		case err := <-done:
			return fmt.Sprintf("out=%q err=%v", b.String(), err)
		case <-time.After(12 * time.Second):
			_ = s.Signal(ssh.SIGKILL)
			return "TIMEOUT"
		}
	}

	t.Log("plain echo      :", run("echo PLAIN_OK"))
	t.Log("sudo -n probe   :", run("sudo -n true && echo A_OK || echo A_FAIL_$?"))
	t.Log("pipe true       :", run("printf 'x\\n' | true && echo P_OK || echo P_FAIL"))
	t.Log("sudo -S probe   :", run("printf '%s\\n' '"+pw+"' | sudo -S -p '' true && echo B_OK || echo B_FAIL_$?"))
	t.Log("sudo -S id      :", run("printf '%s\\n' '"+pw+"' | sudo -S -p '' id -u 2>&1; echo rc=$?"))
	t.Log("sudo -S no -p   :", run("printf '%s\\n' '"+pw+"' | sudo -S true && echo C_OK || echo C_FAIL"))
}
