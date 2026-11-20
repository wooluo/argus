package deploy

// ssh.go: SSH 引导式节点部署——UI 填 VPS 连接信息，server 通过 SSH
// 上传 argus-node 二进制并拉起服务，节点随即自行注册回连。
// 解决 Pull 架构的"鸡生蛋"引导问题。

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// SSHConfig SSH 连接参数（UI 表单提交）。
type SSHConfig struct {
	Host           string `json:"host"`
	Port           int    `json:"port"`
	Username       string `json:"username"`
	AuthType       string `json:"auth_type"` // password | key
	Password       string `json:"password,omitempty"`
	PrivateKey     string `json:"private_key,omitempty"` // PEM 格式（可选）
	NodeName       string `json:"node_name"`
	ServerURL      string `json:"server_url"`  // 节点回连地址
	NodeToken      string `json:"node_token"`  // 节点注册 token
	BinaryPath     string `json:"binary_path"` // 本机 argus-node 二进制路径
}

// Result 部署结果。
type Result struct {
	OK      bool   `json:"ok"`
	Message string `json:"message"`
	Steps   []string `json:"steps,omitempty"`
}

// Deploy 通过 SSH 引导部署 argus-node 到远端机器。
func Deploy(cfg SSHConfig) Result {
	var steps []string
	fail := func(msg string) Result {
		return Result{OK: false, Message: msg, Steps: steps}
	}
	step := func(s string) { steps = append(steps, s) }

	// 1. 建立 SSH 连接
	client, err := sshConnect(cfg)
	if err != nil {
		return fail(fmt.Sprintf("SSH 连接失败: %v", err))
	}
	defer client.Close()
	step("SSH 连接成功")

	session, err := client.NewSession()
	if err != nil {
		return fail(fmt.Sprintf("创建会话失败: %v", err))
	}
	defer session.Close()

	// 2. 检查远端环境
	var out bytes.Buffer
	session.Stdout = &out
	if err := session.Run("uname -s && uname -m"); err != nil {
		return fail(fmt.Sprintf("无法执行命令: %v", err))
	}
	arch := strings.TrimSpace(out.String())
	if !strings.Contains(arch, "Linux") {
		return fail("目标不是 Linux 系统: " + arch)
	}
	step("目标系统: " + strings.ReplaceAll(arch, "\n", " "))

	// 3. 确定目标架构对应的二进制
	// 本地 binary_path 已经是对应架构的（调用方选好），这里只做存在性检查
	if _, err := os.Stat(cfg.BinaryPath); err != nil {
		return fail("本机 argus-node 二进制不存在: " + cfg.BinaryPath)
	}
	step("二进制就绪")

	// 4. 上传二进制（通过 SSH cat 写入）
	if err := uploadFile(client, cfg.BinaryPath, "/tmp/argus-node"); err != nil {
		return fail(fmt.Sprintf("上传二进制失败: %v", err))
	}
	step("二进制已上传")

	// 5. 安装 + 配置 systemd + 启动
	installCmd := fmt.Sprintf(`sudo install -m 755 /tmp/argus-node /usr/local/bin/argus-node &&
sudo tee /etc/systemd/system/argus-node.service > /dev/null << 'SVCEOF'
[Unit]
Description=Argus Pentest Node
After=network.target

[Service]
Type=simple
Environment=ARGUS_SERVER=%s
Environment=ARGUS_NAME=%s
Environment=ARGUS_TOKEN=%s
ExecStart=/usr/local/bin/argus-node
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
SVCEOF
sudo systemctl daemon-reload &&
sudo systemctl enable argus-node &&
sudo systemctl restart argus-node &&
echo DEPLOY_OK`,
		cfg.ServerURL, cfg.NodeName, cfg.NodeToken)

	s2, err := client.NewSession()
	if err != nil {
		return fail(fmt.Sprintf("创建安装会话失败: %v", err))
	}
	defer s2.Close()
	var installOut bytes.Buffer
	s2.Stdout = &installOut
	s2.Stderr = &installOut
	if err := s2.Run(installCmd); err != nil {
		return fail(fmt.Sprintf("安装失败: %v\n输出: %s", err, installOut.String()[:min(500, installOut.Len())]))
	}
	if !strings.Contains(installOut.String(), "DEPLOY_OK") {
		return fail("安装输出异常: " + installOut.String()[:min(300, installOut.Len())])
	}
	step("systemd 服务已创建并启动")

	// 6. 验证节点进程
	time.Sleep(2 * time.Second)
	s3, _ := client.NewSession()
	defer s3.Close()
	var checkOut bytes.Buffer
	s3.Stdout = &checkOut
	_ = s3.Run("systemctl is-active argus-node")
	status := strings.TrimSpace(checkOut.String())
	if status != "active" {
		return fail("服务未运行（状态: " + status + "）")
	}
	step("节点服务运行中")

	// 7. 安全加固：关闭密码登录（可选，仅密钥部署时）
	if cfg.AuthType == "key" && cfg.PrivateKey != "" {
		s4, _ := client.NewSession()
		defer s4.Close()
		var secOut bytes.Buffer
		s4.Stdout = &secOut
		_ = s4.Run(`grep -q "PasswordAuthentication no" /etc/ssh/sshd_config 2>/dev/null || (
			sudo sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config &&
			sudo systemctl reload sshd && echo SSH_HARDENED)`)
		if strings.Contains(secOut.String(), "SSH_HARDENED") {
			step("SSH 已关闭密码登录")
		}
	}

	return Result{
		OK:      true,
		Message: fmt.Sprintf("节点 %s 部署成功，已回连 %s", cfg.NodeName, cfg.ServerURL),
		Steps:   steps,
	}
}

// sshConnect 建立 SSH 连接（密码或密钥）。
func sshConnect(cfg SSHConfig) (*ssh.Client, error) {
	var authMethod ssh.AuthMethod
	switch cfg.AuthType {
	case "password":
		if cfg.Password == "" {
			return nil, fmt.Errorf("密码不能为空")
		}
		authMethod = ssh.Password(cfg.Password)
	case "key":
		if cfg.PrivateKey == "" {
			return nil, fmt.Errorf("私钥不能为空")
		}
		signer, err := ssh.ParsePrivateKey([]byte(cfg.PrivateKey))
		if err != nil {
			return nil, fmt.Errorf("解析私钥失败: %v", err)
		}
		authMethod = ssh.PublicKeys(signer)
	default:
		return nil, fmt.Errorf("不支持的认证方式: %s", cfg.AuthType)
	}

	port := cfg.Port
	if port == 0 {
		port = 22
	}
	config := &ssh.ClientConfig{
		User:            cfg.Username,
		Auth:            []ssh.AuthMethod{authMethod},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), // 首次部署接受未知主机
		Timeout:         15 * time.Second,
	}
	return ssh.Dial("tcp", net.JoinHostPort(cfg.Host, fmt.Sprintf("%d", port)), config)
}

// uploadFile 通过 SSH 会话将本地文件写入远端路径。
func uploadFile(client *ssh.Client, localPath, remotePath string) error {
	data, err := os.ReadFile(localPath)
	if err != nil {
		return fmt.Errorf("读取本地文件: %v", err)
	}
	session, err := client.NewSession()
	if err != nil {
		return err
	}
	defer session.Close()
	session.Stdin = bytes.NewReader(data)
	var stderr bytes.Buffer
	session.Stderr = &stderr
	if err := session.Run(fmt.Sprintf("cat > %s && chmod 755 %s", remotePath, remotePath)); err != nil {
		return fmt.Errorf("写入远端: %v (stderr: %s)", err, stderr.String()[:min(200, stderr.Len())])
	}
	return nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
