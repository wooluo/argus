package deploy

// ssh.go: SSH 引导式节点部署——UI 填 VPS 连接信息，server 通过 SSH
// 上传 argus-node 二进制并拉起服务，节点随即自行注册回连。
// 解决 Pull 架构的"鸡生蛋"引导问题。

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/wooluo/argus/internal/tools"
)

// SSHConfig SSH 连接参数（UI 表单提交）。
type SSHConfig struct {
	Host       string `json:"host"`
	Port       int    `json:"port"`
	Username   string `json:"username"`
	AuthType   string `json:"auth_type"` // password | key
	Password   string `json:"password,omitempty"`
	PrivateKey string `json:"private_key,omitempty"` // PEM 格式（可选）
	NodeName   string `json:"node_name"`
	ServerURL  string `json:"server_url"`  // 节点回连地址
	NodeToken  string `json:"node_token"`  // 节点注册 token
	BinaryPath string `json:"binary_path"` // 本机 argus-node 二进制路径
}

// Result 部署结果。
type Result struct {
	OK      bool     `json:"ok"`
	Message string   `json:"message"`
	Steps   []string `json:"steps,omitempty"`
}

// DeployProgress 部署步骤实时回调（server 侧转发 SSE；nil=不回调）。
type DeployProgress func(step string)

// Deploy 通过 SSH 引导部署 argus-node 到远端机器。
// onStep：每完成一步回调（实时推送部署进度用）。
func DeployWithProgress(cfg SSHConfig, onStep DeployProgress) Result {
	var steps []string
	fail := func(msg string) Result {
		return Result{OK: false, Message: msg, Steps: steps}
	}
	step := func(s string) {
		steps = append(steps, s)
		if onStep != nil {
			onStep(s)
		}
	}
	// runCmd 带超时执行（分步命令卡死会让状态永远「部署中」——实测踩过）
	runCmd := func(s *ssh.Session, cmd string, timeout time.Duration) error {
		done := make(chan error, 1)
		go func() { done <- s.Run(cmd) }()
		select {
		case err := <-done:
			return err
		case <-time.After(timeout):
			_ = s.Signal(ssh.SIGKILL)
			return fmt.Errorf("命令超时（>%s）: %.80s", timeout, cmd)
		}
	}

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

	// 2. 检测远端系统与架构
	var out bytes.Buffer
	session.Stdout = &out
	if err := runCmd(session, "uname -s && uname -m", 20*time.Second); err != nil {
		return fail(fmt.Sprintf("无法执行命令: %v", err))
	}
	uname := strings.TrimSpace(out.String())
	if !strings.Contains(uname, "Linux") {
		return fail("目标不是 Linux 系统: " + uname)
	}
	// 解析架构（uname -m 第二行）
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	remoteArch := ""
	if len(lines) >= 2 {
		remoteArch = strings.TrimSpace(lines[1])
	}
	step("目标: Linux " + remoteArch)

	// 3. 按远端架构自动选择二进制
	binaryPath := pickBinary(remoteArch)
	if binaryPath == "" {
		return fail(fmt.Sprintf(
			"本机没有 %s 架构的 argus-node 二进制。请先交叉编译：\n"+
				"  CGO_ENABLED=0 GOOS=linux GOARCH=%s go build -o argus-node-linux-%s ./cmd/argus-node",
			remoteArch, goArchOf(remoteArch), goArchOf(remoteArch)))
	}
	cfg.BinaryPath = binaryPath
	step("二进制: " + filepath.Base(binaryPath))

	// 4. 上传二进制（通过 SSH cat 写入；7MB 家宽上传给足 3 分钟）
	step("上传二进制（约 7MB，视上行带宽 10s-3min）…")
	if err := uploadFile(client, cfg.BinaryPath, "/tmp/argus-node"); err != nil {
		return fail(fmt.Sprintf("上传二进制失败: %v", err))
	}
	step("二进制已上传")

	// 5. 安装 + 配置 systemd + 启动——分步执行，每步独立报错（单条长命令
	// 在部分 VPS 上出现过 exit 0 + 零输出 + 无 DEPLOY_OK 的幽灵失败，
	// 无法定位；分步后失败信息精确到步骤和原始输出）。每步 120s 超时。
	runStep := func(name, cmd string) error {
		s, err := client.NewSession()
		if err != nil {
			return fmt.Errorf("%s: 创建会话失败: %w", name, err)
		}
		defer s.Close()
		var out bytes.Buffer
		s.Stdout = &out
		s.Stderr = &out
		if err := runCmd(s, cmd, 120*time.Second); err != nil {
			return fmt.Errorf("%s 失败: %v\n远端输出: %s", name, err,
				tools.Truncate(out.String(), 1000))
		}
		step(name + " ✓  " + tools.Truncate(strings.TrimSpace(out.String()), 120))
		return nil
	}

	// 5.1 环境探测：逐条独立执行（实测单条组合命令 `for + $var` 在部分
	// VPS shell 下零输出，导致误判"非 root 且无 sudo"）。每条最简无变量
	// 无循环；echo 自检不过 = 远端 exec 输出通道异常，直接明确报错。
	probeOne := func(cmd string) string {
		s, err := client.NewSession()
		if err != nil {
			return ""
		}
		defer s.Close()
		var b bytes.Buffer
		s.Stdout = &b
		s.Stderr = &b
		_ = runCmd(s, cmd, 15*time.Second)
		return strings.TrimSpace(b.String())
	}
	if sanity := probeOne("echo PROBE_OK"); sanity != "PROBE_OK" {
		return fail(fmt.Sprintf(
			"远端命令无输出（echo 都不回显：sshd/shell 环境异常，echo 返回 %q）"+
				"——检查 VPS 的登录 shell（cat /etc/passwd | grep %s）",
			sanity, cfg.Username))
	}
	uid := probeOne("id -u")
	sudoWork := probeOne("sudo -n true 2>/dev/null && echo SUDO_OK || echo SUDO_NO")
	sysd := probeOne("systemctl --version 2>/dev/null | head -1")
	b64 := probeOne("base64 --version 2>/dev/null | head -1 || echo NOBASE64")
	isRoot := uid == "0"
	hasSudo := strings.Contains(sudoWork, "SUDO_OK")
	hasBase64 := !strings.Contains(b64, "NOBASE64") && b64 != ""
	hasSystemd := sysd != ""
	step(fmt.Sprintf("环境探测: uid=%s sudo=%v systemd=%q base64=%v",
		orDefaultStr(uid, "?"), hasSudo, tools.Truncate(sysd, 40), hasBase64))

	sudo := ""
	if !isRoot {
		if !hasSudo {
			return fail(fmt.Sprintf(
				"远端用户 %s 非 root（uid=%q）且 sudo 不可用（%s）——请用 root 登录部署，或给该用户配免密 sudo",
				cfg.Username, uid, sudoWork))
		}
		sudo = "sudo "
	}
	if !hasSystemd {
		return fail("远端无 systemctl（非 systemd 系统？）")
	}

	// 5.2 安装二进制
	if err := runStep("安装二进制",
		sudo+"install -m 755 /tmp/argus-node /usr/local/bin/argus-node"); err != nil {
		return fail(err.Error())
	}

	// 5.3 写 service 文件（base64 优先；无 base64 时逐行 printf 追加）
	svc := fmt.Sprintf(`[Unit]
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
`, cfg.ServerURL, cfg.NodeName, cfg.NodeToken)
	if hasBase64 {
		svcB64 := base64.StdEncoding.EncodeToString([]byte(svc))
		if err := runStep("写入 service（base64）",
			fmt.Sprintf(`echo %s | base64 -d > /tmp/argus-node.service && %scp /tmp/argus-node.service /etc/systemd/system/argus-node.service`,
				svcB64, sudo)); err != nil {
			return fail(err.Error())
		}
	} else {
		shellQuote := func(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }
		if err := runStep("清空临时 service", sudo+"rm -f /tmp/argus-node.service"); err != nil {
			return fail(err.Error())
		}
		for _, line := range strings.Split(strings.TrimRight(svc, "\n"), "\n") {
			cmd := fmt.Sprintf("%sprintf '%%s\\n' %s >> /tmp/argus-node.service",
				sudo, shellQuote(line))
			if err := runStep("写入 service 行", cmd); err != nil {
				return fail(err.Error())
			}
		}
		if err := runStep("安装 service 文件",
			sudo+"cp /tmp/argus-node.service /etc/systemd/system/argus-node.service"); err != nil {
			return fail(err.Error())
		}
	}

	// 5.4 systemd 三连
	if err := runStep("daemon-reload", sudo+"systemctl daemon-reload"); err != nil {
		return fail(err.Error())
	}
	if err := runStep("enable 开机自启", sudo+"systemctl enable argus-node"); err != nil {
		return fail(err.Error())
	}
	if err := runStep("restart 启动服务", sudo+"systemctl restart argus-node"); err != nil {
		return fail(err.Error())
	}
	step("systemd 服务已创建并启动")

	// 6. 验证节点进程
	time.Sleep(2 * time.Second)
	if s3, err := client.NewSession(); err == nil {
		var checkOut bytes.Buffer
		s3.Stdout = &checkOut
		_ = runCmd(s3, "systemctl is-active argus-node", 30*time.Second)
		s3.Close()
		status := strings.TrimSpace(checkOut.String())
		if status != "active" {
			return fail("服务未运行（状态: " + status + "）")
		}
		step("节点服务运行中")
	}

	// 7. 安全加固：关闭密码登录（可选，仅密钥部署时）
	if cfg.AuthType == "key" && cfg.PrivateKey != "" {
		if s4, err := client.NewSession(); err == nil {
			var secOut bytes.Buffer
			s4.Stdout = &secOut
			_ = runCmd(s4, `grep -q "PasswordAuthentication no" /etc/ssh/sshd_config 2>/dev/null || (
		sudo sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config &&
		sudo systemctl reload sshd && echo SSH_HARDENED)`, 30*time.Second)
			s4.Close()
			if strings.Contains(secOut.String(), "SSH_HARDENED") {
				step("SSH 已关闭密码登录")
			}
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

// uploadFile 通过 SSH 会话将本地文件写入远端路径（3 分钟超时：7MB 家宽上行）。
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
	done := make(chan error, 1)
	go func() {
		done <- session.Run(fmt.Sprintf("cat > %s && chmod 755 %s", remotePath, remotePath))
	}()
	select {
	case err := <-done:
		if err != nil {
			return fmt.Errorf("写入远端: %v (stderr: %s)", err, stderr.String()[:min(200, stderr.Len())])
		}
		return nil
	case <-time.After(3 * time.Minute):
		_ = session.Signal(ssh.SIGKILL)
		return fmt.Errorf("上传超时（>3min，上行带宽不足？）")
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// pickBinary 按远端架构找本机对应的 argus-node 二进制。
// 优先精确匹配 argus-node-linux-{arch}，回退同目录通用名（仅同架构时）。
func pickBinary(remoteArch string) string {
	goArch := goArchOf(remoteArch)
	if goArch == "" {
		return ""
	}
	candidates := []string{
		fmt.Sprintf("argus-node-linux-%s", goArch),   // 交叉编译产物（优先）
		fmt.Sprintf("argus-server-linux-%s", goArch), // 兼容（极端情况）
	}
	// 仅当 server 本身就是 Linux + 同架构时，通用名也可用
	if runtime.GOOS == "linux" && runtime.GOARCH == goArch {
		candidates = append(candidates, "argus-node", "/usr/local/bin/argus-node")
	}
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			abs, _ := filepath.Abs(c)
			return abs
		}
	}
	return ""
}

// goArchOf 将 uname -m 输出映射为 Go GOARCH。
func goArchOf(unameArch string) string {
	switch strings.TrimSpace(unameArch) {
	case "x86_64", "amd64":
		return "amd64"
	case "aarch64", "arm64":
		return "arm64"
	case "armv7l", "armv6l", "arm":
		return "arm"
	case "i386", "i686":
		return "386"
	case "mips":
		return "mips"
	case "mips64", "mips64el":
		return "mips64"
	case "ppc64", "ppc64le":
		return "ppc64"
	case "s390x":
		return "s390x"
	case "riscv64":
		return "riscv64"
	default:
		return ""
	}
}

// orDefaultStr 空串回默认值（探测展示用）。
func orDefaultStr(s, def string) string {
	if s == "" {
		return def
	}
	return s
}
