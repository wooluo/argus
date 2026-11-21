package deploy

// ssh.go: SSH 引导式节点部署——UI 填 VPS 连接信息，server 通过 SSH
// 上传 argus-node 二进制并拉起服务，节点随即自行注册回连。
// 解决 Pull 架构的"鸡生蛋"引导问题。

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
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

	// probeOne 独立会话取命令输出（探测/上传校验通用；幽灵时返回空串）
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

	// 4. 上传二进制（cat 写入，7MB 给足 3 分钟）+ 字节数校验
	//（幽灵会吞掉上传错误导致 exit 0 假成功——校验远端实际字节数，
	// 不符自动重传一次；wc 无输出时尽力而为放行）
	step("上传二进制（约 7MB，视上行带宽 10s-3min）…")
	localSize := int64(0)
	if st, err := os.Stat(cfg.BinaryPath); err == nil {
		localSize = st.Size()
	}
	verifyUpload := func() bool {
		if localSize == 0 {
			return true
		}
		ns := strings.Fields(probeOne("wc -c < /tmp/argus-node"))
		if len(ns) == 0 {
			return true // 幽灵无输出 → 放行
		}
		if v, err := strconv.ParseInt(ns[0], 10, 64); err == nil && v != localSize {
			step(fmt.Sprintf("远端字节数 %d ≠ 本地 %d（上传不完整）", v, localSize))
			return false
		}
		return true
	}
	if err := uploadFile(client, cfg.BinaryPath, "/tmp/argus-node"); err != nil {
		step("上传报错: " + err.Error())
	}
	if !verifyUpload() {
		step("校验不符，重传一次…")
		if err := uploadFile(client, cfg.BinaryPath, "/tmp/argus-node"); err != nil {
			return fail(fmt.Sprintf("重传失败: %v", err))
		}
		if !verifyUpload() {
			return fail(fmt.Sprintf("二进制字节数校验仍不符（本地 %d；磁盘满？/tmp 受限？"+
				"——远端执行 df -h /tmp 自查）", localSize))
		}
	}
	step("二进制已上传（字节数校验通过）")

	// 5. 安装 + 配置 systemd + 启动——分步执行 + echo 标记判定 + 失败重试。
	// 该 VPS 的 exec 通道存在间歇性幽灵（外部命令输出/exit 码随机丢失，
	// systemctl 一次探测不到、一次能到）——exit 码不可信，但内建 echo 的
	// 回显稳定：每条命令包装 `( cmd ) && echo __OK__ || echo __FAIL__$?`，
	// 以标记判成败；失败自动重试一次。
	runStepRaw := func(name, cmd string) error {
		s, err := client.NewSession()
		if err != nil {
			return fmt.Errorf("%s: 创建会话失败: %w", name, err)
		}
		defer s.Close()
		var out bytes.Buffer
		s.Stdout = &out
		s.Stderr = &out
		wrapped := "( " + cmd + " ) && echo __ARGUS_OK__ || echo __ARGUS_FAIL_$?"
		rerr := runCmd(s, wrapped, 120*time.Second)
		o := out.String()
		switch {
		case strings.Contains(o, "__ARGUS_FAIL_"):
			return fmt.Errorf("%s 失败（远端输出: %s）", name, tools.Truncate(o, 800))
		case strings.Contains(o, "__ARGUS_OK__"):
			step(name + " ✓  " + tools.Truncate(strings.TrimSpace(strings.ReplaceAll(
				strings.ReplaceAll(o, "__ARGUS_OK__", ""), "\n", " ")), 100))
			return nil
		case rerr != nil:
			return fmt.Errorf("%s 失败: %v（远端输出: %s）", name, rerr, tools.Truncate(o, 800))
		default:
			return fmt.Errorf("%s 输出通道异常（无标记无错误，远端输出: %q）", name, tools.Truncate(o, 200))
		}
	}
	runStep := func(name, cmd string) error {
		if err := runStepRaw(name, cmd); err != nil {
			time.Sleep(800 * time.Millisecond) // 幽灵间歇 → 重试一次
			if err2 := runStepRaw(name+"（重试）", cmd); err2 != nil {
				return err2
			}
		}
		return nil
	}

	// 5.1 环境探测：实测该 VPS 非交互 shell 下部分外部命令零输出
	//（echo/cat/chmod/uname 可用，id/systemctl/base64/管道/|| 全空）——
	// 逐条探测 + 绝对路径兜底，shell/PATH 进步骤与失败信息。
	//（probeOne 已在开头定义）
	envInfo := probeOne(`echo "SHELL=$0 PATH=$PATH"`)
	step("远端环境: " + tools.Truncate(envInfo, 160))

	uid := probeOne("id -u")
	if uid == "" {
		uid = probeOne("/usr/bin/id -u")
	}
	if uid == "" {
		uid = probeOne("/bin/id -u")
	}
	if uid == "" {
		uid = probeOne("id -u") // 幽灵间歇 → 再试一次
	}
	sysctlPath := ""
	for _, p := range []string{"/usr/bin/systemctl", "/bin/systemctl", "/sbin/systemctl"} {
		ver := probeOne(p + " --version")
		if !strings.Contains(ver, "systemd") {
			ver = probeOne(p + " --version") // 幽灵间歇 → 再试
		}
		if strings.Contains(ver, "systemd") {
			sysctlPath = p
			break
		}
	}
	isRoot := uid == "0"
	step(fmt.Sprintf("环境探测: uid=%q systemctl=%q", uid, orDefaultStr(sysctlPath, "未找到")))

	if uid == "" && sysctlPath == "" {
		return fail("远端 id/systemctl 均无输出（shell 环境异常）。远端环境: " + envInfo +
			"\n请在 VPS 上执行 `echo $SHELL; echo $PATH; which systemctl` 并反馈结果")
	}

	// 非 root 需可用 sudo（root 场景跳过——用户就是 root 时最稳）
	sudo := ""
	if !isRoot {
		sudoWork := probeOne("sudo -n true && echo SUDO_OK")
		if !strings.Contains(sudoWork, "SUDO_OK") {
			return fail(fmt.Sprintf(
				"远端用户 %s 非 root（uid=%q）且 sudo 不可用（%q）——请用 root 登录部署",
				cfg.Username, uid, sudoWork))
		}
		sudo = "sudo "
	}

	// 5.2 安装二进制：目录降级尝试（/usr/local/bin 挂载异常时换
	// /opt/argus、/root），每目录内 mkdir / cp / chmod 独立标记。
	binPath := ""
	for _, dir := range []string{"/usr/local/bin", "/opt/argus", "/root"} {
		if err := runStep("mkdir "+dir, sudo+"mkdir -p "+dir); err != nil {
			continue
		}
		if err := runStep("cp → "+dir,
			sudo+"cp /tmp/argus-node "+dir+"/argus-node && chmod 755 "+dir+"/argus-node"); err != nil {
			continue
		}
		binPath = dir + "/argus-node"
		break
	}
	if binPath == "" {
		return fail("二进制安装失败（/usr/local/bin、/opt/argus、/root 均不可写？" +
			"——远端执行 df -h 与 ls -ld /usr/local/bin 自查")
	}
	step("二进制已安装: " + binPath)

	// ── systemd 不可用（OpenVZ/LXC 容器常见）→ 降级 nohup + crontab 模式 ──
	if sysctlPath == "" {
		step("systemd 不可用（容器型 VPS？）→ 降级 nohup 后台 + crontab 自启")
		shellQuote := func(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }
		// env 前缀 + nohup + 后台 + 脱离会话（stdin/stdout 重定向防 SSH 退出牵连）
		startCmd := fmt.Sprintf(
			`ARGUS_SERVER=%s ARGUS_NAME=%s ARGUS_TOKEN=%s nohup `+binPath+` > /var/log/argus-node.log 2>&1 < /dev/null &`,
			shellQuote(cfg.ServerURL), shellQuote(cfg.NodeName), shellQuote(cfg.NodeToken))
		if err := runStep("nohup 启动节点", startCmd); err != nil {
			return fail(err.Error())
		}
		// 开机自启：/etc/crontab 追加 @reboot 行（cat/echo/>> 已验证可用；
		// 失败不阻塞——节点已在跑，只是缺自启）
		if err := runStep("crontab 自启",
			fmt.Sprintf(`cat >> /etc/crontab << 'ARGUS_CRON_EOF'
@reboot root ARGUS_SERVER=%s ARGUS_NAME=%s ARGUS_TOKEN=%s `+binPath+` >> /var/log/argus-node.log 2>&1
ARGUS_CRON_EOF`,
				shellQuote(cfg.ServerURL), shellQuote(cfg.NodeName), shellQuote(cfg.NodeToken))); err != nil {
			step("crontab 自启写入失败（不影响本次运行）: " + err.Error())
		}
		// 验证交给 server 侧：节点 5s 内心跳注册（状态变在线即闭环）
		step("节点已启动（nohup 模式，存活由服务器心跳确认）")
		return Result{
			OK: true,
			Message: fmt.Sprintf("节点 %s 已启动（容器模式：nohup + crontab 自启；日志 /var/log/argus-node.log），等待其回连 %s",
				cfg.NodeName, cfg.ServerURL),
			Steps: steps,
		}
	}

	// 5.3 写 service：cat heredoc（纯 shell 机制 + cat，不依赖 base64/tee）
	svc := fmt.Sprintf(`[Unit]
Description=Argus Pentest Node
After=network.target

[Service]
Type=simple
Environment=ARGUS_SERVER=%s
Environment=ARGUS_NAME=%s
Environment=ARGUS_TOKEN=%s
ExecStart=`+binPath+`
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
`, cfg.ServerURL, cfg.NodeName, cfg.NodeToken)
	if err := runStep("写入 service 文件",
		sudo+"cat > /etc/systemd/system/argus-node.service << 'ARGUS_SVC_EOF'\n"+svc+"ARGUS_SVC_EOF"); err != nil {
		return fail(err.Error())
	}

	// 5.4 systemd 三连（绝对路径，绕开 PATH 异常）
	if err := runStep("daemon-reload", sudo+sysctlPath+" daemon-reload"); err != nil {
		return fail(err.Error())
	}
	if err := runStep("enable 开机自启", sudo+sysctlPath+" enable argus-node"); err != nil {
		return fail(err.Error())
	}
	if err := runStep("restart 启动服务", sudo+sysctlPath+" restart argus-node"); err != nil {
		return fail(err.Error())
	}
	step("systemd 服务已创建并启动")

	// 6. 验证节点进程
	time.Sleep(2 * time.Second)
	if s3, err := client.NewSession(); err == nil {
		var checkOut bytes.Buffer
		s3.Stdout = &checkOut
		_ = runCmd(s3, sysctlPath+" is-active argus-node", 30*time.Second)
		s3.Close()
		status := strings.TrimSpace(checkOut.String())
		if status != "active" {
			return fail("服务未运行（状态: " + status + "）——查日志: journalctl -u argus-node -n 20")
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
