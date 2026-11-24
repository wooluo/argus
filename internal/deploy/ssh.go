package deploy

// ssh.go: SSH 引导式节点部署——UI 填 VPS 连接信息，server 通过 SSH 把
// argus-node 装到远端并拉起服务，节点随即自行注册回连。
// 解决 Pull 架构的"鸡生蛋"引导问题。节点程序有两种来源：
//   - 平台推送（默认）：上传 server 本机的 argus-node 二进制；
//   - GitHub 下载：远端机器直接从 GitHub Release 下载（见 release.go）。

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
	"unicode"

	"golang.org/x/crypto/ssh"

	"github.com/wooluo/argus/internal/tools"
)

// SSHConfig SSH 连接参数（UI 表单提交）。
type SSHConfig struct {
	Host         string `json:"host"`
	Port         int    `json:"port"`
	Username     string `json:"username"`
	AuthType     string `json:"auth_type"` // password | key
	Password     string `json:"password,omitempty"`
	PrivateKey   string `json:"private_key,omitempty"` // PEM 格式（可选）
	NodeName     string `json:"node_name"`
	ServerURL    string `json:"server_url"`              // 节点回连地址
	NodeToken    string `json:"node_token"`              // 节点注册 token
	SudoPassword string `json:"sudo_password,omitempty"` // 非 root 部署的 sudo 密码（空=回退登录密码，Kali 默认二者相同）
	BinaryPath   string `json:"binary_path"`             // 本机 argus-node 二进制路径
	Tunnel       bool   `json:"tunnel"`                  // SSH 隧道回连（NAT/内网 server 推荐）

	// 节点程序来源：SourceServer（空，平台推送）| SourceGitHub（远端从 GitHub
	// Release 下载）。后两项仅 GitHub 来源使用。
	Source      string `json:"source"`
	ReleaseRepo string `json:"release_repo"` // 仓库 owner/repo（空=release.DefaultReleaseRepo）
	ReleaseTag  string `json:"release_tag"`  // 空/latest=最新 Release，否则指定 tag（如 v0.1.0）
	// GitHubToken 私有仓库鉴权，DeployNode 从设置页注入。只在 server 侧换
	// 签名下载地址用——不序列化（tunnel_ssh 落库、远端命令均不带它）。
	GitHubToken string `json:"-"`
}

// Result 部署结果。
type Result struct {
	OK         bool        `json:"ok"`
	Message    string      `json:"message"`
	Steps      []string    `json:"steps,omitempty"`
	KeepClient *ssh.Client `json:"-"` // Tunnel 模式部署成功后移交的连接（server 接管建隧道）
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

	// 0. SSH 隧道回连模式：ServerURL 强制为远端本机隧道口
	//（server 在 NAT/内网后，节点直连不可能通；部署连接上建 remote
	// forward，节点连 VPS 本机 127.0.0.1:17887 经隧道回到 server）
	if cfg.Tunnel {
		cfg.ServerURL = TunnelServerURL
		step("SSH 隧道回连模式：节点将连 " + cfg.ServerURL + "（经部署连接反向转发）")
	}

	// 1. 建立 SSH 连接
	client, err := sshConnect(cfg)
	if err != nil {
		return fail(fmt.Sprintf("SSH 连接失败: %v", err))
	}
	// Tunnel 模式部署成功后连接移交 server 的隧道管理器——不在此关闭
	keepClient := false
	defer func() {
		if !keepClient {
			client.Close()
		}
	}()
	step("SSH 连接成功")

	// probeOne 独立会话取命令输出（探测/上传校验通用；幽灵时返回空串）
	// probeOne 执行探测命令并取输出。x/crypto SSH 客户端同连接快速开新会话时
	// 存在间歇性输出丢失/损坏（实测 30 次约 4 次返回空或 \x00 字节），
	// 输出无效（空或含 NUL）视为失败并重试。
	probeOne := func(cmd string) string {
		for range 3 {
			s, err := client.NewSession()
			if err != nil {
				return ""
			}
			var b bytes.Buffer
			s.Stdout = &b
			s.Stderr = &b
			_ = runCmd(s, cmd, 15*time.Second)
			s.Close()
			out := strings.TrimSpace(b.String())
			if out != "" && !strings.ContainsRune(out, 0) {
				return out
			}
			time.Sleep(300 * time.Millisecond)
		}
		return ""
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

	// 3. 节点程序来源：平台推送（上传 server 本机二进制）/ GitHub 下载（远端自取）
	goArch := goArchOf(remoteArch)
	fromGitHub := cfg.Source == SourceGitHub
	if fromGitHub {
		step("节点程序来源: GitHub Release（远端机器直接下载，server 不上传）")
	} else {
		binaryPath := pickBinary(remoteArch)
		if binaryPath == "" {
			return fail(fmt.Sprintf(
				"本机没有 %s 架构的 argus-node 二进制。请先交叉编译：\n"+
					"  CGO_ENABLED=0 GOOS=linux GOARCH=%s go build -o argus-node-linux-%s ./cmd/argus-node\n"+
					"或把节点程序来源改选「GitHub 下载」（server 无需本机二进制）",
				remoteArch, goArch, goArch))
		}
		cfg.BinaryPath = binaryPath
		step("二进制: " + filepath.Base(binaryPath))
	}

	// 3.5 环境探测 + sudo 谈判——刻意赶在上传前：该机 exec 通道输出随机
	// 丢失且上传大文件后高发，命令执行本身可靠。sudo 验证走「效果落盘」：
	// sudo touch 的标记文件在磁盘上，ls 探测任意一次拿到输出即定论。
	//（实测该 VPS 非交互 shell 下部分外部命令零输出——echo/cat/chmod/uname
	// 可用，id/systemctl/管道/|| 偶发全空——逐条探测 + 绝对路径兜底）
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

	// 非 root 需可用 sudo（root 场景跳过——用户就是 root 时最稳）。
	// 两条路：免密 sudo（sudo -n）；密码 sudo（sudo -S 从 stdin 喂——
	// Kali 默认用户即此形态，sudo 密码回退登录密码）。printf 是 shell 内建，
	// 密码不落远端 ps；每条命令独立会话，sudo 时间戳缓存不可依赖，逐条完整喂。
	sudo := ""
	if !isRoot {
		quote := func(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }
		mark := fmt.Sprintf("/tmp/.argus-sudo-%d", time.Now().UnixNano()) // 时间戳防残留误判
		trySudo := func(feed string) bool {
			_ = probeOne(feed + "touch " + mark) // 执行可靠，输出丢失无关紧要
			time.Sleep(250 * time.Millisecond)
			_ = probeOne(feed + "touch " + mark) // 双保险
			for range 4 {
				if out := probeOne("ls " + mark + " && echo __ARGUS_OK__ || echo __ARGUS_FAIL_"); out != "" {
					return strings.Contains(out, "__ARGUS_OK__")
				}
				time.Sleep(500 * time.Millisecond)
			}
			return false // ls 输出持续丢失，成败未知
		}
		switch {
		case trySudo("sudo -n "):
			sudo = "sudo "
		default: // 免密不可用 → 密码 sudo
			pw := orDefaultStr(cfg.SudoPassword, cfg.Password)
			if pw == "" {
				return fail(fmt.Sprintf(
					"远端用户 %s 非 root（uid=%q）且免密 sudo 不可用——请用 root 登录部署", cfg.Username, uid))
			}
			sudoFeed := "printf '%s\\n' " + quote(pw) + " | sudo -S -p '' "
			if !trySudo(sudoFeed) {
				return fail("远端用户 " + cfg.Username + " 非 root 且 sudo 密码验证未通过" +
					"（已试登录密码；若密码确信无误，可能为输出丢失，重试部署即可）——或改用 root 登录")
			}
			step("sudo 密码模式（非 root + 非免密 sudo）")
			sudo = sudoFeed
		}
	}

	// 4. 节点程序落到远端 /tmp/argus-node + 字节数校验（平台推送 / GitHub
	// 下载两条来源在此汇合，后续安装启动步骤共用）
	localSize := int64(0)
	if fromGitHub {
		var err error
		if localSize, err = fetchFromGitHub(cfg, goArch, "/tmp/argus-node",
			func(cmd string, timeout time.Duration) (string, error) {
				return remoteRun(client, cmd, timeout)
			}, probeOne, step); err != nil {
			return fail(err.Error())
		}
	} else {
		// 上传（cat 写入，7MB 给足 3 分钟）；幽灵会吞掉上传错误导致 exit 0
		// 假成功——校验远端实际字节数，不符自动重传一次；wc 无输出时尽力而为放行
		step("上传二进制（约 7MB，视上行带宽 10s-3min）…")
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
	}

	// 5. 安装 + 配置 systemd + 启动——分步执行 + echo 标记判定 + 失败重试。
	// 该 VPS 的 exec 通道存在间歇性幽灵（外部命令输出/exit 码随机丢失，
	// systemctl 一次探测不到、一次能到）——exit 码不可信，但内建 echo 的
	// 回显稳定：每条命令包装 `( cmd ) && echo __OK__ || echo __FAIL__$?`，
	// 以标记判成败；失败自动重试一次。
	runStepRaw := func(name, cmd string) error {
		// 幽灵间歇（同连接快速开会话输出丢失，实测上传大文件后高发）→
		// 内部验证标记 + 重试 3 次；真实失败（__ARGUS_FAIL_）立即返回不重试。
		var lastErr error
		for range 3 {
			s, err := client.NewSession()
			if err != nil {
				return fmt.Errorf("%s: 创建会话失败: %w", name, err)
			}
			var out bytes.Buffer
			s.Stdout = &out
			s.Stderr = &out
			wrapped := "( " + cmd + " ) && echo __ARGUS_OK__ || echo __ARGUS_FAIL_$?"
			rerr := runCmd(s, wrapped, 120*time.Second)
			s.Close()
			o := out.String()
			switch {
			case strings.Contains(o, "__ARGUS_FAIL_"):
				return fmt.Errorf("%s 失败（远端输出: %s）", name, tools.Truncate(o, 800))
			case strings.Contains(o, "__ARGUS_OK__"):
				step(name + " ✓  " + tools.Truncate(strings.TrimSpace(strings.ReplaceAll(
					strings.ReplaceAll(o, "__ARGUS_OK__", ""), "\n", " ")), 100))
				return nil
			case rerr != nil:
				lastErr = fmt.Errorf("%s 失败: %v（远端输出: %s）", name, rerr, tools.Truncate(o, 800))
			default:
				lastErr = fmt.Errorf("%s 输出通道异常（无标记无错误，远端输出: %q）", name, tools.Truncate(o, 200))
			}
			time.Sleep(400 * time.Millisecond)
		}
		return lastErr
	}
	runStep := func(name, cmd string) error {
		// 步骤间隔：x/crypto 同连接快速开会话会间歇丢失输出（另一提交实测
		// 30 次约 4 次）——降频规避
		time.Sleep(250 * time.Millisecond)
		if err := runStepRaw(name, cmd); err != nil {
			time.Sleep(800 * time.Millisecond) // 幽灵间歇 → 重试一次
			if err2 := runStepRaw(name+"（重试）", cmd); err2 != nil {
				return err2
			}
		}
		return nil
	}

	// 5.2 安装二进制：目录降级 + **效果验证**（cp 的 OK 标记会被幽灵吞——
	// mkdir 全成功说明目录可写，cp"失败"极可能是误判；以目标文件字节数
	// 等于本地下节数为准，wc 也被吞时回退标记判定）。
	verifyBin := func(path string) bool {
		ns := strings.Fields(probeOne("wc -c < " + path))
		if len(ns) == 0 {
			return false // wc 也被吞 → 无法确认
		}
		v, err := strconv.ParseInt(ns[0], 10, 64)
		return err == nil && v == localSize
	}
	binPath := ""
	for _, dir := range []string{"/usr/local/bin", "/opt/argus", "/root"} {
		_ = runStep("mkdir "+dir, sudo+"mkdir -p "+dir)
		cpErr := runStep("cp → "+dir,
			sudo+"cp /tmp/argus-node "+dir+"/argus-node && "+sudo+"chmod 755 "+dir+"/argus-node")
		target := dir + "/argus-node"
		if cpErr == nil || verifyBin(target) { // 标记成功 或 效果验证成功
			if cpErr != nil {
				step("cp 标记被吞但字节数验证通过: " + target)
			}
			binPath = target
			break
		}
	}
	if binPath == "" {
		return fail("二进制安装失败（三个目录 cp 均无法确认，标记与字节数验证都未通过）——" +
			"远端执行 df -h 与 ls -l /tmp/argus-node 自查后重试")
	}
	step("二进制已安装: " + binPath)

	// ── systemd 不可用（OpenVZ/LXC 容器常见）→ 降级 nohup + cron.d 模式 ──
	if sysctlPath == "" {
		step("systemd 不可用（容器型 VPS？）→ 降级 nohup 后台 + cron.d 自启")
		shellQuote := func(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }
		// env 前缀 + nohup + 后台 + 脱离会话（stdin/stdout 重定向防 SSH 退出牵连；
		// 日志写 $HOME——非 root 写不了 /var/log）
		startCmd := fmt.Sprintf(
			`ARGUS_SERVER=%s ARGUS_NAME=%s ARGUS_TOKEN=%s nohup `+binPath+` > ${HOME:-/tmp}/argus-node.log 2>&1 < /dev/null &`,
			shellQuote(cfg.ServerURL), shellQuote(cfg.NodeName), shellQuote(cfg.NodeToken))
		if err := runStep("nohup 启动节点", startCmd); err != nil {
			return fail(err.Error())
		}
		// 开机自启：/etc/cron.d/argus-node 单文件覆盖写（heredoc 在远端 sh
		// 兼容层 exit 2——echo 单行 + tee 最稳，重定向不经 sudo 会以普通用户
		// 落盘而失败；幂等不堆行；失败不阻塞）
		cronLine := fmt.Sprintf("@reboot root ARGUS_SERVER=%s ARGUS_NAME=%s ARGUS_TOKEN=%s ",
			shellQuote(cfg.ServerURL), shellQuote(cfg.NodeName), shellQuote(cfg.NodeToken)) +
			binPath + " >> ${HOME:-/tmp}/argus-node.log 2>&1"
		if err := runStep("cron.d 自启",
			sudo+"mkdir -p /etc/cron.d && printf '%s\\n' "+shellQuote(cronLine)+" | "+sudo+
				"tee /etc/cron.d/argus-node > /dev/null"); err != nil {
			step("cron.d 自启写入失败（不影响本次运行）: " + err.Error())
		}
		// 验证交给 server 侧：节点 5s 内心跳注册（状态变在线即闭环）
		step("节点已启动（nohup 模式，存活由服务器心跳确认）")
		if cfg.Tunnel {
			keepClient = true
		}
		return Result{
			OK: true,
			Message: fmt.Sprintf("节点 %s 已启动（容器模式：nohup + cron.d 自启），等待其经隧道回连 %s",
				cfg.NodeName, cfg.ServerURL),
			Steps: steps, KeepClient: map[bool]*ssh.Client{true: client, false: nil}[cfg.Tunnel],
		}
	}

	// 5.3 写 service：echo 逐行（heredoc 在远端 sh 兼容层下 exit 2 语法错——
	// Ubuntu /bin/sh=dash，括号+heredoc 组合挑剔；echo 内建 + `;` 链 + cp
	// 从未失手。/etc/systemd/system 同 minimal 容器缺失风险 → mkdir 兜底）
	shellQuote := func(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }
	svcLines := []string{
		"[Unit]",
		"Description=Argus Pentest Node",
		"After=network.target",
		"",
		"[Service]",
		"Type=simple",
		"Environment=ARGUS_SERVER=" + cfg.ServerURL,
		"Environment=ARGUS_NAME=" + cfg.NodeName,
		"Environment=ARGUS_TOKEN=" + cfg.NodeToken,
		"ExecStart=" + binPath,
		"Restart=always",
		"RestartSec=5",
		"",
		"[Install]",
		"WantedBy=multi-user.target",
	}
	var svcCmd strings.Builder
	svcCmd.WriteString(sudo + "mkdir -p /etc/systemd/system; ")
	for i, line := range svcLines {
		op := ">>"
		if i == 0 {
			op = ">"
		}
		svcCmd.WriteString("echo " + shellQuote(line) + " " + op + " /tmp/argus-node.service; ")
	}
	svcCmd.WriteString(sudo + "cp /tmp/argus-node.service /etc/systemd/system/argus-node.service")
	if err := runStep("写入 service 文件", svcCmd.String()); err != nil {
		return fail(err.Error())
	}

	// 5.4 systemd 三连（绝对路径）——全系软化：该机 systemctl 的输出/标记/
	// exit 码都会被幽灵随机吞（daemon-reload 上次 ✓ 这次空），命令可能实际
	// 已成功。全部降级为警告 + 多路兜底，部署成败以服务器侧节点心跳为准。
	softStep := func(name, cmd string) bool {
		if err := runStep(name, cmd); err != nil {
			step(name + " 结果未知（输出被吞，可能已成功）: " + err.Error())
			return false
		}
		return true
	}
	sysdOK := softStep("daemon-reload", sudo+sysctlPath+" daemon-reload") &&
		softStep("enable 开机自启", sudo+sysctlPath+" enable argus-node")
	if !softStep("restart 启动服务", sudo+sysctlPath+" restart argus-node") {
		// systemd 启动不可确认 → nohup 直接拉起兜底（日志写 $HOME——非 root
		// 写不了 /var/log）
		step("systemd 启动不可确认 → nohup 兜底启动")
		shellQuote := func(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }
		_ = softStep("nohup 兜底启动",
			fmt.Sprintf(`ARGUS_SERVER=%s ARGUS_NAME=%s ARGUS_TOKEN=%s nohup `+binPath+` > ${HOME:-/tmp}/argus-node.log 2>&1 < /dev/null &`,
				shellQuote(cfg.ServerURL), shellQuote(cfg.NodeName), shellQuote(cfg.NodeToken)))
	} else {
		step("systemd 服务已启动")
	}
	if !sysdOK {
		// enable 未知 → cron.d 兜底自启（幂等单文件；tee 经 sudo 落盘，
		// 重定向以普通用户执行会失败）
		shellQuote := func(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }
		cronLine := fmt.Sprintf("@reboot root ARGUS_SERVER=%s ARGUS_NAME=%s ARGUS_TOKEN=%s ",
			shellQuote(cfg.ServerURL), shellQuote(cfg.NodeName), shellQuote(cfg.NodeToken)) +
			binPath + " >> ${HOME:-/tmp}/argus-node.log 2>&1"
		_ = softStep("cron.d 兜底自启",
			sudo+"mkdir -p /etc/cron.d && printf '%s\\n' "+shellQuote(cronLine)+" | "+sudo+
				"tee /etc/cron.d/argus-node > /dev/null")
	}

	// 6. 存活验证：is-active 同样不可信（输出被吞）——交服务器心跳判定，
	// 此处只尽力看一眼，结果不影响部署结论。
	time.Sleep(2 * time.Second)
	if s3, err := client.NewSession(); err == nil {
		var checkOut bytes.Buffer
		s3.Stdout = &checkOut
		_ = runCmd(s3, sysctlPath+" is-active argus-node", 15*time.Second)
		s3.Close()
		if strings.TrimSpace(checkOut.String()) == "active" {
			step("节点服务运行中（systemd 确认）")
		}
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

	if cfg.Tunnel {
		keepClient = true
	}
	return Result{
		OK: true,
		Message: fmt.Sprintf("节点 %s 部署成功，等待其%s回连 %s",
			cfg.NodeName, map[bool]string{true: "经隧道", false: ""}[cfg.Tunnel], cfg.ServerURL),
		Steps: steps, KeepClient: map[bool]*ssh.Client{true: client, false: nil}[cfg.Tunnel],
	}
}

// TunnelRemoteAddr 隧道模式在远端 VPS 上监听的地址（节点连它=经隧道回 server）。
const TunnelRemoteAddr = "127.0.0.1:17887"

// TunnelServerAddr 隧道模式在本地转发的目标（argus-server 本机端口）。
const TunnelServerAddr = "127.0.0.1:7887"

// TunnelServerURL 隧道模式下写入节点配置的回连地址。
const TunnelServerURL = "http://" + TunnelRemoteAddr

// DialSSH 建立到远端的 SSH 连接（隧道管理器重连/恢复复用）。
func DialSSH(cfg SSHConfig) (*ssh.Client, error) { return sshConnect(cfg) }

// CleanHostPort 清洗用户输入的主机地址（部署表单/kali 主机表共用的坑）：
//   - host 里内嵌端口："1.2.3.4:22"、"[::1]:2222" 自动拆出——否则
//     JoinHostPort 见冒号拼成 "[1.2.3.4:22]:22"，整串被当域名 lookup 到超时
//   - 剥离所有不可见字符（零宽/控制/BOM/各类 Unicode 空白——TrimSpace 去不掉 U+200B）
//   - 全角数字/句点/冒号归一化半角（中文 IME 输入 IP 的高频坑）
//
// 返回清洗后的 host 与内嵌端口（无则 0）；残留无法识别的字符时报错。
func CleanHostPort(host string) (string, int, error) {
	var b strings.Builder
	for _, r := range host {
		switch {
		case unicode.IsControl(r), unicode.Is(unicode.Cf, r), unicode.IsSpace(r):
			continue // 不可见字符一律剥（IP/域名/URL host 均不含空白）
		case r >= 0xFF10 && r <= 0xFF19:
			b.WriteRune(r - 0xFF10 + '0') // ０-９
		case r == 0xFF0E || r == 0x3002:
			b.WriteByte('.') // ．。
		case r == 0xFF1A:
			b.WriteByte(':') // ：
		case r == '[' || r == ']':
			b.WriteRune(r)
		case r > 0x7E:
			return "", 0, fmt.Errorf("主机地址 %q 含无法识别的字符（请用半角重新输入）", host)
		default:
			b.WriteRune(r)
		}
	}
	h, port := b.String(), 0
	if h == "" {
		return "", 0, fmt.Errorf("主机地址不能为空")
	}
	if strings.HasPrefix(h, "[") { // [host] / [host]:port
		i := strings.IndexByte(h, ']')
		if i < 0 || i == 1 {
			return "", 0, fmt.Errorf("主机地址 %q 括号不成对", h)
		}
		inner, rest := h[1:i], h[i+1:]
		if rest != "" {
			if !strings.HasPrefix(rest, ":") || !isDigits(rest[1:]) {
				return "", 0, fmt.Errorf("主机地址 %q 格式无法识别", h)
			}
			port, _ = strconv.Atoi(rest[1:])
		}
		h = inner
	} else if strings.Count(h, ":") == 1 {
		// 单冒号按 host:port 拆（多冒号 = 裸 IPv6，原样保留给 JoinHostPort 加括号）
		i := strings.LastIndexByte(h, ':')
		suf := h[i+1:]
		switch {
		case isDigits(suf):
			port, _ = strconv.Atoi(suf)
			h = h[:i]
		case suf == "":
			h = h[:i] // 尾随冒号剥掉
		default:
			return "", 0, fmt.Errorf("主机地址 %q 格式无法识别", h)
		}
	}
	if h == "" {
		return "", 0, fmt.Errorf("主机地址不能为空")
	}
	return h, port, nil
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// sshConnect 建立 SSH 连接（密码或密钥）。
func sshConnect(cfg SSHConfig) (*ssh.Client, error) {
	// host 清洗：内嵌端口/全角/零宽字符统一归一（详见 CleanHostPort）
	host, hostPort, err := CleanHostPort(cfg.Host)
	if err != nil {
		return nil, err
	}
	cfg.Host = host
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
	if hostPort > 0 {
		port = hostPort // host 里显式内嵌的端口优先于表单 port 字段
	}
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

// remoteRun 在远端执行一条命令并返回合并输出（GitHub 下载用）。成败不由
// 本函数判定——该机 exec 通道会随机吞输出与 exit 码（见 DeployWithProgress
// 注释），调用方按标记 + 效果校验自行解读。
func remoteRun(client *ssh.Client, cmd string, timeout time.Duration) (string, error) {
	session, err := client.NewSession()
	if err != nil {
		return "", err
	}
	defer session.Close()
	var out bytes.Buffer
	session.Stdout = &out
	session.Stderr = &out
	done := make(chan error, 1)
	go func() { done <- session.Run(cmd) }()
	select {
	case err := <-done:
		return out.String(), err
	case <-time.After(timeout):
		_ = session.Signal(ssh.SIGKILL)
		return out.String(), fmt.Errorf("命令超时（>%s）", timeout)
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
	// shortcut: 永不回退 argus-server——那是管理面二进制，装上节点永远不注册
	names := []string{fmt.Sprintf("argus-node-linux-%s", goArch)}
	if runtime.GOOS == "linux" && runtime.GOARCH == goArch {
		names = append(names, "argus-node")
	}
	// systemd 启动时 CWD=/，须先查可执行文件同目录再查 CWD
	dirs := []string{}
	if exe, err := os.Executable(); err == nil {
		dirs = append(dirs, filepath.Dir(exe))
	}
	if wd, err := os.Getwd(); err == nil {
		dirs = append(dirs, wd)
	}
	dirs = append(dirs, "/usr/local/bin")
	for _, dir := range dirs {
		for _, name := range names {
			c := filepath.Join(dir, name)
			if _, err := os.Stat(c); err == nil {
				return c
			}
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
