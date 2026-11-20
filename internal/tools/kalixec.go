package tools

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// ===== kali_exec / kali_install / run_script / exploitdb（蓝本 4 文件 → 本地直通实现） =====
//
// argus 节点体系：本机即 Kali 执行环境（原版 SSH 远端 → 本地 exec 直通）。

// cmdBlacklist 命令黑名单（对应 kali_exec._BLACKLIST / run_script._CODE_BLACKLIST）。
var cmdBlacklist = []struct {
	pat *regexp.Regexp
	why string
}{
	{regexp.MustCompile(`(?i)rm\s+(-[a-z]+\s+)*-[a-z]*r[a-z]*f[a-z]*\s+/(?!tmp|home/|var/tmp)`), "rm -rf 根路径"},
	{regexp.MustCompile(`(?i)\bmkfs(\.\w+)?\b`), "格式化磁盘"},
	{regexp.MustCompile(`(?i)\b(shutdown|reboot|halt|poweroff)\b`), "关机/重启"},
	{regexp.MustCompile(`(?i)\binit\s+[06]\b`), "切换运行级"},
	{regexp.MustCompile(`(?i)dd\s+[^;]*of=/dev/`), "dd 写裸设备"},
	{regexp.MustCompile(`(?i):\(\)\s*\{.*\};\s*:`), "fork bomb"},
	{regexp.MustCompile(`(?i)chmod\s+-R\s+777\s+/\s*$`), "递归 777 根路径"},
	{regexp.MustCompile(`(?i)>\s*/dev/sd[a-z]`), "覆写磁盘设备"},
	{regexp.MustCompile(`(?i)\bmv\s+/\w*\s+/dev/null\b`), "把系统目录移入 /dev/null"},
	// 代码级补充（run_script._CODE_BLACKLIST）
	{regexp.MustCompile(`(?i)base64\s+(-d|--decode)?\s*\|.*\b(sh|bash|zsh)\b`), "base64 解码管道执行"},
	{regexp.MustCompile(`(?i)printf\s+[^;|]*(\\x|\\\\x)[0-9a-f].*(\||>)\s*(sh|bash)`), "printf 转义序列执行"},
	{regexp.MustCompile(`(?i)\bxxd\b[^;|]*\|\s*(sh|bash|zsh)`), "xxd 反解进 shell"},
	{regexp.MustCompile(`(?i)python3?\s+-c\b[^#]*\b(os\.system|subprocess|popen)`), "python -c 内嵌 shell 调用"},
}

// checkBlacklist 命中黑名单返回原因。
func checkBlacklist(s string) string {
	for _, b := range cmdBlacklist {
		if b.pat.MatchString(s) {
			return b.why
		}
	}
	return ""
}

var ipv4Re = regexp.MustCompile(`\b(\d{1,3}(?:\.\d{1,3}){3})\b`)
var urlRe = regexp.MustCompile(`https?://[^\s'"<>]+`)

// KaliExecTool kali_exec：在执行环境跑任意命令（黑名单+范围校验+nmap 兜底）。
type KaliExecTool struct{}

func (KaliExecTool) Name() string { return "kali_exec" }
func (KaliExecTool) Description() string {
	return "在渗透执行主机上执行任意命令行工具（装有完整 Kali 工具集：nmap 全功能、gobuster、ffuf、" +
		"hydra、nikto、wpscan、responder、impacket 套件等）。适合本地工具链覆盖不了的场景" +
		"（爆破、协议测试、深度枚举等）。参数：command 为完整命令行；purpose 一句话说明意图（审计用）。" +
		"注意：1) 命令中的目标 IP/URL 必须在授权范围内，破坏性命令会被拒绝；" +
		"2) nmap 必须加 -sT（TCP connect）或让本工具自动补 -Pn；网段存活发现请用 host_discovery 工具。"
}
func (KaliExecTool) Parameters() map[string]any {
	return Schema(map[string]any{
		"command": Prop("string", "要执行的完整命令行"),
		"purpose": Prop("string", "一句话说明本次命令的意图"),
		"timeout": Prop("integer", "超时秒数 10-600，默认 300"),
	}, "command")
}
func (KaliExecTool) Execute(ctx context.Context, args map[string]any, tc *Context) (string, error) {
	command := strings.TrimSpace(ArgString(args, "command", ""))
	if command == "" {
		return "", Errorf("command 为空")
	}
	if len(command) > 5000 {
		return "", Errorf("命令过长")
	}
	timeout := ArgInt(args, "timeout", 300)
	if timeout < 10 {
		timeout = 10
	}
	if timeout > 600 {
		timeout = 600
	}
	if why := checkBlacklist(command); why != "" {
		return "", Errorf("命令被安全黑名单拦截（%s）: %s", why, Truncate(command, 100))
	}
	// nmap 兜底：非 root 缺 -Pn 自动补
	tokens := strings.Fields(command)
	if len(tokens) > 0 && strings.HasSuffix(tokens[0], "nmap") {
		for _, t := range tokens {
			if t == "-sn" {
				return "", Errorf("非 root 下 nmap -sn（主机发现）需要 raw socket，必然失败。网段存活发现请直接调用 host_discovery 工具")
			}
		}
		if !contains(tokens, "-Pn") {
			command = "nmap -Pn " + strings.Join(tokens[1:], " ")
		}
	}
	// 范围尽力校验：IPv4 字面量与 URL host
	for _, ip := range ipv4Re.FindAllString(command, -1) {
		if ip == "127.0.0.1" || ip == "0.0.0.0" {
			continue
		}
		if !tc.Scope.CheckHost(ip) {
			return "", Errorf("目标 %s 不在授权范围内", ip)
		}
	}
	for _, u := range urlRe.FindAllString(command, -1) {
		host := ""
		if parsed, err := url.Parse(u); err == nil {
			host = parsed.Hostname()
		}
		host = strings.SplitN(host, ";", 2)[0]
		host = regexp.MustCompile(`[;&,|)]`).Split(host, -1)[0]
		if host == "" || host == "127.0.0.1" || host == "localhost" {
			continue
		}
		if !tc.Scope.CheckHost(host) {
			return "", Errorf("目标 %s 不在授权范围内", host)
		}
	}
	tc.Reporter.Log(ctx, "agent", "kali_exec", Truncate(command, 200))
	out, err := runTool(ctx, time.Duration(timeout)*time.Second, "", "/bin/sh", "-c", command)
	if err != nil && out == "" {
		return "", Errorf("exec: %v", err)
	}
	return MustJSON(map[string]any{
		"tool": "kali_exec", "rc": rcOf(err), "host": "local",
		"purpose":          ArgString(args, "purpose", ""),
		"output_truncated": len(out) > 8000,
		"output":           Truncate(out, 8000),
	}), nil
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

// rcOf 从 exec 错误提取退出码（失败返回 -1）。
func rcOf(err error) int {
	if err == nil {
		return 0
	}
	if ee, ok := err.(*exec.ExitError); ok {
		return ee.ExitCode()
	}
	return -1
}

func init() { Register(KaliExecTool{}) }

// RunScriptTool run_script：Agent 自写脚本在隔离目录执行（对应 run_script.py）。
type RunScriptTool struct{}

func (RunScriptTool) Name() string { return "run_script" }
func (RunScriptTool) Description() string {
	return "编写并执行自定义脚本（python3 / bash）——PoC 开发与迭代、批量分析、调用 radare2/objdump/" +
		"capa 等做逆向辅助、自定义协议交互的通用底座。写代码 → 执行 → 根据输出修改重跑，形成研究闭环。" +
		"脚本在节点工作目录隔离执行；需要第三方库可先 pip3 install --user 安装。遵守安全红线（良性验证）。"
}
func (RunScriptTool) Parameters() map[string]any {
	return Schema(map[string]any{
		"code":     Prop("string", "完整脚本代码（不要省略）"),
		"language": PropEnum("默认 python3", "python3", "bash"),
		"filename": Prop("string", "保存的文件名（默认 auto.py/auto.sh）"),
		"timeout":  Prop("integer", "超时秒 5-600，默认 120"),
	}, "code")
}
func (RunScriptTool) Execute(ctx context.Context, args map[string]any, tc *Context) (string, error) {
	code := ArgString(args, "code", "")
	if strings.TrimSpace(code) == "" {
		return "", Errorf("code 为空")
	}
	if len(code) > 200000 {
		return "", Errorf("脚本过长")
	}
	language := ArgString(args, "language", "python3")
	if language != "python3" && language != "bash" {
		language = "python3"
	}
	timeout := ArgInt(args, "timeout", 120)
	if timeout < 5 {
		timeout = 5
	}
	if timeout > 600 {
		timeout = 600
	}
	filename := sanitizeFilename(ArgString(args, "filename", ""), language)
	if why := checkBlacklist(code); why != "" {
		return "", Errorf("脚本被安全黑名单拦截（%s）", why)
	}
	tc.Reporter.Log(ctx, "agent", "run_script",
		fmt.Sprintf("[脚本] %s %s (%d字)", language, filename, len(code)))
	// 写入脚本（base64 传输防转义）
	dir := tc.Workdir
	if dir == "" {
		dir = "/tmp/argus/scripts"
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	path := filepath.Join(dir, filename)
	if err := os.WriteFile(path, []byte(code), 0o644); err != nil {
		return "", Errorf("脚本写入失败: %v", err)
	}
	_ = base64.StdEncoding // 预留：远程节点传输时启用 base64 通道
	interpreter := "python3"
	if language == "bash" {
		interpreter = "bash"
	}
	out, err := runTool(ctx, time.Duration(timeout)*time.Second, "", interpreter, path)
	return MustJSON(map[string]any{
		"tool": "run_script", "language": language, "filename": filename,
		"saved": path, "rc": rcOf(err),
		"output_truncated": len(out) > 8000,
		"output":           Truncate(out, 8000),
		"note":             ternary(rcOf(err) != 0, "rc=0 成功；报错请读取输出修正代码后重跑", ""),
	}), nil
}

// sanitizeFilename 文件名白名单（防路径逃逸）。
func sanitizeFilename(name, language string) string {
	name = regexp.MustCompile(`[^a-zA-Z0-9._\-]`).ReplaceAllString(name, "_")
	name = strings.Trim(name, "._")
	if len(name) > 60 {
		name = name[:60]
	}
	if name == "" || strings.HasPrefix(name, ".") || strings.Contains(name, "/") {
		if language == "bash" {
			return "auto.sh"
		}
		return "auto.py"
	}
	return name
}

func ternary(cond bool, a, b string) string {
	if cond {
		return a
	}
	return b
}

func init() { Register(RunScriptTool{}) }
