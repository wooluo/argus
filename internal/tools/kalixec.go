package tools

import (
	"context"
	"encoding/base64"
	"encoding/json"
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
// rm 系不在此表：RE2 无负向前瞻，rm -rf 的放行/拦截由 rmrfBlocked 单独处理。
var cmdBlacklist = []struct {
	pat *regexp.Regexp
	why string
}{
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
var rmrfRe = regexp.MustCompile(`(?i)rm\s+(?:-[a-z]+\s+)*-[a-z]*r[a-z]*f[a-z]*\s+(/\S*)`)

// rmrfBlocked 逐个 rm -rf 检查目标：/tmp /home/ /var/tmp 放行，其余绝对路径拦截。
// shortcut: 前缀匹配，/tmpx 也会放行（与蓝本 (?!tmp) 行为一致）
func rmrfBlocked(s string) bool {
	for _, m := range rmrfRe.FindAllStringSubmatch(s, -1) {
		t := strings.ToLower(m[1])
		if strings.HasPrefix(t, "/tmp") || strings.HasPrefix(t, "/home/") || strings.HasPrefix(t, "/var/tmp") {
			continue
		}
		return true
	}
	return false
}

func checkBlacklist(s string) string {
	if rmrfBlocked(s) {
		return "rm -rf 根路径"
	}
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

// KaliInstallTool kali_install：工具缺失时自主安装（对应 kali_install.py）。
type KaliInstallTool struct{}

// PD 官方二进制（GitHub Releases）与 pip 工具白名单。
var pdTools = map[string]string{
	"subfinder": "projectdiscovery/subfinder",
	"katana":    "projectdiscovery/katana",
	"naabu":     "projectdiscovery/naabu",
	"nuclei":    "projectdiscovery/nuclei",
	"httpx":     "projectdiscovery/httpx",
}
var pipTools = map[string]bool{"dirsearch": true, "wafw00f": true, "arjun": true, "webscreenshot": true, "sqliv": true}

func (KaliInstallTool) Name() string { return "kali_install" }
func (KaliInstallTool) Description() string {
	return "安装缺失的渗透工具（当目标工具不可用时先用本工具部署）。支持：subfinder/katana/naabu/" +
		"nuclei/httpx（官方二进制装到 ~/bin）、dirsearch/wafw00f/arjun 等 Python 工具（pip --user）、" +
		"nuclei-templates（更新 nuclei POC 模板库）、以及其他 apt 包。安装后即可正常调用。"
}
func (KaliInstallTool) Parameters() map[string]any {
	return Schema(map[string]any{
		"tool": Prop("string", "工具名，如 subfinder；模板填 nuclei-templates"),
		"why":  Prop("string", "为什么需要该工具（审计用）"),
	}, "tool")
}
func (KaliInstallTool) Execute(ctx context.Context, args map[string]any, tc *Context) (string, error) {
	tool := strings.ToLower(strings.TrimSpace(ArgString(args, "tool", "")))
	if tool == "" || !regexp.MustCompile(`^[a-z0-9][a-z0-9._\-]*$`).MatchString(tool) {
		return "", Errorf("非法工具名: %s", tool)
	}
	tc.Reporter.Log(ctx, "install", "kali_install", "[安装] "+tool)
	home, _ := os.UserHomeDir()
	var out string
	var err error
	switch {
	case tool == "nuclei-templates":
		out, err = runTool(ctx, 600*time.Second, "", "/bin/sh", "-c", "nuclei -update-templates 2>&1 | tail -5")
	case pdTools[tool] != "":
		script := pdInstallScript(pdTools[tool], tool)
		out, err = runTool(ctx, 600*time.Second, "", "/bin/sh", "-c", script)
	case pipTools[tool]:
		out, err = runTool(ctx, 600*time.Second, "", "pip3", "install", "--user", "--quiet", "--break-system-packages", tool)
	default: // apt 系统包
		script := "apt-get install -y --no-install-recommends " + tool + " 2>&1 | tail -5 || sudo -n apt-get install -y --no-install-recommends " + tool + " 2>&1 | tail -5"
		out, err = runTool(ctx, 900*time.Second, "", "/bin/sh", "-c", script)
	}
	rc := rcOf(err)
	// 安装后验证
	path := ""
	if v, verr := runTool(ctx, 15*time.Second, "", "/bin/sh", "-c", "command -v "+tool+" || command -v $HOME/bin/"+tool); verr == nil {
		path = strings.TrimSpace(strings.Split(v, "\n")[0])
	}
	installed := path != "" && strings.HasPrefix(path, "/")
	// ~/bin 可能在 PATH 外，验证时补查
	if !installed {
		if _, serr := os.Stat(filepath.Join(home, "bin", tool)); serr == nil {
			path = filepath.Join(home, "bin", tool)
			installed = true
		}
	}
	note := "工具已就绪，可直接调用"
	if !installed {
		note = "安装未生效，查看 output 排查（apt 类需 sudo 权限）"
	}
	return MustJSON(map[string]any{
		"tool": "kali_install", "target_tool": tool, "rc": rc,
		"installed": installed, "path": path, "host": "local",
		"output": Truncate(out, 2500), "note": note,
	}), nil
}

// pdInstallScript 生成 PD 官方 Releases 下载脚本（对应 _PD_INSTALL_SH；ghfast.top 镜像兜底）。
func pdInstallScript(repo, name string) string {
	return fmt.Sprintf(`set -e
arch=$(uname -m); [ "$arch" = "aarch64" ] && arch=arm64 || arch=amd64
ver=$(curl -s --max-time 20 https://api.github.com/repos/%s/releases/latest | grep -o '"tag_name": *"[^"]*"' | head -1 | cut -d'"' -f4)
[ -n "$ver" ] || { echo "获取版本失败（GitHub API 不可达，可配置代理）"; exit 1; }
vv=${ver#v}
mkdir -p "$HOME/bin" /tmp/pdinst && cd /tmp/pdinst
gh="https://github.com/%s/releases/download/${ver}/%s_${vv}_linux_${arch}.zip"
dl=0
for u in "$gh" "https://ghfast.top/$gh"; do
  echo "下载 $u"
  if curl -sL --max-time 300 -o t.zip "$u" && [ -s t.zip ]; then dl=1; break; fi
done
[ "$dl" = 1 ] || { echo "下载失败（直连与镜像均不可达）"; exit 1; }
unzip -oq t.zip -x "LICENSE*" "README*" "*.md" 2>/dev/null || unzip -oq t.zip
[ -f %[3]q ] && mv -f %[3]q "$HOME/bin/"
chmod +x "$HOME/bin/%[3]q"
"$HOME/bin/%[3]q" -version 2>/dev/null | head -1
`, repo, repo, name)
}

func init() { Register(KaliInstallTool{}) }

// ExploitdbSearchTool exploitdb_search：searchsploit 离线镜像检索（对应 exploitdb.py）。
type ExploitdbSearchTool struct{}

func (ExploitdbSearchTool) Name() string { return "exploitdb_search" }
func (ExploitdbSearchTool) Description() string {
	return "Exploit-DB 漏洞利用检索（searchsploit 离线镜像，4 万+ exploit/shellcode）：按组件/版本/CVE/" +
		"平台检索利用代码。结果含 EDB-ID 与本地路径，用 exploitdb_fetch 下载 exploit 到脚本目录后适配执行（良性验证）。"
}
func (ExploitdbSearchTool) Parameters() map[string]any {
	return Schema(map[string]any{
		"query": Prop("string", "检索词：组件+版本（'Apache 2.4.10'）、CVE（'CVE-2025-25257'）、平台过滤可加 'linux'/'windows'"),
		"limit": Prop("integer", "结果数 1-15，默认 8"),
	}, "query")
}
func (ExploitdbSearchTool) Execute(ctx context.Context, args map[string]any, tc *Context) (string, error) {
	query := cleanQuery(ArgString(args, "query", ""))
	if query == "" {
		return "", Errorf("query 为空")
	}
	limit := ArgInt(args, "limit", 8)
	if limit < 1 {
		limit = 1
	}
	if limit > 15 {
		limit = 15
	}
	out, err := runTool(ctx, 100*time.Second, "", "timeout", "90", "searchsploit", "--json", query)
	if err != nil && out == "" {
		return "", Errorf("searchsploit 执行失败: %v", err)
	}
	raw := strings.TrimSpace(out)
	if !strings.HasPrefix(raw, "{") {
		return "", Errorf("searchsploit 输出异常: %s", Truncate(raw, 200))
	}
	var data struct {
		Results []map[string]any `json:"RESULTS_EXPLOIT"`
	}
	if err := json.Unmarshal([]byte(raw), &data); err != nil {
		return "", Errorf("JSON 解析失败: %v", err)
	}
	results := []map[string]any{}
	for i, e := range data.Results {
		if i >= limit {
			break
		}
		results = append(results, map[string]any{
			"edb_id": e["EDB-ID"], "title": Truncate(fmt.Sprint(e["Title"]), 120),
			"type": e["Type"], "platform": e["Platform"],
			"verified": fmt.Sprint(e["Verified"]) == "1",
			"codes":    e["Codes"], "path": e["Path"],
		})
	}
	note := "无命中，试试更宽泛的组件名或去掉版本号"
	if len(results) > 0 {
		note = "用 exploitdb_fetch 下载命中的 EDB-ID 后适配执行（良性验证）"
	}
	return MustJSON(map[string]any{
		"tool": "exploitdb_search", "query": query, "count": len(results),
		"results": results, "note": note,
	}), nil
}

// cleanQuery 检索词清洗（对应 _clean）。
func cleanQuery(q string) string {
	q = regexp.MustCompile(`[^\w\s.\-+:]`).ReplaceAllString(q, " ")
	q = regexp.MustCompile(`\s+`).ReplaceAllString(q, " ")
	return strings.TrimSpace(q)
}

func init() { Register(ExploitdbSearchTool{}) }

// ExploitdbFetchTool exploitdb_fetch：按 EDB-ID 下载利用代码。
type ExploitdbFetchTool struct{}

func (ExploitdbFetchTool) Name() string { return "exploitdb_fetch" }
func (ExploitdbFetchTool) Description() string {
	return "下载 Exploit-DB 利用代码（按 EDB-ID）到脚本目录，供 run_script / kali_exec 阅读适配执行（良性验证）。"
}
func (ExploitdbFetchTool) Parameters() map[string]any {
	return Schema(map[string]any{
		"edb_id": Prop("string", "EDB-ID（exploitdb_search 结果）"),
	}, "edb_id")
}
func (ExploitdbFetchTool) Execute(ctx context.Context, args map[string]any, tc *Context) (string, error) {
	edbID := regexp.MustCompile(`[^0-9]`).ReplaceAllString(ArgString(args, "edb_id", ""), "")
	if edbID == "" {
		return "", Errorf("edb_id 必须是数字")
	}
	dir := tc.Workdir
	if dir == "" {
		dir = "/tmp/argus/scripts"
	}
	script := fmt.Sprintf("mkdir -p %s && cd %s && timeout 60 searchsploit -m %s 2>&1 | tail -3 && ls -la | grep %s",
		dir, dir, edbID, edbID)
	out, _ := runTool(ctx, 90*time.Second, "", "/bin/sh", "-c", script)
	if !strings.Contains(out, edbID) {
		return "", Errorf("EDB-%s 复制失败: %s", edbID, Truncate(out, 200))
	}
	fname := edbID
	if ls, lerr := runTool(ctx, 15*time.Second, "", "/bin/sh", "-c", "ls "+dir+" | grep "+edbID); lerr == nil && strings.TrimSpace(ls) != "" {
		fname = strings.TrimSpace(strings.Split(ls, "\n")[0])
	}
	return MustJSON(map[string]any{
		"tool": "exploitdb_fetch", "edb_id": edbID,
		"saved": dir + "/" + fname, "output": Truncate(out, 600),
		"note": "下载完成：先阅读理解 exploit 逻辑，适配目标后良性验证",
	}), nil
}

func init() { Register(ExploitdbFetchTool{}) }
