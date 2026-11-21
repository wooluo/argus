package api

// tools_install.go: 一键安装缺失外部工具（工具链状态页按钮）。
// 在 server 本机执行（pull 架构下节点即执行机；server 与节点同机部署时
// 即装即用）。策略：apt 系（nmap/sqlmap/unzip）走 apt-get；projectdiscovery
// 系（httpx/katana/nuclei/subfinder）走 GitHub latest release 精确资产下载。
// 异步执行 + SSE tools_install 事件推送进度。

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os/exec"
	"strings"
	"time"
)

// pdTools projectdiscovery 系工具（GitHub release 安装）。
var pdTools = map[string]bool{
	"httpx": true, "katana": true, "nuclei": true, "subfinder": true,
}

// aptTools apt 系工具（包名）。
var aptTools = map[string]bool{
	"nmap": true, "sqlmap": true,
}

// InstallTools POST /api/tools/install {"tools":["nmap",...]}——空列表 = 自动装全部缺失。
func (a *API) InstallTools(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Tools []string `json:"tools"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	// 自动检测缺失（外部工具中 available=false 的）
	if len(req.Tools) == 0 {
		for _, t := range ToolsStatusList(nil) {
			if kind, _ := t["kind"].(string); kind != "adapter" {
				continue
			}
			avail, _ := t["available"].(bool)
			bin, _ := t["binary"].(string)
			if !avail && bin != "" {
				req.Tools = append(req.Tools, bin)
			}
		}
	}
	if len(req.Tools) == 0 {
		jsonResp(w, 200, map[string]any{"ok": true, "message": "无缺失工具"})
		return
	}
	go func() {
		ok, fail := 0, 0
		for _, t := range req.Tools {
			t = strings.TrimSpace(t)
			if t == "" {
				continue
			}
			a.Bus.Publish("tools_install", map[string]any{"partial": true, "tool": t, "step": "安装中…"})
			var err error
			switch {
			case pdTools[t]:
				err = installPDTool(t)
			case aptTools[t]:
				err = installApt(t)
			default:
				err = fmt.Errorf("未知工具 %q（支持: nmap sqlmap httpx katana nuclei subfinder）", t)
			}
			if err != nil {
				fail++
				a.Bus.Publish("tools_install", map[string]any{"partial": true, "tool": t,
					"step": "❌ " + err.Error()})
			} else {
				ok++
				a.Bus.Publish("tools_install", map[string]any{"partial": true, "tool": t, "step": "✅ 安装成功"})
			}
		}
		a.Bus.Publish("tools_install", map[string]any{
			"done": true, "ok": ok, "fail": fail,
			"message": fmt.Sprintf("安装完成：成功 %d 失败 %d", ok, fail)})
	}()
	jsonResp(w, 200, map[string]any{"ok": true,
		"message": fmt.Sprintf("已开始安装 %d 个工具，进度见右上角通知", len(req.Tools))})
}

func jsonResp(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// runCmd 带超时执行 shell 命令。
func runShell(cmd string, timeout time.Duration) (string, error) {
	c := exec.Command("sh", "-c", cmd)
	var out strings.Builder
	c.Stdout = &out
	c.Stderr = &out
	done := make(chan error, 1)
	go func() { done <- c.Run() }()
	select {
	case err := <-done:
		return out.String(), err
	case <-time.After(timeout):
		_ = c.Process.Kill()
		return out.String(), fmt.Errorf("超时（>%s）", timeout)
	}
}

// installApt apt-get 安装（顺带确保 unzip 存在——pd 工具解压用）。
func installApt(pkg string) error {
	if _, err := exec.LookPath("apt-get"); err != nil {
		return fmt.Errorf("本机无 apt-get（仅支持 Debian/Ubuntu 系），请手动安装 %s", pkg)
	}
	if _, err := exec.LookPath("unzip"); err != nil {
		_, _ = runShell("DEBIAN_FRONTEND=noninteractive apt-get install -y -qq unzip 2>/dev/null", 120*time.Second)
	}
	out, err := runShell("DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "+pkg, 300*time.Second)
	if err != nil {
		return fmt.Errorf("apt 安装失败: %v（%s）", err, truncateStr(out, 200))
	}
	return nil
}

// installPDTool 从 GitHub latest release 安装 projectdiscovery 工具
// （API 查精确资产名——latest/download 短链的资产命名会过期）。
func installPDTool(name string) error {
	apiURL := fmt.Sprintf("https://api.github.com/repos/projectdiscovery/%s/releases/latest", name)
	cl := &http.Client{Timeout: 30 * time.Second}
	resp, err := cl.Get(apiURL)
	if err != nil {
		return fmt.Errorf("查 release 失败: %v", err)
	}
	defer resp.Body.Close()
	var rel struct {
		Assets []struct {
			BrowserDownloadURL string `json:"browser_download_url"`
			Name               string `json:"name"`
		} `json:"assets"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&rel); err != nil {
		return fmt.Errorf("解析 release 失败: %v", err)
	}
	dl := ""
	for _, a := range rel.Assets {
		if strings.Contains(a.Name, "linux_amd64.zip") {
			dl = a.BrowserDownloadURL
			break
		}
	}
	if dl == "" {
		return fmt.Errorf("release 无 linux_amd64 资产")
	}
	tmp := "/tmp/argus-install-" + name
	out, err := runShell(fmt.Sprintf(
		`curl -sL --max-time 240 -o %s.zip "%s" && cd /tmp && unzip -o -q %s.zip %s && install -m 755 /tmp/%s /usr/local/bin/%s`,
		tmp, dl, tmp, name, name, name), 300*time.Second)
	if err != nil {
		return fmt.Errorf("下载/安装失败: %v（%s）", err, truncateStr(out, 200))
	}
	if _, err := exec.LookPath(name); err != nil {
		return fmt.Errorf("安装后仍找不到 %s（%s）", name, truncateStr(out, 200))
	}
	return nil
}
