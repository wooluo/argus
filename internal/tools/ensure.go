package tools

// ensure.go: 外部工具起手前的两项检查——nuclei 的模板库、httpx 是不是
// ProjectDiscovery 那个 httpx。都是在真实节点上踩过的：服务以 root 跑，
// HOME 下什么都没有。

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

var (
	nucleiTmpl    nucleiTemplateState
	httpxVerified sync.Map // 确认过是 ProjectDiscovery 版本的 httpx 路径
)

// nucleiTemplateState 「装模板」每个进程至多尝试一次；做成变量方便测试逐例重置。
type nucleiTemplateState struct {
	once sync.Once
	err  error
}

// nucleiTemplatesDir 当前用户（节点进程）的 nuclei 模板目录：环境变量
// NUCLEI_TEMPLATES_DIRECTORY 优先，否则 ~/nuclei-templates（nuclei 默认位置）。
func nucleiTemplatesDir() string {
	if d := strings.TrimSpace(os.Getenv("NUCLEI_TEMPLATES_DIRECTORY")); d != "" {
		return d
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, "nuclei-templates")
}

// hasTemplates 模板目录里有子目录（cves/、misconfig/ …）才算装过。
func hasTemplates(dir string) bool {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return false
	}
	for _, e := range ents {
		if e.IsDir() {
			return true
		}
	}
	return false
}

// ensureNucleiTemplates 模板库还没有时先装一次（每个进程至多尝试一次）。
// 服务以 root 跑时 HOME 下没有模板，nuclei 起手就报错退出；以前这个错被
// 吞掉，每次扫描都是「0 个发现」。
func ensureNucleiTemplates(ctx context.Context, bin string) error {
	dir := nucleiTemplatesDir()
	if hasTemplates(dir) {
		return nil
	}
	nucleiTmpl.once.Do(func() {
		out, err := runTool(ctx, 10*time.Minute, "", bin, "-update-templates")
		// 更新器的退出码不足为凭，以目录里有没有模板为准
		if !hasTemplates(dir) {
			why := "更新器正常退出，但目录里仍然没有模板"
			if err != nil {
				why = exitReason(err)
			}
			nucleiTmpl.err = fmt.Errorf("nuclei 模板库缺失，自动安装也没装上（%s）：%s；可在节点上执行 `nuclei -update-templates`（模板装到 %s）",
				why, Truncate(tailLines(out, 4), 300), dir)
		}
	})
	return nucleiTmpl.err
}

// ensurePdHTTPX Kali 上有同名异物的 Python 客户端 httpx：参数不认，起手就
// 报用法错误。认一下 banner；通过了的路径记住，不必每次都跑版本命令。
func ensurePdHTTPX(bin string) error {
	if _, ok := httpxVerified.Load(bin); ok {
		return nil
	}
	out, err := runTool(context.Background(), 15*time.Second, "", bin, "-version")
	if err == nil && strings.Contains(strings.ToLower(out), "projectdiscovery") {
		httpxVerified.Store(bin, struct{}{})
		return nil
	}
	msg := fmt.Sprintf("PATH 里的 httpx（%s）不是 ProjectDiscovery 版本，用不了", bin)
	if tail := tailLines(out, 3); tail != "" {
		msg += "；它的输出：" + Truncate(tail, 200)
	}
	return fmt.Errorf("%s。请安装 PD 版 httpx，或用环境变量 ARGUS_TOOL_HTTPX 指向它", msg)
}
