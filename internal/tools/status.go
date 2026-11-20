package tools

import "sort"

// adapterNames: 外部二进制适配器（binary=名字前缀；对应蓝本 _ADAPTERS）。
var adapterNames = map[string]bool{
	"httpx_probe": true, "katana_crawl": true, "sqlmap_detect": true,
	"subfinder": true, "nmap_scan": true, "nuclei_scan": true,
}

// fallbackFor 缺失提示（对齐蓝本 _fallback_for）。
var fallbackFor = map[string]string{
	"subfinder":   "无兜底（仅输入域名直接探测时可用 http_alive）",
	"httpx_probe": "http_alive", "nmap_scan": "port_scan",
	"nuclei_scan": "无兜底（建议安装 nuclei）", "katana_crawl": "web_crawl",
	"sqlmap_detect": "无兜底（建议安装 sqlmap）",
}

// Status 工具链状态列表：name/kind/binary/available/fallback_for/exec_at。
func Status(customPaths map[string]string) []map[string]any {
	out := []map[string]any{}
	names := Names()
	sort.Strings(names)
	for _, n := range names {
		if adapterNames[n] {
			base := n
			if i := indexByte(n, '_'); i > 0 {
				base = n[:i]
			}
			bin := base
			if p, ok := customPaths[base]; ok && p != "" {
				bin = p
			} else {
				bin = toolPath(base)
			}
			ok := toolAvailable(bin)
			note := ""
			if !ok {
				note = fallbackFor[n]
			}
			out = append(out, map[string]any{
				"name": n, "kind": "adapter", "binary": bin,
				"available": ok, "fallback_for": note, "exec_at": "local",
			})
		} else {
			out = append(out, map[string]any{
				"name": n, "kind": "builtin", "binary": "-",
				"available": true, "fallback_for": "", "exec_at": "-",
			})
		}
	}
	return out
}

func indexByte(s string, b byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == b {
			return i
		}
	}
	return -1
}
