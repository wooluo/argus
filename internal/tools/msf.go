package tools

// 移植自 AutoPentest tools/builtin/msf_search.py —— Metasploit 模块检索。
// 原版经 Kali 远端执行；argus 本机即执行环境，直接本地 msfconsole。

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var msfLineRe = regexp.MustCompile(
	`^\s*(\d+)\s+((?:exploit|auxiliary|post|encoder|payload)/[^\s]+)` +
		`(?:\s+(\d{4}-\d{2}-\d{2}))?\s+(\w+)\s+(Yes|No)\s+(.*)$`)

var msfSanitizeRe = regexp.MustCompile(`[^\w:.\- ]`)

type MsfSearchTool struct{}

func (MsfSearchTool) Name() string { return "msf_search" }

func (MsfSearchTool) Description() string {
	return "Metasploit 模块检索（本机 msf，模块库实时最新）：" +
		"按组件名/CVE/平台/关键词搜索 exploit/auxiliary 模块，" +
		"返回模块全路径与评级。命中后用 kali_exec 脚本化运行：" +
		`msfconsole -q -x "use <模块路径>; set RHOSTS <目标>; set PAYLOAD …; run; exit"` +
		"（遵守安全红线：仅良性验证，禁用破坏性载荷）。"
}

func (MsfSearchTool) Parameters() map[string]any {
	return Schema(map[string]any{
		"query": Prop("string", "检索词：组件名（fortinet）、CVE（cve:2025-25257）、"+
			"平台（platform:linux）等 msf search 语法"),
		"search_type": Prop("string", "类型过滤：exploit / auxiliary / payload / post（默认 exploit）"),
		"limit":       Prop("integer", "返回条数 1-20，默认 8"),
	}, "query")
}

func (MsfSearchTool) Execute(ctx context.Context, args map[string]any, tc *Context) (string, error) {
	query := strings.TrimSpace(msfSanitizeRe.ReplaceAllString(
		ArgString(args, "query", ""), " "))
	if query == "" {
		return "", Errorf("query 为空")
	}
	searchType := ArgString(args, "search_type", "exploit")
	switch searchType {
	case "exploit", "auxiliary", "payload", "post", "encoder", "nop":
	default:
		searchType = "exploit"
	}
	limit := ArgInt(args, "limit", 8)
	if limit < 1 {
		limit = 1
	} else if limit > 20 {
		limit = 20
	}
	stype := fmt.Sprintf("type:%s ", searchType)
	if err := ctx.Err(); err != nil {
		return "", err
	}

	cctx, cancel := context.WithTimeout(ctx, 200*time.Second)
	defer cancel()
	script := fmt.Sprintf(`timeout 180 msfconsole -q -x "search %s%s; exit" 2>&1`, stype, query)
	cmd := exec.CommandContext(cctx, "bash", "-c", script)
	out, err := cmd.CombinedOutput()
	if err != nil && len(out) == 0 {
		return "", Errorf("msfconsole 执行失败: %v（本机未安装 msf？）", err)
	}

	type module struct {
		Index      int      `json:"index"`
		Path       string   `json:"path"`
		Disclosure string   `json:"disclosure"`
		Rank       string   `json:"rank"`
		Targets    []string `json:"targets"`
	}
	var modules []*module
	var last *module
	sc := bufio.NewScanner(bytes.NewReader(out))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		if strings.Contains(line, "Interact with a module") || strings.TrimSpace(line) == "" {
			continue
		}
		stripped := strings.TrimSpace(line)
		if strings.HasPrefix(stripped, `\_`) && last != nil { // 子 target 行并入上一条
			t := strings.TrimSpace(stripped[2:])
			if len(t) > 60 {
				t = t[:60]
			}
			last.Targets = append(last.Targets, t)
			continue
		}
		m := msfLineRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		idx, _ := strconv.Atoi(m[1])
		last = &module{
			Index: idx, Path: m[2], Disclosure: m[3], Rank: m[4],
			Targets: []string{},
		}
		modules = append(modules, last)
	}
	if len(modules) > limit {
		modules = modules[:limit]
	}
	for _, m := range modules {
		if len(m.Targets) > 3 {
			m.Targets = m.Targets[:3]
		}
	}
	return MustJSON(map[string]any{
		"tool": "msf_search", "query": stype + query,
		"count": len(modules), "modules": modules,
		"usage": `运行选中模块：kali_exec 执行 msfconsole -q -x ` +
			`"use <模块路径>; set RHOSTS <目标>; run; exit"（良性验证，禁破坏性载荷）`,
	}), nil
}

func init() { Register(MsfSearchTool{}) }
