package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// DalfoxTool dalfox_scan：XSS 验证工具（对应 llms.txt Level 4 Dalfox）。
// 送一组带参数 URL 给 dalfox，它自动检测 XSS。
type DalfoxTool struct{}

func (DalfoxTool) Name() string { return "dalfox_scan" }
func (DalfoxTool) Description() string {
	return "XSS 扫描与验证。输入带参数的 URL，自动检测反射型、存储型和 DOM XSS。" +
		"需要目标上安装了 dalfox（kali_install dalfox 或手动安装：brew install dalfox / go install github.com/hahwul/dalfox/v2@latest）。"
}
func (DalfoxTool) Parameters() map[string]any {
	return Schema(map[string]any{
		"url": Prop("string", "目标 URL，如 https://example.com/search?q=keyword（参数位置由 dalfox 自动分析）"),
	}, "url")
}

func (DalfoxTool) Execute(ctx context.Context, args map[string]any, tc *Context) (string, error) {
	url := strings.TrimSpace(ArgString(args, "url", ""))
	if url == "" {
		return "", Errorf("url 为空")
	}
	if err := tc.Scope.EnsureURL(url); err != nil {
		return "", err
	}

	bin, err := ensurePdTool("dalfox", "github.com/hahwul/dalfox/v2")
	if err != nil {
		bin = "dalfox" // 降级到 PATH 本身
	}

	out, err := runTool(ctx, 300*time.Second, "",
		bin, "scan", url,
		"--silence", "--no-spinner",
		"--format", "json",
	)
	if err != nil && out == "" {
		if strings.Contains(err.Error(), "executable file not found") {
			return "", Errorf("dalfox 未安装。请执行 kali_install dalfox，或手动安装")
		}
		return "", Errorf("dalfox 执行失败: %v", err)
	}

	var vulns []map[string]any
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "{") {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			continue
		}
		param, _ := m["param"].(string)
		typ, _ := m["type"].(string)
		evidence, _ := m["evidence"].(string)
		poctext, _ := m["poc"].(string)
		severity := "medium"
		if strings.Contains(typ, "DOM") || strings.Contains(typ, "Blind") {
			severity = "high"
		}
		vulns = append(vulns, map[string]any{
			"param": param, "type": typ, "severity": severity,
			"evidence": evidence, "poc": poctext,
		})
		tc.Reporter.SaveFinding(ctx, Finding{
			Name:     "XSS - " + typ,
			Severity: severity,
			Target:   url,
			Detail:   fmt.Sprintf("参数 %s 存在 %s XSS", param, typ),
			PoC:      poctext,
			Evidence: evidence,
			Source:   "dalfox",
		})
	}
	return MustJSON(map[string]any{
		"tool": "dalfox_scan", "url": url,
		"vulnerabilities": len(vulns), "results": vulns,
	}), nil
}

func init() { Register(DalfoxTool{}) }