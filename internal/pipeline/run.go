// run.go: 任务执行核心（staged 五阶段 / autonomous 单会话），移植自
// pipeline.py _execute_stages / _run_autonomous / _stage_prompts / _gen_report。
package pipeline

import (
	"context"
	"fmt"
	"net/netip"
	"strings"

	"github.com/wooluo/argus/internal/llm"
	"github.com/wooluo/argus/internal/scope"
	"github.com/wooluo/argus/internal/tools"
)

// snapshot memReporter 的并发安全快照（dataSummary 用）。
func (m *memReporter) snapshot() Result {
	m.mu.Lock()
	defer m.mu.Unlock()
	return Result{
		Status:   m.res.Status,
		Findings: append([]Finding(nil), m.res.Findings...),
		Assets:   append([]Asset(nil), m.res.Assets...),
		Logs:     append([]LogItem(nil), m.res.Logs...),
	}
}

// Run 执行任务，返回最终结果（含 findings/assets/logs 与报告）。
// 取消 ctx 即停止任务（工具侧检查 ctx；结果照常回传）。
// onFlush 可为 nil；非 nil 时每次有新增条目即回调（增量上报用）。
func Run(ctx context.Context, b Brief, onFlush func(Result)) *Result {
	res := &Result{Status: "done"}
	rep := &memReporter{res: res, brief: b}
	if onFlush != nil {
		rep.onFlush = func(_ Brief, inc Result) { onFlush(inc) }
	}
	tc := &tools.Context{
		TaskID: b.TaskID, ProjectID: b.ProjectID, ProjectName: b.ProjectName,
		Description: b.Description,
		Reporter:    rep,
	}
	// scope 护栏
	tc.Scope = scope.New(b.ProjectID, b.Scope, b.AllowHosts)

	client := llm.NewClient(llm.DefaultProvider(b.LLM))

	rep.Log(ctx, "system", "", fmt.Sprintf(
		"任务启动 · 授权范围: %s · 模式: %s · 模型: %s",
		tc.Scope.Describe(), modeName(b.Mode), rep.LLMDesc()))

	if b.Mode == "autonomous" {
		runAutonomous(ctx, b, tc, rep, res, client)
		return res
	}
	runStaged(ctx, b, tc, rep, res, client)
	return res
}

func modeName(mode string) string {
	if mode == "autonomous" {
		return "自主"
	}
	return "阶段流水线"
}

// classifyScope 授权范围分成 (ips, domains)。
func classifyScope(b Brief) (ips, domains []string) {
	for _, r := range b.Scope {
		v := strings.TrimSpace(r.Value)
		if v == "" {
			continue
		}
		if _, err := netip.ParseAddr(v); err == nil {
			ips = append(ips, v)
			continue
		}
		if _, err := netip.ParsePrefix(v); err == nil {
			ips = append(ips, v)
			continue
		}
		domains = append(domains, v)
	}
	return
}

// dataSummary 当前资产与漏洞的紧凑摘要（阶段间上下文，替代原版查库）。
func dataSummary(rep *memReporter) string {
	m := rep.snapshot()
	var domains, urls, ports, techs []string
	for _, a := range m.Assets {
		switch a.Type {
		case "domain":
			domains = append(domains, a.Value)
		case "url":
			urls = append(urls, a.Value)
		case "port":
			ports = append(ports, a.Value)
		case "tech":
			techs = append(techs, a.Value)
		}
	}
	uniq := func(in []string) []string {
		seen := map[string]bool{}
		out := []string{}
		for _, v := range in {
			if !seen[v] {
				seen[v] = true
				out = append(out, v)
			}
		}
		return out
	}
	var fLines []string
	for i, f := range m.Findings {
		status := f.Status
		if status == "" {
			status = "pending"
		}
		fLines = append(fLines, fmt.Sprintf("#%d [%s] %s @ %s (%s)",
			i+1, f.Severity, f.Name, f.Target, status))
	}
	join := func(in []string, n int) string {
		if len(in) > n {
			in = in[:n]
		}
		if len(in) == 0 {
			return "无"
		}
		return strings.Join(in, ", ")
	}
	techStr := "未知"
	if len(uniq(techs)) > 0 {
		techStr = join(uniq(techs), 50)
	}
	fStr := "暂无"
	if len(fLines) > 0 {
		fStr = strings.Join(fLines, "\n")
	}
	return fmt.Sprintf(
		"### 已发现资产\n子域名(%d): %s\nURL(%d): %s\n开放端口(%d): %s\n技术栈: %s\n### 漏洞库(%d条)\n%s",
		len(domains), join(domains, 40),
		len(urls), join(urls, 60),
		len(ports), join(ports, 40),
		techStr, len(m.Findings), fStr)
}

func orDefault(s, def string) string {
	if strings.TrimSpace(s) == "" {
		return def
	}
	return s
}
