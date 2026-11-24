package api

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/wooluo/argus/internal/config"
	"github.com/wooluo/argus/internal/llm"
	"github.com/wooluo/argus/internal/store"
)

// ============ Reports 域（蓝本 api/reports.py） ============

func orDefault(s, def string) string {
	if strings.TrimSpace(s) == "" {
		return def
	}
	return s
}

// listReports GET /api/reports —— 全部项目报告，最新的在前。
func (a *API) ListReports(w http.ResponseWriter, r *http.Request) {
	rows, err := a.DB.Query(`
		SELECT r.id, r.project_id, r.task_id, r.markdown, r.created_at, p.name
		FROM reports r LEFT JOIN projects p ON p.id = r.project_id
		ORDER BY r.id DESC`)
	if err != nil {
		respondErr(w, 500, err.Error())
		return
	}
	defer rows.Close()
	type item struct {
		ID        int    `json:"id"`
		ProjectID int    `json:"project_id"`
		TaskID    int    `json:"task_id"`
		Markdown  string `json:"markdown"`
		CreatedAt string `json:"created_at"`
		Project   string `json:"project_name"`
	}
	list := []item{}
	for rows.Next() {
		var it item
		var proj sql.NullString
		if err := rows.Scan(&it.ID, &it.ProjectID, &it.TaskID, &it.Markdown, &it.CreatedAt, &proj); err != nil {
			respondErr(w, 500, err.Error())
			return
		}
		it.Project = proj.String
		list = append(list, it)
	}
	respondJSON(w, 200, list)
}

// getProjectReport GET /api/projects/{id}/report —— 项目最新报告（无则 404）。
func (a *API) GetProjectReport(w http.ResponseWriter, r *http.Request) {
	id, _ := pathID(r)
	var rep struct {
		ID        int
		ProjectID int
		TaskID    int
		Markdown  string
		CreatedAt string
	}
	err := a.DB.QueryRow(`
		SELECT id, project_id, task_id, markdown, created_at
		FROM reports WHERE project_id = ? ORDER BY id DESC LIMIT 1`, id).
		Scan(&rep.ID, &rep.ProjectID, &rep.TaskID, &rep.Markdown, &rep.CreatedAt)
	if err == sql.ErrNoRows {
		respondErr(w, 404, "报告不存在")
		return
	}
	if err != nil {
		respondErr(w, 500, err.Error())
		return
	}
	respondJSON(w, 200, map[string]any{
		"id": rep.ID, "project_id": rep.ProjectID, "task_id": rep.TaskID,
		"markdown": rep.Markdown, "created_at": rep.CreatedAt,
	})
}

// exportReport GET /api/projects/{id}/report/export?format=md|html|txt|docx
func (a *API) ExportReport(w http.ResponseWriter, r *http.Request) {
	id, _ := pathID(r)
	format := r.URL.Query().Get("format")
	if format == "" {
		format = "md"
	}
	var markdown string
	err := a.DB.QueryRow(
		`SELECT markdown FROM reports WHERE project_id = ? ORDER BY id DESC LIMIT 1`, id).
		Scan(&markdown)
	if err == sql.ErrNoRows {
		respondErr(w, 404, "报告不存在")
		return
	}
	if err != nil {
		respondErr(w, 500, err.Error())
		return
	}
	name := fmt.Sprintf("report-p%d-%s", id, time.Now().Format("20060102-150405"))
	switch format {
	case "html":
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Content-Disposition", "attachment; filename="+name+".html")
		_, _ = w.Write([]byte(renderReportHTML(markdown)))
	case "txt":
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Content-Disposition", "attachment; filename="+name+".txt")
		_, _ = w.Write([]byte(stripMarkdown(markdown)))
	case "docx":
		w.Header().Set("Content-Type",
			"application/vnd.openxmlformats-officedocument.wordprocessingml.document")
		w.Header().Set("Content-Disposition", "attachment; filename="+name+".docx")
		_, _ = w.Write(renderDocx(markdown))
	default: // md
		w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
		w.Header().Set("Content-Disposition", "attachment; filename="+name+".md")
		_, _ = w.Write([]byte(markdown))
	}
}

// previewReport GET /api/projects/{id}/report/preview —— HTML 预览。
func (a *API) PreviewReport(w http.ResponseWriter, r *http.Request) {
	id, _ := pathID(r)
	var markdown string
	err := a.DB.QueryRow(
		`SELECT markdown FROM reports WHERE project_id = ? ORDER BY id DESC LIMIT 1`, id).
		Scan(&markdown)
	if err == sql.ErrNoRows {
		http.Error(w, "报告不存在", 404)
		return
	}
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(renderReportHTML(markdown)))
}

// generateReport POST /api/projects/{id}/report/generate
// 蓝本：读 findings + assets → pipeline.GenerateReport → 落库 + 返回 markdown。
func (a *API) GenerateReport(w http.ResponseWriter, r *http.Request) {
	id, _ := pathID(r)
	var in struct {
		TaskID     int    `json:"task_id"`
		TemplateID string `json:"template_id"`
	}
	_ = json.NewDecoder(r.Body).Decode(&in) // 允许空 body

	var projectName string
	if err := a.DB.QueryRow(`SELECT name FROM projects WHERE id = ?`, id).Scan(&projectName); err != nil {
		respondErr(w, 404, "项目不存在")
		return
	}

	// 数据摘要：资产 + 漏洞（与蓝本 _data_summary 对齐）
	domains := []string{}
	urls := []string{}
	ports := []string{}
	techs := []string{}
	frows, err := a.DB.Query(`SELECT type, value FROM assets WHERE project_id = ? LIMIT 400`, id)
	if err != nil {
		respondErr(w, 500, err.Error())
		return
	}
	for frows.Next() {
		var t, v string
		if err := frows.Scan(&t, &v); err == nil {
			switch t {
			case "domain":
				domains = append(domains, v)
			case "url":
				urls = append(urls, v)
			case "port":
				ports = append(ports, v)
			case "tech":
				techs = append(techs, v)
			}
		}
	}
	frows.Close()

	type findingRow struct {
		ID       int
		Severity string
		Name     string
		Target   string
		Status   string
		Source   string
		Detail   string
		PoC      string
	}
	findings := []findingRow{}
	lrows, err := a.DB.Query(`
		SELECT id, severity, name, target, status, source, detail, poc
		FROM findings WHERE project_id = ? ORDER BY id DESC LIMIT 200`, id)
	if err != nil {
		respondErr(w, 500, err.Error())
		return
	}
	for lrows.Next() {
		var f findingRow
		if err := lrows.Scan(&f.ID, &f.Severity, &f.Name, &f.Target, &f.Status, &f.Source, &f.Detail, &f.PoC); err == nil {
			findings = append(findings, f)
		}
	}
	lrows.Close()

	clip := func(ss []string, n int) string {
		if len(ss) > n {
			ss = ss[:n]
		}
		if len(ss) == 0 {
			return "无"
		}
		return strings.Join(ss, ", ")
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, "### 已发现资产\n子域名(%d): %s\nURL(%d): %s\n开放端口(%d): %s\n技术栈: %s\n",
		len(domains), clip(domains, 40),
		len(urls), clip(urls, 60),
		len(ports), clip(ports, 40),
		orDefault(strings.Join(techs, ", "), "未知"))
	fmt.Fprintf(&sb, "### 漏洞库(%d条)\n", len(findings))
	detailLines := []string{}
	for _, f := range findings {
		if f.Status == "false_positive" {
			continue
		}
		fmt.Fprintf(&sb, "#%d [%s] %s @ %s (%s, 来源:%s)\n", f.ID, f.Severity, f.Name, f.Target, f.Status, f.Source)
		poc := f.PoC
		if len(poc) > 200 {
			poc = poc[:200] + "…"
		}
		detailLines = append(detailLines, fmt.Sprintf(
			"- [%s] %s @ %s（%s）\n  详情: %s\n  PoC: %s",
			f.Severity, f.Name, f.Target, orDefault(f.Status, "pending"), f.Detail, poc))
	}
	if len(detailLines) == 0 {
		sb.WriteString("暂无\n")
	}

	// 模板注入（蓝本：TEMPLATES_DIR / {template_id}.md 追加为额外要求）
	extra := ""
	if tid := strings.TrimSpace(in.TemplateID); tid != "" {
		tpl := filepath.Join(config.Load().DataDir, "templates", tid+".md")
		b, err := os.ReadFile(tpl)
		if err != nil {
			respondErr(w, 404, "模板不存在")
			return
		}
		extra = "\n\n### 模板要求\n" + string(b)
	}

	detailStr := strings.Join(detailLines, "\n")
	if detailStr == "" {
		detailStr = "无确认漏洞"
	}
	client := llm.NewClient(llm.DefaultProvider(llmConfigForRole(a.DB, "aux"))) // 报告生成：分工了用「报告与复盘」的模型
	prompt := "根据以下渗透测试数据生成完整中文 Markdown 报告，结构：\n" +
		"# 概述（项目背景/范围/方法）\n# 资产统计\n# 漏洞汇总（按严重度表格：编号/名称/严重度/目标/状态）\n" +
		"# 漏洞详情（每个漏洞：描述/危害/证据/复现/修复建议）\n# 总结与整体安全建议\n\n" +
		"项目名称: " + projectName + "\n\n" + sb.String() + "\n\n### 漏洞详情数据\n" + detailStr
	md, err := client.ChatText(r.Context(),
		"你是资深渗透测试报告撰写专家，输出严谨专业的中文 Markdown 报告。",
		prompt, 0.2)
	if err != nil || strings.TrimSpace(md) == "" {
		// LLM 失败兜底：数据事实清单即报告（与 pipeline.genReport 一致）
		md = "## 渗透测试数据报告（LLM 生成失败，原始数据）\n\n" + sb.String() + "\n\n" + detailStr
	}
	md += extra

	taskID := in.TaskID
	res, err := a.DB.Exec(
		`INSERT INTO reports(project_id, task_id, markdown, created_at) VALUES (?,?,?,?)`,
		id, taskID, md, store.Now())
	if err != nil {
		respondErr(w, 500, err.Error())
		return
	}
	rid, _ := res.LastInsertId()
	respondJSON(w, 200, map[string]any{
		"id": rid, "project_id": id, "task_id": taskID,
		"markdown": md, "created_at": store.Now(),
	})
}

// renderReportHTML Markdown → 完整 HTML 页（无外部依赖，内联 CSS）。
func renderReportHTML(md string) string {
	var b strings.Builder
	b.WriteString("<!DOCTYPE html>\n<html lang=\"zh\">\n<head>\n<meta charset=\"utf-8\">\n")
	b.WriteString("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n")
	b.WriteString("<title>Argus 报告</title>\n<style>\n")
	b.WriteString("body{font-family:-apple-system,'PingFang SC','Microsoft YaHei',sans-serif;")
	b.WriteString("max-width:860px;margin:2rem auto;padding:0 1rem;line-height:1.7;color:#1a1a1a;}\n")
	b.WriteString("h1{border-bottom:2px solid #2b6cb0;padding-bottom:.4rem;}\n")
	b.WriteString("h2{border-left:4px solid #2b6cb0;padding-left:.6rem;margin-top:2rem;}\n")
	b.WriteString("table{border-collapse:collapse;width:100%;margin:1rem 0;}\n")
	b.WriteString("th,td{border:1px solid #cbd5e0;padding:.4rem .6rem;text-align:left;font-size:.92em;}\n")
	b.WriteString("th{background:#edf2f7;}\npre{background:#f7fafc;padding:.8rem;border-radius:6px;overflow-x:auto;}\n")
	b.WriteString("code{background:#f7fafc;padding:.1rem .3rem;border-radius:3px;font-size:.9em;}\n")
	b.WriteString("pre code{background:none;padding:0;}\nblockquote{border-left:4px solid #cbd5e0;margin:1rem 0;padding:.2rem 1rem;color:#4a5568;}\n")
	b.WriteString("</style>\n</head>\n<body>\n")
	b.WriteString(mdToHTML(md))
	b.WriteString("\n</body>\n</html>\n")
	return b.String()
}

var headingRe = regexp.MustCompile(`^(#{1,6})\s+(.*)$`)

// mdToHTML 轻量 Markdown→HTML（标题/表格/代码块/引用/列表/行内标记），无第三方依赖。
func mdToHTML(md string) string {
	lines := strings.Split(md, "\n")
	var out []string
	for i := 0; i < len(lines); i++ {
		line := lines[i]
		trimmed := strings.TrimSpace(line)
		// 围栏代码块
		if strings.HasPrefix(trimmed, "```") {
			var buf []string
			i++
			for i < len(lines) && !strings.HasPrefix(strings.TrimSpace(lines[i]), "```") {
				buf = append(buf, lines[i])
				i++
			}
			out = append(out, "<pre><code>"+strings.Join(buf, "\n")+"</code></pre>")
			continue
		}
		// 标题
		if m := headingRe.FindStringSubmatch(line); m != nil {
			lvl := len(m[1])
			out = append(out, fmt.Sprintf("<h%d>%s</h%d>", lvl, inlineFmt(m[2]), lvl))
			continue
		}
		// 表格：| a | b | + 分隔行
		if strings.HasPrefix(trimmed, "|") && i+1 < len(lines) &&
			strings.Contains(lines[i+1], "---") {
			header := tableCells(line)
			i += 2
			var rowsHTML []string
			for i < len(lines) && strings.HasPrefix(strings.TrimSpace(lines[i]), "|") {
				cells := tableCells(lines[i])
				var td []string
				for _, c := range cells {
					td = append(td, "<td>"+inlineFmt(c)+"</td>")
				}
				rowsHTML = append(rowsHTML, "<tr>"+strings.Join(td, "")+"</tr>")
				i++
			}
			i-- // 回退，外层 for 会自增
			var th []string
			for _, c := range header {
				th = append(th, "<th>"+inlineFmt(c)+"</th>")
			}
			out = append(out, "<table><thead><tr>"+strings.Join(th, "")+"</tr></thead><tbody>"+
				strings.Join(rowsHTML, "")+"</tbody></table>")
			continue
		}
		// 引用
		if strings.HasPrefix(trimmed, "> ") {
			out = append(out, "<blockquote>"+inlineFmt(strings.TrimPrefix(trimmed, "> "))+"</blockquote>")
			continue
		}
		// 列表
		if strings.HasPrefix(trimmed, "- ") || strings.HasPrefix(trimmed, "* ") {
			out = append(out, "<li>"+inlineFmt(trimmed[2:])+"</li>")
			continue
		}
		if strings.TrimSpace(line) == "" {
			continue
		}
		out = append(out, "<p>"+inlineFmt(line)+"</p>")
	}
	return strings.Join(out, "\n")
}

func tableCells(line string) []string {
	t := strings.TrimSpace(line)
	t = strings.TrimPrefix(t, "|")
	t = strings.TrimSuffix(t, "|")
	parts := strings.Split(t, "|")
	cells := make([]string, 0, len(parts))
	for _, p := range parts {
		cells = append(cells, strings.TrimSpace(p))
	}
	return cells
}

// inlineFmt 行内标记：先转义 HTML，再恢复加粗/斜体/行内码标记。
func inlineFmt(s string) string {
	s = htmlEscape(s)
	boldRe := regexp.MustCompile(`\*\*(.+?)\*\*`)
	s = boldRe.ReplaceAllString(s, "<strong>$1</strong>")
	emRe := regexp.MustCompile(`\*(.+?)\*`)
	s = emRe.ReplaceAllString(s, "<em>$1</em>")
	codeRe := regexp.MustCompile("`([^`]+)`")
	s = codeRe.ReplaceAllString(s, "<code>$1</code>")
	return s
}

func htmlEscape(s string) string {
	replacer := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", "\"", "&quot;")
	return replacer.Replace(s)
}

func stripMarkdown(md string) string {
	s := strings.ReplaceAll(md, "```", "")
	s = strings.ReplaceAll(s, "###", "")
	s = strings.ReplaceAll(s, "##", "")
	s = strings.ReplaceAll(s, "#", "")
	s = strings.ReplaceAll(s, "**", "")
	return s
}
