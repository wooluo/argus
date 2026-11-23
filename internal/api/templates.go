package api

import (
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/wooluo/argus/internal/config"
)

// ============ Templates 域（蓝本 api/templates.py）============
// 报告模板管理：上传 Markdown 模板（{{占位符}}）/ 列表 / 内容 / 删除。
// 模板存 DATA_DIR/templates/*.md；default.md 不存在时自动落盘内置默认模板。

// defaultTemplate 与蓝本 DEFAULT_TEMPLATE 逐字一致。
const defaultTemplate = `# {{project_name}} 渗透测试报告

- 测试日期：{{date}}
- 授权范围：{{scope}}
- 项目描述：{{project_desc}}

## 一、资产统计

{{stats}}

## 二、漏洞汇总

{{findings_table}}

## 三、漏洞详情

{{findings_detail}}

## 四、总结与安全建议

{{summary}}
`

// 平台直接填充的占位符；分析性占位符由 LLM 生成
var templateAutoSlots = map[string]bool{
	"project_name": true, "project_desc": true, "scope": true,
	"date": true, "stats": true, "findings_table": true,
}

var templateLLMSlots = map[string]bool{"findings_detail": true, "summary": true}

var templateSlotRe = regexp.MustCompile(`{{\s*(\w+)\s*}}`)
var templateNameRe = regexp.MustCompile(`[^\w\-]+`)

func templatesDir() string {
	return filepath.Join(config.Load().DataDir, "templates")
}

// templatesEnsureDir 建目录并在 default.md 缺失时写入内置默认模板。
func templatesEnsureDir() error {
	dir := templatesDir()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	def := filepath.Join(dir, "default.md")
	if _, err := os.Stat(def); os.IsNotExist(err) {
		return os.WriteFile(def, []byte(defaultTemplate), 0o644)
	}
	return nil
}

// templatesValidate 返回模板中的未知占位符（既非平台槽位也非 LLM 槽位）。
func templatesValidate(content string) []string {
	seen := map[string]bool{}
	for _, m := range templateSlotRe.FindAllStringSubmatch(content, -1) {
		s := m[1]
		if !templateAutoSlots[s] && !templateLLMSlots[s] && !seen[s] {
			seen[s] = true
		}
	}
	out := make([]string, 0, len(seen))
	for s := range seen {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// templatesMeta 组装单条模板元信息。
func templatesMeta(path string) (map[string]any, error) {
	st, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	name := strings.TrimSuffix(filepath.Base(path), ".md")
	return map[string]any{
		"id":         name,
		"name":       strings.ReplaceAll(name, "_", " "),
		"size":       st.Size(),
		"mtime":      st.ModTime().Format("2006-01-02 15:04"),
		"is_default": filepath.Base(path) == "default.md",
	}, nil
}

// ListTemplates GET /api/templates — 列表（默认模板排前，其余按名排序）。
func (a *API) ListTemplates(w http.ResponseWriter, r *http.Request) {
	if err := templatesEnsureDir(); err != nil {
		respondErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	entries, err := filepath.Glob(filepath.Join(templatesDir(), "*.md"))
	if err != nil {
		respondErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	out := make([]map[string]any, 0, len(entries))
	for _, p := range entries {
		m, err := templatesMeta(p)
		if err != nil {
			continue
		}
		out = append(out, m)
	}
	sort.Slice(out, func(i, j int) bool {
		di, _ := out[i]["is_default"].(bool)
		dj, _ := out[j]["is_default"].(bool)
		if di != dj {
			return di
		}
		ni, _ := out[i]["name"].(string)
		nj, _ := out[j]["name"].(string)
		return ni < nj
	})
	respondJSON(w, http.StatusOK, out)
}

// UploadTemplate POST /api/templates/upload — 上传 .md 模板（multipart file 字段）。
func (a *API) UploadTemplate(w http.ResponseWriter, r *http.Request) {
	if err := templatesEnsureDir(); err != nil {
		respondErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := r.ParseMultipartForm(32 << 20); err != nil {
		respondErr(w, http.StatusBadRequest, "解析 multipart 失败: "+err.Error())
		return
	}
	file, hdr, err := r.FormFile("file")
	if err != nil {
		respondErr(w, http.StatusBadRequest, "缺少 file 字段")
		return
	}
	defer file.Close()
	if !strings.HasSuffix(hdr.Filename, ".md") {
		respondErr(w, http.StatusBadRequest, "仅支持 .md 模板文件")
		return
	}
	content, err := io.ReadAll(io.LimitReader(file, 200001))
	if err != nil {
		respondErr(w, http.StatusBadRequest, "读取文件失败")
		return
	}
	if len(content) > 200000 {
		respondErr(w, http.StatusBadRequest, "模板过大")
		return
	}
	unknown := templatesValidate(string(content))
	stem := strings.TrimSuffix(filepath.Base(hdr.Filename), ".md")
	name := templateNameRe.ReplaceAllString(stem, "_")
	if name == "" {
		name = "template"
	}
	path := filepath.Join(templatesDir(), name+".md")
	if err := os.WriteFile(path, content, 0o644); err != nil {
		respondErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	meta, _ := templatesMeta(path)
	resp := map[string]any{"ok": true, "unknown_slots": unknown}
	for k, v := range meta {
		resp[k] = v
	}
	respondJSON(w, http.StatusOK, resp)
}

// GetTemplateContent GET /api/templates/{id}/content — 读模板原文。
func (a *API) GetTemplateContent(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "template_id")
	path := filepath.Join(templatesDir(), id+".md")
	data, err := os.ReadFile(path)
	if err != nil {
		respondErr(w, http.StatusNotFound, "模板不存在")
		return
	}
	respondJSON(w, http.StatusOK, map[string]any{"id": id, "content": string(data)})
}

// DeleteTemplate DELETE /api/templates/{id} — 删除模板（default 不可删）。
func (a *API) DeleteTemplate(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "template_id")
	if id == "default" {
		respondErr(w, http.StatusBadRequest, "默认模板不可删除")
		return
	}
	path := filepath.Join(templatesDir(), id+".md")
	if _, err := os.Stat(path); err != nil {
		respondErr(w, http.StatusNotFound, "模板不存在")
		return
	}
	if err := os.Remove(path); err != nil {
		respondErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	respondJSON(w, http.StatusOK, map[string]any{"ok": true})
}
