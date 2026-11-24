package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/wooluo/argus/internal/config"
	"github.com/wooluo/argus/internal/store"
)

// ============ Knowledge 域（蓝本 api/knowledge.py；_slug/_save_meta 范式与 skills 域一致） ============

func knowledgeDir() string {
	dir := filepath.Join(config.Load().DataDir, "knowledge")
	_ = os.MkdirAll(dir, 0o755)
	return dir
}

// knowledgeSlug 标题→安全 id（蓝本 _slug：非法字符→_，截 40）。
func knowledgeSlug(title string) string {
	safe := extSkillSafeRe.ReplaceAllString(strings.TrimSpace(title), "_")
	if len(safe) > 40 {
		safe = safe[:40]
	}
	if safe == "" {
		safe = "k"
	}
	return safe
}

// stripOwnHeader 剥离内容开头与标题重复的 # 行，防编辑保存时标题堆叠（蓝本 _strip_own_header）。
func stripOwnHeader(content string) string {
	text := strings.TrimLeft(content, "\n")
	if strings.HasPrefix(text, "# ") {
		if i := strings.Index(text, "\n"); i >= 0 {
			return strings.TrimLeft(text[i+1:], "\n")
		}
		return ""
	}
	return text
}

// ListKnowledge GET /api/knowledge — 扫 knowledge/*.md 合并 settings 元数据。
func (a *API) ListKnowledge(w http.ResponseWriter, r *http.Request) {
	saved := map[string]map[string]any{}
	var meta []map[string]any
	_ = json.Unmarshal([]byte(store.GetSetting(a.DB, "knowledge")), &meta)
	for _, m := range meta {
		saved[fmt.Sprint(m["id"])] = m
	}
	out := []map[string]any{}
	entries, _ := os.ReadDir(knowledgeDir())
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".md") {
			continue
		}
		kid := strings.TrimSuffix(e.Name(), ".md")
		// 无元数据的条目（迁移来的旧库）：标题取文件首行，而不是显示文件名
		title, enabled := kid, true
		if t, _, err := knowledgeRead(kid); err == nil && t != "" {
			title = t
		}
		if m := saved[kid]; m != nil {
			if t, ok := m["title"].(string); ok && t != "" {
				title = t
			}
			if en, ok := m["enabled"].(bool); ok {
				enabled = en
			}
		}
		info, _ := e.Info()
		item := map[string]any{
			"id": kid, "title": title, "enabled": enabled,
			"chars":   info.Size(),
			"updated": info.ModTime().Format("2006-01-02 15:04"),
		}
		// 任务自动沉淀的条目带说明与来源（适用范围见 scope）
		if m := saved[kid]; m != nil {
			for _, k := range []string{"summary", "scope", "source"} {
				if v, _ := m[k].(string); v != "" {
					item[k] = v
				}
			}
		}
		out = append(out, item)
	}
	respondJSON(w, http.StatusOK, out)
}

// CreateKnowledge POST /api/knowledge — _slug 命名，存在 400，写 # 标题+正文。
func (a *API) CreateKnowledge(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Title   string `json:"title"`
		Content string `json:"content"`
		Enabled bool   `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil || strings.TrimSpace(in.Title) == "" {
		respondErr(w, http.StatusBadRequest, "title 必填")
		return
	}
	kid := knowledgeSlug(in.Title)
	path := filepath.Join(knowledgeDir(), kid+".md")
	if _, err := os.Stat(path); err == nil {
		respondErr(w, http.StatusBadRequest, "同名知识「"+kid+"」已存在")
		return
	}
	body := fmt.Sprintf("# %s\n\n%s", in.Title, stripOwnHeader(in.Content))
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		respondErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	a.knowledgeSaveMeta(kid, in.Title, in.Enabled)
	respondJSON(w, http.StatusOK, map[string]any{"ok": true, "id": kid})
}

// knowledgeSaveMeta 落 settings["knowledge"]：条目已存在则只改标题与启用位
// （保留自动条目的说明/适用范围/来源等字段），否则追加。
func (a *API) knowledgeSaveMeta(kid, title string, enabled bool) {
	for _, m := range knowledgeMetaList(a.DB) {
		if fmt.Sprint(m["id"]) == kid {
			m["title"], m["enabled"] = title, enabled
			knowledgePutMeta(a.DB, m)
			return
		}
	}
	knowledgePutMeta(a.DB, map[string]any{"id": kid, "title": title, "enabled": enabled})
}

// KnowledgeContent GET /api/knowledge/{kid}/content — 原文返回。
func (a *API) KnowledgeContent(w http.ResponseWriter, r *http.Request) {
	kid := chi.URLParam(r, "kid")
	data, err := os.ReadFile(filepath.Join(knowledgeDir(), kid+".md"))
	if err != nil {
		respondErr(w, http.StatusNotFound, "知识条目不存在")
		return
	}
	respondJSON(w, http.StatusOK, map[string]any{"id": kid, "content": string(data)})
}

// GetGithubConfig GET /api/knowledge/github-config — token 掩码（不回明文）。
func (a *API) GetGithubConfig(w http.ResponseWriter, r *http.Request) {
	tok := store.GetSetting(a.DB, "github_token")
	masked := ""
	if tok != "" {
		masked = strings.Repeat("*", len(tok))
	}
	respondJSON(w, http.StatusOK, map[string]any{"has_token": tok != "", "token": masked})
}

// PutGithubConfig PUT /api/knowledge/github-config — 空/全* 保留旧值。
func (a *API) PutGithubConfig(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Token string `json:"token"`
	}
	_ = json.NewDecoder(r.Body).Decode(&in)
	tok := in.Token
	if strings.TrimSpace(tok) == "" || strings.Trim(tok, "*") == "" {
		tok = store.GetSetting(a.DB, "github_token")
	}
	if err := store.SetSetting(a.DB, "github_token", tok); err != nil {
		respondErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	respondJSON(w, http.StatusOK, map[string]any{"ok": true, "has_token": tok != ""})
}

// UpdateKnowledge PUT /api/knowledge/{kid} — 覆写文件+元数据。
func (a *API) UpdateKnowledge(w http.ResponseWriter, r *http.Request) {
	kid := chi.URLParam(r, "kid")
	path := filepath.Join(knowledgeDir(), kid+".md")
	if _, err := os.Stat(path); err != nil {
		respondErr(w, http.StatusNotFound, "知识条目不存在")
		return
	}
	var in struct {
		Title   string `json:"title"`
		Content string `json:"content"`
		Enabled bool   `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil || strings.TrimSpace(in.Title) == "" {
		respondErr(w, http.StatusBadRequest, "title 必填")
		return
	}
	body := fmt.Sprintf("# %s\n\n%s", in.Title, stripOwnHeader(in.Content))
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		respondErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	a.knowledgeSaveMeta(kid, in.Title, in.Enabled)
	respondJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// DeleteKnowledge DELETE /api/knowledge/{kid} — 删文件+移除 meta。
func (a *API) DeleteKnowledge(w http.ResponseWriter, r *http.Request) {
	kid := chi.URLParam(r, "kid")
	if _, err := os.Stat(filepath.Join(knowledgeDir(), kid+".md")); err == nil {
		_ = os.Remove(filepath.Join(knowledgeDir(), kid+".md"))
	}
	var saved []map[string]any
	_ = json.Unmarshal([]byte(store.GetSetting(a.DB, "knowledge")), &saved)
	kept := saved[:0]
	for _, m := range saved {
		if fmt.Sprint(m["id"]) != kid {
			kept = append(kept, m)
		}
	}
	b, _ := json.Marshal(kept)
	_ = store.SetSetting(a.DB, "knowledge", string(b))
	respondJSON(w, http.StatusOK, map[string]any{"ok": true})
}
