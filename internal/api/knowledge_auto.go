package api

// knowledge_auto.go: 知识库的自动沉淀与注入。
//
// 结构借鉴 sapper-v2 的知识库：条目分三层（标题 / 一句话「何时用它」/ 全文），
// 任务书只推索引、全文按需拉取。打分不学它（token 集合求交、无 IDF、同分取
// 最早），沿用 BM25 并给标题与说明加权。
//
// 修复两个断点：节点侧沉淀的经验（任务后复盘、knowledge_save、验证过的凭据）
// 原先只落一条日志行、从不入库——任务一结束就丢；开局注入按文件名顺序取前
// 5 条，与当前目标是否相关全凭运气。

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/wooluo/argus/internal/rank"
	"github.com/wooluo/argus/internal/store"
	"github.com/wooluo/argus/internal/tools"
)

const (
	KnowledgeScopeProject = "project"
	KnowledgeScopeGlobal  = "global"
)

// KnowledgeIn 节点回传的一条经验（与 tools.Knowledge 同形）。
type KnowledgeIn struct {
	Title   string `json:"title"`
	Content string `json:"content"`
	Summary string `json:"summary"`
	Scope   string `json:"scope"`
	Kind    string `json:"kind"` // reflection | agent | credential
}

// KnowledgeBrief 知识索引里的一行：只给 id、标题与「何时用它」。
type KnowledgeBrief struct {
	ID      string `json:"id"`
	Title   string `json:"title"`
	Summary string `json:"summary"`
	Scope   string `json:"scope"`
}

// knowledgeEntry 知识库里的一个条目（文件 + 元数据合并后的视图）。
type knowledgeEntry struct {
	id, title, summary, scope string
	enabled                   bool
	projectID                 int64
	updated                   string
	content                   string
	// source 来源类别：任务自动沉淀的条目带（reflection/agent/credential），
	// 人工创建或迁移来的旧条目为空——空的不允许被自动覆盖。
	source string
}

var knowledgeIDRe = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

// knowledgeMetaList 读 settings["knowledge"]（[{id,title,enabled,...}]）。
func knowledgeMetaList(db *sql.DB) []map[string]any {
	var saved []map[string]any
	_ = json.Unmarshal([]byte(store.GetSetting(db, "knowledge")), &saved)
	return saved
}

// knowledgeStoreMeta 整表落 settings["knowledge"]。
func knowledgeStoreMeta(db *sql.DB, saved []map[string]any) {
	b, err := json.Marshal(saved)
	if err != nil {
		return
	}
	_ = store.SetSetting(db, "knowledge", string(b))
}

// knowledgePutMeta 写入/替换一条元数据（按 id），其余条目不动。
func knowledgePutMeta(db *sql.DB, m map[string]any) {
	saved := knowledgeMetaList(db)
	for i, old := range saved {
		if fmt.Sprint(old["id"]) == fmt.Sprint(m["id"]) {
			saved[i] = m
			knowledgeStoreMeta(db, saved)
			return
		}
	}
	saved = append(saved, m)
	knowledgeStoreMeta(db, saved)
}

// knowledgeEntries 列出知识库条目（文件为准，元数据补标题/说明/范围/启用位）。
// 无元数据的条目（迁移来的旧库、手工放进目录的文件）视为启用、跨项目通用。
func knowledgeEntries(db *sql.DB) ([]knowledgeEntry, error) {
	meta := map[string]map[string]any{}
	for _, m := range knowledgeMetaList(db) {
		meta[fmt.Sprint(m["id"])] = m
	}
	dir, err := os.ReadDir(knowledgeDir())
	if err != nil {
		return nil, err
	}
	var out []knowledgeEntry
	for _, e := range dir {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".md") {
			continue
		}
		kid := strings.TrimSuffix(e.Name(), ".md")
		title, content, err := knowledgeRead(kid)
		if err != nil {
			continue
		}
		k := knowledgeEntry{id: kid, title: title, content: content,
			enabled: true, scope: KnowledgeScopeGlobal, updated: ""}
		if m := meta[kid]; m != nil {
			if t, _ := m["title"].(string); t != "" {
				k.title = t
			}
			if s, _ := m["summary"].(string); s != "" {
				k.summary = s
			}
			if en, ok := m["enabled"].(bool); ok {
				k.enabled = en
			}
			if s, _ := m["scope"].(string); s == KnowledgeScopeProject {
				k.scope = KnowledgeScopeProject
				if v, ok := m["project_id"].(float64); ok {
					k.projectID = int64(v)
				}
			}
			k.updated, _ = m["updated_at"].(string)
			k.source, _ = m["source"].(string)
		}
		if k.summary == "" {
			k.summary = tools.ClipRunes(knowledgeFirstLine(k.content), 80)
		}
		out = append(out, k)
	}
	return out, nil
}

// knowledgeRead 读条目文件：首行 `# 标题`，其余为正文。
func knowledgeRead(kid string) (title, content string, err error) {
	b, err := os.ReadFile(filepath.Join(knowledgeDir(), kid+".md"))
	if err != nil {
		return "", "", err
	}
	s := string(b)
	if !strings.HasPrefix(s, "# ") {
		return kid, s, nil
	}
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return strings.TrimSpace(s[2:i]), strings.TrimLeft(s[i+1:], "\n"), nil
	}
	return strings.TrimSpace(s[2:]), "", nil
}

func knowledgeFirstLine(s string) string {
	for _, line := range strings.Split(s, "\n") {
		if l := strings.TrimSpace(line); l != "" {
			return l
		}
	}
	return ""
}

// SaveKnowledgeAuto 节点回传的经验入库，projectID / taskID 标来源。
//
// 同标题的自动条目更新而不堆重复（标题不带任务编号，同一主题的经验越用越准）；
// 人工在知识库页创建的条目不被覆盖，改另存新条目；别的项目的专属条目同理
// （两个项目各有「已验证凭据 https://x/login」时互不覆盖）。
// 返回条目 id 与 created / updated。
func SaveKnowledgeAuto(db *sql.DB, k KnowledgeIn, projectID, taskID int64) (string, string, error) {
	title, content := strings.TrimSpace(k.Title), strings.TrimSpace(k.Content)
	if title == "" || content == "" {
		return "", "", fmt.Errorf("title 与 content 必填")
	}
	summary := strings.TrimSpace(k.Summary)
	if summary == "" {
		summary = knowledgeFirstLine(content)
	}
	scope := KnowledgeScopeProject
	if k.Scope == KnowledgeScopeGlobal {
		scope = KnowledgeScopeGlobal
	}

	entries, err := knowledgeEntries(db)
	if err != nil {
		return "", "", err
	}
	// 自动条目的 id 按标题哈希：同标题同 id（天然去重），短且无歧义——Agent
	// 要把它原样抄给 knowledge_get。中文标题若沿用蓝本的「非法字符换下划线」
	// 规则，id 会是一串下划线：既数不清，不同的中文标题还会撞同一个 id。
	base := "k-" + titleHash(title)
	byID := make(map[string]bool, len(entries))
	for _, e := range entries {
		byID[e.id] = true
	}
	kid, status := base, "created"
	for _, e := range entries {
		if e.title != title || e.source == "" {
			continue
		}
		// 同标题的自动条目，且归属本项目（或本身通用）→ 更新它
		if e.scope == KnowledgeScopeGlobal || e.projectID == projectID {
			kid, status = e.id, "updated"
			break
		}
	}
	if status == "created" {
		// 基 id 被别的项目的同名专属条目占着 → 加项目后缀；再不行加序号
		for _, cand := range []string{base, fmt.Sprintf("%s-p%d", base, projectID)} {
			if !byID[cand] {
				kid = cand
				break
			}
		}
		for i := 2; byID[kid]; i++ {
			kid = fmt.Sprintf("%s-%d", base, i)
		}
	}

	body := fmt.Sprintf("# %s\n\n%s", title, stripOwnHeader(content))
	if err := knowledgeWrite(kid, body); err != nil {
		return "", "", err
	}
	now := store.Now()
	m := map[string]any{
		"id": kid, "title": title, "enabled": true,
		"summary": tools.ClipRunes(summary, 80),
		"scope":   scope, "project_id": projectID,
		"source": k.Kind, "task_id": taskID,
		"created_at": now, "updated_at": now,
	}
	if old := knowledgeMetaOf(db, kid); old != nil {
		if en, ok := old["enabled"].(bool); ok {
			m["enabled"] = en // 更新不动用户的启用/停用选择
		}
		if c, ok := old["created_at"].(string); c != "" && ok {
			m["created_at"] = c
		}
	}
	knowledgePutMeta(db, m)
	return kid, status, nil
}

// knowledgeWrite 先写临时文件再改名：读方（索引、拉全文）不会读到半截文件。
func knowledgeWrite(kid, body string) error {
	path := filepath.Join(knowledgeDir(), kid+".md")
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(body), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func knowledgeMetaOf(db *sql.DB, kid string) map[string]any {
	for _, m := range knowledgeMetaList(db) {
		if fmt.Sprint(m["id"]) == kid {
			return m
		}
	}
	return nil
}

// titleHash 标题的 8 位十六进制哈希（自动条目 id 的后缀）。
func titleHash(title string) string {
	sum := sha256.Sum256([]byte(title))
	return hex.EncodeToString(sum[:4])
}

// KnowledgeIndexFor 任务书的知识索引：本项目的专属条目（凭据、目标环境细节）
// 优先，其后是与项目最相关的通用条目——BM25（标题 ×3、说明 ×2、正文 ×1）对
// 「项目名 + 授权范围 + 项目说明」打分，无命中的按最近更新补位。
func KnowledgeIndexFor(db *sql.DB, projectID int64, query string, limit int) []KnowledgeBrief {
	entries, err := knowledgeEntries(db)
	if err != nil || limit <= 0 {
		return nil
	}
	var mine, global []knowledgeEntry
	for _, e := range entries {
		if !e.enabled {
			continue
		}
		if e.scope == KnowledgeScopeProject {
			if e.projectID == projectID {
				mine = append(mine, e)
			}
			continue
		}
		global = append(global, e)
	}
	byRecent := func(list []knowledgeEntry) {
		sort.SliceStable(list, func(i, j int) bool { return list[i].updated > list[j].updated })
	}
	byRecent(mine)
	byRecent(global)

	docs := make([]rank.Doc, len(global))
	for i, e := range global {
		docs[i] = rank.Doc{ID: e.id, Text: rank.Weighted(e.title, e.summary, "", e.content)}
	}
	scored := map[string]float64{}
	for _, h := range rank.New(docs).Search(query, 0) {
		scored[h.ID] = h.Score
	}
	// 有命中的按得分在前（保持 byRecent 的同分顺序），无命中的按最近更新补位
	sort.SliceStable(global, func(i, j int) bool {
		si, sj := scored[global[i].id], scored[global[j].id]
		if (si > 0) != (sj > 0) {
			return si > 0
		}
		return si > sj
	})

	out := []KnowledgeBrief{}
	add := func(list []knowledgeEntry) {
		for _, e := range list {
			if len(out) >= limit {
				return
			}
			out = append(out, KnowledgeBrief{ID: e.id, Title: e.title, Summary: e.summary, Scope: e.scope})
		}
	}
	add(mine)
	add(global)
	return out
}

// KnowledgeIndexMarkdown 知识索引的任务书形态（无条目返回空串）。只给 id、
// 标题与「何时用它」，全文由节点经 knowledge_get 按需拉取。
func KnowledgeIndexMarkdown(db *sql.DB, projectID int64, query string, limit int) string {
	briefs := KnowledgeIndexFor(db, projectID, query, limit)
	if len(briefs) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("## 知识库索引（历史任务沉淀，只列标题与「何时用它」）\n")
	b.WriteString("与当前目标或当前问题相关的条目，用 knowledge_get（参数 id）拉取完整做法；" +
		"标「本项目」的是此前在本项目验证过的事实，可直接使用。\n")
	for _, k := range briefs {
		mark := ""
		if k.Scope == KnowledgeScopeProject {
			mark = "（本项目）"
		}
		fmt.Fprintf(&b, "- [%s] %s%s —— %s\n", k.ID, k.Title, mark, k.Summary)
	}
	return b.String() + "\n"
}

// KnowledgeBody 条目全文（节点按需拉取）。只放行 id 合法、已启用、且对该项目
// 可见（通用，或正是本项目的专属条目）的知识。
func KnowledgeBody(db *sql.DB, kid string, projectID int64) (title, content string, ok bool) {
	if !knowledgeIDRe.MatchString(kid) {
		return "", "", false
	}
	entries, err := knowledgeEntries(db)
	if err != nil {
		return "", "", false
	}
	for _, e := range entries {
		if e.id != kid || !e.enabled {
			continue
		}
		if e.scope == KnowledgeScopeProject && e.projectID != projectID {
			return "", "", false
		}
		return e.title, e.content, true
	}
	return "", "", false
}
