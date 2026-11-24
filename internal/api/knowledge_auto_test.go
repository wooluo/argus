package api

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wooluo/argus/internal/store"
)

// 知识库自动沉淀回归：节点回传的经验要真的落库（原先只写一条日志行，任务一
// 结束就丢）；同标题去重更新；人工条目与别的项目的专属条目不被覆盖；索引按
//「本项目专属优先 + 相关性」排序；拉全文只放行本项目可见的条目。

func newKnowledgeFixture(t *testing.T) (*sql.DB, *API) {
	t.Helper()
	t.Setenv("ARGUS_DATA", t.TempDir())
	db, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db, &API{DB: db}
}

func readKnowledge(t *testing.T, kid string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(knowledgeDir(), kid+".md"))
	if err != nil {
		t.Fatalf("读条目 %s: %v", kid, err)
	}
	return string(b)
}

func indexIDs(briefs []KnowledgeBrief) string {
	ids := make([]string, len(briefs))
	for i, b := range briefs {
		ids[i] = b.ID
	}
	return strings.Join(ids, " ")
}

func TestSaveKnowledgeAuto(t *testing.T) {
	db, a := newKnowledgeFixture(t)
	k := KnowledgeIn{Title: "CSRF token 表单要原子提交", Summary: "遇到带 user_token 的表单时",
		Content: "先 GET 取 token 再 POST。", Scope: KnowledgeScopeGlobal, Kind: "reflection"}

	kid, status, err := SaveKnowledgeAuto(db, k, 1, 10)
	if err != nil || status != "created" {
		t.Fatalf("首次入库: status=%q err=%v", status, err)
	}
	if body := readKnowledge(t, kid); !strings.HasPrefix(body, "# CSRF token 表单要原子提交\n\n先 GET 取 token 再 POST。") {
		t.Errorf("条目文件应与知识库页同一格式（# 标题 + 正文）: %q", body)
	}

	// 同标题再来：更新而不堆重复；来源与更新时间刷新，创建时间保留
	k.Content = "先 GET 取 token，连同表单一次性 POST；会话失效要重连。"
	k.Summary = "" // 未给说明 → 取正文首行
	if kid2, status, err := SaveKnowledgeAuto(db, k, 1, 11); err != nil || status != "updated" || kid2 != kid {
		t.Fatalf("同标题应更新: id=%q status=%q err=%v", kid2, status, err)
	}
	body := readKnowledge(t, kid)
	if !strings.Contains(body, "一次性 POST") || strings.Contains(body, "先 GET 取 token 再 POST。") {
		t.Errorf("正文应被新版本替换: %q", body)
	}
	m := knowledgeMetaOf(db, kid)
	if m["task_id"] != float64(11) || m["source"] != "reflection" || m["scope"] != KnowledgeScopeGlobal ||
		m["summary"] != "先 GET 取 token，连同表单一次性 POST；会话失效要重连。" {
		t.Errorf("元数据不符: %v", m)
	}

	// 用户停用后再次沉淀：保持停用（更新不动用户的启用选择）
	a.knowledgeSaveMeta(kid, k.Title, false)
	if _, _, err := SaveKnowledgeAuto(db, k, 1, 12); err != nil {
		t.Fatal(err)
	}
	if en := knowledgeMetaOf(db, kid)["enabled"]; en != false {
		t.Errorf("更新不应改回启用: enabled=%v", en)
	}

	// 知识库页改标题/启用位时，不丢自动条目的说明与来源
	a.knowledgeSaveMeta(kid, "改过的标题", true)
	if m := knowledgeMetaOf(db, kid); m["summary"] == "" || m["source"] != "reflection" {
		t.Errorf("保存启用位不应清掉其他字段: %v", m)
	}
}

func TestSaveKnowledgeAutoKeepsManualAndOtherProject(t *testing.T) {
	db, a := newKnowledgeFixture(t)

	// 人工在知识库页创建的条目：同名经验另存，不覆盖
	manual := httptest.NewRecorder()
	a.CreateKnowledge(manual, httptest.NewRequest(http.MethodPost, "/api/knowledge",
		strings.NewReader(`{"title":"人工写的条目","content":"人工正文","enabled":true}`)))
	if manual.Code != 200 {
		t.Fatalf("CreateKnowledge code=%d body=%s", manual.Code, manual.Body.String())
	}
	manualID := knowledgeSlug("人工写的条目")
	kid, status, err := SaveKnowledgeAuto(db, KnowledgeIn{Title: "人工写的条目", Content: "自动版"}, 1, 1)
	if err != nil || status != "created" || kid == manualID || !strings.HasPrefix(kid, "k-") {
		t.Fatalf("同名时应另存为新条目（id 按标题哈希）: id=%q status=%q err=%v", kid, status, err)
	}
	if body := readKnowledge(t, manualID); !strings.Contains(body, "人工正文") {
		t.Errorf("人工条目应原样保留: %q", body)
	}
	if body := readKnowledge(t, kid); !strings.Contains(body, "自动版") {
		t.Errorf("新条目应写入自动版内容: %q", body)
	}

	// 两个项目各有「已验证凭据 http://x/login」：互不覆盖，各自更新自己那条
	cred := func(pw string) KnowledgeIn {
		return KnowledgeIn{Title: "已验证凭据 http://x/login", Content: pw, Kind: "credential"} // 默认仅本项目
	}
	id1, _, _ := SaveKnowledgeAuto(db, cred("admin/admin"), 1, 1)
	id2, status, _ := SaveKnowledgeAuto(db, cred("root/root"), 2, 2)
	if id1 == id2 || status != "created" || !strings.HasPrefix(id1, "k-") || id2 != id1+"-p2" {
		t.Fatalf("别的项目的同名专属条目应另存（基 id + 项目后缀）: id1=%q id2=%q status=%q", id1, id2, status)
	}
	if id2b, status, _ := SaveKnowledgeAuto(db, cred("root/toor"), 2, 3); id2b != id2 || status != "updated" {
		t.Fatalf("同一项目应更新自己那条: id=%q status=%q", id2b, status)
	}
	if body := readKnowledge(t, id1); !strings.Contains(body, "admin/admin") {
		t.Errorf("项目 1 的条目被项目 2 改写了: %q", body)
	}
	// id 好抄：短、无歧义（Agent 要原样传给 knowledge_get）
	if len(id1) != len("k-")+8 {
		t.Errorf("自动条目 id 应为 k- + 8 位哈希: %q", id1)
	}

	// 缺标题/正文：拒绝入库
	if _, _, err := SaveKnowledgeAuto(db, KnowledgeIn{Title: "只有标题"}, 1, 1); err == nil {
		t.Error("空正文不应入库")
	}
}

// seedKnowledge 建一条条目并返回 id。
func seedKnowledge(t *testing.T, db *sql.DB, title, summary, content, scope string, project int64) string {
	t.Helper()
	kid, _, err := SaveKnowledgeAuto(db, KnowledgeIn{
		Title: title, Summary: summary, Content: content, Scope: scope, Kind: "agent",
	}, project, 1)
	if err != nil {
		t.Fatal(err)
	}
	return kid
}

func TestKnowledgeIndexFor(t *testing.T) {
	db, a := newKnowledgeFixture(t)
	cred := seedKnowledge(t, db, "已验证凭据 http://x/login", "admin/admin（web_login 实测）",
		"[已验证凭据] admin/admin", KnowledgeScopeProject, 1)
	foreign := seedKnowledge(t, db, "别项目的专属条目", "不该出现在项目 1", "x",
		KnowledgeScopeProject, 2)
	dvwa := seedKnowledge(t, db, "DVWA 默认凭据与安全等级", "测 DVWA 或类似靶场时先试 admin/password",
		"DVWA 默认 admin/password；Security Level 影响过滤强度。", KnowledgeScopeGlobal, 1)
	blind := seedKnowledge(t, db, "SQL 盲注的布尔与时间桩", "页面无回显时用布尔/时间差异判断注入",
		"无回显时构造布尔条件对比响应长度。", KnowledgeScopeGlobal, 1)
	cloud := seedKnowledge(t, db, "云存储桶配置核查", "遇到对象存储域名时", "列桶、ACL、可写。", KnowledgeScopeGlobal, 1)

	got := KnowledgeIndexFor(db, 1, "DVWA 登录", 10)
	// 本项目专属条目最前；其后是与查询相关的通用条目；再后是无命中的（按最近更新）
	if len(got) != 4 || got[0].ID != cred || got[1].ID != dvwa {
		t.Fatalf("索引顺序不符: %s", indexIDs(got))
	}
	has := func(id string) bool {
		for _, b := range got {
			if b.ID == id {
				return true
			}
		}
		return false
	}
	if has(foreign) {
		t.Errorf("别的项目的专属条目不该出现在项目 1 的索引里: %s", indexIDs(got))
	}
	if !has(blind) || !has(cloud) {
		t.Errorf("无命中的通用条目应按最近更新补位: %s", indexIDs(got))
	}
	if got[0].Summary != "admin/admin（web_login 实测）" {
		t.Errorf("索引行应带「何时用它」: %+v", got[0])
	}

	// 条数上限
	if got := KnowledgeIndexFor(db, 1, "", 2); len(got) != 2 || got[0].ID != cred {
		t.Errorf("limit 应生效且专属条目仍在前: %s", indexIDs(got))
	}

	// 停用的条目不进索引
	a.knowledgeSaveMeta(cloud, "云存储桶配置核查", false)
	if got := KnowledgeIndexFor(db, 1, "对象存储", 10); len(got) != 3 {
		t.Errorf("停用条目不应出现: %s", indexIDs(got))
	}

	// Markdown 形态：只给 id、标题、「何时用它」，并说明怎么拉全文
	md := KnowledgeIndexMarkdown(db, 1, "DVWA", 10)
	for _, want := range []string{"knowledge_get", "[" + cred + "] 已验证凭据 http://x/login（本项目）",
		"—— admin/admin（web_login 实测）", "[" + dvwa + "] DVWA 默认凭据与安全等级 —— "} {
		if !strings.Contains(md, want) {
			t.Errorf("索引 Markdown 缺 %q:\n%s", want, md)
		}
	}
	if strings.Contains(md, "Security Level 影响过滤强度") {
		t.Errorf("索引不应带全文正文:\n%s", md)
	}
}

func TestKnowledgeBodyVisibility(t *testing.T) {
	db, a := newKnowledgeFixture(t)
	cred := seedKnowledge(t, db, "已验证凭据 http://x/login", "admin/admin", "[已验证凭据] admin/admin",
		KnowledgeScopeProject, 1)
	dvwa := seedKnowledge(t, db, "DVWA 默认凭据", "测 DVWA 时", "DVWA 默认 admin/password",
		KnowledgeScopeGlobal, 1)

	if title, content, ok := KnowledgeBody(db, cred, 1); !ok || title != "已验证凭据 http://x/login" ||
		!strings.Contains(content, "admin/admin") {
		t.Errorf("本项目应能拉到自己的专属条目: ok=%v title=%q content=%q", ok, title, content)
	}
	if _, _, ok := KnowledgeBody(db, cred, 2); ok {
		t.Error("别的项目不应拉到本项目的专属条目（凭据不外泄）")
	}
	if _, _, ok := KnowledgeBody(db, dvwa, 2); !ok {
		t.Error("通用条目对所有项目可见")
	}
	for _, bad := range []string{"nope", "../argus", "..", "a/b", "x.db", ""} {
		if _, _, ok := KnowledgeBody(db, bad, 1); ok {
			t.Errorf("非法或未知的 id %q 不应放行", bad)
		}
	}
	a.knowledgeSaveMeta(dvwa, "DVWA 默认凭据", false)
	if _, _, ok := KnowledgeBody(db, dvwa, 1); ok {
		t.Error("停用的条目不应能拉到")
	}
}

// 迁移来的旧条目没有元数据：视为启用、跨项目通用，说明取正文首行，且不被自动覆盖。
func TestLegacyKnowledgeEntry(t *testing.T) {
	db, _ := newKnowledgeFixture(t)
	kid := knowledgeSlug("旧条目")
	path := filepath.Join(knowledgeDir(), kid+".md")
	if err := os.WriteFile(path, []byte("# 旧条目\n\n正文第一行\n第二行"), 0o644); err != nil {
		t.Fatal(err)
	}
	entries, err := knowledgeEntries(db)
	if err != nil {
		t.Fatal(err)
	}
	var found *knowledgeEntry
	for i := range entries {
		if entries[i].id == kid {
			found = &entries[i]
		}
	}
	if found == nil || !found.enabled || found.scope != KnowledgeScopeGlobal ||
		found.summary != "正文第一行" || found.source != "" {
		t.Fatalf("旧条目视图不符: %+v", found)
	}
	if got := KnowledgeIndexFor(db, 7, "旧条目", 5); len(got) != 1 || got[0].Summary != "正文第一行" {
		t.Errorf("旧条目应进入任何项目的索引: %+v", got)
	}
	newID, status, err := SaveKnowledgeAuto(db, KnowledgeIn{Title: "旧条目", Content: "自动版"}, 1, 1)
	if err != nil || status != "created" || newID == kid {
		t.Fatalf("无元数据的条目视同人工条目，不应被覆盖: id=%q status=%q err=%v", newID, status, err)
	}
	if body := readKnowledge(t, kid); body != "# 旧条目\n\n正文第一行\n第二行" {
		t.Errorf("旧条目被改动了: %q", body)
	}
}

// 知识库页列表带出自动条目的说明、范围与来源（供前端展示）。
func TestListKnowledgeExposesAutoFields(t *testing.T) {
	db, a := newKnowledgeFixture(t)
	kid := seedKnowledge(t, db, "DVWA 默认凭据", "测 DVWA 时", "DVWA 默认 admin/password",
		KnowledgeScopeGlobal, 1)
	rec := httptest.NewRecorder()
	a.ListKnowledge(rec, httptest.NewRequest(http.MethodGet, "/api/knowledge", nil))
	var list []map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil || len(list) != 1 {
		t.Fatalf("列表解析失败: %v %s", err, rec.Body.String())
	}
	if list[0]["id"] != kid || list[0]["summary"] != "测 DVWA 时" ||
		list[0]["scope"] != KnowledgeScopeGlobal || list[0]["source"] != "agent" {
		t.Errorf("列表应带出说明/范围/来源: %v", list[0])
	}
}
