package server

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/wooluo/argus/internal/api"
	"github.com/wooluo/argus/internal/store"
)

// 知识闭环的 server 侧：节点回传的经验落库（progress 与最终结果两条路都走）；
// 任务下发时只给本项目可见的索引；节点按 id 拉全文时按项目隔离。
func TestKnowledgeRoundTrip(t *testing.T) {
	t.Setenv("ARGUS_DATA", t.TempDir())
	db, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, q := range []string{
		`INSERT INTO projects(name) VALUES ('p1'), ('p2')`,
		`INSERT INTO tasks(project_id,status,mode) VALUES (1,'assigned','autonomous'), (2,'assigned','autonomous')`,
	} {
		if _, err := db.Exec(q); err != nil {
			t.Fatal(err, q)
		}
	}
	rec := &eventRecorder{}
	n := &NodeAPI{DB: db, Bus: rec}
	post := func(h http.HandlerFunc, body string) *httptest.ResponseRecorder {
		t.Helper()
		w := httptest.NewRecorder()
		h(w, httptest.NewRequest(http.MethodPost, "/api/nodes", strings.NewReader(body)))
		if w.Code != 200 {
			t.Fatalf("code=%d body=%s", w.Code, w.Body.String())
		}
		return w
	}

	// 运行中（progress）沉淀一条本项目凭据
	post(n.Progress, `{"task_id":1,"knowledge":[{"title":"已验证凭据 http://x/login",`+
		`"content":"admin/admin","summary":"admin/admin（web_login 实测）","scope":"project","kind":"credential"}]}`)
	// 任务结束（最终结果）沉淀一条通用方法论
	post(n.ReportResult, `{"task_id":1,"status":"done","message":"ok","knowledge":[`+
		`{"title":"CSRF token 表单要原子提交","summary":"带 user_token 的表单","content":"先取 token 再提交。","scope":"global","kind":"reflection"}]}`)

	p1 := api.KnowledgeIndexFor(db, 1, "", 10)
	if len(p1) != 2 || p1[0].Scope != api.KnowledgeScopeProject || p1[0].Title != "已验证凭据 http://x/login" {
		t.Fatalf("项目 1 的索引应为本项目凭据在前 + 通用条目: %+v", p1)
	}
	if p2 := api.KnowledgeIndexFor(db, 2, "", 10); len(p2) != 1 || p2[0].Title != "CSRF token 表单要原子提交" {
		t.Fatalf("项目 2 只应看到通用条目，不该看到项目 1 的凭据: %+v", p2)
	}

	// 节点按需拉全文
	r := chi.NewRouter()
	r.Get("/api/nodes/knowledge/{kid}", n.NodeKnowledge)
	get := func(kid string, task int64) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest(http.MethodGet,
			fmt.Sprintf("/api/nodes/knowledge/%s?task_id=%d", kid, task), nil))
		return w
	}
	credID, globalID := p1[0].ID, p1[1].ID
	if w := get(credID, 1); w.Code != 200 || !strings.Contains(w.Body.String(), "admin/admin") {
		t.Errorf("项目 1 的任务应能拉到本项目凭据: code=%d body=%s", w.Code, w.Body.String())
	}
	if w := get(credID, 2); w.Code != 404 {
		t.Errorf("项目 2 的任务不应拉到项目 1 的凭据: code=%d", w.Code)
	}
	if w := get(globalID, 2); w.Code != 200 || !strings.Contains(w.Body.String(), "先取 token 再提交") {
		t.Errorf("通用条目对所有项目可见: code=%d body=%s", w.Code, w.Body.String())
	}
	for _, bad := range []string{"k-nope0000", "..%2Fargus.db", "no-such-entry"} {
		if w := get(bad, 1); w.Code != 404 {
			t.Errorf("未知或非法 id %q 应 404，实际 %d", bad, w.Code)
		}
	}
}
