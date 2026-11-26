package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
)

// 任务中心「项目」列读的是 project_name；接口曾只带 project_id，整列空白。
func TestTaskQueriesIncludeProjectName(t *testing.T) {
	db, a := newKnowledgeFixture(t)
	must := func(q string, args ...any) {
		t.Helper()
		if _, err := db.Exec(q, args...); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	must(`INSERT INTO projects(id,name,scope,authorized) VALUES(1,'甲','[]',1),(2,'乙','[]',1)`)
	must(`INSERT INTO tasks(project_id,name,status,mode) VALUES(1,'t1','done','staged'),(2,'t2','running','autonomous')`)
	must(`INSERT INTO tasks(project_id,name,status,mode) VALUES(7,'孤儿','failed','autonomous')`) // 项目已不存在

	get := func(url string) (int, []byte) {
		rec := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, url, nil)
		if id := strings.TrimPrefix(url, "/api/tasks/"); id != url { // 详情
			rctx := chi.NewRouteContext()
			rctx.URLParams.Add("id", id)
			r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))
			a.GetTask(rec, r)
		} else {
			a.ListTasks(rec, r)
		}
		return rec.Code, rec.Body.Bytes()
	}

	code, body := get("/api/tasks")
	if code != http.StatusOK {
		t.Fatalf("列表 %d: %s", code, body)
	}
	var list []struct {
		ID          int    `json:"id"`
		ProjectName string `json:"project_name"`
		Status      string `json:"status"`
		IsLive      bool   `json:"is_live"`
	}
	if err := json.Unmarshal(body, &list); err != nil || len(list) != 3 {
		t.Fatalf("解析列表: %v %s", err, body)
	}
	names := map[int]string{}
	for _, x := range list {
		names[x.ID] = x.ProjectName
		if x.ID == 2 && (x.Status != "running" || !x.IsLive) {
			t.Errorf("运行中的任务应仍是 running / is_live: %+v", x)
		}
		if x.ID == 1 && x.Status != "completed" {
			t.Errorf("done 的出口状态词应为 completed: %+v", x)
		}
	}
	if names[1] != "甲" || names[2] != "乙" || names[3] != "#7" {
		t.Fatalf("project_name = %v（应为 甲 / 乙 / #7）", names)
	}

	code, body = get("/api/tasks?project_id=2")
	if err := json.Unmarshal(body, &list); err != nil || code != 200 || len(list) != 1 || list[0].ProjectName != "乙" {
		t.Fatalf("按项目过滤: %d %s", code, body)
	}

	code, body = get("/api/tasks/2")
	var one struct {
		ProjectName string `json:"project_name"`
	}
	if code != 200 || json.Unmarshal(body, &one) != nil || one.ProjectName != "乙" {
		t.Fatalf("详情: %d %s", code, body)
	}
	if code, _ = get("/api/tasks/99"); code != 404 {
		t.Fatalf("不存在的任务应 404，得到 %d", code)
	}
}
