package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// 资产中心（和项目资产页）按页请求，读的是 data.items / data.total。接口曾
// 只返回数组、也不认 page：页面拿到 undefined，表永远是空的。
func TestListAssetsPaginated(t *testing.T) {
	db, a := newKnowledgeFixture(t)
	must := func(q string, args ...any) {
		t.Helper()
		if _, err := db.Exec(q, args...); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	must(`INSERT INTO projects(id,name,scope,authorized) VALUES(1,'甲','[]',1),(2,'乙','[]',1)`)
	for i := 1; i <= 5; i++ {
		must(`INSERT INTO assets(project_id,type,value,detail) VALUES(1,'domain',?,'{"root":"a.test"}')`, "h"+string(rune('0'+i))+".a.test")
	}
	must(`INSERT INTO assets(project_id,type,value,detail) VALUES(2,'url','https://b.test/','{}')`)
	must(`INSERT INTO assets(project_id,type,value,detail) VALUES(2,'port','1.2.3.4:80','{"service":"http"}')`)

	get := func(query string) (map[string]json.RawMessage, []map[string]any) {
		rec := httptest.NewRecorder()
		a.ListAssets(rec, httptest.NewRequest(http.MethodGet, "/api/assets?"+query, nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("%s → %d: %s", query, rec.Code, rec.Body.String())
		}
		var page struct {
			Items []map[string]any `json:"items"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &page); err != nil {
			t.Fatalf("%s → 不是对象: %v %s", query, err, rec.Body.String())
		}
		return map[string]json.RawMessage{"total": mustField(t, rec.Body.String(), "total"), "size": mustField(t, rec.Body.String(), "size")}, page.Items
	}

	if m, items := get("page=1&size=3"); string(m["total"]) != "7" || string(m["size"]) != "3" || len(items) != 3 {
		t.Fatalf("第 1 页: %v, %d 条", m, len(items))
	}
	if _, items := get("page=3&size=3"); len(items) != 1 {
		t.Fatalf("第 3 页应只剩 1 条，得到 %d", len(items))
	}
	if m, items := get("page=1&size=100&project_id=2"); string(m["total"]) != "2" || len(items) != 2 {
		t.Fatalf("按项目过滤: total=%s, %d 条", m["total"], len(items))
	}
	if m, items := get("page=1&size=100&project_id=2&type=port"); string(m["total"]) != "1" || len(items) != 1 ||
		items[0]["detail"].(map[string]any)["service"] != "http" {
		t.Fatalf("按类型过滤: %s %v", m["total"], items)
	}
	// 「所属项目」列读 project_name（接口曾不带这个字段，整列空白）
	if _, items := get("page=1&size=100&project_id=2"); items[0]["project_name"] != "乙" {
		t.Fatalf("应带出项目名「乙」: %v", items[0])
	}
	if m, items := get("page=1&size=100&q=h3.a.test"); string(m["total"]) != "1" || len(items) != 1 {
		t.Fatalf("模糊搜索: %s %v", m["total"], items)
	}
	if m, _ := get("page=9&size=100"); string(m["total"]) != "7" {
		t.Fatalf("越过末页 total 仍应是总数: %s", m["total"])
	}
}

func mustField(t *testing.T, body, key string) json.RawMessage {
	t.Helper()
	var m map[string]json.RawMessage
	if err := json.Unmarshal([]byte(body), &m); err != nil {
		t.Fatalf("响应不是对象: %v %s", err, body)
	}
	return m[key]
}

// 不带 page 的旧调用方仍然拿到数组。
func TestListAssetsLegacyArray(t *testing.T) {
	db, a := newKnowledgeFixture(t)
	if _, err := db.Exec(`INSERT INTO assets(project_id,type,value,detail) VALUES(1,'ip','1.1.1.1','{}')`); err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	a.ListAssets(rec, httptest.NewRequest(http.MethodGet, "/api/assets", nil))
	if !strings.HasPrefix(strings.TrimSpace(rec.Body.String()), "[") {
		t.Fatalf("不带 page 应返回数组: %s", rec.Body.String())
	}
}

// 一条 detail 不合法的记录不能让整个列表的响应体变空（资产中心曾因此整页
// 空白）。启动迁移会把空串修成 {}，这里测迁移管不到的那种：非空但不合法。
func TestListAssetsSurvivesInvalidDetail(t *testing.T) {
	db, a := newKnowledgeFixture(t)
	for _, d := range []string{`{"status_code":200}`, `oops`, ``} {
		if _, err := db.Exec(`INSERT INTO assets(project_id,type,value,detail) VALUES(1,'url',?,?)`, "https://x/"+d, d); err != nil {
			t.Fatal(err)
		}
	}
	rec := httptest.NewRecorder()
	a.ListAssets(rec, httptest.NewRequest(http.MethodGet, "/api/assets?page=1&size=10", nil))
	if rec.Code != http.StatusOK || !json.Valid(rec.Body.Bytes()) {
		t.Fatalf("响应应是合法 JSON: %d %q", rec.Code, rec.Body.String())
	}
	var page struct {
		Items []struct {
			Detail json.RawMessage `json:"detail"`
		} `json:"items"`
		Total int `json:"total"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &page); err != nil || page.Total != 3 || len(page.Items) != 3 {
		t.Fatalf("应原样列出 3 条: %v %s", err, rec.Body.String())
	}
	for _, it := range page.Items {
		if !json.Valid(it.Detail) {
			t.Fatalf("detail 应是合法 JSON: %s", it.Detail)
		}
	}
}
