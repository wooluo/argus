package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// 项目页每行的「资产/漏洞」「最近任务」两格按 stats / last_task 渲染。接口曾
// 一度不带它们：「资产/漏洞」一格渲染报错被整格丢掉，右边的列全部左移一格。
func TestListProjectsIncludesStatsAndLastTask(t *testing.T) {
	db, a := newKnowledgeFixture(t)
	mustExec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.Exec(q, args...); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	mustExec(`INSERT INTO projects(id,name,description,scope,authorized) VALUES(1,'甲','','[]',1)`)
	mustExec(`INSERT INTO projects(id,name,description,scope,authorized) VALUES(2,'乙','','[]',1)`) // 没有资产也没跑过任务
	for i := 0; i < 3; i++ {
		mustExec(`INSERT INTO assets(project_id,type,value) VALUES(1,'domain',?)`, "a"+string(rune('a'+i))+".test")
	}
	mustExec(`INSERT INTO assets(project_id,type,value) VALUES(1,'url','https://a.test/')`)
	mustExec(`INSERT INTO assets(project_id,type,value) VALUES(1,'port','1.2.3.4:80')`)
	mustExec(`INSERT INTO assets(project_id,type,value) VALUES(1,'tech','nginx')`) // 不计入三类资产
	mustExec(`INSERT INTO findings(project_id,name,severity) VALUES(1,'XSS','high')`)
	mustExec(`INSERT INTO tasks(project_id,name,status) VALUES(1,'旧任务','failed')`)
	mustExec(`INSERT INTO tasks(project_id,name,status) VALUES(1,'新任务','running')`)
	mustExec(`INSERT INTO tasks(project_id,name,status) VALUES(2,'已结束','done')`)

	rec := httptest.NewRecorder()
	a.ListProjects(rec, httptest.NewRequest(http.MethodGet, "/api/projects", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("状态码 %d: %s", rec.Code, rec.Body.String())
	}
	var rows []struct {
		ID       int                                          `json:"id"`
		Stats    struct{ Domains, URLs, Ports, Findings int } `json:"stats"`
		LastTask *struct {
			ID     int    `json:"id"`
			Status string `json:"status"`
		} `json:"last_task"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &rows); err != nil || len(rows) != 2 {
		t.Fatalf("解析失败: %v %s", err, rec.Body.String())
	}
	if rows[0].ID != 2 || rows[1].ID != 1 {
		t.Fatalf("应按 id 倒序: %v", rows)
	}
	one := rows[1]
	if one.Stats.Domains != 3 || one.Stats.URLs != 1 || one.Stats.Ports != 1 || one.Stats.Findings != 1 {
		t.Errorf("项目 1 的统计不对: %+v", one.Stats)
	}
	if one.LastTask == nil || one.LastTask.ID != 2 || one.LastTask.Status != "running" {
		t.Errorf("项目 1 的最近任务应是 #2 running，得到 %+v", one.LastTask)
	}
	two := rows[0]
	if two.Stats.Domains != 0 || two.Stats.Findings != 0 {
		t.Errorf("项目 2 没有资产和漏洞: %+v", two.Stats)
	}
	if two.LastTask == nil || two.LastTask.Status != "completed" {
		t.Errorf("项目 2 的最近任务状态词应为 completed（done 的出口映射），得到 %+v", two.LastTask)
	}
}
