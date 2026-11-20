package store

import (
	"strings"
	"testing"
)

// 自检：等价类划分 + 日志触及判定 + 查询串形态差异 + 人话摘要。
func TestCoverage(t *testing.T) {
	db, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	seed := []string{
		`INSERT INTO projects(name) VALUES ('p1')`,
		`INSERT INTO tasks(project_id,status) VALUES (1,'running')`,
		// 4 个等价类：2 url + 1 domain + 1 type 不计入（port）
		`INSERT INTO assets(project_id,type,value) VALUES
		(1,'url','http://a.com/x?debug=1'),(1,'url','http://b.com/y'),
		(1,'domain','a.com'),(1,'port','1.2.3.4:80')`,
		// 日志：触及 a.com/x（带查询串）+ b.com/y 原文出现
		`INSERT INTO agent_logs(task_id,type,content) VALUES
		(1,'thought','扫描 http://a.com/x?debug=1 开始'),
		(1,'tool_result','✅ http_fetch http://b.com/y → 200')`,
	}
	for _, q := range seed {
		if _, err := db.Exec(q); err != nil {
			t.Fatal(err, q)
		}
	}

	total, tested, untested := CoverageStats(db, 1, 1)
	// a.com 虽无独立提及，但 blob 里 url "http://a.com/x?debug=1" 子串命中 domain "a.com"
	if total != 3 || tested != 3 {
		t.Fatalf("stats = %d/%d, untested=%v (want 3/3)", tested, total, untested)
	}
	if len(untested) != 0 {
		t.Fatalf("untested = %v (want [])", untested)
	}

	d := CoverageDescribe(db, 1, 1)
	if !strings.Contains(d, "100%") || !strings.Contains(d, "3/3") || !strings.Contains(d, "（无）") {
		t.Fatalf("describe = %q", d)
	}

	// taskID<=0：项目全任务口径
	total2, tested2, _ := CoverageStats(db, 1, 0)
	if total2 != 3 || tested2 != 3 {
		t.Fatalf("project-wide = %d/%d (want 3/3)", tested2, total2)
	}

	// 空项目
	if d := CoverageDescribe(db, 99, 0); d != "覆盖率: 暂无资产等价类" {
		t.Fatalf("empty = %q", d)
	}
}
