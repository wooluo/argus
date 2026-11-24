package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/wooluo/argus/internal/store"
)

// 发现链路的 server 侧回归：节点上报的发现按「项目 + 名称 + 目标」插入或更新。
// 曾只有「不存在才插入」一条路：状态更新与补充的步骤永远到不了 server、插入
// 时不写 status、重复上报时步骤被挂到别的发现上（LastInsertId 误用）。
func TestFindingUpsertLifecycle(t *testing.T) {
	db, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, q := range []string{
		`INSERT INTO projects(name) VALUES ('p1')`,
		`INSERT INTO tasks(project_id,status,mode) VALUES (1,'assigned','staged')`,
		// 连接上先有别的插入——旧实现里重复上报的步骤会被挂到「上一次插入的行」上
		`INSERT INTO agent_logs(task_id,stage,type,tool,content) VALUES (1,'recon','system','system','先于发现的一行日志')`,
	} {
		if _, err := db.Exec(q); err != nil {
			t.Fatal(err, q)
		}
	}
	n := &NodeAPI{DB: db, Bus: &eventRecorder{}}
	post := func(h http.HandlerFunc, body string) {
		t.Helper()
		w := httptest.NewRecorder()
		h(w, httptest.NewRequest(http.MethodPost, "/api/nodes/x", strings.NewReader(body)))
		if w.Code != 200 {
			t.Fatalf("code=%d body=%s", w.Code, w.Body.String())
		}
	}
	type fRow struct {
		id, steps    int64
		name, status string
	}
	read := func() map[string]fRow {
		t.Helper()
		rows, err := db.Query(`SELECT f.id, f.name, f.status,
			(SELECT COUNT(*) FROM finding_steps s WHERE s.finding_id=f.id) FROM findings f ORDER BY f.id`)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		out := map[string]fRow{}
		for rows.Next() {
			var r fRow
			if err := rows.Scan(&r.id, &r.name, &r.status, &r.steps); err != nil {
				t.Fatal(err)
			}
			out[r.name] = r
		}
		return out
	}

	// 1) 漏洞扫描阶段上报两条发现：状态取节点上报值（原先落库一律 pending）
	post(n.Progress, `{"task_id":1,"findings":[
		{"name":"SQL 注入","severity":"high","target":"http://t/a","detail":"id 参数","status":"confirmed"},
		{"name":"XSS","severity":"medium","target":"http://t/b","status":"confirmed"}]}`)
	got := read()
	if len(got) != 2 || got["SQL 注入"].status != "confirmed" || got["SQL 注入"].id != 1 {
		t.Fatalf("首次上报后: %+v", got)
	}
	sqli := got["SQL 注入"].id

	// 2) 同一批里重复上报带步骤：并入已有条目，步骤挂到它自己身上
	post(n.Progress, `{"task_id":1,"findings":[
		{"name":"SQL 注入","severity":"high","target":"http://t/a","status":"confirmed","steps":[
			{"note":"触发","request":"GET http://t/a?id=1'","response":"500 SQL syntax error","conclusion":"回显报错"}]}]}`)
	if got = read(); len(got) != 2 || got["SQL 注入"].steps != 1 || got["XSS"].steps != 0 {
		t.Fatalf("重复上报应并入且步骤归位: %+v", got)
	}

	// 3) AI 验证阶段：一条改判误报并附说明，另一条确认为真
	post(n.Progress, `{"task_id":1,"finding_updates":[
		{"name":"SQL 注入","severity":"high","target":"http://t/a","status":"false_positive",
		 "detail":"id 参数\n\n【误报判定】WAF 拦截页被误判"},
		{"name":"XSS","severity":"medium","target":"http://t/b","status":"confirmed"}]}`)
	got = read()
	if got["SQL 注入"].status != "false_positive" {
		t.Fatalf("改判误报应落到 server: %+v", got)
	}
	var detail string
	_ = db.QueryRow(`SELECT detail FROM findings WHERE id=?`, sqli).Scan(&detail)
	if !strings.Contains(detail, "【误报判定】WAF 拦截页被误判") {
		t.Errorf("验证说明应写进详情: %q", detail)
	}

	// 4) 最终结果全量对账：追加一步、新增一条；已存在的不重复
	post(n.ReportResult, `{"task_id":1,"status":"done","message":"ok","finding_upserts":[
		{"name":"SQL 注入","severity":"high","target":"http://t/a","status":"false_positive",
		 "steps":[{"note":"触发","request":"GET http://t/a?id=1'","response":"500","conclusion":"报错"},
		          {"note":"复核","request":"GET http://t/a?id=1","response":"500","conclusion":"同样报错→WAF 页"}]},
		{"name":"XSS","severity":"medium","target":"http://t/b","status":"confirmed"},
		{"name":"信息泄露","severity":"low","target":"http://t/c","status":"confirmed"}]}`)
	got = read()
	if len(got) != 3 || got["SQL 注入"].steps != 2 || got["SQL 注入"].status != "false_positive" ||
		got["信息泄露"].id == 0 {
		t.Fatalf("全量对账后: %+v", got)
	}
	// 步骤确实挂在 SQL 注入那条上，而不是别的行
	var misplaced int
	_ = db.QueryRow(`SELECT COUNT(*) FROM finding_steps WHERE finding_id NOT IN (SELECT id FROM findings)`).
		Scan(&misplaced)
	if misplaced != 0 {
		t.Errorf("有 %d 条步骤挂在不存在的发现上", misplaced)
	}

	// 5) 旧版节点形态（只带 findings、不带 status）仍然可用：新条目按 pending 入库
	post(n.Progress, `{"task_id":1,"findings":[{"name":"旧节点上报","severity":"info","target":"http://t/old"}]}`)
	if got = read(); len(got) != 4 || got["旧节点上报"].status != "pending" {
		t.Fatalf("旧节点形态: %+v", got)
	}
}
