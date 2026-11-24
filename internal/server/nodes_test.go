package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/wooluo/argus/internal/events"
	"github.com/wooluo/argus/internal/store"
)

// 任务收尾落库回归：token 用量入库、阶段进度按日志推进、状态值保持库内原样
// （出口换词由 store.PresentStatus 负责）。
func TestReportResultPersistsTokensAndStage(t *testing.T) {
	db, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, q := range []string{
		`INSERT INTO projects(name) VALUES ('p1')`,
		`INSERT INTO tasks(project_id,status,mode) VALUES (1,'assigned','staged')`,
	} {
		if _, err := db.Exec(q); err != nil {
			t.Fatal(err, q)
		}
	}
	n := &NodeAPI{DB: db, Bus: events.NewBus()}

	row := func() (status, tokens, stage, done string) {
		t.Helper()
		if err := db.QueryRow(`SELECT status,tokens,current_stage,stages_done FROM tasks WHERE id=1`).
			Scan(&status, &tokens, &stage, &done); err != nil {
			t.Fatal(err)
		}
		return
	}

	// 旧节点（不回传 tokens）先报一批进度：阶段推进，token 保持默认
	rec := httptest.NewRecorder()
	n.Progress(rec, httptest.NewRequest(http.MethodPost, "/api/nodes/progress", strings.NewReader(
		`{"task_id":1,"logs":[{"stage":"recon","tool":"system","content":"—— 进入阶段【侦察】——"}]}`)))
	if rec.Code != 200 {
		t.Fatalf("progress code=%d body=%s", rec.Code, rec.Body.String())
	}
	if _, tokens, stage, done := row(); stage != "recon" || done != "[]" || tokens != "{}" {
		t.Fatalf("首批进度后: stage=%q done=%s tokens=%s", stage, done, tokens)
	}

	// 最终结果：带 token 与后续阶段日志
	rec = httptest.NewRecorder()
	n.ReportResult(rec, httptest.NewRequest(http.MethodPost, "/api/nodes/result", strings.NewReader(
		`{"task_id":1,"status":"done","message":"全部阶段完成","tokens":{"prompt":120,"completion":80,"calls":4},`+
			`"logs":[{"stage":"verify","tool":"agent","content":"x"},{"stage":"evidence","tool":"evidence","content":"y"}]}`)))
	if rec.Code != 200 {
		t.Fatalf("result code=%d body=%s", rec.Code, rec.Body.String())
	}
	status, tokens, stage, done := row()
	if status != "done" {
		t.Errorf("库内状态应保持 done（出口再换词），得到 %q", status)
	}
	if tokens != `{"calls":4,"completion":80,"prompt":120}` {
		t.Errorf("token 用量未落库: %s", tokens)
	}
	if stage != "verify" || done != `["recon","mapping","vulnscan"]` {
		t.Errorf("阶段进度不符: stage=%q done=%s（未知 stage 应忽略）", stage, done)
	}
}

// 阶段进度只前进不后退；自主模式不适用。
func TestAdvanceStage(t *testing.T) {
	db, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, q := range []string{
		`INSERT INTO projects(name) VALUES ('p1')`,
		`INSERT INTO tasks(project_id,status,mode) VALUES (1,'assigned','staged')`,     // id 1
		`INSERT INTO tasks(project_id,status,mode) VALUES (1,'assigned','autonomous')`, // id 2
	} {
		if _, err := db.Exec(q); err != nil {
			t.Fatal(err, q)
		}
	}
	n := &NodeAPI{DB: db}
	read := func(id int64) (stage, done string) {
		t.Helper()
		if err := db.QueryRow(`SELECT current_stage,stages_done FROM tasks WHERE id=?`, id).
			Scan(&stage, &done); err != nil {
			t.Fatal(err)
		}
		return
	}

	n.advanceStage(1, []string{"", "recon"})
	if stage, done := read(1); stage != "recon" || done != "[]" {
		t.Fatalf("进入侦察: stage=%q done=%s", stage, done)
	}
	n.advanceStage(1, []string{"mapping", "recon"})
	if stage, done := read(1); stage != "mapping" || done != `["recon"]` {
		t.Fatalf("推进到测绘: stage=%q done=%s", stage, done)
	}
	n.advanceStage(1, []string{"recon"}) // 乱序到达的旧批次
	if stage, done := read(1); stage != "mapping" || done != `["recon"]` {
		t.Fatalf("进度不应回退: stage=%q done=%s", stage, done)
	}
	n.advanceStage(1, []string{"evidence", "knowledge", "hunt"}) // 非流水线阶段
	if stage, done := read(1); stage != "mapping" || done != `["recon"]` {
		t.Fatalf("未知 stage 不应影响进度: stage=%q done=%s", stage, done)
	}
	n.advanceStage(1, []string{"report"})
	if stage, done := read(1); stage != "report" || done != `["recon","mapping","vulnscan","verify"]` {
		t.Fatalf("跳到报告阶段: stage=%q done=%s", stage, done)
	}

	n.advanceStage(2, []string{"vulnscan"})
	if stage, done := read(2); stage != "" || done != "[]" {
		t.Fatalf("自主模式不应投影阶段进度: stage=%q done=%s", stage, done)
	}
	n.advanceStage(999, []string{"recon"}) // 任务不存在：静默
	if err := db.QueryRow(`SELECT COUNT(*) FROM tasks`).Scan(new(int)); err != nil {
		t.Fatal(err)
	}
}
