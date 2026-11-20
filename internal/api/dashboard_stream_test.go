package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/wooluo/argus/internal/events"
	"github.com/wooluo/argus/internal/store"
)

// 自检：内存库造数 → GetDashboard 聚合断言 + GetStream SSE 握手/转发/心跳。
func TestDashboardAndStream(t *testing.T) {
	db, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	seed := []string{
		`INSERT INTO projects(name) VALUES ('p1')`,
		`INSERT INTO findings(project_id,name,severity,status) VALUES
		(1,'f-crit','critical','confirmed'),(1,'f-high','high','pending'),(1,'f-info','info','pending')`,
		`INSERT INTO tasks(project_id,status,mode,tokens,created_at) VALUES
		(1,'running','fast','{"prompt":1500,"completion":500,"calls":3}','` + todayUTC() + `T10:00:00.000Z'),
		(1,'completed','autonomous','{"prompt":100,"completion":100,"calls":1}','2020-01-01T00:00:00.000Z')`,
		`INSERT INTO approvals(task_id,project_id,tool) VALUES (1,1,'nmap')`,
		`INSERT INTO agent_logs(task_id,type,tool,content) VALUES (1,'tool_call','nmap','x')`,
	}
	for _, q := range seed {
		if _, err := db.Exec(q); err != nil {
			t.Fatal(err, q)
		}
	}

	a := &API{DB: db, Bus: events.NewBus()}

	// ---- Dashboard ----
	rec := httptest.NewRecorder()
	a.GetDashboard(rec, httptest.NewRequest(http.MethodGet, "/api/dashboard", nil))
	if rec.Code != 200 {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var got map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"activity", "recent_tasks", "recent_findings"} {
		delete(got, k) // 只精确断言下面挑的字段
	}
	want := map[string]any{
		"projects":          float64(1),
		"findings":          float64(3), // 未读=全部（read_at NULL）
		"confirmed":         float64(1),
		"high_critical":     float64(2),
		"sev":               map[string]any{"critical": float64(1), "high": float64(1), "medium": float64(0), "low": float64(0)},
		"running":           float64(1),
		"completed":         float64(1),
		"tasks_total":       float64(2),
		"pending_approvals": float64(1),
		"traffic":           float64(0),
		"assets":            float64(0),
	}
	for k, v := range want {
		if !reflect.DeepEqual(got[k], v) {
			t.Errorf("key=%s got=%v want=%v", k, got[k], v)
		}
	}
	if got["tokens_k"] != nil && got["tokens_k"].(float64) != 2.2 {
		t.Errorf("tokens_k=%v want 2.2", got["tokens_k"])
	}
	days := got["days"].([]any)
	if len(days) != 7 || days[6].(map[string]any)["tasks"].(float64) != 1 {
		t.Errorf("days=%v", days)
	}
	ts := got["task_status"].(map[string]any)
	if ts["running"] != float64(1) || ts["completed"] != float64(1) {
		t.Errorf("task_status=%v", ts)
	}

	// ---- Stream：SSE 握手 / 事件转发 / 断开退出 ----
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sreq := httptest.NewRequest(http.MethodGet, "/api/stream", nil).WithContext(ctx)
	srec := httptest.NewRecorder()
	done := make(chan struct{})
	go func() { a.GetStream(srec, sreq); close(done) }()
	time.Sleep(200 * time.Millisecond) // 等订阅建立并刷出首帧
	a.Bus.Publish("task_started", map[string]any{"id": 1})
	cancel()
	<-done
	body := srec.Body.String()
	if ct := srec.Header().Get("Content-Type"); ct != "text/event-stream" {
		t.Errorf("content-type=%q", ct)
	}
	for _, want := range []string{": ping", "event: task_started", `"id":1`} {
		if !strings.Contains(body, want) {
			t.Errorf("sse body missing %q: %q", want, body)
		}
	}

	// 无 SSE 能力的总线 → 500
	bad := &API{DB: db, Bus: publishOnly{}}
	badRec := httptest.NewRecorder()
	bad.GetStream(badRec, httptest.NewRequest(http.MethodGet, "/api/stream", nil))
	if badRec.Code != 500 {
		t.Errorf("non-sse bus: code=%d want 500", badRec.Code)
	}
}

// publishOnly: 只实现 Publish 的最小桩，验证 GetStream 的失败分支。
type publishOnly struct{}

func (publishOnly) Publish(string, any) {}

func todayUTC() string { return time.Now().UTC().Format("2006-01-02") }
