package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/wooluo/argus/internal/store"
)

// 任务下发接口带上：收工后独立核验的开关、时间预算（剩余时长自首次领取起算）。
func TestPollSendsSwitchesAndTimeBudget(t *testing.T) {
	t.Setenv("ARGUS_DATA", t.TempDir())
	db, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, q := range []string{
		`INSERT INTO projects(name,authorized,scope) VALUES ('p1',1,'[{"type":"domain","value":"example.com"}]')`,
		`INSERT INTO nodes(name,token,status) VALUES ('n1','tok','online')`,
		`INSERT INTO tasks(project_id,status,mode) VALUES (1,'pending','autonomous'), (1,'pending','autonomous')`,
	} {
		if _, err := db.Exec(q); err != nil {
			t.Fatal(err, q)
		}
	}
	n := &NodeAPI{DB: db}
	poll := func() map[string]any {
		t.Helper()
		w := httptest.NewRecorder()
		n.Poll(w, httptest.NewRequest(http.MethodGet, "/api/nodes/poll?node_id=1", nil))
		if w.Code != 200 {
			t.Fatalf("code=%d body=%s", w.Code, w.Body.String())
		}
		var out map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		return out
	}
	budgetOf := func(out map[string]any) (remaining, limit float64) {
		tb, _ := out["time_budget"].(map[string]any)
		remaining, _ = tb["remaining_seconds"].(float64)
		limit, _ = tb["limit_seconds"].(float64)
		return
	}

	// 默认：核验开；上限 360 分钟
	out := poll()
	if out["verify_findings"] != true {
		t.Errorf("默认应开启独立核验: %v", out["verify_findings"])
	}
	if remaining, limit := budgetOf(out); limit != 360*60 || remaining <= 0 || remaining > limit {
		t.Errorf("默认时间预算不符: remaining=%.0f limit=%.0f", remaining, limit)
	}

	// 改设置：核验关；上限 30 分钟
	_ = store.SetSetting(db, "limits", `{"autonomous_verify":false,"max_task_minutes":30}`)
	out = poll()
	if out["verify_findings"] != false {
		t.Errorf("设置关闭后不应核验: %v", out["verify_findings"])
	}
	if remaining, limit := budgetOf(out); limit != 1800 || remaining <= 0 || remaining > 1800 {
		t.Errorf("时间预算应随设置变化: remaining=%.0f limit=%.0f", remaining, limit)
	}
}
