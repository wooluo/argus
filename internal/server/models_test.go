package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/wooluo/argus/internal/store"
)

const (
	zhipuCoding = "https://open.bigmodel.cn/api/coding/paas/v4"
	presetKey   = "preset-key-0123456789"
)

// 分层用脑：任务下发带上按角色解析好的模型配置（没分工的角色不出现），
// Key 在 server 侧解析完再下发。
func TestPollSendsRoleModels(t *testing.T) {
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
	_ = store.SetSetting(db, "llm", `{"base_url":"http://localhost:1234/v1","api_key":"","model":"local-m"}`)
	_ = store.SetSetting(db, "llm_preset_keys", `{"zhipu-coding":"`+presetKey+`"}`)
	_ = store.SetSetting(db, "models", `[{"id":"glm54","base_url":"`+zhipuCoding+`","model":"glm-5.4","enabled":true},
		{"id":"flash","base_url":"`+zhipuCoding+`","model":"glm-5.3-flash","enabled":true}]`)
	_ = store.SetSetting(db, "model_roles", `{"hunt":"glm54","review":"flash"}`) // aux 没分工
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
	role := func(out map[string]any, name string) map[string]any {
		m, _ := out["models"].(map[string]any)
		c, _ := m[name].(map[string]any)
		return c
	}

	out := poll()
	hunt, review := role(out, "hunt"), role(out, "review")
	if hunt["model"] != "glm-5.4" || hunt["api_key"] != presetKey || hunt["base_url"] != zhipuCoding {
		t.Errorf("主循环应拿到 GLM-5.4 及解析好的 Key: %v", hunt)
	}
	if review["model"] != "glm-5.3-flash" {
		t.Errorf("审查核验应拿到 GLM-5.3-Flash: %v", review)
	}
	if role(out, "aux") != nil {
		t.Errorf("没分工的角色不应下发: %v", out["models"])
	}

	// 取消全部分工 → 不下发任何角色配置，节点沿用主配置
	_ = store.SetSetting(db, "model_roles", `{}`)
	if m, _ := poll()["models"].(map[string]any); len(m) != 0 {
		t.Errorf("取消分工后不应下发角色配置: %v", m)
	}
}

// 分模型用量随合计一起落 tasks.tokens（合计键原样，分模型的在 "models" 下）。
func TestReportResultStoresTokensByModel(t *testing.T) {
	db, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, q := range []string{
		`INSERT INTO projects(name) VALUES ('p1')`,
		`INSERT INTO tasks(project_id,status,mode) VALUES (1,'assigned','autonomous')`,
	} {
		if _, err := db.Exec(q); err != nil {
			t.Fatal(err, q)
		}
	}
	n := &NodeAPI{DB: db, Bus: &eventRecorder{}}
	w := httptest.NewRecorder()
	n.ReportResult(w, httptest.NewRequest(http.MethodPost, "/api/nodes/result", strings.NewReader(
		`{"task_id":1,"status":"done","message":"ok","tokens":{"prompt":100,"completion":50,"calls":9},`+
			`"tokens_by_model":{"glm-5.4":{"prompt":90,"completion":40,"calls":7},`+
			`"glm-5.3-flash":{"prompt":10,"completion":10,"calls":2}}}`)))
	if w.Code != 200 {
		t.Fatalf("code=%d body=%s", w.Code, w.Body.String())
	}
	var tokens struct {
		Prompt  float64 `json:"prompt"`
		Calls   float64 `json:"calls"`
		ByModel map[string]struct {
			Calls float64 `json:"calls"`
		} `json:"models"`
	}
	var stored string
	_ = db.QueryRow(`SELECT tokens FROM tasks WHERE id=1`).Scan(&stored)
	if err := json.Unmarshal([]byte(stored), &tokens); err != nil {
		t.Fatalf("tasks.tokens 不是 JSON: %q", stored)
	}
	if tokens.Prompt != 100 || tokens.Calls != 9 || tokens.ByModel["glm-5.4"].Calls != 7 ||
		tokens.ByModel["glm-5.3-flash"].Calls != 2 {
		t.Errorf("token 落库不符: %s", stored)
	}
}
