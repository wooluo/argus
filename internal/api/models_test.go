package api

import (
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/wooluo/argus/internal/store"
)

const (
	zhipuCoding = "https://open.bigmodel.cn/api/coding/paas/v4"
	presetKey   = "preset-key-0123456789abcdef"
)

func newSettingsFixture(t *testing.T) (*API, *sql.DB) {
	t.Helper()
	db, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return &API{DB: db}, db
}

// callHandler 发请求并返回响应；body 为空时不带请求体。
func callHandler(t *testing.T, h http.HandlerFunc, method, body string) *httptest.ResponseRecorder {
	t.Helper()
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	w := httptest.NewRecorder()
	h(w, httptest.NewRequest(method, "/x", rd))
	return w
}

func decode(t *testing.T, w *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var out map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("响应不是 JSON 对象: %v %s", err, w.Body.String())
	}
	return out
}

// 回归：limits 里现在有布尔开关（autonomous_verify）。早先按整数解码，设置页
// 带着开关保存参数会直接 400。
func TestPutLimitsAcceptsMixedTypes(t *testing.T) {
	a, _ := newSettingsFixture(t)
	w := callHandler(t, a.PutLimits, http.MethodPut,
		`{"limits":{"max_agent_steps":30,"max_task_minutes":120,"autonomous_verify":false}}`)
	if w.Code != 200 {
		t.Fatalf("带布尔开关的 limits 应能保存: code=%d body=%s", w.Code, w.Body.String())
	}
	got := callHandler(t, a.GetSettings, http.MethodGet, "")
	limits, _ := decode(t, got)["limits"].(map[string]any)
	if limits["max_agent_steps"] != float64(30) || limits["autonomous_verify"] != false ||
		limits["max_task_minutes"] != float64(120) || limits["tool_timeout"] != float64(300) {
		t.Fatalf("保存后的 limits 不符（缺项应补默认值）: %v", limits)
	}
}

// 模型池整表保存：Key 留空 / 掩码 = 保留；同接入点的行沿用预设 Key；角色只能
// 指向启用的行；启用的行接入点与模型 ID 必填。
func TestModelPoolSaveAndResolve(t *testing.T) {
	a, db := newSettingsFixture(t)
	_ = store.SetSetting(db, "llm_preset_keys", `{"zhipu-coding":"`+presetKey+`"}`)
	_ = store.SetSetting(db, "llm", `{"base_url":"http://localhost:1234/v1","api_key":"","model":"local-m"}`)

	w := callHandler(t, a.PutModels, http.MethodPut, `{
		"models":[
			{"id":"glm54","label":"GLM-5.4","base_url":"`+zhipuCoding+`/","model":"glm-5.4","enabled":true},
			{"id":"glm53","label":"GLM-5.3","base_url":"`+zhipuCoding+`","model":"glm-5.3","enabled":true},
			{"id":"flash","label":"GLM-5.3-Flash","base_url":"`+zhipuCoding+`","model":"glm-5.3-flash","enabled":false},
			{"id":"local","label":"本地 LM Studio","base_url":"http://localhost:1234/v1","model":"qwen-local","enabled":true},
			{"label":"没写编号的停用行","base_url":"http://x/v1","model":"","enabled":false}
		],
		"roles":{"hunt":"glm54","review":"flash","aux":"local","bogus":"glm54","nope":""}}`)
	if w.Code != 200 {
		t.Fatalf("code=%d body=%s", w.Code, w.Body.String())
	}
	view := decode(t, w)
	models, _ := view["models"].([]any)
	if len(models) != 5 {
		t.Fatalf("应有 5 行: %v", models)
	}
	row := func(i int) map[string]any {
		m, _ := models[i].(map[string]any)
		return m
	}
	// Key 只回掩码；GLM 行没填 Key，但接入点与「智谱 Coding Plan」预设相同 → 沿用预设 Key
	if row(0)["api_key"] != maskKey(presetKey) || row(0)["has_key"] != true {
		t.Errorf("GLM 行应显示已沿用的预设 Key（掩码）: %v", row(0))
	}
	if strings.Contains(w.Body.String(), presetKey) {
		t.Error("响应里不能出现明文 Key")
	}
	if row(4)["id"] == "" {
		t.Errorf("没写编号的行应自动生成编号: %v", row(4))
	}
	// 角色：指向停用行的 review、未知角色 bogus 一律清空
	if roles := view["roles"].(map[string]any); roles["hunt"] != "glm54" || roles["aux"] != "local" ||
		roles["review"] != nil || len(roles) != 2 {
		t.Errorf("角色分工不符: %v", roles)
	}

	hunt := ResolveModel(db, "hunt")
	if hunt == nil || hunt.Model != "glm-5.4" || hunt.BaseURL != zhipuCoding || hunt.APIKey != presetKey {
		t.Errorf("主循环应解析到 GLM-5.4 并沿用预设 Key: %+v", hunt)
	}
	if ResolveModel(db, "review") != nil {
		t.Error("指向停用行的角色应回落主配置")
	}
	if aux := ResolveModel(db, "aux"); aux == nil || aux.Model != "qwen-local" || aux.APIKey != "" {
		t.Errorf("本地模型应解析为空 Key: %+v", aux)
	}
	if ResolveModel(db, "nope") != nil {
		t.Error("未知角色应回落主配置")
	}
	if cfg := llmConfigForRole(db, "review"); cfg.Model != "local-m" {
		t.Errorf("没分工的角色应得到主配置: %+v", cfg)
	}

	// 再存一次：GLM-5.4 的 Key 仍留空（保持「沿用」）；GLM-5.3 填了自己的 Key；
	// 之后回传掩码也不会把它冲掉
	for _, key := range []string{`"api_key":"own-key-9876543210"`, `"api_key":"` + maskKey("own-key-9876543210") + `"`, `"api_key":""`} {
		w = callHandler(t, a.PutModels, http.MethodPut, `{"models":[
			{"id":"glm54","base_url":"`+zhipuCoding+`","model":"glm-5.4","enabled":true},
			{"id":"glm53","base_url":"`+zhipuCoding+`","model":"glm-5.3","enabled":true,`+key+`},
			{"id":"local","base_url":"http://localhost:1234/v1","model":"qwen-local","enabled":true}],
			"roles":{"hunt":"glm54","aux":"local"}}`)
		if w.Code != 200 {
			t.Fatalf("code=%d body=%s", w.Code, w.Body.String())
		}
	}
	if c := ResolveModel(db, "hunt"); c == nil || c.APIKey != presetKey {
		t.Errorf("留空的 Key 应保持「沿用预设」: %+v", c)
	}
	if c := ResolveModel(db, "nope"); c != nil {
		t.Errorf("不应凭空多出分工: %+v", c)
	}
	if c := ResolveModel(db, "glm53"); c != nil { // 池里的行不是角色
		t.Errorf("角色名不是行编号: %+v", c)
	}
	var stored []ModelEntry
	_ = json.Unmarshal([]byte(store.GetSetting(db, "models")), &stored)
	for _, e := range stored {
		if e.ID == "glm53" && e.APIKey != "own-key-9876543210" {
			t.Errorf("自己的 Key 被掩码 / 留空回传冲掉了: %q", e.APIKey)
		}
	}
	var ownKey string
	for _, e := range loadModels(db) {
		if e.ID == "glm53" {
			ownKey = modelKey(db, e)
		}
	}
	if ownKey != "own-key-9876543210" {
		t.Errorf("填了自己 Key 的行应优先用自己的: %q", ownKey)
	}

	// 启用的行接入点 / 模型 ID 不完整 → 400，且不落库
	for _, bad := range []string{
		`{"id":"a","base_url":"` + zhipuCoding + `","model":"","enabled":true}`,
		`{"id":"a","base_url":"","model":"m","enabled":true}`,
		`{"id":"a","base_url":"not a url","model":"m","enabled":true}`,
		`{"id":"a","base_url":"ftp://x/v1","model":"m","enabled":true}`,
	} {
		w = callHandler(t, a.PutModels, http.MethodPut, `{"models":[`+bad+`]}`)
		if w.Code != 400 {
			t.Errorf("不完整的启用行应被拒绝: %s → code=%d", bad, w.Code)
		}
	}
}

// 与主配置同接入点的行，Key 留空时沿用主配置的 Key。
func TestModelKeyInheritsFromMainConfig(t *testing.T) {
	_, db := newSettingsFixture(t)
	_ = store.SetSetting(db, "llm", `{"base_url":"http://10.0.0.9:8000/v1","api_key":"main-key-abcdefghij","model":"m"}`)
	_ = store.SetSetting(db, "models", `[{"id":"x","base_url":"http://10.0.0.9:8000/v1/","model":"x","enabled":true},
		{"id":"y","base_url":"http://10.0.0.9:9999/v1","model":"y","enabled":true}]`)
	if k := modelKey(db, ModelEntry{ID: "x", BaseURL: "http://10.0.0.9:8000/v1"}); k != "main-key-abcdefghij" {
		t.Errorf("同接入点应沿用主配置 Key（忽略末尾斜杠与大小写）: %q", k)
	}
	if k := modelKey(db, ModelEntry{ID: "y", BaseURL: "http://10.0.0.9:9999/v1"}); k != "" {
		t.Errorf("不同接入点不该拿到主配置的 Key: %q", k)
	}
}

// fakeLLMServer 记录收到的 Authorization，回一句「正常」。
func fakeLLMServer(t *testing.T, seen *[]string) string {
	t.Helper()
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		*seen = append(*seen, r.Header.Get("Authorization"))
		mu.Unlock()
		_, _ = w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"正常"}}],` +
			`"usage":{"prompt_tokens":10,"completion_tokens":2}}`))
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

// 单行测试连接：表单 Key 留空 / 回传掩码 → 用该行已存的；新接入点同主配置 → 沿用主配置的。
func TestModelTestResolvesKeyLikeRuntime(t *testing.T) {
	a, db := newSettingsFixture(t)
	var seenOwn, seenMain []string
	ownURL, mainURL := fakeLLMServer(t, &seenOwn), fakeLLMServer(t, &seenMain)
	_ = store.SetSetting(db, "llm", `{"base_url":"`+mainURL+`","api_key":"main-key-abcdefghij","model":"m"}`)
	w := callHandler(t, a.PutModels, http.MethodPut, `{"models":[
		{"id":"own","base_url":"`+ownURL+`","model":"own-m","api_key":"own-key-0123456789","enabled":true}]}`)
	if w.Code != 200 {
		t.Fatalf("code=%d body=%s", w.Code, w.Body.String())
	}

	// 已保存的行，表单里 Key 留空
	w = callHandler(t, a.TestModel, http.MethodPost,
		`{"id":"own","base_url":"`+ownURL+`","model":"own-m"}`)
	if r := decode(t, w); r["ok"] != true {
		t.Fatalf("测试连接应成功: %v", r)
	}
	// 已保存的行，表单回传掩码
	masked := maskKey("own-key-0123456789")
	w = callHandler(t, a.TestModel, http.MethodPost,
		`{"id":"own","base_url":"`+ownURL+`","model":"own-m","api_key":"`+masked+`"}`)
	_ = decode(t, w)
	// 还没保存的新行：接入点与主配置相同 → 沿用主配置的 Key
	w = callHandler(t, a.TestModel, http.MethodPost,
		`{"base_url":"`+mainURL+`","model":"other-m","api_key":"`+maskKey("main-key-abcdefghij")+`"}`)
	if r := decode(t, w); r["ok"] != true {
		t.Fatalf("新行测试连接应成功: %v", r)
	}
	if len(seenOwn) != 2 || seenOwn[0] != "Bearer own-key-0123456789" || seenOwn[1] != "Bearer own-key-0123456789" {
		t.Errorf("该行应始终用自己的 Key: %v", seenOwn)
	}
	if len(seenMain) != 1 || seenMain[0] != "Bearer main-key-abcdefghij" {
		t.Errorf("同主配置接入点的新行应沿用主配置 Key: %v", seenMain)
	}

	w = callHandler(t, a.TestModel, http.MethodPost, `{"id":"own"}`)
	if w.Code != 400 {
		t.Errorf("缺接入点 / 模型 ID 应 400: %d", w.Code)
	}
}
