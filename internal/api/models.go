package api

// models.go: 模型池与角色分工（分层用脑）。
//
// 主配置（settings.llm）只有一份：一个接入点、一个模型。分层用脑需要多个
// 模型——强模型做决策与执行，轻量模型做审查、报告这类量产活（借鉴
// sapper-v2 的「经济」：旗舰脑做决策，轻量脑做量产）。模型池里每行一个模型
// （接入点 + 模型 ID + 可选 Key），勾选启用后，再为各类工作各选一个；没选的
// 角色沿用主配置。
//
// Key 不必逐行重填：接入点与某个服务商预设相同的行，Key 留空即沿用该预设
// 存过的 Key；与主配置同接入点的，沿用主配置的 Key。存库的是「留空」这个
// 事实本身，换 Key 时不必逐行改。

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/wooluo/argus/internal/llm"
	"github.com/wooluo/argus/internal/store"
)

// ModelEntry 模型池里的一行。
type ModelEntry struct {
	ID      string `json:"id"`
	Label   string `json:"label"`
	BaseURL string `json:"base_url"`
	Model   string `json:"model"`
	APIKey  string `json:"api_key,omitempty"` // 明文存库；空 = 按接入点沿用预设 / 主配置的 Key
	Enabled bool   `json:"enabled"`
}

// RoleDef 一类工作（角色）及其职责。
type RoleDef struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Desc string `json:"desc"`
}

// ModelRoles 角色清单（顺序即界面顺序）。
var ModelRoles = []RoleDef{
	{"hunt", "主循环（决策与执行）", "自主模式的推进；阶段模式的各阶段"},
	{"review", "审查与核验", "收工前的盲区审查；收工后对发现的独立核验；发现复测判定"},
	{"aux", "报告与复盘", "报告生成与事实校验；任务后复盘"},
}

const (
	modelsSettingKey = "models"
	rolesSettingKey  = "model_roles"
)

// presetBaseURLs 服务商预设的接入点 → 预设 ID（与设置页下拉一致）。
var presetBaseURLs = map[string]string{
	"https://open.bigmodel.cn/api/coding/paas/v4": "zhipu-coding",
	"https://open.bigmodel.cn/api/paas/v4":        "zhipu-api",
	"https://api.openai.com/v1":                   "openai",
}

func normBase(u string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(u), "/"))
}

// loadModels 读模型池（坏值回落空）。
func loadModels(db *sql.DB) []ModelEntry {
	var out []ModelEntry
	_ = json.Unmarshal([]byte(store.GetSetting(db, modelsSettingKey)), &out)
	return out
}

func loadRoles(db *sql.DB) map[string]string {
	out := map[string]string{}
	_ = json.Unmarshal([]byte(store.GetSetting(db, rolesSettingKey)), &out)
	return out
}

// modelKey 某一行实际使用的 Key：自己的 → 同接入点的预设 Key → 主配置的 Key
// （接入点相同）。本地服务（LM Studio / Ollama）三者皆空，返回空串。
func modelKey(db *sql.DB, e ModelEntry) string {
	if e.APIKey != "" {
		return e.APIKey
	}
	base := normBase(e.BaseURL)
	if pid, ok := presetBaseURLs[base]; ok {
		if k, _ := settingJSON(db, "llm_preset_keys")[pid].(string); k != "" {
			return k
		}
	}
	if main := llmConfigFrom(db); normBase(main.BaseURL) == base {
		return main.APIKey
	}
	return ""
}

// modelUsable 启用的行必须接入点、模型 ID 俱全。
func modelUsable(e ModelEntry) bool {
	return e.Enabled && strings.TrimSpace(e.BaseURL) != "" && strings.TrimSpace(e.Model) != ""
}

// ResolveModel 某类工作实际使用的模型配置；没分工、或所指的行未启用 / 不完整
// 时返回 nil，调用方回落主配置。
func ResolveModel(db *sql.DB, role string) *llm.Config {
	id := loadRoles(db)[role]
	if id == "" {
		return nil
	}
	for _, e := range loadModels(db) {
		if e.ID != id || !modelUsable(e) {
			continue
		}
		main := llmConfigFrom(db)
		return &llm.Config{
			BaseURL: strings.TrimSuffix(strings.TrimSpace(e.BaseURL), "/"),
			APIKey:  modelKey(db, e),
			Model:   strings.TrimSpace(e.Model),
			Proxy:   main.Proxy, // 出站代理与主配置一致
		}
	}
	return nil
}

// llmConfigForRole server 自己调模型时用：分工了用分工的，否则主配置。
func llmConfigForRole(db *sql.DB, role string) llm.Config {
	if cfg := ResolveModel(db, role); cfg != nil {
		return *cfg
	}
	return llmConfigFrom(db)
}

// modelsView 设置页看到的样子：Key 只回掩码。
func modelsView(db *sql.DB) map[string]any {
	list := make([]map[string]any, 0)
	for _, e := range loadModels(db) {
		key := modelKey(db, e)
		list = append(list, map[string]any{
			"id": e.ID, "label": e.Label, "base_url": e.BaseURL, "model": e.Model,
			"enabled": e.Enabled, "api_key": maskKey(key), "has_key": key != "",
		})
	}
	return map[string]any{"models": list, "roles": loadRoles(db), "role_defs": ModelRoles}
}

// GetModels GET /api/settings/models —— 模型池、角色分工与角色说明。
func (a *API) GetModels(w http.ResponseWriter, _ *http.Request) {
	respondJSON(w, 200, modelsView(a.DB))
}

// PutModels PUT /api/settings/models —— 整表保存。
//
// Key 留空或掩码回传 = 保留该行原来的（仍为「留空」的照旧留空）；启用的行
// 接入点与模型 ID 必填，接入点必须是 http(s) 地址；角色只能指向启用的行，
// 指向不了的一律清空（回落主配置），不让设置页存进一份跑不起来的分工。
func (a *API) PutModels(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Models []struct {
			ID      string `json:"id"`
			Label   string `json:"label"`
			BaseURL string `json:"base_url"`
			Model   string `json:"model"`
			APIKey  string `json:"api_key"`
			Enabled bool   `json:"enabled"`
		} `json:"models"`
		Roles map[string]string `json:"roles"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		respondErr(w, 400, err.Error())
		return
	}
	old := map[string]ModelEntry{}
	for _, e := range loadModels(a.DB) {
		old[e.ID] = e
	}
	entries := make([]ModelEntry, 0, len(in.Models))
	seen := map[string]bool{}
	for _, m := range in.Models {
		e := ModelEntry{
			ID: strings.TrimSpace(m.ID), Label: strings.TrimSpace(m.Label),
			BaseURL: strings.TrimSuffix(strings.TrimSpace(m.BaseURL), "/"),
			Model:   strings.TrimSpace(m.Model), Enabled: m.Enabled,
		}
		if e.ID == "" || seen[e.ID] {
			e.ID = fmt.Sprintf("m%d", time.Now().UnixNano())
			for seen[e.ID] {
				e.ID += "x"
			}
		}
		seen[e.ID] = true
		switch prev := old[e.ID]; {
		case strings.TrimSpace(m.APIKey) == "" || isMasked(m.APIKey):
			e.APIKey = prev.APIKey // 留空 / 掩码：保留原来的
		default:
			e.APIKey = strings.TrimSpace(m.APIKey)
		}
		if e.Enabled {
			u, err := url.Parse(e.BaseURL)
			if e.BaseURL == "" || e.Model == "" || err != nil ||
				(u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
				respondErr(w, 400, fmt.Sprintf(
					"模型「%s」已启用，但接入点或模型 ID 不完整（接入点须为 http(s) 地址）", orDefaultLabel(e)))
				return
			}
		}
		entries = append(entries, e)
	}

	roles := map[string]string{}
	for _, def := range ModelRoles {
		id := strings.TrimSpace(in.Roles[def.ID])
		for _, e := range entries {
			if e.ID == id && modelUsable(e) {
				roles[def.ID] = id
				break
			}
		}
	}
	if err := saveSettingKey(a.DB, modelsSettingKey, entries); err != nil {
		respondErr(w, 500, err.Error())
		return
	}
	if err := saveSettingKey(a.DB, rolesSettingKey, roles); err != nil {
		respondErr(w, 500, err.Error())
		return
	}
	respondJSON(w, 200, modelsView(a.DB))
}

// TestModel POST /api/settings/models/test —— 测某一行的模型（可先测后存）。
// Key 的取法与实际运行时一致：留空 / 掩码 → 该行已存的 → 按接入点沿用。
func (a *API) TestModel(w http.ResponseWriter, r *http.Request) {
	var in struct {
		ID      string `json:"id"`
		BaseURL string `json:"base_url"`
		Model   string `json:"model"`
		APIKey  string `json:"api_key"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		respondErr(w, 400, err.Error())
		return
	}
	e := ModelEntry{ID: strings.TrimSpace(in.ID), Enabled: true,
		BaseURL: strings.TrimSuffix(strings.TrimSpace(in.BaseURL), "/"), Model: strings.TrimSpace(in.Model)}
	if e.BaseURL == "" || e.Model == "" {
		respondErr(w, 400, "接入点与模型 ID 必填")
		return
	}
	e.APIKey = strings.TrimSpace(in.APIKey)
	if e.APIKey == "" || isMasked(e.APIKey) {
		e.APIKey = oldModelKey(a.DB, e.ID) // 留空 / 掩码回传：沿用该行已存的 Key
	}
	client := llm.NewClient(llm.DefaultProvider(llm.Config{
		BaseURL: e.BaseURL, APIKey: modelKey(a.DB, e), Model: e.Model}))
	client.SetRetryPolicy(llm.RetryPolicy{MaxAttempts: 1}) // 连接测试不重试
	respondJSON(w, 200, client.TestConnection(r.Context()))
}

// oldModelKey 某一行自己存的 Key（没存过或没有这一行时返回空）。
func oldModelKey(db *sql.DB, id string) string {
	for _, e := range loadModels(db) {
		if id != "" && e.ID == id {
			return e.APIKey
		}
	}
	return ""
}

func orDefaultLabel(e ModelEntry) string {
	if e.Label != "" {
		return e.Label
	}
	if e.Model != "" {
		return e.Model
	}
	return e.ID
}
