package api

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/wooluo/argus/internal/store"
)

// ================= Settings（对应蓝本 settings.py；存储 = settings 表键值） =================

// maskKey 掩码：短 key 全星号，长 key 前6...后4。
func maskKey(key string) string {
	if key == "" || len(key) < 10 {
		return strings.Repeat("*", len(key))
	}
	return key[:6] + "..." + key[len(key)-4:]
}

// isMasked 是否为掩码回传：含 "..." 或全星号。
func isMasked(key string) bool {
	return key != "" && (strings.Contains(key, "...") || strings.Trim(key, "*") == "")
}

// settingJSON 读键并反序列化；空/坏值回落空 map。
func settingJSON(db *sql.DB, key string) map[string]any {
	m := map[string]any{}
	_ = json.Unmarshal([]byte(store.GetSetting(db, key)), &m)
	return m
}

// saveSettingKey 序列化后写 settings 表。
func saveSettingKey(db *sql.DB, key string, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return store.SetSetting(db, key, string(b))
}

// proxyOrDefault 补齐 enabled/url 默认值（键缺失时 SPA 显示关闭态）。
func proxyOrDefault(m map[string]any) map[string]any {
	if _, ok := m["enabled"]; !ok {
		m["enabled"] = false
	}
	if _, ok := m["url"]; !ok {
		m["url"] = ""
	}
	return m
}

// GetSettings GET /api/settings —— 全量设置（api_key 掩码返回）。
func (a *API) GetSettings(w http.ResponseWriter, r *http.Request) {
	s := settingJSON(a.DB, "llm")
	key, _ := s["api_key"].(string)
	respondJSON(w, 200, map[string]any{
		"llm": map[string]any{
			"base_url": s["base_url"],
			"api_key":  maskKey(key),
			"model":    s["model"],
			"has_key":  key != "",
		},
		"limits":       limitsOrDefault(settingJSON(a.DB, "limits")),
		"tools":        settingJSON(a.DB, "tools"),
		"proxy":        proxyOrDefault(settingJSON(a.DB, "proxy")),
		"target_proxy": proxyOrDefault(settingJSON(a.DB, "target_proxy")),
	})
}

// PutLLM PUT /api/settings/llm —— key 留空=不变（换服务商则清空）；掩码回传=还原。
func (a *API) PutLLM(w http.ResponseWriter, r *http.Request) {
	var in struct {
		BaseURL string `json:"base_url"`
		APIKey  string `json:"api_key"`
		Model   string `json:"model"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		respondErr(w, 400, err.Error())
		return
	}
	cur := settingJSON(a.DB, "llm")
	curKey, _ := cur["api_key"].(string)
	curBase, _ := cur["base_url"].(string)

	newKey := in.APIKey
	if strings.TrimSuffix(in.BaseURL, "/") != strings.TrimSuffix(curBase, "/") {
		if newKey == "" {
			newKey = "" // 换服务商：旧 key 必然无效，直接清空
		}
	} else if newKey == "" {
		newKey = curKey
	}
	if newKey != "" && isMasked(newKey) {
		newKey = a.unmaskKey(newKey, curKey)
	}
	if err := saveSettingKey(a.DB, "llm", map[string]any{
		"base_url": strings.TrimSuffix(in.BaseURL, "/"),
		"api_key":  newKey,
		"model":    in.Model,
	}); err != nil {
		respondErr(w, 500, err.Error())
		return
	}
	respondJSON(w, 200, map[string]any{"ok": true})
}

// putProxyKey proxy/target-proxy 共用：启用时地址必填。
func (a *API) putProxyKey(w http.ResponseWriter, r *http.Request, key string) {
	var in struct {
		Enabled bool   `json:"enabled"`
		URL     string `json:"url"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		respondErr(w, 400, err.Error())
		return
	}
	url := strings.TrimSpace(in.URL)
	if in.Enabled && url == "" {
		respondErr(w, 400, "启用代理时地址不能为空")
		return
	}
	if err := saveSettingKey(a.DB, key, map[string]any{"enabled": in.Enabled, "url": url}); err != nil {
		respondErr(w, 500, err.Error())
		return
	}
	respondJSON(w, 200, map[string]any{"ok": true})
}

// PutProxy PUT /api/settings/proxy —— 出站代理（GitHub/OSINT/外网 LLM）。
func (a *API) PutProxy(w http.ResponseWriter, r *http.Request) { a.putProxyKey(w, r, "proxy") }

// PutTargetProxy PUT /api/settings/target-proxy —— 测试流量代理。
func (a *API) PutTargetProxy(w http.ResponseWriter, r *http.Request) {
	a.putProxyKey(w, r, "target_proxy")
}

// PutLimits PUT /api/settings/limits —— Agent 步数/超时/并发/速率。
func (a *API) PutLimits(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Limits map[string]int `json:"limits"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		respondErr(w, 400, err.Error())
		return
	}
	if in.Limits == nil {
		in.Limits = map[string]int{}
	}
	if err := saveSettingKey(a.DB, "limits", in.Limits); err != nil {
		respondErr(w, 500, err.Error())
		return
	}
	respondJSON(w, 200, map[string]any{"ok": true})
}

// limitsOrDefault limits 为空时返回蓝本默认（Python config.py DEFAULTS），
// 已存值与默认合并（缺字段补齐）。
func limitsOrDefault(saved map[string]any) map[string]any {
	def := map[string]any{
		"max_agent_steps":  25,  // 阶段模式：每阶段 Agent 最大步数
		"autonomous_steps": 120, // 自主模式步数基准
		"tool_timeout":     300, // 单次外部工具超时(秒)
		"max_concurrency":  10,  // 自研模块并发
		"request_rate":     20,  // 每秒最大请求数(自研模块)
	}
	if saved == nil {
		return def
	}
	for k, v := range def {
		if _, ok := saved[k]; !ok {
			saved[k] = v
		}
	}
	return saved
}
