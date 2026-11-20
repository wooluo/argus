package api

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/wooluo/argus/internal/llm"
	"github.com/wooluo/argus/internal/store"
	"github.com/wooluo/argus/internal/tools"
)

// ================= Settings 第二部分：auth / tools / llm test+models / preset-keys =================

// unmaskKey 掩码回传时找回真 key：按长度匹配预设密钥库，匹配不上保留当前值。
func (a *API) unmaskKey(candidate, fallback string) string {
	presets := settingJSON(a.DB, "llm_preset_keys")
	for _, v := range presets {
		s, _ := v.(string)
		if s != "" && strings.Repeat("*", len(s)) == candidate {
			return s
		}
	}
	return fallback
}

// GetAuth GET /api/settings/auth —— 只回预览，不回全 token。
func (a *API) GetAuth(w http.ResponseWriter, r *http.Request) {
	tok, _ := settingJSON(a.DB, "auth")["token"].(string)
	preview := ""
	if tok != "" {
		preview = tok[:4] + "…" + tok[len(tok)-4:]
	}
	respondJSON(w, 200, map[string]any{"has_token": tok != "", "token_preview": preview})
}

// PutAuth PUT /api/settings/auth —— 空串=关闭认证（本地模式）；写后热更新内存中间件。
func (a *API) PutAuth(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		respondErr(w, 400, err.Error())
		return
	}
	tok := strings.TrimSpace(in.Token)
	if err := saveSettingKey(a.DB, "auth", map[string]any{"token": tok}); err != nil {
		respondErr(w, 500, err.Error())
		return
	}
	if a.Auth != nil {
		a.Auth.SetToken(tok)
	}
	respondJSON(w, 200, map[string]any{"ok": true})
}

// GenerateAuth POST /api/settings/auth/generate —— 32 字节随机令牌，立即生效。
func (a *API) GenerateAuth(w http.ResponseWriter, r *http.Request) {
	raw := make([]byte, 32)
	_, _ = rand.Read(raw)
	tok := base64.RawURLEncoding.EncodeToString(raw)
	if err := saveSettingKey(a.DB, "auth", map[string]any{"token": tok}); err != nil {
		respondErr(w, 500, err.Error())
		return
	}
	if a.Auth != nil {
		a.Auth.SetToken(tok)
	}
	respondJSON(w, 200, map[string]any{"ok": true, "token": tok})
}

// ToolsStatus GET /api/tools —— 注册表状态（name/kind/binary/available/fallback_for/exec_at）。
func (a *API) ToolsStatus(w http.ResponseWriter, r *http.Request) {
	paths := settingJSON(a.DB, "tools")
	respondJSON(w, 200, ToolsStatusList(paths))
}

// PutTools PUT /api/settings/tools —— 自定义工具路径（空值剔除），保存后重探测。
func (a *API) PutTools(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Tools map[string]string `json:"tools"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		respondErr(w, 400, err.Error())
		return
	}
	clean := map[string]string{}
	for k, v := range in.Tools {
		if strings.TrimSpace(v) != "" {
			clean[k] = v
		}
	}
	if err := saveSettingKey(a.DB, "tools", clean); err != nil {
		respondErr(w, 500, err.Error())
		return
	}
	respondJSON(w, 200, map[string]any{"ok": true, "tools_status": tools.Status(clean)})
}

// TestLLM POST /api/settings/llm/test —— 用当前 settings 表里的 llm 配置实测。
func (a *API) TestLLM(w http.ResponseWriter, r *http.Request) {
	cfg := llmConfigFrom(a.DB)
	client := llm.NewClient(llm.DefaultProvider(cfg))
	respondJSON(w, 200, client.TestConnection(r.Context()))
}

// LLMModels GET /api/settings/llm/models?base_url=&api_key= —— 探测 OpenAI 兼容模型列表。
func (a *API) LLMModels(w http.ResponseWriter, r *http.Request) {
	baseURL := strings.TrimSuffix(r.URL.Query().Get("base_url"), "/")
	apiKey := r.URL.Query().Get("api_key")
	if isMasked(apiKey) {
		apiKey = a.unmaskKey(apiKey, "")
	}
	hc := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequestWithContext(r.Context(), "GET", baseURL+"/models", nil)
	if err != nil {
		respondJSON(w, 200, map[string]any{"ok": false, "error": err.Error(), "models": []string{}})
		return
	}
	if apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+apiKey)
	}
	resp, err := hc.Do(req)
	if err != nil {
		respondJSON(w, 200, map[string]any{"ok": false, "error": fmt.Sprintf("%T: %v", err, err), "models": []string{}})
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode == 404 || resp.StatusCode == 405 {
		// 网关未实现模型列表（如内网 DeepSeek 只有 /chat/completions），非错误
		respondJSON(w, 200, map[string]any{"ok": true, "models": []string{}, "unsupported": true})
		return
	}
	if resp.StatusCode != 200 {
		respondJSON(w, 200, map[string]any{"ok": false, "error": fmt.Sprintf("HTTP %d", resp.StatusCode), "models": []string{}})
		return
	}
	var data struct {
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&data); err != nil {
		respondJSON(w, 200, map[string]any{"ok": false, "error": err.Error(), "models": []string{}})
		return
	}
	models := make([]string, 0, len(data.Data))
	seen := map[string]bool{}
	for _, m := range data.Data {
		if m.ID != "" && !seen[m.ID] {
			seen[m.ID] = true
			models = append(models, m.ID)
		}
	}
	sort.Strings(models)
	respondJSON(w, 200, map[string]any{"ok": true, "models": models})
}

// GetPresetKeys GET /api/settings/llm/preset-keys —— 掩码长度显示。
func (a *API) GetPresetKeys(w http.ResponseWriter, r *http.Request) {
	out := map[string]string{}
	for k, v := range settingJSON(a.DB, "llm_preset_keys") {
		s, _ := v.(string)
		out[k] = strings.Repeat("*", len(s))
	}
	respondJSON(w, 200, out)
}

// PutPresetKey PUT /api/settings/llm/preset-keys —— 全星号回传=保留原值。
func (a *API) PutPresetKey(w http.ResponseWriter, r *http.Request) {
	var in struct {
		PresetID string `json:"preset_id"`
		APIKey   string `json:"api_key"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		respondErr(w, 400, err.Error())
		return
	}
	cur := settingJSON(a.DB, "llm_preset_keys")
	if in.APIKey == "" || strings.Trim(in.APIKey, "*") == "" {
		if old, ok := cur[in.PresetID].(string); ok {
			in.APIKey = old
		} else {
			in.APIKey = ""
		}
	}
	cur[in.PresetID] = in.APIKey
	if err := saveSettingKey(a.DB, "llm_preset_keys", cur); err != nil {
		respondErr(w, 500, err.Error())
		return
	}
	respondJSON(w, 200, map[string]any{"ok": true})
}

// llmConfigFrom settings 表 → llm.Config（nodes.go Poll 同源）。
func llmConfigFrom(db *sql.DB) llm.Config {
	var cfg llm.Config
	_ = json.Unmarshal([]byte(store.GetSetting(db, "llm")), &cfg)
	return cfg
}
