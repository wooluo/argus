package api

// sources.go: 数据源配置域（蓝本 api/dashboard.py sources）+ FOFA 凭据配置
// （蓝本 api/settings.py GET/PUT /api/settings/fofa）。

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/wooluo/argus/internal/store"
)

// GetSources GET /api/dashboard/sources — 自定义 nuclei 模板仓库 + 情报目录。
func (a *API) GetSources(w http.ResponseWriter, r *http.Request) {
	respondJSON(w, 200, map[string]any{
		"custom_nuclei_repo": store.GetSetting(a.DB, "custom_nuclei_repo"),
		"intel_dir":          store.GetSetting(a.DB, "intel_dir"),
	})
}

// PutSources PUT /api/dashboard/sources。
func (a *API) PutSources(w http.ResponseWriter, r *http.Request) {
	var req struct {
		CustomNucleiRepo string `json:"custom_nuclei_repo"`
		IntelDir         string `json:"intel_dir"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondErr(w, 422, err.Error())
		return
	}
	if err := store.SetSetting(a.DB, "custom_nuclei_repo", strings.TrimSpace(req.CustomNucleiRepo)); err != nil {
		respondErr(w, 500, err.Error())
		return
	}
	if err := store.SetSetting(a.DB, "intel_dir", strings.TrimSpace(req.IntelDir)); err != nil {
		respondErr(w, 500, err.Error())
		return
	}
	respondJSON(w, 200, map[string]bool{"ok": true})
}

// GetFofaConfig GET /api/settings/fofa — FOFA 凭据（key 掩码）。
func (a *API) GetFofaConfig(w http.ResponseWriter, r *http.Request) {
	key := store.GetSetting(a.DB, "fofa_key")
	respondJSON(w, 200, map[string]any{
		"email":      store.GetSetting(a.DB, "fofa_email"),
		"key":        maskKey(key),
		"has_key":    key != "",
		"configured": key != "" && store.GetSetting(a.DB, "fofa_email") != "",
	})
}

// PutFofaConfig PUT /api/settings/fofa — 保存 FOFA 凭据（掩码回传保留旧值）。
// 保存后经 Poll 下发到节点（fofa_search 优先用下发值，回落环境变量）。
func (a *API) PutFofaConfig(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email string `json:"email"`
		Key   string `json:"key"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondErr(w, 422, err.Error())
		return
	}
	if err := store.SetSetting(a.DB, "fofa_email", strings.TrimSpace(req.Email)); err != nil {
		respondErr(w, 500, err.Error())
		return
	}
	key := strings.TrimSpace(req.Key)
	if key != "" && !strings.Contains(key, "*") { // 掩码回传不动旧值
		if err := store.SetSetting(a.DB, "fofa_key", key); err != nil {
			respondErr(w, 500, err.Error())
			return
		}
	}
	respondJSON(w, 200, map[string]bool{"ok": true})
}
