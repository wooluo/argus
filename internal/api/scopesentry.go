package api

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/wooluo/argus/internal/store"
)

// ============ ScopeSentry 资产同步域（蓝本 api/scopesentry.py）============
// 配置 base_url + api_key（X-Token 头）存 settings["scopesentry"]；
// 按项目一键导入平台资产（子域/URL/端口），与 assets 表按 (type,value) 去重后入库。
// 与蓝本差异：蓝本 import 走 proxy_for_url 代理，Go 侧 internal/api/extension.go 无现成
// proxy helper（grep 无 'proxy'），故直连；如需代理待统一 http client 封装后再接。

// ssConf 读 settings["scopesentry"]（蓝本 _conf）。
func (a *API) ssConf() map[string]string {
	var m map[string]string
	_ = json.Unmarshal([]byte(store.GetSetting(a.DB, "scopesentry")), &m)
	if m == nil {
		m = map[string]string{}
	}
	return m
}

// GetScopeSentryConfig GET /api/scopesentry/config — api_key 掩码（不回明文）。
func (a *API) GetScopeSentryConfig(w http.ResponseWriter, r *http.Request) {
	c := a.ssConf()
	key := c["api_key"]
	masked := ""
	if key != "" {
		masked = strings.Repeat("*", len(key))
	}
	respondJSON(w, http.StatusOK, map[string]any{
		"base_url": c["base_url"], "api_key": masked, "has_key": key != "",
	})
}

// PutScopeSentryConfig PUT /api/scopesentry/config — 空/全* 保留旧 key。
func (a *API) PutScopeSentryConfig(w http.ResponseWriter, r *http.Request) {
	var in struct {
		BaseURL string `json:"base_url"`
		APIKey  string `json:"api_key"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		respondErr(w, http.StatusBadRequest, "参数错误")
		return
	}
	key := in.APIKey
	if strings.TrimSpace(key) == "" || strings.Trim(key, "*") == "" {
		key = a.ssConf()["api_key"]
	}
	b, _ := json.Marshal(map[string]string{
		"base_url": strings.TrimRight(in.BaseURL, "/"),
		"api_key":  key,
	})
	if err := store.SetSetting(a.DB, "scopesentry", string(b)); err != nil {
		respondErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	respondJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// ScopeSentryTest POST /api/scopesentry/test — GET {base}/api/config/info 验连通，10s 超时。
func (a *API) ScopeSentryTest(w http.ResponseWriter, r *http.Request) {
	c := a.ssConf()
	if c["base_url"] == "" {
		respondJSON(w, http.StatusOK, map[string]any{"ok": false, "error": "未配置地址"})
		return
	}
	url := c["base_url"] + "/api/config/info"
	client := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		respondJSON(w, http.StatusOK, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	req.Header.Set("X-Token", c["api_key"])
	resp, err := client.Do(req)
	if err != nil {
		respondJSON(w, http.StatusOK, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 200))
	respondJSON(w, http.StatusOK, map[string]any{
		"ok":   resp.StatusCode == http.StatusOK,
		"info": fmt.Sprintf("HTTP %d: %s", resp.StatusCode, string(body)),
	})
}

// ssFetchAssets 从 ScopeSentry 拉资产（蓝本 _fetch_assets）：三个端点各取 size=500，
// 单端点失败不阻断；返回 {kind, raw} 列表。30s 超时。
func ssFetchAssets(conf map[string]string) []map[string]any {
	client := &http.Client{Timeout: 30 * time.Second}
	var out []map[string]any
	for path, kind := range map[string]string{
		"/api/subdomain/results": "subdomain",
		"/api/url/info":          "url",
		"/api/port/info":         "port",
	} {
		req, err := http.NewRequest(http.MethodGet, conf["base_url"]+path+"?size=500", nil)
		if err != nil {
			continue
		}
		req.Header.Set("X-Token", conf["api_key"])
		resp, err := client.Do(req)
		if err != nil || resp.StatusCode != http.StatusOK {
			if resp != nil {
				_ = resp.Body.Close()
			}
			continue
		}
		var data struct {
			Data []map[string]any `json:"data"`
		}
		err = json.NewDecoder(resp.Body).Decode(&data)
		_ = resp.Body.Close()
		if err != nil {
			continue
		}
		for i, it := range data.Data {
			if i >= 500 {
				break
			}
			out = append(out, map[string]any{"kind": kind, "raw": it})
		}
	}
	return out
}

var ssDomainRe = regexp.MustCompile(`^[a-z0-9.\-]+\.[a-z]{2,}$`)

// ssExtract (type, value, detail) 或空串——蓝本 _extract 的字段兼容逻辑。
func ssExtract(item map[string]any) (string, string, string) {
	raw, _ := item["raw"].(map[string]any)
	kind, _ := item["kind"].(string)
	for _, key := range []string{"subdomain", "host", "url", "ip", "asset"} {
		v, _ := raw[key].(string)
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		switch kind {
		case "subdomain":
			return "domain", v, `{"via":"ScopeSentry"}`
		case "url":
			return "url", v, `{"via":"ScopeSentry"}`
		case "port":
			port, _ := raw["port"].(string)
			if port == "" {
				if p, ok := raw["port"].(float64); ok {
					port = fmt.Sprintf("%d", int(p))
				}
			}
			host := strings.Split(v, ":")[0]
			svc, _ := raw["service"].(string)
			detail, _ := json.Marshal(map[string]string{"host": host, "port": port, "service": svc})
			return "port", host + ":" + port, string(detail)
		}
		if net.ParseIP(v) != nil {
			return "ip", v, `{"via":"ScopeSentry"}`
		}
		if ssDomainRe.MatchString(strings.ToLower(v)) {
			return "domain", v, `{"via":"ScopeSentry"}`
		}
	}
	return "", "", ""
}

// ScopeSentryImport POST /api/scopesentry/projects/{id}/import — 拉资产→与 assets 表
// (project_id,type,value) 去重→入库（value 截 512，source='ScopeSentry'）。
func (a *API) ScopeSentryImport(w http.ResponseWriter, r *http.Request) {
	pid, err := pathID(r)
	if err != nil {
		respondErr(w, http.StatusBadRequest, "invalid id")
		return
	}
	var name string
	if err := a.DB.QueryRow(`SELECT name FROM projects WHERE id=?`, pid).Scan(&name); err != nil {
		respondErr(w, http.StatusNotFound, "项目不存在")
		return
	}
	conf := a.ssConf()
	if conf["base_url"] == "" {
		respondErr(w, http.StatusBadRequest, "未配置 ScopeSentry 地址（设置 → 资产同步）")
		return
	}
	items := ssFetchAssets(conf)
	if len(items) == 0 {
		respondErr(w, http.StatusBadGateway, "未从 ScopeSentry 拉到资产（检查地址/Key/接口版本）")
		return
	}
	existing := map[string]bool{}
	rows, err := a.DB.Query(`SELECT type,value FROM assets WHERE project_id=?`, pid)
	if err != nil {
		respondErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	for rows.Next() {
		var t, v string
		if err := rows.Scan(&t, &v); err != nil {
			continue
		}
		existing[t+"\x00"+v] = true
	}
	_ = rows.Close()

	added := map[string]int{"domain": 0, "ip": 0, "url": 0, "port": 0}
	skipped := 0
	for _, it := range items {
		t, v, detail := ssExtract(it)
		if t == "" || v == "" || existing[t+"\x00"+v] {
			skipped++
			continue
		}
		if len(v) > 512 {
			v = v[:512]
		}
		if _, err := a.DB.Exec(
			`INSERT INTO assets(project_id,type,value,detail,source) VALUES(?,?,?,?,?)`,
			pid, t, v, detail, "ScopeSentry"); err != nil {
			respondErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		existing[t+"\x00"+v] = true
		added[t]++
	}
	respondJSON(w, http.StatusOK, map[string]any{
		"ok": true, "fetched": len(items), "added": added, "skipped_dup_or_unknown": skipped,
	})
}
