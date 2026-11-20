package api

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/wooluo/argus/internal/store"
)

// ============ Kali 主机池域（蓝本 api/kali.py）：多主机管理 / 测试 / 监控 / 活动 ============
// 与蓝本差异：Go 侧暂无 SSH 层——hosts/test 仅测 host:port TCP 连通（蓝本走真实 SSH 登录验证）；
// metrics/activity 蓝本经 SSH 采集，Go 降级为存根（TODO：接入 SSH 客户端后实现真实采集）。

const kaliHostsKey = "kali_hosts"

// kaliLoadHosts 读 settings["kali_hosts"]（蓝本 kali.hosts()）。
func (a *API) kaliLoadHosts() []map[string]any {
	var hosts []map[string]any
	_ = json.Unmarshal([]byte(store.GetSetting(a.DB, kaliHostsKey)), &hosts)
	return hosts
}

// kaliSaveHosts 落 settings["kali_hosts"]（蓝本 kali.save_hosts()）。
func (a *API) kaliSaveHosts(hosts []map[string]any) error {
	b, err := json.Marshal(hosts)
	if err != nil {
		return err
	}
	return store.SetSetting(a.DB, kaliHostsKey, string(b))
}

// kaliMask 掩码（蓝本 _mask：<8 位全 *，否则前4...后2）。
func kaliMask(v string) string {
	if v == "" {
		return ""
	}
	if len(v) < 8 {
		return strings.Repeat("*", len(v))
	}
	return v[:4] + "..." + v[len(v)-2:]
}

// kaliIsMasked 空 / 含 "..." / 全 * —— 视为掩码回传，PUT 时保留旧值。
func kaliIsMasked(v string) bool {
	return v == "" || strings.Contains(v, "...") || strings.Trim(v, "*") == ""
}

// kaliMaskedConf 掩码单条主机配置（蓝本 _mask_conf），只回掩码 + has_xxx，绝不回明文。
func kaliMaskedConf(h map[string]any) map[string]any {
	out := map[string]any{}
	for k, v := range h {
		if k == "password" || k == "sudo_password" {
			continue
		}
		out[k] = v
	}
	for _, k := range []string{"password", "sudo_password"} {
		val, _ := h[k].(string)
		out[k] = kaliMask(val)
		out["has_"+k] = val != ""
	}
	return out
}

// ListKaliHosts GET /api/kali/hosts — 列表（密码掩码）。
func (a *API) ListKaliHosts(w http.ResponseWriter, r *http.Request) {
	hosts := a.kaliLoadHosts()
	out := make([]map[string]any, 0, len(hosts))
	for _, h := range hosts {
		out = append(out, kaliMaskedConf(h))
	}
	respondJSON(w, http.StatusOK, out)
}

// PutKaliHosts PUT /api/kali/hosts — 整表保存；password/sudo_password 空/掩码回传时按 id 保留旧值。
func (a *API) PutKaliHosts(w http.ResponseWriter, r *http.Request) {
	var in []map[string]any
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		respondErr(w, http.StatusBadRequest, "参数错误")
		return
	}
	old := map[string]map[string]any{}
	for _, h := range a.kaliLoadHosts() {
		if id, ok := h["id"].(string); ok {
			old[id] = h
		}
	}
	for _, h := range in {
		id, _ := h["id"].(string)
		if id == "" {
			id = fmt.Sprintf("h%d", time.Now().UnixNano()) // 新主机补 id
			h["id"] = id
		}
		for _, key := range []string{"password", "sudo_password"} {
			val, _ := h[key].(string)
			if kaliIsMasked(val) {
				if o := old[id]; o != nil {
					h[key] = o[key] // 掩码回传 → 保留旧值
				} else {
					h[key] = ""
				}
			}
		}
	}
	if err := a.kaliSaveHosts(in); err != nil {
		respondErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	respondJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// TestKaliHost POST /api/kali/hosts/test — 单台测试（无需先保存；掩码密码自动取已存值）。
// 差异：蓝本走 SSH 登录验证，Go 侧无 SSH 层，降级为 net.DialTimeout 测 host:port TCP 连通。
func (a *API) TestKaliHost(w http.ResponseWriter, r *http.Request) {
	var in map[string]any
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		respondErr(w, http.StatusBadRequest, "参数错误")
		return
	}
	id, _ := in["id"].(string)
	if v, _ := in["password"].(string); kaliIsMasked(v) || v == "" {
		for _, h := range a.kaliLoadHosts() {
			if hid, _ := h["id"].(string); hid == id && id != "" {
				in["password"] = h["password"]
				in["sudo_password"] = h["sudo_password"]
				break
			}
		}
	}
	host, _ := in["host"].(string)
	if host == "" {
		respondErr(w, http.StatusBadRequest, "host 必填")
		return
	}
	port := 22
	if p, ok := in["port"].(float64); ok && p > 0 && p < 65536 {
		port = int(p)
	}
	addr := fmt.Sprintf("%s:%d", host, port)
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		respondJSON(w, http.StatusOK, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	_ = conn.Close()
	respondJSON(w, http.StatusOK, map[string]any{
		"ok":   true,
		"info": fmt.Sprintf("TCP %s 可达（Go 侧无 SSH 层，仅测端口连通；蓝本为 SSH 登录测试）", addr),
	})
}

// KaliHostMetrics GET /api/kali/hosts/{id}/metrics — 蓝本经 SSH 采集 CPU/内存等，
// Go 降级为存根（TODO：接 SSH 层后实现，或从本地任务库聚合）。
func (a *API) KaliHostMetrics(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	for _, h := range a.kaliLoadHosts() {
		if hid, _ := h["id"].(string); hid == id {
			respondJSON(w, http.StatusOK, map[string]any{
				"configured": true,
				"host":       h["host"],
				"note":       "Go 侧未实现 SSH 采集，metrics 为存根",
			})
			return
		}
	}
	respondErr(w, http.StatusNotFound, "主机不存在")
}

// KaliHostActivity GET /api/kali/hosts/{id}/activity — 蓝本读 KaliHost.activity（SSH 执行记录），
// Go 降级为空列表存根（TODO：接 SSH 层后实现）。
func (a *API) KaliHostActivity(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	for _, h := range a.kaliLoadHosts() {
		if hid, _ := h["id"].(string); hid == id {
			respondJSON(w, http.StatusOK, map[string]any{"items": []any{}})
			return
		}
	}
	respondErr(w, http.StatusNotFound, "主机不存在")
}

// DeleteKaliHost DELETE /api/kali/hosts/{id} — 过滤后整表保存。
func (a *API) DeleteKaliHost(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	hosts := a.kaliLoadHosts()
	kept := hosts[:0]
	for _, h := range hosts {
		if hid, _ := h["id"].(string); hid != id {
			kept = append(kept, h)
		}
	}
	if err := a.kaliSaveHosts(kept); err != nil {
		respondErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	respondJSON(w, http.StatusOK, map[string]any{"ok": true})
}
