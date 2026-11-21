package api

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/wooluo/argus/internal/deploy"
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
// 蓝本对齐：真实 SSH 登录验证（执行 echo）；密钥路径为空 = 免密默认密钥。
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
	host = strings.TrimSpace(host)
	if host == "" {
		respondErr(w, http.StatusBadRequest, "host 必填")
		return
	}
	port := 22
	if p, ok := in["port"].(float64); ok && p > 0 && p < 65536 {
		port = int(p)
	}
	user, _ := in["username"].(string)
	if user == "" {
		user = "kali"
	}
	authType, _ := in["auth_type"].(string)
	pass, _ := in["password"].(string)
	keyPEM := ""
	if authType == "key" {
		if p, _ := in["private_key_path"].(string); p != "" {
			if b, err := os.ReadFile(p); err == nil {
				keyPEM = string(b)
			}
		}
	}
	out, err := deploy.RunSSH(host, port, user, authType, pass, keyPEM, "echo SSH_OK", 10*time.Second)
	if err != nil || !strings.Contains(out, "SSH_OK") {
		// SSH 失败给出 TCP 兜底诊断（区分网络不通 vs 认证失败）
		msg := fmt.Sprintf("SSH 登录失败: %v（host=%q）", err, host)
		addr := net.JoinHostPort(host, strconv.Itoa(port))
		if conn, derr := net.DialTimeout("tcp", addr, 5*time.Second); derr == nil {
			_ = conn.Close()
			msg += fmt.Sprintf("（TCP %s 可达，多为认证失败：检查用户名/密码/密钥）", addr)
		} else {
			msg += fmt.Sprintf("（TCP %s 不可达: %v）", addr, derr)
		}
		respondJSON(w, http.StatusOK, map[string]any{"ok": false, "error": msg})
		return
	}
	respondJSON(w, http.StatusOK, map[string]any{
		"ok":   true,
		"info": fmt.Sprintf("SSH 登录成功（%s@%s:%d）", user, host, port),
	})
}

// metricsCache 指标缓存节流（蓝本 collect_metrics max_age：公网 VPS 的 SSH
// 握手可达 20s+，节点页轮询每次新建连接会拖垮——15s 内直接返回缓存）。
var (
	metricsMu    sync.Mutex
	metricsCache = map[string]struct {
		at time.Time
		m  map[string]any
	}{}
)

// KaliHostMetrics GET /api/kali/hosts/{id}/metrics — SSH 采集 CPU/内存/磁盘/负载
// （/proc/stat 差分 + /proc/meminfo + df，对齐蓝本 parse_metrics）。
func (a *API) KaliHostMetrics(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	for _, h := range a.kaliLoadHosts() {
		if hid, _ := h["id"].(string); hid != id {
			continue
		}
		name, _ := h["name"].(string)
		host := strings.TrimSpace(strValue(h["host"]))
		now := time.Now().UTC().Format(time.RFC3339)
		metricsMu.Lock()
		if c, ok := metricsCache[id]; ok && time.Since(c.at) < 15*time.Second {
			m := c.m
			metricsMu.Unlock()
			m["time"] = now
			respondJSON(w, http.StatusOK, m)
			return
		}
		metricsMu.Unlock()

		port := 22
		if p, ok := h["port"].(float64); ok && p > 0 {
			port = int(p)
		}
		user, _ := h["username"].(string)
		authType, _ := h["auth_type"].(string)
		pass, _ := h["password"].(string)
		keyPEM := ""
		if authType == "key" {
			if p, _ := h["private_key_path"].(string); p != "" {
				if b, err := os.ReadFile(p); err == nil {
					keyPEM = string(b)
				}
			}
		}
		cmd := `echo =CPU1=; grep '^cpu ' /proc/stat; sleep 1; grep '^cpu ' /proc/stat; ` +
			`echo =MEM=; grep -E '^(MemTotal|MemAvailable|SwapTotal|SwapFree):' /proc/meminfo; ` +
			`echo =DISK=; df -k / | tail -1`
		out, err := deploy.RunSSH(host, port, orDefault(user, "kali"), authType, pass, keyPEM, cmd, 25*time.Second)
		if err != nil {
			respondJSON(w, http.StatusOK, map[string]any{
				"connected": false, "host": orDefault(name, host),
				"error": err.Error(), "time": now})
			return
		}
		m := parseKaliMetrics(out)
		m["connected"] = true
		m["host"] = orDefault(name, host)
		m["time"] = now
		metricsMu.Lock()
		metricsCache[id] = struct {
			at time.Time
			m  map[string]any
		}{time.Now(), m}
		metricsMu.Unlock()
		respondJSON(w, http.StatusOK, m)
		return
	}
	respondErr(w, http.StatusNotFound, "主机不存在")
}

// parseKaliMetrics 解析 =SECTION= 分节的采集输出（对齐蓝本 parse_metrics）。
func parseKaliMetrics(raw string) map[string]any {
	out := map[string]any{}
	section := func(name string) []string {
		var lines []string
		in := false
		for _, l := range strings.Split(raw, "\n") {
			if strings.HasPrefix(l, "="+name+"=") {
				in = true
				continue
			}
			if strings.HasPrefix(l, "=") {
				in = false
				continue
			}
			if in && strings.TrimSpace(l) != "" {
				lines = append(lines, l)
			}
		}
		return lines
	}
	// CPU：两次 /proc/stat 采样差分
	cpuLines := []string{}
	for _, l := range section("CPU1") {
		if strings.HasPrefix(l, "cpu ") {
			cpuLines = append(cpuLines, l)
		}
	}
	if len(cpuLines) >= 2 {
		fields := func(line string) []int {
			var v []int
			for _, p := range strings.Fields(line)[1:] {
				n, _ := strconv.Atoi(p)
				v = append(v, n)
			}
			return v
		}
		a, b := fields(cpuLines[0]), fields(cpuLines[1])
		total, idle := 0, 0
		for i := range b {
			total += b[i] - a[i]
		}
		idleA, idleB := a[3], b[3]
		if len(a) > 4 {
			idleA += a[4]
		}
		if len(b) > 4 {
			idleB += b[4]
		}
		idle = idleB - idleA
		if total > 0 {
			out["cpu_percent"] = float64(int(float64(total-idle)/float64(total)*1000)) / 10
		} else {
			out["cpu_percent"] = 0.0
		}
	}
	// 内存（kB → B）
	mem := map[string]int{}
	for _, l := range section("MEM") {
		parts := strings.Fields(l)
		if len(parts) >= 2 {
			n, _ := strconv.Atoi(parts[1])
			mem[strings.TrimSuffix(parts[0], ":")] = n * 1024
		}
	}
	if t, ok := mem["MemTotal"]; ok && t > 0 {
		used := t - mem["MemAvailable"]
		out["mem_total"], out["mem_used"] = t, used
		out["mem_percent"] = float64(int(float64(used)/float64(t)*1000)) / 10
		out["swap_total"] = mem["SwapTotal"]
		out["swap_used"] = mem["SwapTotal"] - mem["SwapFree"]
	}
	// 磁盘 /：df -k
	for _, l := range section("DISK") {
		parts := strings.Fields(l)
		if len(parts) >= 3 {
			t, _ := strconv.Atoi(parts[1])
			u, _ := strconv.Atoi(parts[2])
			if t > 0 {
				out["disk_total"], out["disk_used"] = t*1024, u*1024
				out["disk_percent"] = float64(int(float64(u)/float64(t)*1000)) / 10
			}
		}
	}
	return out
}

// KaliHostActivity GET /api/kali/hosts/{id}/activity — 该主机相关的命令执行审计
// （agent_logs 中 kali_exec 记录按主机名过滤；节点架构下命令在节点执行，此处聚合平台侧日志）。
func (a *API) KaliHostActivity(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	for _, h := range a.kaliLoadHosts() {
		if hid, _ := h["id"].(string); hid != id {
			continue
		}
		host := strings.TrimSpace(strValue(h["host"]))
		rows, err := a.DB.Query(
			`SELECT tool,content,created_at FROM agent_logs
			 WHERE tool IN ('kali_exec','run_script','kali_install')
			 ORDER BY id DESC LIMIT 200`)
		if err != nil {
			respondJSON(w, http.StatusOK, map[string]any{"items": []any{}})
			return
		}
		defer rows.Close()
		items := []map[string]any{}
		for rows.Next() {
			var tool, content, createdAt string
			if rows.Scan(&tool, &content, &createdAt) != nil {
				continue
			}
			// 平台侧日志未按主机分表——内容含主机名的即视为该主机活动
			if host != "" && !strings.Contains(content, host) {
				continue
			}
			items = append(items, map[string]any{
				"tool": tool, "cmd": truncate(content, 300), "time": createdAt})
			if len(items) >= 50 {
				break
			}
		}
		respondJSON(w, http.StatusOK, map[string]any{"items": items})
		return
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

// strValue map 取 string（清洗隐藏字符用）。
func strValue(v any) string {
	s, _ := v.(string)
	return s
}
