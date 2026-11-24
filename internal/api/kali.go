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

	"github.com/go-chi/chi/v5"
	"github.com/wooluo/argus/internal/deploy"
)

// ============ 节点 SSH 观测域 ============
// 原「渗透测试主机」（settings.kali_hosts，Python 蓝本遗留）已并入执行节点：
// 节点表是唯一主机档案，nodes.ssh_conf 列存观测凭据（部署自动写入，也可
// 单独配置）。连通测试 / 资源监控 / 活动审计一律按节点 id 操作。

// SSHConf 节点 SSH 观测凭据（nodes.ssh_conf 列的 JSON 形状）。
// deploy.SSHConfig 的观测子集——只收服务端真实消费的字段，与 tunnel_ssh
// （部署/隧道语义，直连部署会清空）分离，直连节点也能挂观测。
type SSHConf struct {
	Host       string `json:"host"`
	Port       int    `json:"port"`
	Username   string `json:"username"`
	AuthType   string `json:"auth_type"` // password | key
	Password   string `json:"password,omitempty"`
	PrivateKey string `json:"private_key,omitempty"` // PEM
}

// nodeSSH 取节点的观测凭据（ssh_conf 为空/解析失败时 ok=false）。
func (a *API) nodeSSH(id int64) (SSHConf, string, bool) {
	var conf SSHConf
	var raw, name, host string
	err := a.DB.QueryRow(`SELECT name, host, ssh_conf FROM nodes WHERE id=?`, id).Scan(&name, &host, &raw)
	if err != nil || raw == "" {
		return conf, name, false
	}
	if err := json.Unmarshal([]byte(raw), &conf); err != nil {
		return SSHConf{}, name, false
	}
	if conf.Host == "" {
		conf.Host = host
	}
	return conf, name, true
}

// PutNodeSSH PUT /api/nodes/exec/{id}/ssh — 设置/更新节点 SSH 观测凭据。
// 密码/私钥留空（或掩码回传）= 保留旧值；host 缺省用节点已存地址；
// 顺手把规范化的 host 回写 nodes.host。
func (a *API) PutNodeSSH(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil || id <= 0 {
		respondErr(w, http.StatusBadRequest, "invalid id")
		return
	}
	var in struct {
		Host           string `json:"host"`
		Port           int    `json:"port"`
		Username       string `json:"username"`
		AuthType       string `json:"auth_type"`
		Password       string `json:"password"`
		PrivateKey     string `json:"private_key"`
		PrivateKeyPath string `json:"private_key_path"` // server 本地路径（可选，读取后落库）
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		respondErr(w, http.StatusBadRequest, "参数错误")
		return
	}
	var nodeHost, oldRaw string
	if err := a.DB.QueryRow(`SELECT host, ssh_conf FROM nodes WHERE id=?`, id).Scan(&nodeHost, &oldRaw); err != nil {
		respondErr(w, http.StatusNotFound, "节点不存在")
		return
	}
	var old SSHConf
	_ = json.Unmarshal([]byte(oldRaw), &old)

	host := in.Host
	if host == "" {
		host = nodeHost
	}
	if host == "" {
		host = old.Host
	}
	hc, hp, herr := deploy.CleanHostPort(host)
	if herr != nil {
		respondErr(w, http.StatusBadRequest, herr.Error())
		return
	}
	conf := SSHConf{Host: hc, Username: in.Username, AuthType: in.AuthType,
		Password: in.Password, PrivateKey: in.PrivateKey}
	if conf.Username == "" {
		conf.Username = orDefault(old.Username, "kali")
	}
	if conf.AuthType == "" {
		conf.AuthType = orDefault(old.AuthType, "password")
	}
	port := in.Port
	if port == 0 {
		port = old.Port
	}
	if hp > 0 {
		port = hp // host 里显式内嵌的端口优先
	}
	if port == 0 {
		port = 22
	}
	conf.Port = port
	// 密码留空/掩码回传 → 保留旧值（前端不回传明文）
	if conf.Password == "" || strings.Contains(conf.Password, "...") {
		conf.Password = old.Password
	}
	if conf.PrivateKey == "" && in.PrivateKeyPath != "" {
		if b, rerr := os.ReadFile(in.PrivateKeyPath); rerr == nil {
			conf.PrivateKey = string(b)
		}
	}
	if conf.PrivateKey == "" {
		conf.PrivateKey = old.PrivateKey
	}
	switch {
	case conf.AuthType == "key" && conf.PrivateKey == "":
		respondErr(w, http.StatusBadRequest, "密钥认证需要提供私钥")
		return
	case conf.AuthType == "password" && conf.Password == "":
		respondErr(w, http.StatusBadRequest, "密码不能为空")
		return
	}
	b, _ := json.Marshal(conf)
	if _, err := a.DB.Exec(`UPDATE nodes SET ssh_conf=?, host=? WHERE id=?`, string(b), hc, id); err != nil {
		respondErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	respondJSON(w, http.StatusOK, map[string]any{"ok": true,
		"message": fmt.Sprintf("SSH 凭据已保存: %s@%s:%d", conf.Username, hc, port)})
}

// TestNodeSSH POST /api/nodes/exec/{id}/ssh-test — 用节点已存凭据做真实 SSH
// 登录验证（执行 echo）。蓝本对齐：密钥路径为空 = 免密默认密钥。
func (a *API) TestNodeSSH(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil || id <= 0 {
		respondErr(w, http.StatusBadRequest, "invalid id")
		return
	}
	conf, _, ok := a.nodeSSH(id)
	if !ok {
		respondJSON(w, http.StatusOK, map[string]any{"ok": false,
			"error": "节点未配置 SSH 凭据（详情里配置，或重新部署时自动写入）"})
		return
	}
	// echo 重试 3 次：该类 VPS 存在 x/crypto SSH 输出间歇丢失（命令成功
	// 但 stdout 被吞，err=<nil> 且无 SSH_OK）——任一次拿到标记即算通。
	var out string
	for i := 0; i < 3; i++ {
		out, err = deploy.RunSSH(conf.Host, conf.Port, conf.Username, conf.AuthType,
			conf.Password, conf.PrivateKey, "echo SSH_OK", 10*time.Second)
		if strings.Contains(out, "SSH_OK") {
			err = nil
			break
		}
		if err != nil {
			break // 真实错误（认证/网络）不重试
		}
		time.Sleep(300 * time.Millisecond)
	}
	if !strings.Contains(out, "SSH_OK") {
		if err == nil {
			// TCP+认证已过、命令成功但输出被吞——按可用处理并如实标注
			respondJSON(w, http.StatusOK, map[string]any{
				"ok": true,
				"info": fmt.Sprintf("SSH 登录成功（%s@%s:%d；远端输出被吞无法回显，该机已知 SSH 库输出丢失问题）",
					conf.Username, conf.Host, conf.Port),
			})
			return
		}
		// SSH 失败给出 TCP 兜底诊断（区分网络不通 vs 认证失败）
		msg := fmt.Sprintf("SSH 登录失败: %v（host=%q user=%q）", err, conf.Host, conf.Username)
		addr := net.JoinHostPort(conf.Host, strconv.Itoa(conf.Port))
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
		"info": fmt.Sprintf("SSH 登录成功（%s@%s:%d）", conf.Username, conf.Host, conf.Port),
	})
}

// metricsCache 资源监控 15s 缓存（键=节点 id 字符串；探测一次 SSH 成本不低）。
var (
	metricsMu    sync.Mutex
	metricsCache = map[string]struct {
		at time.Time
		m  map[string]any
	}{}
)

// NodeMetrics GET /api/nodes/exec/{id}/metrics — SSH 采集 CPU/内存/磁盘/负载/
// Top 进程（/proc/stat 差分 + /proc/meminfo + df + loadavg + ps，对齐蓝本
// parse_metrics）。
func (a *API) NodeMetrics(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil || id <= 0 {
		respondErr(w, http.StatusBadRequest, "invalid id")
		return
	}
	conf, name, ok := a.nodeSSH(id)
	key := strconv.FormatInt(id, 10)
	now := time.Now().UTC().Format(time.RFC3339)
	if !ok {
		respondJSON(w, http.StatusOK, map[string]any{
			"connected": false, "host": name,
			"error": "节点未配置 SSH 凭据", "time": now})
		return
	}
	metricsMu.Lock()
	if c, cached := metricsCache[key]; cached && time.Since(c.at) < 15*time.Second {
		m := c.m
		metricsMu.Unlock()
		m["time"] = now
		respondJSON(w, http.StatusOK, m)
		return
	}
	metricsMu.Unlock()

	// 标记必须引号包裹：zsh 对 =开头 的词做 =cmd 等号展开，裸 echo =CPU1=
	// 报 "CPU1= not found" 整行中止 exit 1（Kali 默认 shell 即 zsh）
	cmd := `echo '=CPU1='; grep '^cpu ' /proc/stat; sleep 1; grep '^cpu ' /proc/stat; ` +
		`echo '=MEM='; grep -E '^(MemTotal|MemAvailable|SwapTotal|SwapFree):' /proc/meminfo; ` +
		`echo '=DISK='; df -k / | tail -1; ` +
		`echo '=LOAD='; cat /proc/loadavg; ` +
		`echo '=TOP='; ps -eo pid,pcpu,pmem,comm --sort=-pcpu | head -8`
	out, err := deploy.RunSSH(conf.Host, conf.Port, conf.Username, conf.AuthType,
		conf.Password, conf.PrivateKey, cmd, 25*time.Second)
	if err != nil {
		respondJSON(w, http.StatusOK, map[string]any{
			"connected": false, "host": orDefault(name, conf.Host),
			"error": err.Error(), "time": now})
		return
	}
	m := parseKaliMetrics(out)
	m["connected"] = true
	m["host"] = orDefault(name, conf.Host)
	m["time"] = now
	metricsMu.Lock()
	metricsCache[key] = struct {
		at time.Time
		m  map[string]any
	}{time.Now(), m}
	metricsMu.Unlock()
	respondJSON(w, http.StatusOK, m)
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
	// 负载：/proc/loadavg 前三字段（1/5/15 分钟）——UI 负载行 join(" / ")
	if ls := section("LOAD"); len(ls) > 0 {
		f := strings.Fields(ls[0])
		var load []float64
		for i := 0; i < 3 && i < len(f); i++ {
			if v, err := strconv.ParseFloat(f[i], 64); err == nil {
				load = append(load, v)
			}
		}
		if len(load) > 0 {
			out["load"] = load
		}
	}
	// Top 进程：ps -eo pid,pcpu,pmem,comm --sort=-pcpu（表头行 Atoi 失败自然
	// 跳过；comm 可含空格，取第 4 列起的余串）——UI Top 进程表
	procs := []map[string]any{}
	for _, l := range section("TOP") {
		parts := strings.Fields(l)
		if len(parts) < 4 {
			continue
		}
		pid, e1 := strconv.Atoi(parts[0])
		cpu, e2 := strconv.ParseFloat(parts[1], 64)
		memP, e3 := strconv.ParseFloat(parts[2], 64)
		if e1 == nil && e2 == nil && e3 == nil {
			procs = append(procs, map[string]any{
				"pid": pid, "name": strings.Join(parts[3:], " "),
				"cpu": cpu, "mem": memP})
		}
	}
	if len(procs) > 0 {
		out["top_procs"] = procs
	}
	return out
}

// NodeActivity GET /api/nodes/exec/{id}/activity — 该主机相关的命令执行审计
// （agent_logs 中 kali_exec/run_script/kali_install 记录；按节点 host 字符串
// 过滤 content——蓝本同款弱匹配，节点名仅作 host 缺失时回退）。
func (a *API) NodeActivity(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil || id <= 0 {
		respondErr(w, http.StatusBadRequest, "invalid id")
		return
	}
	var name, host string
	if err := a.DB.QueryRow(`SELECT name, host FROM nodes WHERE id=?`, id).Scan(&name, &host); err != nil {
		respondErr(w, http.StatusNotFound, "节点不存在")
		return
	}
	match := host
	if match == "" {
		match = name
	}
	rows, err := a.DB.Query(
		`SELECT tool,content,created_at FROM agent_logs
		 WHERE tool IN ('kali_exec','run_script','kali_install')
		 ORDER BY id DESC LIMIT 200`)
	if err != nil {
		respondErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	defer rows.Close()
	type act struct {
		Tool string `json:"tool"`
		Cmd  string `json:"cmd"`
		Time string `json:"time"`
	}
	items := []act{}
	for rows.Next() {
		var tool, content, at string
		if err := rows.Scan(&tool, &content, &at); err != nil {
			break
		}
		if match != "" && !strings.Contains(content, match) {
			continue
		}
		items = append(items, act{Tool: tool, Cmd: truncateStr(content, 300), Time: at})
		if len(items) >= 50 {
			break
		}
	}
	respondJSON(w, http.StatusOK, map[string]any{"items": items})
}
