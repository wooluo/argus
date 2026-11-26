package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/wooluo/argus/internal/api"
	"github.com/wooluo/argus/internal/deploy"
	"github.com/wooluo/argus/internal/events"
)

// 「编辑 → 重新部署」回归：弹窗只带出主机和节点名、用户名还是默认的 root，
// 拿节点的密码去登 root，远端直接拒绝（unable to authenticate）。现在连接
// 参数随节点列表下发，密码留空时沿用该节点已保存的。
func TestReuseSavedSecret(t *testing.T) {
	db := openTestDB(t)
	saved := `{"host":"10.211.55.4","port":2222,"username":"wooluo","auth_type":"password","password":"pw-kali","node_token":"argus-node-auto"}`
	if _, err := db.Exec(`INSERT INTO nodes(name,token,platform,ssh_conf) VALUES('kali','tok','',?)`, saved); err != nil {
		t.Fatal(err)
	}
	base := func() deploy.SSHConfig {
		return deploy.SSHConfig{Host: "10.211.55.4", Port: 22, Username: "wooluo",
			AuthType: "password", NodeName: "kali"}
	}

	cases := []struct {
		name   string
		mutate func(*deploy.SSHConfig)
		want   string // 沿用后的密码
	}{
		{"主机用户名没变、密码留空 → 沿用", func(c *deploy.SSHConfig) {}, "pw-kali"},
		{"自己填了密码 → 不动", func(c *deploy.SSHConfig) { c.Password = "typed" }, "typed"},
		{"换了用户名 → 不沿用", func(c *deploy.SSHConfig) { c.Username = "root" }, ""},
		{"换了主机 → 不沿用", func(c *deploy.SSHConfig) { c.Host = "10.0.0.9" }, ""},
		{"换了认证方式 → 不沿用", func(c *deploy.SSHConfig) { c.AuthType = "key" }, ""},
	}
	for _, c := range cases {
		req := base()
		c.mutate(&req)
		reuseSavedSecret(db, &req)
		if req.Password != c.want {
			t.Errorf("%s：密码 = %q，应为 %q", c.name, req.Password, c.want)
		}
	}

	req := base()
	req.NodeName = "never-deployed"
	reuseSavedSecret(db, &req)
	if req.Password != "" {
		t.Errorf("没有保存记录的节点不应凭空得到密码，得到 %q", req.Password)
	}
}

// 节点列表把已保存的连接参数带给前端，但密码 / 私钥不能跟着出去。
func TestListNodesExposesSSHParamsNotSecrets(t *testing.T) {
	db := openTestDB(t)
	if _, err := db.Exec(`INSERT INTO nodes(name,token,platform,ssh_conf) VALUES('kali','tok','',
		'{"host":"10.211.55.4","port":2222,"username":"wooluo","auth_type":"key","password":"pw-kali","private_key":"PEM-SECRET"}')`); err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	(&NodeAPI{DB: db}).ListNodes(rec, httptest.NewRequest(http.MethodGet, "/api/nodes", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("状态码 %d: %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "pw-kali") || strings.Contains(rec.Body.String(), "PEM-SECRET") {
		t.Fatalf("节点列表泄露了密码或私钥: %s", rec.Body.String())
	}
	var rows []struct {
		Name    string `json:"name"`
		HasSSH  bool   `json:"has_ssh"`
		SSHPort int    `json:"ssh_port"`
		SSHUser string `json:"ssh_user"`
		SSHAuth string `json:"ssh_auth"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &rows); err != nil || len(rows) != 1 {
		t.Fatalf("解析节点列表失败: %v %s", err, rec.Body.String())
	}
	r := rows[0]
	if !r.HasSSH || r.SSHPort != 2222 || r.SSHUser != "wooluo" || r.SSHAuth != "key" {
		t.Fatalf("连接参数不对: %+v", r)
	}
}

// 节点随心跳上报工具状态：设置页「工具链状态」按节点看的就是这份。有变化才
// 落库；旧版节点的心跳不带工具字段，不能报错，也不能把已有状态清掉。
func TestHeartbeatStoresNodeTools(t *testing.T) {
	db := openTestDB(t)
	if _, err := db.Exec(`INSERT INTO nodes(name,token,platform,status) VALUES('kali','tok','','offline')`); err != nil {
		t.Fatal(err)
	}
	hb := func(body string) {
		rec := httptest.NewRecorder()
		(&NodeAPI{DB: db, Bus: events.NewBus()}).Heartbeat(rec,
			httptest.NewRequest(http.MethodPost, "/api/nodes/heartbeat", strings.NewReader(body)))
		if rec.Code != http.StatusOK {
			t.Fatalf("心跳 %d: %s", rec.Code, rec.Body.String())
		}
	}
	status := `[{"name":"subfinder","kind":"adapter","binary":"subfinder","available":false,"fallback_for":"无兜底","exec_at":"local"}]`
	hb(`{"node_id":1,"tools":` + status + `}`)
	var raw, at string
	if err := db.QueryRow(`SELECT tools,tools_at FROM nodes WHERE id=1`).Scan(&raw, &at); err != nil {
		t.Fatal(err)
	}
	if raw != status || at == "" {
		t.Fatalf("工具状态没落库: tools=%q at=%q", raw, at)
	}

	hb(`{"node_id":1}`) // 旧版节点
	if err := db.QueryRow(`SELECT tools,tools_at FROM nodes WHERE id=1`).Scan(&raw, &at); err != nil || raw != status {
		t.Fatalf("旧版节点的心跳把工具状态弄丢了: %q %v", raw, err)
	}

	nodes := api.NodeToolStatus(db)
	if len(nodes) != 1 || nodes[0]["name"] != "kali" {
		t.Fatalf("节点工具状态 = %v", nodes)
	}
	tools, _ := nodes[0]["tools"].([]map[string]any)
	if len(tools) != 1 || tools[0]["exec_at"] != "node" || tools[0]["available"] != false {
		t.Fatalf("节点上报的行应标成 node 且保留可用性: %v", tools)
	}
}
