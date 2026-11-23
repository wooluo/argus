package store

// migrateKaliHosts 单测：kali_hosts → nodes 合并（原「渗透测试主机」域退役）。
import (
	"database/sql"
	"encoding/json"
	"testing"
)

func TestMigrateKaliHosts(t *testing.T) {
	db, err := Open(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()

	// 模拟老库升级：Open 已打标记，清掉重放（生产路径=旧库带着 kali_hosts
	// 遇到新版二进制）
	SetSetting(db, "kali_merged_v1", "")
	// 场景一：按 host 合并进现有节点
	seedNode(t, db, "kali", "10.211.55.4")
	// 场景二：无匹配 → 新增 offline 节点行
	// 场景三：host 为空的条目跳过；无 name 条目用 host 当名
	SetSetting(db, "kali_hosts", `[
		{"id":"kali-1","name":"Kali-主力机","host":"10.211.55.4","port":22,
		 "username":"wooluo","auth_type":"password","password":"secret-pw",
		 "sudo_password":"ignored","proxy":"","enabled":false,"primary":false},
		{"id":"ub-1","name":"ubuntu-box","host":"139.180.137.242","port":2222,
		 "username":"root","auth_type":"key","private_key_path":"/nonexistent/key","password":""},
		{"id":"bad","host":"","username":"x"}
	]`)

	migrateKaliHosts(db)

	// 合并：现有节点获得凭据，host 保持
	var conf string
	if err := db.QueryRow(`SELECT ssh_conf FROM nodes WHERE name='kali'`).Scan(&conf); err != nil {
		t.Fatalf("merged node not found: %v", err)
	}
	var c map[string]any
	if err := json.Unmarshal([]byte(conf), &c); err != nil {
		t.Fatalf("ssh_conf not JSON: %v", err)
	}
	for k, want := range map[string]any{
		"host": "10.211.55.4", "port": float64(22),
		"username": "wooluo", "auth_type": "password", "password": "secret-pw",
	} {
		if c[k] != want {
			t.Errorf("merged ssh_conf[%q] = %v, want %v", k, c[k], want)
		}
	}
	if _, has := c["sudo_password"]; has {
		t.Error("ssh_conf 不应包含 sudo_password（服务端从未消费）")
	}

	// 新增：offline 行 + key 认证（路径读不到 → 无 private_key 字段）
	var status string
	if err := db.QueryRow(`SELECT status FROM nodes WHERE name='ubuntu-box'`).Scan(&status); err != nil {
		t.Fatalf("new node not inserted: %v", err)
	}
	if status != "offline" {
		t.Errorf("new node status = %q, want offline", status)
	}
	if err := db.QueryRow(`SELECT ssh_conf FROM nodes WHERE name='ubuntu-box'`).Scan(&conf); err != nil {
		t.Fatal(err)
	}
	c = map[string]any{}
	_ = json.Unmarshal([]byte(conf), &c)
	if c["port"] != float64(2222) || c["username"] != "root" {
		t.Errorf("new node ssh_conf = %v", c)
	}
	if _, has := c["private_key"]; has {
		t.Error("读不到的私钥路径应丢弃 private_key 字段")
	}

	// 空条目不产生行
	var n int
	_ = db.QueryRow(`SELECT COUNT(*) FROM nodes`).Scan(&n)
	if n != 2 {
		t.Errorf("nodes count = %d, want 2", n)
	}

	// 备份与清空 + 标记
	if bak := GetSetting(db, "kali_hosts_backup_v1"); bak == "" || !json.Valid([]byte(bak)) {
		t.Error("kali_hosts_backup_v1 应保留原 JSON")
	}
	if GetSetting(db, "kali_hosts") != "" {
		t.Error("kali_hosts 应已清空")
	}
	if GetSetting(db, "kali_merged_v1") == "" {
		t.Error("kali_merged_v1 标记缺失")
	}

	// 幂等：二次运行 no-op（改回 kali_hosts 也不会再迁）
	SetSetting(db, "kali_hosts", `[{"host":"1.2.3.4"}]`)
	migrateKaliHosts(db)
	_ = db.QueryRow(`SELECT COUNT(*) FROM nodes`).Scan(&n)
	if n != 2 {
		t.Errorf("re-run migrated again: nodes = %d, want 2", n)
	}
}

func TestMigrateKaliHostsEmpty(t *testing.T) {
	db, err := Open(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()
	// 全新库：无 kali_hosts → 只打标记
	migrateKaliHosts(db)
	if GetSetting(db, "kali_merged_v1") == "" {
		t.Error("全新库也应打上迁移完成标记")
	}
	var n int
	_ = db.QueryRow(`SELECT COUNT(*) FROM nodes`).Scan(&n)
	if n != 0 {
		t.Errorf("全新库不应产生节点行, got %d", n)
	}
}

func seedNode(t *testing.T, db *sql.DB, name, host string) {
	t.Helper()
	if _, err := db.Exec(`INSERT INTO nodes(name,token,platform,status,last_seen,host)
		VALUES(?, '', '', 'online', '', ?)`, name, host); err != nil {
		t.Fatalf("seed node: %v", err)
	}
}
