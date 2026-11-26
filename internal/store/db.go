// Package store: SQLite 存储（modernc.org/sqlite，纯 Go 无 CGO）。
// schema 对齐原 AutoPentest models.py 的 11 张表 + Argus 新增 nodes 表。
package store

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	_ "modernc.org/sqlite"
)

func Open(path string) (*sql.DB, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fmt.Errorf("create data dir: %w", err)
	}
	dsn := fmt.Sprintf("file:%s?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)", path)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	// modernc sqlite 安全并发写：单写连接
	db.SetMaxOpenConns(1)
	if err := migrate(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrate: %w", err)
	}
	migrateKaliHosts(db)
	return db, nil
}

// migrateKaliHosts 一次性迁移：settings['kali_hosts']（渗透测试主机池，Python
// 蓝本遗留）并入 nodes 表——节点成为唯一主机档案，SSH 观测凭据落 ssh_conf
// 列。按 host 匹配现有节点合并凭据，无匹配则新增 offline 节点行；原值备份
// 到 kali_hosts_backup_v1 后清空，kali_merged_v1 标记防重跑（失败静默——
// 下次启动重试，迁移失败不阻塞启动）。
func migrateKaliHosts(db *sql.DB) {
	if GetSetting(db, "kali_merged_v1") != "" {
		return
	}
	raw := GetSetting(db, "kali_hosts")
	if raw == "" {
		SetSetting(db, "kali_merged_v1", Now())
		return
	}
	var hosts []map[string]any
	if err := json.Unmarshal([]byte(raw), &hosts); err != nil || len(hosts) == 0 {
		SetSetting(db, "kali_merged_v1", Now()) // 非法/空——标记完成防反复尝试
		return
	}
	for _, h := range hosts {
		host, _ := h["host"].(string)
		host = strings.TrimSpace(host)
		if host == "" {
			continue
		}
		// ssh_conf 只收服务端真实消费的字段；sudo_password/proxy/enabled/
		// primary 从未被 Go 侧读过，迁移即退役
		conf := map[string]any{"host": host, "port": 22, "username": "kali", "auth_type": "password"}
		if p, ok := h["port"].(float64); ok && p > 0 && p < 65536 {
			conf["port"] = int(p)
		}
		if u, ok := h["username"].(string); ok && u != "" {
			conf["username"] = u
		}
		if at, ok := h["auth_type"].(string); ok && (at == "password" || at == "key") {
			conf["auth_type"] = at
		}
		if pw, ok := h["password"].(string); ok && pw != "" {
			conf["password"] = pw
		}
		// private_key_path 是 server 本地路径——尽力读入内容（读不到丢弃）
		if kp, ok := h["private_key_path"].(string); ok && kp != "" {
			if b, err := os.ReadFile(kp); err == nil {
				conf["private_key"] = string(b)
			}
		}
		b, _ := json.Marshal(conf)
		var id int64
		err := db.QueryRow(`SELECT id FROM nodes WHERE host=? ORDER BY id LIMIT 1`, host).Scan(&id)
		if err == nil {
			_, _ = db.Exec(`UPDATE nodes SET ssh_conf=? WHERE id=?`, string(b), id)
			continue
		}
		// 无匹配 → 新增 offline 节点行；name 取条目名，为空/撞名回退 host
		name, _ := h["name"].(string)
		if name == "" {
			name = host
		}
		var n int
		_ = db.QueryRow(`SELECT COUNT(*) FROM nodes WHERE name=?`, name).Scan(&n)
		if n > 0 {
			name = host
			_ = db.QueryRow(`SELECT COUNT(*) FROM nodes WHERE name=?`, name).Scan(&n)
			if n > 0 {
				name = fmt.Sprintf("%s-%s", host, Now())
			}
		}
		_, _ = db.Exec(`INSERT INTO nodes(name,token,platform,status,last_seen,host,ssh_conf)
			VALUES(?, '', '', 'offline', '', ?, ?)`, name, host, string(b))
	}
	SetSetting(db, "kali_hosts_backup_v1", raw)
	SetSetting(db, "kali_hosts", "")
	SetSetting(db, "kali_merged_v1", Now())
}

func migrate(db *sql.DB) error {
	for _, stmt := range migrations {
		if _, err := db.Exec(stmt); err != nil {
			return fmt.Errorf("%w\nSQL: %.120s", err, stmt)
		}
	}
	// 增量补列（老库升级）：重复执行时报 duplicate column，幂等忽略。
	for _, stmt := range alters {
		_, _ = db.Exec(stmt)
	}
	// 数据修复（幂等）：资产的 detail 曾被写成空串——不是合法 JSON，接口把
	// 整个资产列表转成 JSON 时失败、响应体为空，资产中心整页空白。
	if _, err := db.Exec(`UPDATE assets SET detail='{}' WHERE detail=''`); err != nil {
		return fmt.Errorf("fix assets.detail: %w", err)
	}
	return nil
}

var alters = []string{
	`ALTER TABLE tasks ADD COLUMN continue_from INTEGER NOT NULL DEFAULT 0`,
	`ALTER TABLE tasks ADD COLUMN retries INTEGER NOT NULL DEFAULT 0`, // 看门狗重排次数
	`ALTER TABLE nodes ADD COLUMN host TEXT NOT NULL DEFAULT ''`,
	`ALTER TABLE nodes ADD COLUMN last_deploy TEXT NOT NULL DEFAULT ''`,
	`ALTER TABLE nodes ADD COLUMN tunnel_ssh TEXT NOT NULL DEFAULT ''`,
	`ALTER TABLE nodes ADD COLUMN ssh_conf TEXT NOT NULL DEFAULT ''`,
	`ALTER TABLE nodes ADD COLUMN tools TEXT NOT NULL DEFAULT ''`,    // 节点心跳上报的工具状态 JSON
	`ALTER TABLE nodes ADD COLUMN tools_at TEXT NOT NULL DEFAULT ''`, // 最近一次上报时间
}

var migrations = []string{
	`CREATE TABLE IF NOT EXISTS projects (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT NOT NULL,
		description TEXT NOT NULL DEFAULT '',
		scope TEXT NOT NULL DEFAULT '[]',
		authorized INTEGER NOT NULL DEFAULT 0,
		allow_hosts TEXT NOT NULL DEFAULT '[]',
		created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
	)`,
	`CREATE TABLE IF NOT EXISTS tasks (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		project_id INTEGER NOT NULL,
		name TEXT NOT NULL DEFAULT '',
		status TEXT NOT NULL DEFAULT 'pending',
		mode TEXT NOT NULL DEFAULT 'autonomous',
		current_stage TEXT NOT NULL DEFAULT '',
		tokens TEXT NOT NULL DEFAULT '{}',
		stages_done TEXT NOT NULL DEFAULT '[]',
		message TEXT NOT NULL DEFAULT '',
		created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
		started_at TEXT,
		finished_at TEXT,
		node_id INTEGER NOT NULL DEFAULT 0,
		assigned_at TEXT
	)`,
	`CREATE INDEX IF NOT EXISTS idx_tasks_project ON tasks(project_id)`,
	`CREATE TABLE IF NOT EXISTS assets (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		project_id INTEGER NOT NULL,
		type TEXT NOT NULL,
		value TEXT NOT NULL,
		detail TEXT NOT NULL DEFAULT '{}',
		source TEXT NOT NULL DEFAULT '',
		created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
	)`,
	`CREATE INDEX IF NOT EXISTS idx_assets_project ON assets(project_id)`,
	`CREATE INDEX IF NOT EXISTS idx_assets_type ON assets(type)`,
	`CREATE INDEX IF NOT EXISTS idx_assets_value ON assets(value)`,
	`CREATE TABLE IF NOT EXISTS findings (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		project_id INTEGER NOT NULL,
		name TEXT NOT NULL,
		severity TEXT NOT NULL DEFAULT 'info',
		target TEXT NOT NULL DEFAULT '',
		detail TEXT NOT NULL DEFAULT '',
		evidence TEXT NOT NULL DEFAULT '',
		poc TEXT NOT NULL DEFAULT '',
		status TEXT NOT NULL DEFAULT 'pending',
		read_at TEXT,
		source TEXT NOT NULL DEFAULT '',
		created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
	)`,
	`CREATE INDEX IF NOT EXISTS idx_findings_project ON findings(project_id)`,
	`CREATE TABLE IF NOT EXISTS agent_logs (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		task_id INTEGER NOT NULL,
		stage TEXT NOT NULL DEFAULT '',
		type TEXT NOT NULL,
		tool TEXT NOT NULL DEFAULT '',
		args TEXT NOT NULL DEFAULT '{}',
		content TEXT NOT NULL DEFAULT '',
		result_summary TEXT NOT NULL DEFAULT '',
		created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
	)`,
	`CREATE INDEX IF NOT EXISTS idx_agent_logs_task ON agent_logs(task_id)`,
	`CREATE TABLE IF NOT EXISTS reports (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		project_id INTEGER NOT NULL,
		task_id INTEGER NOT NULL DEFAULT 0,
		markdown TEXT NOT NULL DEFAULT '',
		created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
	)`,
	`CREATE TABLE IF NOT EXISTS project_intel (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		project_id INTEGER NOT NULL,
		content TEXT NOT NULL,
		source TEXT NOT NULL DEFAULT 'intel',
		created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
	)`,
	`CREATE TABLE IF NOT EXISTS finding_steps (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		finding_id INTEGER NOT NULL,
		project_id INTEGER NOT NULL,
		seq INTEGER NOT NULL DEFAULT 1,
		note TEXT NOT NULL DEFAULT '',
		request TEXT NOT NULL DEFAULT '',
		response TEXT NOT NULL DEFAULT '',
		conclusion TEXT NOT NULL DEFAULT '',
		created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
	)`,
	`CREATE INDEX IF NOT EXISTS idx_finding_steps_finding ON finding_steps(finding_id)`,
	`CREATE TABLE IF NOT EXISTS traffic_logs (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		project_id INTEGER NOT NULL,
		task_id INTEGER NOT NULL DEFAULT 0,
		method TEXT NOT NULL DEFAULT 'GET',
		url TEXT NOT NULL DEFAULT '',
		request_body TEXT NOT NULL DEFAULT '',
		status INTEGER NOT NULL DEFAULT 0,
		response_snippet TEXT NOT NULL DEFAULT '',
		source_tool TEXT NOT NULL DEFAULT '',
		created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
	)`,
	`CREATE TABLE IF NOT EXISTS repeater_logs (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		project_id INTEGER NOT NULL,
		method TEXT NOT NULL DEFAULT 'GET',
		url TEXT NOT NULL DEFAULT '',
		request_body TEXT NOT NULL DEFAULT '',
		headers TEXT NOT NULL DEFAULT '',
		cookies TEXT NOT NULL DEFAULT '',
		status INTEGER NOT NULL DEFAULT 0,
		response_snippet TEXT NOT NULL DEFAULT '',
		source TEXT NOT NULL DEFAULT 'manual',
		origin_traffic_id INTEGER NOT NULL DEFAULT 0,
		created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
	)`,
	`CREATE TABLE IF NOT EXISTS approvals (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		task_id INTEGER NOT NULL,
		project_id INTEGER NOT NULL DEFAULT 0,
		tool TEXT NOT NULL,
		args TEXT NOT NULL DEFAULT '{}',
		reason TEXT NOT NULL DEFAULT '',
		status TEXT NOT NULL DEFAULT 'pending',
		decided_by TEXT NOT NULL DEFAULT '',
		created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
		decided_at TEXT
	)`,
	// ---- Argus 新增 ----
	`CREATE TABLE IF NOT EXISTS nodes (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT NOT NULL UNIQUE,
		token TEXT NOT NULL,
		capabilities TEXT NOT NULL DEFAULT '[]',
		platform TEXT NOT NULL DEFAULT '',
		hostname TEXT NOT NULL DEFAULT '',
		version TEXT NOT NULL DEFAULT '',
		tags TEXT NOT NULL DEFAULT '[]',
		status TEXT NOT NULL DEFAULT 'offline',
		last_seen TEXT NOT NULL DEFAULT '',
		created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
	)`,
	`CREATE TABLE IF NOT EXISTS node_jobs (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		node_id INTEGER NOT NULL,
		task_id INTEGER NOT NULL DEFAULT 0,
		tool TEXT NOT NULL DEFAULT '',
		args TEXT NOT NULL DEFAULT '{}',
		status TEXT NOT NULL DEFAULT 'queued',
		result TEXT NOT NULL DEFAULT '',
		error TEXT NOT NULL DEFAULT '',
		created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
		finished_at TEXT
	)`,
	`CREATE INDEX IF NOT EXISTS idx_node_jobs_node ON node_jobs(node_id, status)`,
	`CREATE TABLE IF NOT EXISTS settings (
		key TEXT PRIMARY KEY,
		value TEXT NOT NULL DEFAULT '{}'
	)`,
	`INSERT OR IGNORE INTO settings(key, value) VALUES ('llm', '{}')`,
	`INSERT OR IGNORE INTO settings(key, value) VALUES ('auth', '{}')`,
}

// GetSetting 读 settings 表；不存在返回空串。
func GetSetting(db *sql.DB, key string) string {
	var v string
	_ = db.QueryRow(`SELECT value FROM settings WHERE key=?`, key).Scan(&v)
	return v
}

// SetSetting 写 settings 表（UPSERT；对应原 settings.json 的键级保存）。
func SetSetting(db *sql.DB, key, value string) error {
	_, err := db.Exec(`INSERT INTO settings(key,value) VALUES(?,?)
		ON CONFLICT(key) DO UPDATE SET value=excluded.value`, key, value)
	return err
}
