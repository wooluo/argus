// argus-server: 管理面（API + UI + SQLite + 调度）。
package main

import (
	"database/sql"
	"log"
	"net/http"
	"os"

	"github.com/wooluo/argus/internal/api"
	"github.com/wooluo/argus/internal/auth"
	"github.com/wooluo/argus/internal/config"
	"github.com/wooluo/argus/internal/events"
	"github.com/wooluo/argus/internal/server"
	"github.com/wooluo/argus/internal/store"
)

func main() {
	cfg := config.Load()
	if err := os.MkdirAll(cfg.DataDir, 0o755); err != nil {
		log.Fatalf("mkdir %s: %v", cfg.DataDir, err)
	}
	db, err := store.Open(cfg.DBPath)
	if err != nil {
		log.Fatalf("open db: %v", err)
	}
	defer db.Close()

	bus := events.NewBus()
	am := auth.New(cfg.Token)
	na := auth.NewNodeAuth()
	seedNodeAuth(db, na) // 重启后从 DB 恢复节点 token

	// v0: Runner=nil，任务由 argus-node 领取执行（StartTask 检查 nil）
	a := &api.API{DB: db, Bus: bus, Auth: am}
	tunnels := server.NewTunnelManager()
	go tunnels.Restore(db) // 重启后按节点表存的 SSH 凭据恢复隧道回连
	nodeAPI := &server.NodeAPI{DB: db, Bus: bus, NodeAuth: na, Admin: am, Tunnels: tunnels}
	h := server.NewRouter(a, bus, am, na, nodeAPI, cfg.StaticDir)

	log.Printf("argus-server listening on %s (data=%s, auth=%v)",
		cfg.ListenAddr, cfg.DataDir, cfg.Token != "")
	log.Fatal(http.ListenAndServe(cfg.ListenAddr, h))
}

// seedNodeAuth: 节点 token 持久化在 nodes 表，重启后重载进内存鉴权表。
func seedNodeAuth(db *sql.DB, na *auth.NodeAuth) {
	rows, err := db.Query(`SELECT id, token FROM nodes`)
	if err != nil {
		return
	}
	defer rows.Close()
	n := 0
	for rows.Next() {
		var id int64
		var tok string
		if err := rows.Scan(&id, &tok); err == nil {
			na.Set(tok, id)
			n++
		}
	}
	if n > 0 {
		log.Printf("restored %d node token(s)", n)
	}
}
