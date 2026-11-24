// argus-server: 管理面（API + UI + SQLite + 调度）。
package main

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

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
	nodeAPI := &server.NodeAPI{DB: db, Bus: bus, NodeAuth: na, Admin: am, Tunnels: tunnels,
		Watchdog: server.NewWatchdog(db, bus)}
	go nodeAPI.Watchdog.Run(context.Background()) // 零策略看门狗：失联任务重排/代停、到点收卷
	h := server.NewRouter(a, bus, am, na, nodeAPI, cfg.StaticDir)

	log.Printf("argus-server listening on %s (data=%s, auth=%v)",
		cfg.ListenAddr, cfg.DataDir, cfg.Token != "")
	openBrowser(cfg.ListenAddr)
	log.Fatal(http.ListenAndServe(cfg.ListenAddr, h))
}

// openBrowser 在 server 就绪后打开系统默认浏览器（环境变量 ARGUS_NO_OPEN 可关闭）。
func openBrowser(addr string) {
	if os.Getenv("ARGUS_NO_OPEN") != "" {
		return
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		host, port = "127.0.0.1", strings.TrimLeft(addr, ":")
	}
	if port == "" || port == "0" {
		port = "7887"
	}
	url := fmt.Sprintf("http://%s", net.JoinHostPort(host, port))
	// 通配监听（0.0.0.0 / :port）改 127.0.0.1，否则浏览器打不开
	if host == "" || host == "0.0.0.0" {
		url = fmt.Sprintf("http://127.0.0.1:%s", port)
	}
	// 等 500ms 让 server 先完成端口绑定
	time.Sleep(500 * time.Millisecond)
	var cmd string
	var args []string
	switch runtime.GOOS {
	case "darwin":
		cmd, args = "open", []string{url}
	case "linux":
		cmd, args = "xdg-open", []string{url}
	case "windows":
		cmd, args = "cmd", []string{"/c", "start", url}
	default:
		return
	}
	if err := exec.Command(cmd, args...).Start(); err != nil {
		log.Printf("打开浏览器失败: %v（设置 ARGUS_NO_OPEN=1 关闭此行为）", err)
	}
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
