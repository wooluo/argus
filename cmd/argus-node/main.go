// argus-node: 执行面（注册 → 心跳 → 轮询领任务 → 执行 → 回传）。
// 环境变量:
//
//	ARGUS_SERVER           服务器地址，默认 http://127.0.0.1:7887
//	ARGUS_NAME             节点名，默认 hostname
//	ARGUS_TOKEN            管理凭证，仅用于首次注册
//	ARGUS_NODE_TOKEN_FILE  节点 token 文件，默认 ~/.argus-node.json
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"sync/atomic"
	"syscall"
	"time"
)

var (
	serverURL string
	nodeName  string
	adminTok  string
	nodeTok   string
	nodeID    int64
	client    = &http.Client{Timeout: 30 * time.Second}
)

func main() {
	serverURL = envOr("ARGUS_SERVER", "http://127.0.0.1:7887")
	nodeName = envOr("ARGUS_NAME", defaultName())
	adminTok = os.Getenv("ARGUS_TOKEN")
	tokFile := envOr("ARGUS_NODE_TOKEN_FILE",
		filepath.Join(homeDir(), ".argus-node.json"))

	log.SetPrefix("[argus-node] ")
	log.Printf("server=%s name=%s", serverURL, nodeName)

	nodeTok = loadToken(tokFile)
	if nodeTok == "" {
		// 注册重试：server 未就绪/网络抖动不致命
		ok := false
		for i := 0; i < 10 && !ok; i++ {
			ok = registerAndSave(tokFile)
			if !ok {
				time.Sleep(3 * time.Second)
			}
		}
		if !ok {
			log.Fatalf("register failed: %s", serverURL)
		}
	}

	// 启动心跳失败不再 Fatal——server 可能在重启窗口（部署更新时节点会
	// 撞上 connection refused，自杀会让 systemd 循环重启且丢执行中任务）。
	// 改为无限重试直到 server 恢复。
	for !heartbeat() {
		if registerAndSave(tokFile) && heartbeat() {
			break
		}
		log.Printf("heartbeat rejected（server 重启中？5s 后重试）: %s", serverURL)
		time.Sleep(5 * time.Second)
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		t := time.NewTicker(15 * time.Second)
		defer t.Stop()
		var running atomic.Bool // 执行异步化：长任务不再阻塞心跳（否则界面显示离线）
		for range t.C {
			if !heartbeat() {
				_ = registerAndSave(tokFile)
			}
			if !running.CompareAndSwap(false, true) {
				continue // 上一个任务还在执行
			}
			go func() {
				defer running.Store(false)
				// 每次心跳后最多连做 3 个任务
				for i := 0; i < 3; i++ {
					if !pollAndRun() {
						break
					}
				}
			}()
		}
	}()

	log.Printf("running")
	<-stop
	log.Printf("shutting down")
}

// pollAndRun: 领一个任务并执行；true=领到了（可继续），false=无任务或出错。
func pollAndRun() bool {
	code, body, err := call("GET", fmt.Sprintf("/api/nodes/poll?node_id=%d", nodeID), nil)
	if err != nil || code != 200 {
		return false
	}
	var p pollTask
	if json.Unmarshal(body, &p) != nil || p.Task.TaskID == 0 {
		return false
	}
	log.Printf("task %d picked: %s (mode=%s)", p.Task.TaskID, p.Task.Name, p.Task.Mode)

	start := time.Now()
	res := execTask(&p)
	elapsed := time.Since(start).Seconds()

	payload := map[string]any{
		"task_id":  p.Task.TaskID,
		"status":   res.Status,
		"message":  fmt.Sprintf("%s（node %s, %.1fs）", res.Message, nodeName, elapsed),
		// 只发 progress 未上报过的增量（最终 result 全量会造成双写重复）
		"findings": res.Findings[minInt(res.Reported.Findings, len(res.Findings)):],
		"assets":   res.Assets[minInt(res.Reported.Assets, len(res.Assets)):],
		"logs":     res.Logs[minInt(res.Reported.Logs, len(res.Logs)):],
		"traffic":  res.Traffic[minInt(res.Reported.Traffic, len(res.Traffic)):],
	}
	if res.Report != "" {
		payload["report"] = res.Report
	}
	c, _, err := call("POST", "/api/nodes/result", payload)
	if err != nil || c != 200 {
		log.Printf("report result failed: %v (code=%d)", err, c)
	} else {
		log.Printf("task %d %s in %.1fs", p.Task.TaskID, res.Status, elapsed)
	}
	return true
}

// registerAndSave: 注册并把节点 token 落盘。
func registerAndSave(tokFile string) bool {
	payload := map[string]any{
		"name":         nodeName,
		"platform":     runtime.GOOS + "/" + runtime.GOARCH,
		"capabilities": []string{"recon"},
	}
	code, body, err := call("POST", "/api/nodes/register", payload)
	if err != nil || code != 201 {
		log.Printf("register: %v code=%d body=%s", err, code, string(body))
		return false
	}
	var res struct {
		NodeID int64  `json:"node_id"`
		Token  string `json:"token"`
	}
	if json.Unmarshal(body, &res) != nil || res.Token == "" {
		return false
	}
	nodeTok = res.Token
	nodeID = res.NodeID
	saveToken(tokFile, res.Token, res.NodeID)
	log.Printf("registered (node %d), token saved to %s", res.NodeID, tokFile)
	return true
}

func heartbeat() bool {
	code, _, err := call("POST", "/api/nodes/heartbeat", map[string]any{"node_id": nodeID})
	return err == nil && code == 200
}

func loadToken(f string) string {
	b, err := os.ReadFile(f)
	if err != nil {
		return ""
	}
	var saved struct {
		Token  string `json:"token"`
		NodeID int64  `json:"node_id"`
	}
	if json.Unmarshal(b, &saved) != nil {
		return ""
	}
	nodeID = saved.NodeID
	return saved.Token
}

func saveToken(f, token string, nodeID int64) {
	saved := struct {
		Token  string `json:"token"`
		NodeID int64  `json:"node_id"`
	}{token, nodeID}
	b, _ := json.MarshalIndent(saved, "", "  ")
	_ = os.WriteFile(f, b, 0o600)
}

// call: 统一 JSON 请求；注册端点用管理 token，其余用节点 token。
func call(method, path string, payload any) (int, []byte, error) {
	var rd io.Reader
	if payload != nil {
		b, _ := json.Marshal(payload)
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, serverURL+path, rd)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	tok := nodeTok
	if path == "/api/nodes/register" {
		tok = adminTok
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	return do(req)
}

func do(req *http.Request) (int, []byte, error) {
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	return resp.StatusCode, b, err
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func defaultName() string {
	h, err := os.Hostname()
	if err != nil {
		return "node"
	}
	return h
}

func homeDir() string {
	h, err := os.UserHomeDir()
	if err != nil {
		return "."
	}
	return h
}

func minInt(a, b int) int {
	if a > b {
		return b
	}
	return a
}
