// Package intel: 运行中情报的内存中转（蓝本 pipeline.submit_intel 的分布式版）。
// 管理面（api.SubmitIntel）Push → 节点面（server NodeIntel）按任务 Drain 拉走 →
// agent 循环注入。仅存活于 server 进程内：任务停止/重启后队列即弃
// （持久情报走 project_intel 表）。
package intel

import "sync"

var (
	mu    sync.Mutex
	queue = map[int64][]string{}
)

// Push 向指定任务追加情报（操作员在会话页提交）。
func Push(taskID int64, content string) {
	mu.Lock()
	defer mu.Unlock()
	queue[taskID] = append(queue[taskID], content)
	if len(queue[taskID]) > 100 {
		queue[taskID] = queue[taskID][len(queue[taskID])-100:]
	}
}

// Drain 取出并清空指定任务的待注入情报（节点轮询调用）。
func Drain(taskID int64) []string {
	mu.Lock()
	defer mu.Unlock()
	out := queue[taskID]
	delete(queue, taskID)
	return out
}

// Discard 丢弃指定任务的全部待注入情报（任务结束时兜底清理）。
func Discard(taskID int64) {
	mu.Lock()
	defer mu.Unlock()
	delete(queue, taskID)
}
