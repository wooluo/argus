// intel.go: 运行中情报注入节点侧（蓝本 pipeline.submit_intel 的分布式版）。
// 任务执行期间后台 goroutine 每 5s 轮询 server 的 /api/nodes/intel 拉取操作员
// 提交的情报攒入本地队列；agent 循环每步 Drain 注入高优先级消息。
package main

import (
	"context"
	"encoding/json"
	"log"
	"strconv"
	"sync"
	"time"
)

// intelQueue agent.IntelQueue 实现：线程安全的待注入情报队列。
type intelQueue struct {
	mu   sync.Mutex
	list []string
}

func (q *intelQueue) push(items []string) {
	if len(items) == 0 {
		return
	}
	q.mu.Lock()
	q.list = append(q.list, items...)
	q.mu.Unlock()
}

// Drain 取出并清空队列。
func (q *intelQueue) Drain() []string {
	q.mu.Lock()
	defer q.mu.Unlock()
	out := q.list
	q.list = nil
	return out
}

// startIntelPoller 启动情报轮询（任务结束即停）；返回停止函数。
func startIntelPoller(taskID int64, q *intelQueue) (stop func()) {
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		t := time.NewTicker(5 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				code, body, err := call("GET",
					"/api/nodes/intel?task_id="+strconv.FormatInt(taskID, 10), nil)
				if err != nil || code != 200 {
					continue // 瞬时网络错误不致命
				}
				var items []string
				if json.Unmarshal(body, &items) == nil {
					for _, s := range items {
						log.Printf("[intel] 收到操作员情报: %.80s", s)
					}
					q.push(items)
				}
			}
		}
	}()
	return cancel
}
