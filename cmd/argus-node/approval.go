// approval.go: HITL 审批门节点端实现——经 server HTTP 写 pending 并轮询决定
// （蓝本 core/approvals.py request_approval 的分布式版：审批表在 server SQLite，
// 节点无法直连库，走 /api/nodes/approvals 回连）。
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"time"
)

// approvalWait 等待人工决定的最长时间；超时视为拒绝（与蓝本默认 600s 一致）。
const approvalWait = 600 * time.Second

// approvalGate 经 server HTTP 的 agent.ApprovalGate 实现。
// Request: POST 创建 pending → 每 3s 轮询决定 → approved/denied/超时。
// 创建失败 fail-closed 直接拒绝（审批服务不可达时不能放行高危工具）。
type approvalGate struct {
	taskID    int64
	projectID int64
}

func (g approvalGate) Request(ctx context.Context, tool string, args map[string]any, purpose string) bool {
	payload := map[string]any{
		"task_id":    g.taskID,
		"project_id": g.projectID,
		"tool":       tool,
		"args":       args,
		"reason":     purpose,
	}
	code, body, err := call("POST", "/api/nodes/approvals", payload)
	if err != nil || (code != 200 && code != 201) {
		log.Printf("[approval] 创建审批失败 tool=%s code=%d err=%v → 按拒绝处理", tool, code, err)
		return false
	}
	var res struct {
		ID int64 `json:"id"`
	}
	if json.Unmarshal(body, &res) != nil || res.ID == 0 {
		log.Printf("[approval] 响应异常: %s", string(body))
		return false
	}
	log.Printf("[approval] #%d pending: %s（等待人工决定，最长 %s）", res.ID, tool, approvalWait)

	deadline := time.Now().Add(approvalWait)
	for {
		switch g.poll(res.ID) {
		case "approved":
			log.Printf("[approval] #%d 已批准", res.ID)
			return true
		case "denied":
			log.Printf("[approval] #%d 已拒绝", res.ID)
			return false
		}
		if time.Now().After(deadline) {
			log.Printf("[approval] #%d 等待超时 → 拒绝", res.ID)
			return false // server 下次 GET 轮询时落库 timeout 拒绝
		}
		select {
		case <-ctx.Done():
			return false
		case <-time.After(3 * time.Second):
		}
	}
}

// poll 单次查询审批状态；网络抖动返回空串（下轮重试）。
func (g approvalGate) poll(id int64) string {
	code, body, err := call("GET", fmt.Sprintf("/api/nodes/approvals/%d", id), nil)
	if err != nil || code != 200 {
		return ""
	}
	var s struct {
		Status string `json:"status"`
	}
	_ = json.Unmarshal(body, &s)
	return s.Status
}
