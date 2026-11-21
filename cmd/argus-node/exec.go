// exec.go: argus-node 任务执行——Poll 拿到的任务经 pipeline 执行并回传。
package main

import (
	"context"
	"encoding/json"
	"log"
	"time"

	"github.com/wooluo/argus/internal/pipeline"
	"github.com/wooluo/argus/internal/scope"
)

// pollTask Poll 响应（扩展后含 project 概要与 llm 配置）。
type pollTask struct {
	Task struct {
		TaskID    int    `json:"id"`
		Name      string `json:"name"`
		Mode      string `json:"mode"`
		ProjectID int    `json:"project_id"`
	} `json:"task"`
	Project struct {
		Name        string          `json:"name"`
		Description string          `json:"description"`
		Scope       json.RawMessage `json:"scope"`
		AllowHosts  json.RawMessage `json:"allow_hosts"`
	} `json:"project"`
	LLM struct {
		BaseURL string `json:"base_url"`
		APIKey  string `json:"api_key"`
		Model   string `json:"model"`
		Proxy   string `json:"proxy"`
	} `json:"llm"`
	Knowledge        string      `json:"knowledge"`         // server 注入的知识库块
	ApprovalsRequire []string    `json:"approvals_require"` // HITL 审批名单（空=无审批）
	Intel            []string    `json:"intel"`             // 项目情报（跨任务持久）
	Skills           string      `json:"skills"`            // 启用的 Skill 领域知识块
	MCP              []mcpServer `json:"mcp"`               // 启用的 MCP 服务器（动态注入工具）
	Agent            struct {
		Prompt   string `json:"prompt"`    // hunt 角色自定义系统提示词
		MaxSteps int    `json:"max_steps"` // 步数预算覆盖（0=默认）
	} `json:"agent"`
	FOFA struct {
		Email string `json:"email"`
		Key   string `json:"key"`
	} `json:"fofa"`
	ContinueSummary string `json:"continue_summary"` // 断点续测：上轮成果摘要
}

// buildBrief 从 Poll 响应组装 pipeline.Brief。
func (p *pollTask) buildBrief() pipeline.Brief {
	var b pipeline.Brief
	b.TaskID = int64(p.Task.TaskID)
	b.Mode = p.Task.Mode
	b.ProjectID = int64(p.Task.ProjectID)
	b.ProjectName = p.Project.Name
	b.Description = p.Project.Description
	_ = json.Unmarshal(p.Project.Scope, &b.Scope)
	if len(p.Project.AllowHosts) > 0 {
		// allow_hosts 兼容 [{type,value}] 与 ["host"] 两种形态
		var rules []scope.Rule
		if json.Unmarshal(p.Project.AllowHosts, &rules) == nil && len(rules) > 0 {
			for _, r := range rules {
				b.AllowHosts = append(b.AllowHosts, r.Value)
			}
		} else {
			_ = json.Unmarshal(p.Project.AllowHosts, &b.AllowHosts)
		}
	}
	b.LLM.BaseURL = p.LLM.BaseURL
	b.LLM.APIKey = p.LLM.APIKey
	b.LLM.Model = p.LLM.Model
	b.LLM.Proxy = p.LLM.Proxy
	b.Knowledge = p.Knowledge
	b.ApprovalsRequire = p.ApprovalsRequire
	b.Intel = p.Intel
	b.Skills = p.Skills
	b.AgentPrompt = p.Agent.Prompt
	b.AgentMaxSteps = p.Agent.MaxSteps
	b.FOFAEmail = p.FOFA.Email
	b.FOFAKey = p.FOFA.Key
	b.ContinueSummary = p.ContinueSummary
	return b
}

// execTask 真执行：pipeline.Run → 结果由调用方经 /api/nodes/result 回传。
// 增量上报走 onFlush（≥5s 节流；失败不致命，最终 result 兜底）。
func execTask(p *pollTask) *pipeline.Result {
	brief := p.buildBrief()
	// HITL 审批门：经 server HTTP 回连（名单命中时写 pending + 轮询人工决定）
	brief.ApprovalGate = approvalGate{taskID: brief.TaskID, projectID: brief.ProjectID}
	// 运行中情报：后台轮询 server 攒队列，agent 每步 Drain；
	// 轮询同时探测任务停止（server 标记 stopped → 5s 内取消执行）
	iq := &intelQueue{}
	brief.IntelQueue = iq
	execCtx, cancelExec := context.WithCancel(context.Background())
	defer cancelExec()
	stopIntel := startIntelPoller(brief.TaskID, iq, cancelExec)
	defer stopIntel()
	// MCP 动态工具注入（启用的服务器 → 全局 Registry，agent 即刻可用）
	if n := registerMCPTools(p.MCP); n > 0 {
		log.Printf("[exec] task=%d MCP 注入 %d 个工具", p.Task.TaskID, n)
	}
	var lastFlush time.Time
	onFlush := func(inc pipeline.Result) {
		if time.Since(lastFlush) < 5*time.Second {
			return
		}
		lastFlush = time.Now()
		payload := map[string]any{
			"task_id":  brief.TaskID,
			"findings": inc.Findings,
			"assets":   inc.Assets,
			"logs":     inc.Logs,
			"traffic":  inc.Traffic,
		}
		if code, _, err := call("POST", "/api/nodes/progress", payload); err != nil || code != 200 {
			log.Printf("progress flush skipped (code=%d err=%v)", code, err)
		}
	}
	log.Printf("[exec] task=%d name=%s mode=%s project=%d → pipeline",
		p.Task.TaskID, p.Task.Name, p.Task.Mode, p.Task.ProjectID)
	return pipeline.Run(execCtx, brief, onFlush)
}
