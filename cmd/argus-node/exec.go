// exec.go: argus-node 任务执行——Poll 拿到的任务经 pipeline 执行并回传。
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/url"

	"github.com/wooluo/argus/internal/llm"
	"github.com/wooluo/argus/internal/pipeline"
	"github.com/wooluo/argus/internal/scope"
	"github.com/wooluo/argus/internal/tools"
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
	VerifyFindings  bool   `json:"verify_findings"`  // 收工后独立核验（设置 limits.autonomous_verify）
	TimeBudget      struct {
		RemainingSeconds int `json:"remaining_seconds"` // 领取时刻的剩余秒数（0=不限时）
		LimitSeconds     int `json:"limit_seconds"`     // 总时长上限
	} `json:"time_budget"` // 时间预算：到点由 server 看门狗代停
	// 分层用脑：按角色的模型配置（设置页「模型分工」）；没分工的角色不出现
	Models map[string]struct {
		BaseURL string `json:"base_url"`
		APIKey  string `json:"api_key"`
		Model   string `json:"model"`
		Proxy   string `json:"proxy"`
	} `json:"models"`
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
	b.VerifyFindings = p.VerifyFindings
	b.TimeBudgetSeconds = p.TimeBudget.RemainingSeconds
	b.TimeLimitSeconds = p.TimeBudget.LimitSeconds
	// 分层用脑：分工给「主循环」的模型覆盖主配置，另两类各自下发
	roleCfg := func(role string) llm.Config {
		c, ok := p.Models[role]
		if !ok || c.BaseURL == "" {
			return llm.Config{}
		}
		return llm.Config{BaseURL: c.BaseURL, APIKey: c.APIKey, Model: c.Model, Proxy: c.Proxy}
	}
	if c := roleCfg("hunt"); c.BaseURL != "" {
		b.LLM = c
	}
	b.LLMReview, b.LLMAux = roleCfg("review"), roleCfg("aux")
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
	// 知识条目全文拉取（knowledge_get 用）：任务书只带索引，命中后回连 server
	brief.KnowledgeFetch = knowledgeFetch(brief.TaskID)
	// 增量上报：节流与重发由 pipeline 的 flusher 负责（≥5s 一次、server 确认
	// 后才推进游标、失败下个周期重发）——这里只管发并如实返回成败
	onFlush := func(inc pipeline.Result) error {
		payload := map[string]any{
			"task_id":   brief.TaskID,
			"findings":  inc.Findings,
			"assets":    inc.Assets,
			"logs":      inc.Logs,
			"traffic":   inc.Traffic,
			"knowledge": inc.Knowledge,
			// 运行中被改过状态、补充过步骤或说明的发现（尽力而为；收尾有全量对账兜底）
			"finding_updates": inc.FindingUpdates,
		}
		code, _, err := call("POST", "/api/nodes/progress", payload)
		if err != nil || code != 200 {
			log.Printf("progress flush deferred (code=%d err=%v)", code, err)
			return fmt.Errorf("code=%d err=%v", code, err)
		}
		return nil
	}
	log.Printf("[exec] task=%d name=%s mode=%s project=%d → pipeline",
		p.Task.TaskID, p.Task.Name, p.Task.Mode, p.Task.ProjectID)
	return pipeline.Run(execCtx, brief, onFlush)
}

// knowledgeFetch 按需拉取知识条目全文：回连 server 的节点面接口，由 server
// 按 task_id 判定该条目对本项目是否可见（别的项目的专属条目拿不到）。
func knowledgeFetch(taskID int64) tools.KnowledgeFetcher {
	return func(id string) (string, error) {
		code, body, err := call("GET",
			fmt.Sprintf("/api/nodes/knowledge/%s?task_id=%d", url.PathEscape(id), taskID), nil)
		if err != nil || code != 200 {
			return "", fmt.Errorf("server 返回 code=%d err=%v", code, err)
		}
		var res struct {
			Title   string `json:"title"`
			Content string `json:"content"`
		}
		if json.Unmarshal(body, &res) != nil || res.Content == "" {
			return "", errors.New("条目不存在或响应无法解析")
		}
		return "# " + res.Title + "\n\n" + res.Content, nil
	}
}
