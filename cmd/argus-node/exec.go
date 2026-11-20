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
	return b
}

// execTask 真执行：pipeline.Run → 结果由调用方经 /api/nodes/result 回传。
// 增量上报走 onFlush（≥5s 节流；失败不致命，最终 result 兜底）。
func execTask(p *pollTask) *pipeline.Result {
	brief := p.buildBrief()
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
		}
		if code, _, err := call("POST", "/api/nodes/progress", payload); err != nil || code != 200 {
			log.Printf("progress flush skipped (code=%d err=%v)", code, err)
		}
	}
	log.Printf("[exec] task=%d name=%s mode=%s project=%d → pipeline",
		p.Task.TaskID, p.Task.Name, p.Task.Mode, p.Task.ProjectID)
	return pipeline.Run(context.Background(), brief, onFlush)
}
