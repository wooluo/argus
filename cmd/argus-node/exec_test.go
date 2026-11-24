package main

import (
	"encoding/json"
	"testing"
)

// 分层用脑：server 下发的角色模型映射到任务书——分工给「主循环」的模型覆盖
// 主配置，另两类各自下发；空配置（没分工）保持零值，pipeline 回落主配置。
func TestBuildBriefMapsRoleModels(t *testing.T) {
	var p pollTask
	if err := json.Unmarshal([]byte(`{
		"task":{"id":7,"mode":"autonomous","project_id":3},
		"project":{"name":"p","scope":[{"type":"domain","value":"example.com"}]},
		"llm":{"base_url":"http://main/v1","api_key":"k0","model":"main-m"},
		"models":{
			"hunt":{"base_url":"http://strong/v1","api_key":"k1","model":"glm-5.4"},
			"review":{"base_url":"http://light/v1","api_key":"k2","model":"glm-5.3-flash","proxy":"http://px:1"},
			"aux":{"base_url":"","api_key":"","model":""}
		}}`), &p); err != nil {
		t.Fatal(err)
	}
	b := p.buildBrief()
	if b.LLM.Model != "glm-5.4" || b.LLM.BaseURL != "http://strong/v1" || b.LLM.APIKey != "k1" {
		t.Errorf("主循环应改用分工给它的模型: %+v", b.LLM)
	}
	if b.LLMReview.Model != "glm-5.3-flash" || b.LLMReview.Proxy != "http://px:1" {
		t.Errorf("审查核验模型不符: %+v", b.LLMReview)
	}
	if b.LLMAux.BaseURL != "" || b.LLMAux.Model != "" {
		t.Errorf("没分工的角色应保持零值: %+v", b.LLMAux)
	}

	// 旧版 server 不带 models → 全部沿用主配置
	var old pollTask
	_ = json.Unmarshal([]byte(`{"task":{"id":1},"llm":{"base_url":"http://main/v1","model":"main-m"}}`), &old)
	ob := old.buildBrief()
	if ob.LLM.Model != "main-m" || ob.LLMReview.BaseURL != "" || ob.LLMAux.BaseURL != "" {
		t.Errorf("旧版 server 的下发应原样用主配置: %+v", ob)
	}
}
