package tools

import (
	"context"
	"testing"
)

// captureReporter 记录工具经 Reporter 发出的调用（发现链路的契约回归）。
type captureReporter struct {
	saved   []Finding
	updated map[int64][]map[string]any
}

func (r *captureReporter) SaveAsset(context.Context, string, string, map[string]any)      {}
func (r *captureReporter) SaveSession(context.Context, string, string, map[string]string) {}
func (r *captureReporter) SaveTraffic(context.Context, string, string, string, int, string, string) {
}
func (r *captureReporter) SaveEvidence(context.Context, string, string, map[string]any)  {}
func (r *captureReporter) SaveKnowledge(context.Context, Knowledge) error                { return nil }
func (r *captureReporter) SearchKnowledge(context.Context, string, int) []map[string]any { return nil }
func (r *captureReporter) Log(context.Context, string, string, string)                   {}
func (r *captureReporter) LLMDesc() string                                               { return "test" }

func (r *captureReporter) SaveFinding(_ context.Context, f Finding) (int64, error) {
	r.saved = append(r.saved, f)
	return int64(len(r.saved)), nil
}
func (r *captureReporter) UpdateFinding(_ context.Context, id int64, patch map[string]any) error {
	if r.updated == nil {
		r.updated = map[int64][]map[string]any{}
	}
	r.updated[id] = append(r.updated[id], patch)
	return nil
}

// 曾有两处键名无人处理：finding_step 传 "append_step" 字符串、update_finding 传
// "note"——节点内存端只认 status/detail/evidence/poc/steps，步骤与验证说明被静默丢弃。
func TestFindingToolsEmitRecognizedKeys(t *testing.T) {
	rep := &captureReporter{}
	tc := &Context{Reporter: rep}

	if _, err := (FindingStepTool{}).Execute(context.Background(), map[string]any{
		"finding_id": 2, "note": "触发", "request": "GET http://t/a?id=1'",
		"response": "500 You have an error in your SQL syntax", "conclusion": "回显报错，存在注入",
	}, tc); err != nil {
		t.Fatal(err)
	}
	patches := rep.updated[2]
	if len(patches) != 1 {
		t.Fatalf("finding_step 应产生一次更新: %v", rep.updated)
	}
	step, ok := patches[0]["step"].(FindingStep)
	if !ok || step.Note != "触发" || step.Request != "GET http://t/a?id=1'" ||
		step.Response != "500 You have an error in your SQL syntax" || step.Conclusion != "回显报错，存在注入" {
		t.Fatalf("步骤应以结构化 FindingStep 传入: %#v", patches[0])
	}

	if _, err := (UpdateFindingTool{}).Execute(context.Background(), map[string]any{
		"finding_id": 2, "status": "false_positive", "note": "WAF 拦截页被误判",
	}, tc); err != nil {
		t.Fatal(err)
	}
	patches = rep.updated[2]
	if len(patches) != 2 || patches[1]["status"] != "false_positive" || patches[1]["note"] != "WAF 拦截页被误判" {
		t.Fatalf("update_finding 应传 status 与 note: %#v", patches)
	}

	if _, err := (ReportFindingTool{}).Execute(context.Background(), map[string]any{
		"name": "SQL 注入", "severity": "high", "target": "http://t/a", "detail": "id 参数",
	}, tc); err != nil {
		t.Fatal(err)
	}
	if len(rep.saved) != 1 || rep.saved[0].Status != "confirmed" || rep.saved[0].Name != "SQL 注入" {
		t.Fatalf("report_finding 应经 SaveFinding 入库: %+v", rep.saved)
	}
}
