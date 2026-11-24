package pipeline

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/wooluo/argus/internal/tools"
)

// 发现链路的节点内存端回归：
//   - 同名同目标本地合并（后续更新落到 server 上那一条）；
//   - update_finding 的状态与说明、finding_step 的结构化步骤都写进条目；
//   - 更新过的发现随下次增量上报（FindingUpdates），且只带一次。
func TestFindingLifecycleInSession(t *testing.T) {
	ctx := context.Background()
	m := &memReporter{res: &Result{}, brief: Brief{}}
	var flushed []Result
	m.onFlush = func(_ context.Context, _ Brief, inc Result) error {
		flushed = append(flushed, inc)
		return nil
	}
	save := func(detail string) int64 {
		id, err := m.SaveFinding(ctx, tools.Finding{Name: "SQL 注入", Severity: "high",
			Target: "http://t/a", Detail: detail, Status: "confirmed"})
		if err != nil {
			t.Fatal(err)
		}
		return id
	}

	id := save("")
	// 重复上报：并入同一条，补上首次缺失的详情，不产生第二条
	if again := save("id 参数可注入"); again != id || len(m.res.Findings) != 1 || m.res.Findings[0].Detail != "id 参数可注入" {
		t.Fatalf("同名同目标应合并: ids=%d/%d count=%d detail=%q", id, again, len(m.res.Findings), m.res.Findings[0].Detail)
	}
	if err := m.UpdateFinding(ctx, id, map[string]any{"step": tools.FindingStep{
		Note: "触发", Request: "GET http://t/a?id=1'", Response: "500 SQL syntax error"}}); err != nil {
		t.Fatal(err)
	}
	if err := m.UpdateFinding(ctx, id, map[string]any{"status": "false_positive", "note": "WAF 拦截页被误判"}); err != nil {
		t.Fatal(err)
	}
	f := m.res.Findings[0]
	if f.Status != "false_positive" || len(f.Steps) != 1 || f.Steps[0].Request != "GET http://t/a?id=1'" ||
		!strings.HasSuffix(f.Detail, "【误报判定】WAF 拦截页被误判") {
		t.Fatalf("更新未写进条目: status=%q steps=%+v detail=%q", f.Status, f.Steps, f.Detail)
	}

	// 另一条发现未被更新过：增量里只应出现标脏的那条
	if _, err := m.SaveFinding(ctx, tools.Finding{Name: "XSS", Severity: "medium",
		Target: "http://t/b", Status: "confirmed"}); err != nil {
		t.Fatal(err)
	}
	m.flush(ctx)
	if len(flushed) != 1 || len(flushed[0].Findings) != 2 || len(flushed[0].FindingUpdates) != 1 ||
		flushed[0].FindingUpdates[0].Name != "SQL 注入" {
		t.Fatalf("增量应含 2 条新增 + 1 条更新: flushes=%d %+v", len(flushed), flushed)
	}
	m.flush(ctx) // 无新动作：不再重发更新
	if len(flushed) != 1 {
		t.Fatalf("更新过的发现只应带一次，实际 flush 了 %d 次", len(flushed))
	}
	if err := m.UpdateFinding(ctx, 99, map[string]any{"status": "confirmed"}); err == nil {
		t.Error("更新不存在的编号应报错")
	}
}

// 线路形态与 server 的解码结构对齐：status 入库、steps 为结构化对象。
func TestFindingWireShape(t *testing.T) {
	b, err := json.Marshal(Finding{Name: "n", Status: "confirmed", Steps: []tools.FindingStep{{
		Note: "触发", Request: "GET /", Response: "200 ok", Conclusion: "成立"}}})
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	for _, want := range []string{`"status":"confirmed"`, `"steps":[{"note":"触发","request":"GET /",`,
		`"conclusion":"成立"}`} {
		if !strings.Contains(s, want) {
			t.Errorf("线路形态缺 %s: %s", want, s)
		}
	}
}
