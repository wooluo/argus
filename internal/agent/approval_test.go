package agent

// approval_test.go: 审批门与失败连击的单元测试（不依赖 LLM/网络）。

import (
	"context"
	"strings"
	"testing"

	"github.com/wooluo/argus/internal/llm"
	"github.com/wooluo/argus/internal/tools"
)

// fakeGate 可编程审批门：Approved 决定放行；记录收到的工具名。
type fakeGate struct {
	Approved   bool
	GotTool    string
	GotPurpose string
}

func (g *fakeGate) Request(_ context.Context, tool string, _ map[string]any, purpose string) bool {
	g.GotTool, g.GotPurpose = tool, purpose
	return g.Approved
}

// fakeTool 永远成功/失败的可控假工具。
type fakeTool struct {
	name string
	fail bool
}

func (f fakeTool) Name() string               { return f.name }
func (f fakeTool) Description() string        { return "fake" }
func (f fakeTool) Parameters() map[string]any { return map[string]any{"type": "object"} }
func (f fakeTool) Execute(_ context.Context, _ map[string]any, _ *tools.Context) (string, error) {
	if f.fail {
		return "", tools.Errorf("boom")
	}
	return "ok", nil
}

func newTestAgent(extra map[string]any) *Agent {
	tc := &tools.Context{Extra: extra}
	return &Agent{opts: Options{Stage: "hunt"}, ctx: tc,
		recentCalls: map[string]string{}, failStreak: map[string]int{}}
}

func mkCall(name, args string) llm.ToolCall {
	var c llm.ToolCall
	c.ID = "call-1"
	c.Function.Name = name
	c.Function.Arguments = args
	return c
}

// 拒绝 → BLOCKED，工具不执行。
func TestApprovalDeniedBlocks(t *testing.T) {
	gate := &fakeGate{Approved: false}
	a := newTestAgent(map[string]any{
		"approvals_require": []string{"kali_exec"},
		"approval_gate":     gate,
	})
	byName := map[string]tools.Tool{"kali_exec": fakeTool{name: "kali_exec"}}
	msg, final := a.executeOne(context.Background(), mkCall("kali_exec", `{"purpose":"提权探测"}`), byName, 1)
	if final != "" {
		t.Fatalf("unexpected final: %s", final)
	}
	if !strings.HasPrefix(msg.Content, "BLOCKED") {
		t.Fatalf("want BLOCKED prefix, got: %s", msg.Content)
	}
	if gate.GotTool != "kali_exec" || gate.GotPurpose != "提权探测" {
		t.Fatalf("gate got tool=%q purpose=%q", gate.GotTool, gate.GotPurpose)
	}
}

// 批准 → 正常执行。
func TestApprovalApprovedExecutes(t *testing.T) {
	a := newTestAgent(map[string]any{
		"approvals_require": []string{"kali_exec"},
		"approval_gate":     &fakeGate{Approved: true},
	})
	byName := map[string]tools.Tool{"kali_exec": fakeTool{name: "kali_exec"}}
	msg, _ := a.executeOne(context.Background(), mkCall("kali_exec", `{}`), byName, 1)
	if msg.Content != "ok" {
		t.Fatalf("want ok, got: %s", msg.Content)
	}
}

// 名单外工具不受审批影响。
func TestApprovalSkipsUnlisted(t *testing.T) {
	a := newTestAgent(map[string]any{
		"approvals_require": []string{"kali_exec"},
		"approval_gate":     &fakeGate{}, // 若被调用 GotTool 会非空
	})
	byName := map[string]tools.Tool{"http_fetch": fakeTool{name: "http_fetch"}}
	msg, _ := a.executeOne(context.Background(), mkCall("http_fetch", `{}`), byName, 1)
	if msg.Content != "ok" {
		t.Fatalf("want ok, got: %s", msg.Content)
	}
}

// 名单非空但门未接线 → fail-closed。
func TestApprovalFailClosedWithoutGate(t *testing.T) {
	a := newTestAgent(map[string]any{"approvals_require": []string{"kali_exec"}})
	byName := map[string]tools.Tool{"kali_exec": fakeTool{name: "kali_exec"}}
	msg, _ := a.executeOne(context.Background(), mkCall("kali_exec", `{}`), byName, 1)
	if !strings.HasPrefix(msg.Content, "BLOCKED") {
		t.Fatalf("want BLOCKED (fail-closed), got: %s", msg.Content)
	}
}

// 失败连击按签名计数：同参数第 2 次失败才提示，不同参数互不影响（蓝本 _track_failure）。
func TestFailStreakPerSignature(t *testing.T) {
	a := newTestAgent(nil)
	byName := map[string]tools.Tool{"port_scan": fakeTool{name: "port_scan", fail: true}}
	callA := mkCall("port_scan", `{"host":"1.1.1.1"}`)
	callB := mkCall("port_scan", `{"host":"2.2.2.2"}`)

	m1, _ := a.executeOne(context.Background(), callA, byName, 1)
	if strings.Contains(m1.Content, "原样重复失败") {
		t.Fatalf("first failure should not nag: %s", m1.Content)
	}
	m2, _ := a.executeOne(context.Background(), callA, byName, 2)
	if !strings.Contains(m2.Content, "原样重复失败 2 次") {
		t.Fatalf("second identical failure should nag: %s", m2.Content)
	}
	// 不同参数（不同签名）失败不触发提示
	m3, _ := a.executeOne(context.Background(), callB, byName, 3)
	if strings.Contains(m3.Content, "原样重复失败") {
		t.Fatalf("different args = different streak: %s", m3.Content)
	}
}
