package store

import "testing"

// 前端与仪表盘按蓝本只认 running / completed；Go 执行面的 assigned / done
// 必须在出口换词（曾因不映射：完成的任务显示红色、进度条走不完、仪表盘
// 完成数恒为 0）。
func TestPresentStatus(t *testing.T) {
	for in, want := range map[string]string{
		"assigned": "running",
		"running":  "running",
		"done":     "completed",
		"pending":  "pending",
		"failed":   "failed",
		"stopped":  "stopped",
	} {
		if got := PresentStatus(in); got != want {
			t.Errorf("PresentStatus(%q) = %q, 期望 %q", in, got, want)
		}
	}
}

func TestTaskPresent(t *testing.T) {
	for _, c := range []struct {
		raw    string
		want   string
		isLive bool
	}{
		{"pending", "pending", true},  // 排队中：保留原词（看板有「排队中」文案）
		{"assigned", "running", true}, // 执行中
		{"done", "completed", false},
		{"stopped", "stopped", false},
		{"failed", "failed", false},
	} {
		task := Task{Status: c.raw}
		task.Present()
		// is_live 必须按库内状态算——换词后 assigned 已不存在
		if task.Status != c.want || task.IsLive != c.isLive {
			t.Errorf("Present(%q): status=%q is_live=%v, 期望 %q/%v",
				c.raw, task.Status, task.IsLive, c.want, c.isLive)
		}
	}
}
