package tools

import (
	"context"
	"sync"
	"testing"
	"time"
)

func TestNewThrottleAcquireRelease(t *testing.T) {
	t.Parallel()
	th := NewThrottle(Limits{RequestRate: 1000, MaxConcurrency: 5})
	release, err := th.Acquire(context.Background())
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	if th.Factor() != 1 {
		t.Fatalf("初始 factor 应为 1，得到 %f", th.Factor())
	}
	release()
}

func TestThrottlePenalizeReducesRate(t *testing.T) {
	t.Parallel()
	th := NewThrottle(Limits{RequestRate: 100, MaxConcurrency: 1})
	th.Penalize()
	if th.Factor() > 0.6 {
		t.Fatalf("Penalize 后 factor 应 ≤ 0.5，得到 %f", th.Factor())
	}
}

// 连续罚到最低
func TestThrottlePenalizeFloor(t *testing.T) {
	t.Parallel()
	th := NewThrottle(Limits{RequestRate: 100, MaxConcurrency: 1})
	for i := 0; i < 10; i++ {
		th.Penalize()
	}
	if th.Factor() != 0.125 {
		t.Fatalf("最低应为 0.125，得到 %f", th.Factor())
	}
}

func TestThrottleOkRecovers(t *testing.T) {
	th := NewThrottle(Limits{RequestRate: 100, MaxConcurrency: 1})
	for i := 0; i < 3; i++ {
		th.Penalize()
	}
	if th.Factor() >= 0.5 {
		t.Fatalf("三次 Penalize 后 factor 应 ≤ 0.25，得到 %f", th.Factor())
	}
	for i := 0; i < 20; i++ {
		th.okRequest()
	}
	if th.Factor() <= 0.125 {
		t.Fatalf("20 次 okRequest 后应有恢复（高于 0.125），得到 %f", th.Factor())
	}
}

// 并发安全：多 goroutine 同时 Acquire 不 panic
func TestThrottleConcurrentSafe(t *testing.T) {
	th := NewThrottle(Limits{RequestRate: 500, MaxConcurrency: 10})
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			release, err := th.Acquire(context.Background())
			if err == nil {
				release()
			}
		}()
	}
	wg.Wait()
}

// 上下文取消
func TestThrottleContextCancel(t *testing.T) {
	th := NewThrottle(Limits{RequestRate: 1000, MaxConcurrency: 1})
	release, err := th.Acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	release()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = th.Acquire(ctx)
	if err == nil {
		t.Fatal("已取消的上下文应返回错误")
	}
}

// factor=1 时 Wait 时间为 0
func TestThrottleRunsAtFullRate(t *testing.T) {
	th := NewThrottle(Limits{RequestRate: 50, MaxConcurrency: 5})
	start := time.Now()
	n := 5
	for i := 0; i < n; i++ {
		r, err := th.Acquire(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		r()
	}
	elapsed := time.Since(start)
	// 50 req/s → interval 20ms, 5 个请求约 80ms（不算相近并发）
	if elapsed > 2*time.Second {
		t.Fatalf("全速 5 个请求不应超过 2s，用了 %v", elapsed)
	}
}

func TestLimitsDefaults(t *testing.T) {
	l := Limits{}.withDefaults()
	if l.RequestRate != DefaultRequestRate || l.MaxConcurrency != DefaultMaxConcurrency {
		t.Fatalf("默认值不对: %+v", l)
	}
	partial := Limits{RequestRate: 5}.withDefaults()
	if partial.RequestRate != 5 || partial.MaxConcurrency != DefaultMaxConcurrency {
		t.Fatalf("部分覆盖: %+v", partial)
	}
}
