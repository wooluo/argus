// Package events: 进程内事件总线 + SSE 推送（对齐原 core/events.py）。
package events

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"
)

type Event struct {
	Event string `json:"event"`
	Data  any    `json:"data"`
}

type subscriber struct {
	ch     chan Event
	filter string // 空=全部
}

type Bus struct {
	mu   sync.RWMutex
	subs map[*subscriber]struct{}
}

func NewBus() *Bus {
	return &Bus{subs: map[*subscriber]struct{}{}}
}

func (b *Bus) Subscribe(filter string) (*subscriber, func()) {
	s := &subscriber{ch: make(chan Event, 256), filter: filter}
	b.mu.Lock()
	b.subs[s] = struct{}{}
	b.mu.Unlock()
	return s, func() {
		b.mu.Lock()
		if _, ok := b.subs[s]; ok {
			delete(b.subs, s)
			close(s.ch)
		}
		b.mu.Unlock()
	}
}

func (b *Bus) Publish(event string, data any) {
	evt := Event{Event: event, Data: data}
	b.mu.RLock()
	defer b.mu.RUnlock()
	for s := range b.subs {
		if s.filter != "" && s.filter != event {
			continue
		}
		select {
		case s.ch <- evt:
		default: // 慢消费者丢事件（SSE 只做实时提示，历史走 DB 查询）
		}
	}
}

// ServeSSE: /api/stream — text/event-stream（按 ?event= 过滤事件名）。
func (b *Bus) ServeSSE(w http.ResponseWriter, r *http.Request) {
	b.serveSSE(w, r, r.URL.Query().Get("event"), nil)
}

// ServeSSETask: /api/stream/{task_id} — 单任务事件流
// （data.task_id 或 data.id 等于该任务的事件；蓝本 api/stream.py）。
func (b *Bus) ServeSSETask(w http.ResponseWriter, r *http.Request, taskID int64) {
	b.serveSSE(w, r, "", func(evt Event) bool {
		m, ok := evt.Data.(map[string]any)
		if !ok {
			return false
		}
		for _, k := range []string{"task_id", "id"} {
			switch v := m[k].(type) {
			case int64:
				if v == taskID {
					return true
				}
			case int:
				if int64(v) == taskID {
					return true
				}
			case float64:
				if int64(v) == taskID {
					return true
				}
			}
		}
		return false
	})
}

// serveSSE SSE 主循环：nameFilter 订阅期过滤（空=全部），evtKeep 逐事件过滤（nil=全放行）。
func (b *Bus) serveSSE(w http.ResponseWriter, r *http.Request,
	nameFilter string, evtKeep func(Event) bool) {
	fl, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	sub, cancel := b.Subscribe(nameFilter)
	defer cancel()

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	// 初始 ping 立即刷出（代理缓冲友好）
	fmt.Fprintf(w, ": ping\n\n")
	fl.Flush()

	ping := time.NewTicker(15 * time.Second)
	defer ping.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case <-ping.C:
			fmt.Fprint(w, ": ping\n\n")
			fl.Flush()
		case evt := <-sub.ch:
			if evtKeep != nil && !evtKeep(evt) {
				continue
			}
			payload, err := json.Marshal(evt.Data)
			if err != nil {
				continue
			}
			fmt.Fprintf(w, "event: %s\ndata: %s\n\n", evt.Event, payload)
			fl.Flush()
		}
	}
}
