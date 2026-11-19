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

// ServeSSE: /api/stream — text/event-stream。
func (b *Bus) ServeSSE(w http.ResponseWriter, r *http.Request) {
	fl, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	filter := r.URL.Query().Get("event")
	sub, cancel := b.Subscribe(filter)
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
			payload, err := json.Marshal(evt.Data)
			if err != nil {
				continue
			}
			fmt.Fprintf(w, "event: %s\ndata: %s\n\n", evt.Event, payload)
			fl.Flush()
		}
	}
}
