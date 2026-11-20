package api

import "net/http"

// ============ Stream 域（蓝本 api/stream.py） ============

// sseBus: events.Bus 的 SSE 能力。api.EventBus 只暴露 Publish，
// 运行期注入的实现是 *events.Bus（自带订阅 + SSE 循环）。
type sseBus interface {
	ServeSSE(w http.ResponseWriter, r *http.Request)
}

// GetStream GET /api/stream —— SSE 实时事件流，复用 events.Bus.ServeSSE：
// text/event-stream + Flusher、?event= 过滤、15s 心跳保活、客户端断开即退出。
// TODO: 蓝本还有按任务过滤的 /api/stream/{task_id}（校验任务存在后单任务推送），
// 当前 Go 总线按事件名过滤，无按 task_id 订阅；需要时给 events.Bus 加过滤再补。
func (a *API) GetStream(w http.ResponseWriter, r *http.Request) {
	sb, ok := a.Bus.(sseBus)
	if !ok {
		respondErr(w, 500, "事件总线不支持 SSE")
		return
	}
	sb.ServeSSE(w, r)
}
