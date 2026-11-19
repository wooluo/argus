package api

import (
	"database/sql"
)

// Runner: 任务执行引擎接口（由 pipeline 包实现，api 层只做 HTTP 契约）。
type Runner interface {
	Run(taskID int)
	Stop(taskID int)
}

// API 组合根。
type API struct {
	DB     *sql.DB
	Bus    EventBus
	Runner Runner
}

// EventBus 由 events 包注入。
type EventBus interface {
	Publish(event string, data any)
}
