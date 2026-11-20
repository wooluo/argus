package api

import (
	"database/sql"

	"github.com/wooluo/argus/internal/auth"
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
	Auth   *auth.Middleware // 设置页 token 热更新（可空）
}

// EventBus 由 events 包注入。
type EventBus interface {
	Publish(event string, data any)
}
