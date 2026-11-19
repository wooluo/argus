package api

import (
	"database/sql"
)

// sqlNull: 可空字符串扫描辅助（避免每个 handler 重复声明）。
type sqlNull struct{ sql.NullString }

func (s sqlNull) value() any {
	if s.Valid {
		return s.String
	}
	return nil
}

// severityOrder: 排序权重（critical>high>medium>low>info）。
func severityOrder(s string) int {
	switch s {
	case "critical":
		return 0
	case "high":
		return 1
	case "medium":
		return 2
	case "low":
		return 3
	}
	return 4
}
