package api

import (
	"github.com/wooluo/argus/internal/tools"
)

// ToolsStatusList 工具链状态（形状对齐蓝本 registry.status()）。
func ToolsStatusList(customPaths map[string]any) []map[string]any {
	paths := map[string]string{}
	for k, v := range customPaths {
		if s, ok := v.(string); ok {
			paths[k] = s
		}
	}
	return tools.Status(paths)
}
