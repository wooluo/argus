package api

import (
	"net/http"

	"github.com/wooluo/argus/internal/tools"
)

// ============ Toolbox 域（蓝本 api/toolbox.py）============
// 渗透工具箱只读聚合：RevShell 模板 / Payload 库 / TTY 提权 / 速查表。
// 数据经 go:embed 内嵌（tools/data/toolbox.json），无需落盘缓存。

// GetToolbox GET /api/toolbox — 全量工具箱数据。
func (a *API) GetToolbox(w http.ResponseWriter, r *http.Request) {
	data, err := tools.ToolboxData()
	if err != nil {
		respondErr(w, http.StatusInternalServerError, "工具箱数据解析失败: "+err.Error())
		return
	}
	respondJSON(w, http.StatusOK, data)
}
