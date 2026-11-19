// Package ui: 内嵌前端静态资源（构建时把 dist/ 放到本包下再编译）。
package ui

import "embed"

//go:embed all:dist
var Dist embed.FS
