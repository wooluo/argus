#!/bin/bash
# 前端 dist 同步：Argus 复用 AutoPentest 的 Vue3 前端（源码在 Python 仓库维护）。
# 本脚本从 AutoPentest 前端构建并拷贝 dist 到 internal/ui/dist（go:embed 内嵌）。
# 用法：make frontend 或 ./scripts/build-frontend.sh [AutoPentest 仓库路径]
set -e

SRC="${1:-$HOME/DEV/AutoPentest}"
DIST_SRC="$SRC/frontend/dist"
DIST_DST="$(cd "$(dirname "$0")/.." && pwd)/internal/ui/dist"

if [ ! -f "$SRC/frontend/package.json" ]; then
    echo "❌ 未找到前端源码：$SRC/frontend（传参指定 AutoPentest 仓库路径）"
    exit 1
fi

echo "── 构建前端（$SRC/frontend）──"
( cd "$SRC/frontend" && npm install --no-audit --no-fund && npm run build )

if [ ! -f "$DIST_SRC/index.html" ]; then
    echo "❌ 构建产物缺失：$DIST_SRC/index.html"
    exit 1
fi

echo "── 同步 dist → $DIST_DST ──"
rm -rf "$DIST_DST"
cp -R "$DIST_SRC" "$DIST_DST"
echo "✅ 完成。重新 make build 即可内嵌新前端。"
