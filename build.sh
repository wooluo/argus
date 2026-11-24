#!/bin/bash
set -euo pipefail

# build.sh — 快速编译 Argus（server + node + 前端 + 交叉编译），替代手动敲 make。
# 用法：
#   ./build.sh                # 全量：前端 → 本机 server+node → Linux 交叉编译
#   ./build.sh server         # 只编译本机 server
#   ./build.sh node           # 只编译本机 node  
#   ./build.sh cross          # 只做交叉编译（Linux amd64 + arm64）
#   ./build.sh frontend       # 只构建前端并同步 dist
#   ./build.sh run            # 编译后启动 server（:7887）
#   ./build.sh test           # 全量测试
#   ./build.sh clean          # 清理构建产物

cd "$(dirname "$0")"

GO="${GO:-go}"
LDFLAGS="-s -w"
BOLD='\033[1m'
NC='\033[0m'

info()  { echo -e "${BOLD}$*${NC}"; }

case "${1:-all}" in
  frontend)
    info "── 构建前端 ──"
    ./scripts/build-frontend.sh
    exit 0
    ;;

  server)
    info "── 编译 server（本机） ──"
    CGO_ENABLED=0 $GO build -trimpath -ldflags="$LDFLAGS" -o argus-server ./cmd/argus-server
    echo "→ argus-server"
    exit 0
    ;;

  node)
    info "── 编译 node（本机） ──"
    CGO_ENABLED=0 $GO build -trimpath -ldflags="$LDFLAGS" -o argus-node ./cmd/argus-node
    echo "→ argus-node"
    exit 0
    ;;

  cross)
    info "── 交叉编译（Linux amd64 + arm64） ──"
    for osarch in "linux/amd64" "linux/arm64"; do
      os="${osarch%/*}"
      arch="${osarch#*/}"
      for bin in argus-server argus-node; do
        CGO_ENABLED=0 GOOS=$os GOARCH=$arch $GO build -trimpath -ldflags="$LDFLAGS" \
          -o "${bin}-${os}-${arch}" "./cmd/${bin}"
        echo "→ ${bin}-${os}-${arch}"
      done
    done
    exit 0
    ;;

  run)
    info "── 编译 + 启动 server ──"
    CGO_ENABLED=0 $GO build -trimpath -ldflags="$LDFLAGS" -o argus-server ./cmd/argus-server
    echo "→ argus-server 启动中…"
    ARGUS_ADDR="${ARGUS_ADDR:-:7887}" ./argus-server
    exit 0
    ;;

  test)
    info "── 全量测试 ──"
    $GO test ./...
    exit 0
    ;;

  clean)
    info "── 清理 ──"
    rm -f argus-server argus-node argus-server-linux-* argus-node-linux-*
    echo "✅ 已清理"
    exit 0
    ;;

  all|"")
    info "── 1/3 构建前端 ──"
    ./scripts/build-frontend.sh

    info "── 2/3 编译 server + node（本机） ──"
    CGO_ENABLED=0 $GO build -trimpath -ldflags="$LDFLAGS" -o argus-server ./cmd/argus-server
    CGO_ENABLED=0 $GO build -trimpath -ldflags="$LDFLAGS" -o argus-node ./cmd/argus-node
    echo "→ argus-server / argus-node"

    info "── 3/3 交叉编译（Linux amd64 + arm64） ──"
    for osarch in "linux/amd64" "linux/arm64"; do
      os="${osarch%/*}"
      arch="${osarch#*/}"
      for bin in argus-server argus-node; do
        CGO_ENABLED=0 GOOS=$os GOARCH=$arch $GO build -trimpath -ldflags="$LDFLAGS" \
          -o "${bin}-${os}-${arch}" "./cmd/${bin}"
        echo "→ ${bin}-${os}-${arch}"
      done
    done

    echo ""
    echo "✅ 全部完成。运行：./build.sh run"
    exit 0
    ;;

  *)
    echo "用法: $0 [server|node|cross|frontend|run|test|clean|all]"
    exit 1
    ;;
esac
