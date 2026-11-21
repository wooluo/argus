# Argus Makefile —— 常用构建/测试/交叉编译入口。
# make            = build（本机 server+node）
# make test       = 全量测试
# make cross      = 交叉编译 Linux amd64/arm64（SSH 部署用产物，git 提交）
# make frontend   = 从 AutoPentest 前端源码构建并同步 dist（见 scripts/build-frontend.sh）
# make run        = 本地起 server（:7887）

GO ?= go
VERSION ?= $(shell git describe --tags --always 2>/dev/null || echo dev)
LDFLAGS := -s -w

.PHONY: build node test vet fmt lint cross frontend run clean docker

build:
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags="$(LDFLAGS)" -o argus-server ./cmd/argus-server

node:
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags="$(LDFLAGS)" -o argus-node ./cmd/argus-node

test:
	$(GO) test ./...

vet:
	$(GO) vet ./...

fmt:
	$(GO) fmt ./...
	@out=$$(gofmt -l . 2>/dev/null); if [ -n "$$out" ]; then echo "未格式化文件:"; echo "$$out"; exit 1; fi

lint: vet fmt

# 交叉编译 Linux 产物（deploy/ssh.go 自动按架构挑选）
cross: build node
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO) build -trimpath -ldflags="$(LDFLAGS)" -o argus-server-linux-amd64 ./cmd/argus-server
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO) build -trimpath -ldflags="$(LDFLAGS)" -o argus-node-linux-amd64 ./cmd/argus-node
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 $(GO) build -trimpath -ldflags="$(LDFLAGS)" -o argus-server-linux-arm64 ./cmd/argus-server
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 $(GO) build -trimpath -ldflags="$(LDFLAGS)" -o argus-node-linux-arm64 ./cmd/argus-node

frontend:
	./scripts/build-frontend.sh

run: build
	ARGUS_ADDR=:7887 ./argus-server

docker:
	docker build -t argus .

clean:
	rm -f argus-server argus-node argus-server-linux-* argus-node-linux-*
