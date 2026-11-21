# Argus 多阶段构建：Go 编译 → 极简运行镜像（前端 dist 已内嵌二进制）。
# 用法：docker build -t argus . && docker run -p 7887:7887 -v argus-data:/data argus
FROM golang:1.24-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# 纯 Go 无 CGO（modernc sqlite），交叉无依赖
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/argus-server ./cmd/argus-server

FROM alpine:3.20
RUN adduser -D -u 10001 argus && apk add --no-cache ca-certificates tzdata
COPY --from=build /out/argus-server /usr/local/bin/argus-server
USER argus
ENV ARGUS_ADDR=:7887 ARGUS_DATA=/data
VOLUME /data
EXPOSE 7887
HEALTHCHECK --interval=30s --timeout=3s \
  CMD wget -q -O /dev/null http://127.0.0.1:7887/healthz || exit 1
ENTRYPOINT ["argus-server"]
