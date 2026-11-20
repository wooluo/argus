#!/bin/bash
# Argus VPS 一键部署（Ubuntu/Debian + 公网安全加固）
# 用法：在 VPS 上以 root 运行  bash deploy-vps.sh
set -e

# ===== 配置区（按需修改）=====
SERVER_PORT=7887
ADMIN_TOKEN=$(openssl rand -hex 16)   # 自动生成管理 token
ALLOW_IP=""                            # 你的 Mac 公网 IP（留空=只本机+节点）
DATA_DIR="$HOME/argus-data"
BIN_DIR="/usr/local/bin"
# ============================

echo "═══ Argus VPS 部署 ═══"
echo "端口: $SERVER_PORT"
echo "Token: $ADMIN_TOKEN"
echo "数据目录: $DATA_DIR"
echo ""

# 1. 检查二进制
if [ ! -f ./argus-server ]; then
    echo "❌ 当前目录没有 argus-server 二进制"
    echo "   先在 Mac 上交叉编译并上传："
    echo "   CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o argus-server ./cmd/argus-server"
    echo "   CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o argus-node ./cmd/argus-node"
    echo "   scp argus-server argus-node root@VPS:~/"
    exit 1
fi

# 2. 安装二进制
install -m 755 argus-server "$BIN_DIR/argus-server"
install -m 755 argus-node   "$BIN_DIR/argus-node" 2>/dev/null || true

# 3. 数据目录
mkdir -p "$DATA_DIR"

# 4. systemd 服务（开机自启 + 崩溃重启）
cat > /etc/systemd/system/argus-server.service << EOF
[Unit]
Description=Argus Pentest Server
After=network.target

[Service]
Type=simple
User=$(whoami)
Environment=ARGUS_ADDR=:$SERVER_PORT
Environment=ARGUS_TOKEN=$ADMIN_TOKEN
Environment=ARGUS_DATA=$DATA_DIR
ExecStart=$BIN_DIR/argus-server
Restart=always
RestartSec=5
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable argus-server
systemctl start argus-server
sleep 2

# 5. 防火墙
if command -v ufw >/dev/null 2>&1; then
    if [ -n "$ALLOW_IP" ]; then
        ufw allow from "$ALLOW_IP" to any port $SERVER_PORT proto tcp
        echo "✅ 防火墙：仅 $ALLOW_IP 可访问 :$SERVER_PORT"
    else
        ufw allow $SERVER_PORT/tcp
        echo "⚠️  防火墙：$SERVER_PORT 对全公网开放（建议设置 ALLOW_IP）"
    fi
else
    echo "⚠️  未检测到 ufw，请手动配置防火墙"
fi

# 6. 验证
if curl -s -m 3 "http://127.0.0.1:$SERVER_PORT/healthz" | grep -q ok; then
    echo "✅ 服务健康检查通过"
else
    echo "❌ 服务未启动，查看日志：journalctl -u argus-server -n 20"
    exit 1
fi

# 7. 验证 token 鉴权生效
NO_AUTH=$(curl -s -o /dev/null -w "%{http_code}" "http://127.0.0.1:$SERVER_PORT/api/projects")
WITH_AUTH=$(curl -s -o /dev/null -w "%{http_code}" -H "Authorization: Bearer $ADMIN_TOKEN" "http://127.0.0.1:$SERVER_PORT/api/projects")
echo "   无 token 访问 API: $NO_AUTH（应为 401/403）"
echo "   有 token 访问 API: $WITH_AUTH（应为 200）"

echo ""
echo "═══ 部署完成 ═══"
echo ""
echo "📋 连接信息（保存好）："
echo "   Server 地址: http://$(curl -s ifconfig.me 2>/dev/null || echo 'VPS_IP'):$SERVER_PORT"
echo "   管理 Token:  $ADMIN_TOKEN"
echo ""
echo "🖥  浏览器访问: http://VPS_IP:$SERVER_PORT（Token 在请求头或 UI 登录框）"
echo ""
echo "📦 节点接入（在任何 Kali/VPS/内网机器上）："
echo "   ARGUS_SERVER=http://VPS_IP:$SERVER_PORT \\"
echo "   ARGUS_TOKEN=$ADMIN_TOKEN \\"
echo "   ./argus-node --name my-node"
echo ""
echo "📖 常用命令："
echo "   systemctl status argus-server    # 状态"
echo "   journalctl -u argus-server -f   # 实时日志"
echo "   systemctl restart argus-server  # 重启"
