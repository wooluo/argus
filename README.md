# Argus — 自主渗透测试平台（Go 重构版）

[English](README_EN.md) | 中文

AutoPentest 的 Go 重构：**单二进制 + 分布式节点架构**。LLM Agent 自主编排「侦察 → 资产测绘 → 漏洞扫描 → AI 验证 → 报告」全流程，支持 FOFA 空间测绘、知识自我迭代、AIMD 自适应限速等完整能力。

> ⚠️ **仅限对已获书面授权的目标使用。** 内置范围护栏（ScopeGuard）与全量审计，范围外请求强制拦截。使用前请阅读[免责声明](#免责声明)。

## 界面预览

| 发现页：漏洞条目 + 展开即证据 | 任务看板：实时日志 + 决策树 + 情报注入 |
|---|---|
| ![发现页](docs/discoveries.png) | ![任务看板](docs/task-board.png) |

| 探索链路：血缘 DAG | 知识库：Agent 经验自动沉淀 |
|---|---|
| ![探索链路](docs/exploration-graph.png) | ![知识库](docs/knowledge.png) |

## 快速开始

```bash
# 构建（Go ≥ 1.22）
go build -o argus-server ./cmd/argus-server
go build -o argus-node   ./cmd/argus-node

# 启动管理面（API + UI + SQLite，默认 :7887）
./argus-server

# 浏览器打开 http://127.0.0.1:7887
```

### 节点接入（执行面）

argus-node 是自治执行体——在任何 Kali/VPS/内网机器上运行一个小二进制即可接入：

```bash
# 在执行机上（首次注册需管理 token，之后自动心跳保活）
ARGUS_SERVER=http://your-server:7887 \
ARGUS_TOKEN=your-admin-token \
./argus-node --name kali-1
```

节点注册 → 心跳 → 轮询领任务 → 执行 → 回传。**NAT 后节点无需暴露端口**，只要能访问 server 即可。

也可以在「节点管理 → SSH 部署」里让平台远程安装，节点程序来源二选一：

| 来源 | 二进制从哪来 | 适用场景 |
|---|---|---|
| 平台推送（默认） | server 经 SSH 上传**本机同目录**的 `argus-node-linux-{arch}` | server 所在机器有交叉编译产物 |
| GitHub 下载 | 远端机器直接从 GitHub Release 下载（可选 `latest` 或指定 tag） | server 无本机二进制（Docker 部署）/ 上行带宽小 |

「GitHub 下载」用于私有仓库时需在设置页配置 GitHub Token：token 只在 server 侧换取短时效的签名下载地址，**不下发到远端机器**；远端下载后按 Release 的字节数 + sha256 校验。

### LLM 配置

设置页配置 OpenAI 兼容端点（智谱 Coding Plan / 内网 DeepSeek / Ollama / LM Studio 均可）。内网地址自动绕过系统代理。

### FOFA 空间测绘（可选，强烈推荐）

```bash
export ARGUS_FOFA_EMAIL=your@email
export ARGUS_FOFA_KEY=your-key   # fofa.info 个人中心获取
```

Agent 侦察阶段自主检索目标公网暴露资产（被动测绘，零目标请求），结果按授权范围分流标注。

## 环境变量

### 服务器（argus-server）

| 变量 | 默认 | 说明 |
|---|---|---|
| `ARGUS_ADDR` | `:7887` | 监听地址 |
| `ARGUS_DATA` | `./data` | 数据目录（SQLite + 设置） |
| `ARGUS_TOKEN` | 空 | 管理 token（启用 API 鉴权） |
| `ARGUS_STATIC` | 内嵌 | 前端静态目录（默认用内嵌 dist） |
| `ARGUS_RELEASE_REPO` | `wooluo/argus` | 「GitHub 下载」部署节点时的默认 Release 仓库（fork 部署改这里） |
| `ARGUS_TASK_MAX_MINUTES` | 空 | 单任务运行上限（分钟），到点看门狗代停；设置页 `limits.max_task_minutes` 优先 |

### 节点（argus-node）

| 变量 | 默认 | 说明 |
|---|---|---|
| `ARGUS_SERVER` | `http://127.0.0.1:7887` | 管理面地址 |
| `ARGUS_NAME` | hostname | 节点名（Agent 按名选用） |
| `ARGUS_NODE_TOKEN_FILE` | `~/.argus-node-token` | 节点凭证持久化 |

### 网络策略（节点侧）

| 变量 | 说明 |
|---|---|
| `ARGUS_OUT_PROXY` | 平台出站代理（FOFA/crt.sh），公网走代理内网自动绕过 |
| `ARGUS_TARGET_PROXY` | 测试流量代理（对目标请求走代理，规避 WAF 封 IP），显式即全量 |
| `ARGUS_FOFA_EMAIL` / `ARGUS_FOFA_KEY` | FOFA API 认证 |

## 架构

```
├── cmd/
│   ├── argus-server/   管理面（API + UI + SQLite + 调度）
│   └── argus-node/     执行面（注册 → 心跳 → 领任务 → 执行 → 回传）
├── internal/
│   ├── agent/          ReAct 循环 + 防空转（重复闸门/收敛检测）
│   ├── api/            REST 域（projects/tasks/findings/knowledge/...）
│   ├── llm/            OpenAI 兼容客户端（重试/内网绕代理）
│   ├── pipeline/       自主/阶段模式 + 任务后复盘 + 自适应预算
│   ├── scope/          授权范围护栏（域名/IP/CIDR + allow_hosts）
│   ├── store/          SQLite + 覆盖率测度
│   ├── tools/          32 个内置工具（FOFA/nuclei/payload_search/...）
│   └── ui/             前端构建产物（内嵌托管）
└── go.mod              纯 Go 依赖（chi + modernc/sqlite，无 CGO）
```

### 安全护栏（不可关闭）

- **ScopeGuard**：每次工具请求校验授权范围；`allow_hosts` 支持证明回调白名单（SRC 内网证明地址）
- **自毁命令黑名单**：rm -rf 分级拦截、mkfs/shutdown/dd/fork bomb 全禁
- **公共 DNS 白名单**：`dig @8.8.8.8` 等被动查询不误拦
- **全量审计**：每步思考/工具调用/范围拦截入库，组成决策树
- **AIMD 限速**：WAF 拦截率反馈自动退避（×2 上限 ×8），正常加性恢复

### 无人值守（零策略看门狗）

- **数据不丢**：节点增量上报以 server 确认为准推进游标，失败下个周期重发；收尾时未确认的部分随最终结果送达，最终结果回传带退避重试
- **LLM 失败分层**：限流 / 5xx / 网络错误退避重试（尊重 `Retry-After`，总预算 5 分钟）；鉴权失败、额度耗尽、请求被拒立即失败并给出处置提示
- **任务看门狗**：节点心跳停止 ≥10 分钟，或节点在线但任务执行心跳中断 ≥15 分钟（节点被 systemd 拉起、任务却已没人跑）→ 携带已得成果重新排队，最多 2 次，超出代停；运行超过上限 → 代停。看门狗只认这几个铁信号，不判断「多久没出新发现」——长耗时工具与审批等待从外部看也是静默
- **时间预算**：任务书写明最长运行时间与剩余时间（`limits.max_task_minutes`，默认 360 分钟）；临近结束前提醒收敛，到点由看门狗代停
- **无进展提醒**：连续 15 步没有任何新资产或新发现时提醒换方向（每个会话最多 3 次）。这是提醒不是熔断——深度手工验证阶段连续多步不出新资产是正常的
- **发现链路**：`update_finding` 的状态与验证说明、`finding_step` 的利用链步骤都同步到 server 的发现库，任务收尾时再全量对账；阶段模式的「AI 验证」阶段因此才真正生效

### 自我迭代闭环

```
任务运行 → 工具发现实时回流资产中心（幂等合并）；验证过的经验、可用凭据随手沉淀
任务结束 → 自动复盘（LLM 提炼 ≤2 条可复用经验：标题 / 一句话「何时用它」/ 全文）
           → 知识库（同标题更新而不堆重复；凭据等只对本项目可见）
下个任务 → 成果盘点开局 + 知识索引随任务书下发（本项目专属优先，其余按相关性）
           → Agent 命中后 knowledge_get 拉取全文 → 越用越强
```

### 收工前后的两道独立把关（自主模式）

执行和自评在同一个上下文里进行时，Agent 容易把自己做过的事当成做全了。所以换一个视角再过一遍：

- **收工前盲区审查**：Agent 给出报告时不直接采信。另起一个无工具的审查上下文，只看平台记录（资产、发现、工具调用纪要）找「缺什么」——只提问、不派活，挑出的盲区回灌给 Agent 补齐；至多拦下 2 次，审查员说没有缺口才放行
- **收工后独立核验**：另起一个只握只读工具的会话逐条复核发现——确认的是 PoC 响应本身，而不是扫描器告警；WAF 拦截页、通用错误页都不算证据。结论写回发现库并同步 server；有发现被改判为误报时，报告按数据重写。单次最多复核 12 条，可在设置的 `limits.autonomous_verify` 关闭

## 与 AutoPentent（Python 版）的关系

本仓库是 [wooluo/AutoPentest](https://github.com/wooluo/AutoPentest) 的 Go 重构，功能对齐：

- ✅ 全部 32 个内置工具 + FOFA + 泛解析过滤 + 响应折叠 + 防空转双闸
- ✅ 知识迭代（保存/BM25 检索/任务后复盘）+ 覆盖率测度 + 探索图
- ✅ 代理体系（出站/测试流量/AIMD）+ WAF 识别 + 证明回调白名单
- 🌟 **架构升级**：单二进制部署 / 分布式节点（NAT 友好）/ 纯 Go 无 CGO 交叉编译

## 开发

```bash
go build ./...     # 编译
go test ./...      # 测试
```

## 免责声明

**下载、安装、运行或以任何方式使用本项目，即视为您已阅读、理解并同意接受本声明全部条款的约束。若您不同意，请立即停止使用并删除本项目。**

1. 本项目仅供网络安全学习、技术研究及合法授权范围内的安全测试使用
2. 使用者必须严格遵守《中华人民共和国网络安全法》《刑法》（第 285/286 条）等法律法规。**未经授权对计算机信息系统进行扫描、入侵、破坏属于违法犯罪行为**
3. 使用者的一切操作行为与本项目开发者无关，法律责任自行承担
4. 测试前须获得目标系统所有者的书面授权，并将测试活动限制在授权范围内

## License

[MIT](LICENSE)

## VPS 部署（一键）

```bash
# 1. Mac 上交叉编译（二进制已在仓库根目录）
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o argus-server ./cmd/argus-server
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o argus-node ./cmd/argus-node

# 2. 上传到 VPS
scp argus-server argus-node deploy-vps.sh root@your-vps:~/

# 3. VPS 上执行（自动配 systemd + 防火墙 + token）
ssh root@your-vps "bash deploy-vps.sh"
```

脚本自动完成：安装二进制 → systemd 服务（开机自启/崩溃重启）→ **随机生成管理 token** → 防火墙规则（可配 IP 白名单）→ 健康检查 → 输出节点接入命令。
