// autonomous.go: 自主模式（单一连续 Agent 会话，全工具），移植 _run_autonomous。
package pipeline

import (
	"math"
	"context"
	"fmt"
	"strings"

	"github.com/wooluo/argus/internal/agent"
	"github.com/wooluo/argus/internal/llm"
	"github.com/wooluo/argus/internal/tools"
)

// runAutonomous 单会话全工具自主执行；Agent 最终输出若已是报告直接采用。
func runAutonomous(ctx context.Context, b Brief, tc *tools.Context, rep *memReporter,
	res *Result, client *llm.Client) {
	// 自适应步数预算（移植自 AutoPentent：对数缩放，边际收益递减）：
	// base × max(1, log2(1+资产数)/6)，下限 60 上限 300
	base := 120
	maxSteps := adaptiveSteps(base, rep.assetCount())
	rep.Log(ctx, "system", "hunt", fmt.Sprintf(
		"任务启动 · 授权范围: %s · 模式: 自主（步数预算 %d）· 模型: %s",
		tc.Scope.Describe(), maxSteps, rep.LLMDesc()))

	system, brief := autonomousBrief(b)
	a := agent.New(client, agent.Options{
		TaskID: b.TaskID, Stage: "hunt", ContextLimit: 40,
		MaxSteps: maxSteps, RequireReport: true,
	}, tools.All(), tc)

	final, err := a.Run(ctx, system, brief)
	// Token 统计写入结果（server 侧存 tasks.tokens）
	p, c, calls := a.Tokens()
	res.Tokens = map[string]int64{"prompt": p, "completion": c, "calls": calls}
	if err != nil {
		res.Status, res.Message = failStatus(ctx, err)
		return
	}
	// Agent 输出已是报告（含标题结构）→ 直接采用；否则模板兜底
	if len(final) > 600 && strings.HasPrefix(strings.TrimSpace(final), "#") {
		res.Report = final
		res.Message = "报告已由 Agent 生成"
		return
	}
	res.Report = genReport(ctx, b, rep, client)
	res.Message = "报告已按模板生成"
}

// autonomousBrief 自主模式任务书（移植 _autonomous_brief）。
func autonomousBrief(b Brief) (system, brief string) {
	system = AUTONOMOUS_SYSTEM_PROMPT + SAFETY_RULES
	ips, domains := classifyScope(b)
	var envLines []string
	envLines = append(envLines, "- 授权范围: "+scopeDescOf(b))
	if len(domains) > 0 {
		envLines = append(envLines, fmt.Sprintf(
			"- 域名目标: %s（可子域名枚举）", strings.Join(domains, ", ")))
	}
	if len(ips) > 0 {
		envLines = append(envLines, fmt.Sprintf(
			"- IP/网段目标: %s（网段先做存活发现）", strings.Join(ips, ", ")))
	}

	knowledgeBlock := ""
	if strings.TrimSpace(b.Knowledge) != "" {
		knowledgeBlock = b.Knowledge
	}

	rulesBlock := ""
	if strings.TrimSpace(b.Description) != "" {
		d := b.Description
		if len(d) > 2500 {
			d = d[:2500]
		}
		rulesBlock = "## 项目说明 / 测试规范（委托方要求，必须遵守并优先应用）\n" + d + "\n"
	}

	brief = `# 渗透测试任务书

## 目标
对以下授权范围完成系统性的渗透测试，找到真实存在的问题并给出专业报告。
` + rulesBlock + knowledgeBlock + `
## 环境情报（供参考，不是步骤指令）
` + strings.Join(envLines, "\n") + `
- 会话工具：web_login 可登录站点（自动处理表单/CSRF），http_fetch 带会话访问任意页面——有凭据时优先登录并系统测试认证后的每个功能模块
- web_crawl 自动复用登录会话（爬认证后页面优先用它，katana 不带会话）
- 工具不可用时可用 kali_install 自行安装；平台工具覆盖不了的场景直接 kali_exec
- **run_script 是万能底座**：自写 python3/bash 脚本在隔离目录执行迭代——PoC 开发、批量分析、自定义协议交互都靠它
- **osint_lookup**：whois / crt.sh 证书透明被动情报（攻击面画像第一步）
- **自我迭代闭环**：探测到陌生组件/版本时 → github_search 检索公开 POC/CVE
  研究 → github_fetch 下载 POC → 先阅读理解再 run_script 适配执行（良性验证）
  → 验证过的经验用 knowledge_save 沉淀；本地历史经验用 knowledge_search 检索复用；
  已知可利用漏洞用 msf_search 检索 Metasploit 模块并 kali_exec 脚本化运行
  （msfconsole -q -x "use 模块; set RHOSTS 目标; run; exit"，仅良性验证载荷，
  禁破坏性 payload）；exploitdb_search / exploitdb_fetch 检索并下载 Exploit-DB
  利用代码（4 万+ 离线镜像）适配执行

## 方法论框架（参考，具体打法你自己定）
目标存活与资产识别 → 攻击面分析（端口/服务/指纹/入口）→ 漏洞验证（已知组件
漏洞、注入类、配置错误、认证与权限问题、业务逻辑；认证后功能面优先）→ 良性
验证确认（对比响应、带外回连，不利用不破坏）→ 记录并继续扩大覆盖。发现凭据/
入口/可疑点立即跟进；同一目标多个角度可以并行推进。

## 工作纪律
0. **情报优先**：项目情报里有凭据或入口的，第一步就去用（登录、访问、验证），
   已知信息不要重复外围侦察浪费步数
1. **证据驱动交付**：挖洞的同时固定复现过程——**你验证确认的每个漏洞必须先
   report_finding 创建入库**（拿到 finding_id），再用 finding_step 逐步记录利用链
   （说明+真实请求+关键响应+结论，至少"触发+验证差异"两步）；update_finding
   仅用于更新已有条目状态
2. 结论只基于工具实际返回，未验证的明确写"未验证"，严禁编造
3. 同一调用失败 2 次后必须换思路，不要原样重试
4. 每隔一段在思考里更新简短进度（已覆盖/待覆盖）

## 终止条件（自主判断）
攻击面已系统覆盖且无更多有价值的测试方向，或步数预算接近耗尽时收尾。

## 最终交付
结束时输出**完整的中文 Markdown 渗透测试报告**（结构：概述与范围 → 资产与
攻击面 → 漏洞汇总表（编号/名称/严重度/位置/状态）→ 漏洞详情（原理/证据/
复现步骤/修复建议）→ 总结与整体建议）。该报告将直接交付委托方，请专业、严谨、可复现。`
	return system, brief
}

// adaptiveSteps 对数缩放步数预算：资产 50≈base，6678≈base×2.1；夹在 [60,300]。
func adaptiveSteps(base, assets int) int {
	if assets <= 0 {
		return base
	}
	f := math.Log2(1+float64(assets)) / 6
	if f < 1 {
		f = 1
	}
	n := int(float64(base)*f + 0.5)
	if n < 60 {
		n = 60
	} else if n > 300 {
		n = 300
	}
	return n
}
