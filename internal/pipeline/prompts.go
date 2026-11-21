// pipeline 提示词与阶段工具映射，移植自 pipeline.py / agent.py / registry stages。
package pipeline

import _ "embed"

// SAFETY_RULES 安全红线（agent.py SAFETY_RULES 原文）。
const SAFETY_RULES = `## 安全与合规红线（必须遵守，违反即任务失败）
1. 只能对授权范围内目标发起请求（工具会强制校验，范围外目标会被拒绝）
2. 只做良性验证：验证漏洞存在即可（回显/无害 PoC），严禁破坏性操作
3. 严禁：删除/修改数据、写入 webshell、拖库、提权、横向移动、DoS、数据外传
4. sqlmap 只能用于检测，绝不使用 --dump/--os-shell 等提取参数（平台已禁用）
5. 发现高危漏洞确认后立即记录，不做进一步利用`

// 内置系统提示词（用户 wooluo 2026-11-21 在 /agents 页撰写并实战验证后
// 收录为出厂默认——六态证据分类 / 最小影响原则 / Think-Act-Observe-Update-
// Decide 闭环 / 按目标形态选工具。自定义 Agent 仍可整体覆盖）。
//go:embed prompts/hunt.md
var AUTONOMOUS_SYSTEM_PROMPT string

// STAGED_SYSTEM_PROMPT 阶段模式系统提示词（%s = 阶段名占位符）。
//go:embed prompts/staged.md
var STAGED_SYSTEM_PROMPT string

// RETESTER_SYSTEM_PROMPT 复测判定系统提示词（api/retest.go 使用）。
//go:embed prompts/retester.md
var RETESTER_SYSTEM_PROMPT string

// STAGES / STAGE_NAMES 五阶段（staged 模式）。
var STAGES = []string{"recon", "mapping", "vulnscan", "verify", "report"}

var STAGE_NAMES = map[string]string{
	"recon": "侦察", "mapping": "资产测绘", "vulnscan": "漏洞扫描",
	"verify": "AI 验证", "report": "报告生成", "hunt": "自主推进",
}

// STAGE_TOOLS 阶段 → 可用工具名（原版各工具 stages 声明聚合）。
var STAGE_TOOLS = map[string][]string{
	"recon": {"host_discovery", "subfinder", "http_alive", "httpx_probe",
		"osint_lookup", "web_login", "http_fetch", "kali_exec", "kali_install",
		"run_script", "knowledge_save", "knowledge_search", "msf_search",
		"github_search", "github_fetch", "exploitdb_search"},
	"mapping": {"host_discovery", "http_alive", "httpx_probe", "nmap_scan",
		"port_scan", "katana_crawl", "web_crawl", "web_login", "http_fetch",
		"dir_brute", "kali_exec", "kali_install", "run_script",
		"knowledge_save", "knowledge_search", "msf_search", "github_search",
		"github_fetch", "exploitdb_search"},
	"vulnscan": {"web_crawl", "web_login", "http_fetch", "nuclei_scan",
		"sqlmap_detect", "dir_brute", "dnslog_payload", "dnslog_check",
		"report_finding", "finding_step", "payload_search", "exploitdb_fetch",
		"kali_exec", "kali_install", "run_script", "knowledge_save",
		"knowledge_search", "msf_search", "github_search", "github_fetch",
		"exploitdb_search"},
	"verify": {"web_login", "http_fetch", "http_alive", "update_finding",
		"dnslog_check", "dnslog_payload", "report_finding", "finding_step",
		"payload_search", "exploitdb_fetch", "kali_exec", "kali_install",
		"run_script", "knowledge_save", "knowledge_search", "msf_search",
		"github_search", "github_fetch", "exploitdb_search"},
	"hunt": nil, // 全量（All()）
}
