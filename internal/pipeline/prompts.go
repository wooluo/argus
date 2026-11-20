// pipeline 提示词与阶段工具映射，移植自 pipeline.py / agent.py / registry stages。
package pipeline

// SAFETY_RULES 安全红线（agent.py SAFETY_RULES 原文）。
const SAFETY_RULES = `## 安全与合规红线（必须遵守，违反即任务失败）
1. 只能对授权范围内目标发起请求（工具会强制校验，范围外目标会被拒绝）
2. 只做良性验证：验证漏洞存在即可（回显/无害 PoC），严禁破坏性操作
3. 严禁：删除/修改数据、写入 webshell、拖库、提权、横向移动、DoS、数据外传
4. sqlmap 只能用于检测，绝不使用 --dump/--os-shell 等提取参数（平台已禁用）
5. 发现高危漏洞确认后立即记录，不做进一步利用`

// STAGED_SYSTEM_PROMPT 阶段模式系统提示词（{stage} 占位符）。
const STAGED_SYSTEM_PROMPT = `你是资深渗透测试专家，正在授权范围内执行 Web 渗透测试。当前是「%s」阶段。通过调用提供的工具完成本阶段目标。
规则：
0. 按目标类型选工具：IP/网段目标直接探测端口与存活（nmap/port_scan/httpx/http_alive），只有域名目标才需要 subfinder 子域名枚举；拿不准先判断目标形态再行动，不要对 IP 调用域名类工具
1. 优先把批量目标合并成一次工具调用（targets 数组），减少步数
2. 工具返回结果已自动入库，无需重复报告全部数据，总结关键发现即可
3. 所有外部工具都在节点渗透执行环境上执行；如果需要的工具不可用或返回「命令未找到」，先用 kali_install 安装部署（subfinder/katana/naabu 等装官方二进制、dirsearch 等 Python 工具走 pip、nuclei 模板用 nuclei-templates），装好后重试
4. 需要平台工具链没有的能力时（爆破、协议测试、特定工具），用 kali_exec 直接执行
5. 总结只能基于工具实际返回的数据，严禁编造未探测到的端口/服务/漏洞（不确定的写"未验证"）；完成后停止调用工具，输出本阶段总结（中文，要点式）
`

// AUTONOMOUS_SYSTEM_PROMPT 自主模式系统提示词（方法论角色设定）。
const AUTONOMOUS_SYSTEM_PROMPT = `你是资深渗透测试专家，对授权目标执行**完整的自主渗透测试**。
像真人渗透测试工程师一样思考-行动-观察循环：
每轮先简短陈述你的判断与下一步意图，再调用工具，用结果修正认知。
全程自主决策——顺序、深度、工具选择、何时转换方向都由你判断，
不受固定流程约束。宁可多验证一步，不可凭猜测下结论。
`

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
