// Package pipeline 移植自 AutoPentest core/pipeline.py —— 任务执行流水线。
// 节点侧运行：Poll 领任务 → 组装 Brief → Run() 执行（staged/autonomous）
// → Result 经 /api/nodes/result 回传 server 落库。
package pipeline

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/wooluo/argus/internal/agent"
	"github.com/wooluo/argus/internal/llm"
	"github.com/wooluo/argus/internal/rank"
	"github.com/wooluo/argus/internal/scope"
	"github.com/wooluo/argus/internal/tools"
)

// Rule 授权范围规则（与 Project.scope 一致）——直接复用 scope.Rule。
// Brief Poll 下发的任务书输入（node 侧从扩展 Poll 响应组装）。
type Brief struct {
	TaskID      int64        `json:"task_id"`
	Mode        string       `json:"mode"` // autonomous | staged
	ProjectID   int64        `json:"project_id"`
	ProjectName string       `json:"project_name"`
	Description string       `json:"description"`
	Knowledge   string       `json:"knowledge"` // server 注入的知识库块（跨任务经验）
	Scope       []scope.Rule `json:"scope"`
	AllowHosts  []string     `json:"allow_hosts"`
	LLM         llm.Config   `json:"llm"`
	// HITL 审批门：名单由 server Poll 下发，门实现由节点注入（HTTP 回连）。
	ApprovalsRequire []string           `json:"approvals_require"`
	ApprovalGate     agent.ApprovalGate `json:"-"`
	// 运行中情报注入：节点轮询 server 攒入队列，agent 循环每步 Drain（蓝本 intel_queue）。
	IntelQueue agent.IntelQueue `json:"-"`
	// 项目情报（跨任务持久，任务书携带）。
	Intel []string `json:"intel"`
	// Skill 领域知识块（启用的 skills 拼接，server 下发）。
	Skills string `json:"skills"`
	// KnowledgeFetch 按需拉取知识条目全文（节点注入，回连 server）。此时
	// Knowledge 字段只是索引（标题 + 何时用它），条目再多也不撑爆任务书。
	KnowledgeFetch tools.KnowledgeFetcher `json:"-"`
	// 自定义 Agent（hunt 角色覆盖：prompt 非空时替换内置系统提示词；步数>0 时覆盖预算）。
	AgentPrompt   string `json:"agent_prompt"`
	AgentMaxSteps int    `json:"agent_max_steps"`
	// FOFA / GitHub 凭据（server 设置页下发，覆盖节点环境变量）。
	FOFAEmail   string `json:"fofa_email"`
	FOFAKey     string `json:"fofa_key"`
	GitHubToken string `json:"github_token"`
	// 断点续测：continue_from 指定任务的历史成果摘要（server 生成下发）。
	ContinueSummary string `json:"continue_summary"`
	// VerifyFindings 收工后做独立核验（server 按设置 limits.autonomous_verify 下发，默认开）。
	VerifyFindings bool `json:"verify_findings"`
	// 分层用脑：「审查与核验」「报告与复盘」两类工作的模型（server 按设置页的
	// 角色分工下发）。零值 = 没分工，沿用 LLM（主配置）；LLM 本身也可能是分工
	// 给「主循环」的模型。
	LLMReview llm.Config `json:"llm_review"`
	LLMAux    llm.Config `json:"llm_aux"`
	// 时间预算（server 按单任务最长运行时间下发）：TimeBudgetSeconds 是领取
	// 时刻的剩余秒数，TimeLimitSeconds 是总时长上限；0=不限时。
	TimeBudgetSeconds int `json:"time_budget_seconds"`
	TimeLimitSeconds  int `json:"time_limit_seconds"`
}

// Finding / Asset / LogItem 与 server ReportResult 请求体字段一一对应。
type Finding struct {
	Name     string              `json:"name"`
	Severity string              `json:"severity"`
	Target   string              `json:"target"`
	Detail   string              `json:"detail"`
	Evidence string              `json:"evidence"`
	PoC      string              `json:"poc"`
	Status   string              `json:"status"`          // pending/confirmed/false_positive（update_finding 可改，随更新同步到 server）
	Steps    []tools.FindingStep `json:"steps,omitempty"` // 利用链步骤（finding_step 追加）
}

type Asset struct {
	Type   string `json:"type"`
	Value  string `json:"value"`
	Detail string `json:"detail"`
}

type LogItem struct {
	Stage   string `json:"stage"`
	Tool    string `json:"tool"`
	Content string `json:"content"`
}

// Result 任务执行产物（node → server）。
type Result struct {
	Status   string           `json:"status"` // done | failed
	Message  string           `json:"message"`
	Findings []Finding        `json:"findings"`
	Assets   []Asset          `json:"assets"`
	Logs     []LogItem        `json:"logs"`
	Traffic  []TrafficItem    `json:"traffic,omitempty"`
	Report   string           `json:"report"`
	Tokens   map[string]int64 `json:"tokens,omitempty"`
	// TokensByModel 分模型用量 {模型 ID: {prompt,completion,calls}}——分层用脑后
	// 各角色可能是不同模型，只看合计不知道哪个模型花了多少。
	TokensByModel map[string]map[string]int64 `json:"tokens_by_model,omitempty"`
	// Knowledge 本任务沉淀的经验（结构化回传，server 落知识库）。
	Knowledge []tools.Knowledge `json:"knowledge,omitempty"`
	// FindingUpdates 自上次增量以来被更新过的发现（最新状态，尽力而为）；
	// server 按「项目 + 名称 + 目标」更新对应条目。
	FindingUpdates []Finding `json:"finding_updates,omitempty"`
	// Reported 经 progress 增量**已被 server 确认**的条数（findings/assets/logs/
	// traffic/knowledge）——最终 ReportResult 只需发 [Reported.X:] 之后的增量，
	// 避免全量双写；未经确认的条目自然落在其中，随最终结果送达。
	Reported struct {
		Findings  int `json:"findings"`
		Assets    int `json:"assets"`
		Logs      int `json:"logs"`
		Traffic   int `json:"traffic"`
		Knowledge int `json:"knowledge"`
	} `json:"reported"`
}

// TrafficItem 结构化流量（http_fetch/web_login 自动录制，server 落 traffic_logs）。
type TrafficItem struct {
	Method          string `json:"method"`
	URL             string `json:"url"`
	RequestBody     string `json:"request_body"`
	Status          int    `json:"status"`
	ResponseSnippet string `json:"response_snippet"`
	SourceTool      string `json:"source_tool"`
}

// memReporter 缓冲式 Reporter：工具产出先攒在内存（阶段间 _data_summary 直接
// 读缓冲，替代原版查库），flusher 协程把新增条目增量推给 server（长任务可见
// 进度）。游标以 server 确认为准——onFlush 返回 error 即视为未送达，下个周期
// 重发；任务收尾时未经确认的条目随最终结果一并回传，不丢发现。
type memReporter struct {
	mu        sync.Mutex
	res       *Result
	sentF     int // 已经 server 确认（onFlush 返回 nil）的条数
	sentA     int
	sentL     int
	sentT     int
	sentK     int
	inflight  bool                                       // 有尚未确认的增量
	lastFlush time.Time                                  // 上次成功上报时刻（节流基准）
	onFlush   func(context.Context, Brief, Result) error // 可选：只带未确认条目
	stop      chan struct{}
	done      chan struct{}
	stopOnce  sync.Once
	brief     Brief
	knowledge []knowledgeEntry // 会话内知识（SaveKnowledge 入此，供 SearchKnowledge）
	kSeq      int
	dirtyIDs  []int64 // 被更新过、尚未随增量上报的发现（本地编号）
	dirtySet  map[int64]bool
}

const (
	flushEvery  = 5 * time.Second // 增量上报最小间隔
	flushTicker = time.Second     // flusher 巡检周期（首条增量最迟 1s 内发出）
)

// flushLocked 标记有新增量待上报（实际上报见 flush）。
func (m *memReporter) flushLocked() {
	if m.onFlush == nil {
		return
	}
	m.inflight = true
}

// startFlusher 起上报协程（onFlush 为 nil 时不启动）；stopFlusher 收尾。
func (m *memReporter) startFlusher(ctx context.Context) {
	if m.onFlush == nil {
		return
	}
	m.stop, m.done = make(chan struct{}), make(chan struct{})
	go func() {
		defer close(m.done)
		t := time.NewTicker(flushTicker)
		defer t.Stop()
		for {
			select {
			case <-m.stop:
				// 收尾：剩余增量尽量送出。任务被取消时 ctx 已 Done，用脱离
				// 取消的副本——已产出的发现必须送达
				m.flush(context.WithoutCancel(ctx))
				return
			case <-t.C:
				m.mu.Lock()
				due := m.inflight && time.Since(m.lastFlush) >= flushEvery
				m.mu.Unlock()
				if due {
					m.flush(ctx)
				}
			}
		}
	}()
}

// stopFlusher 停上报协程并等其收尾（幂等）。
func (m *memReporter) stopFlusher() {
	if m.stop == nil {
		return
	}
	m.stopOnce.Do(func() { close(m.stop) })
	<-m.done
}

// flush 把未确认增量交给 onFlush；成功才推进游标。失败不动游标，下个周期重发。
func (m *memReporter) flush(ctx context.Context) {
	m.mu.Lock()
	if !m.inflight || m.onFlush == nil {
		m.mu.Unlock()
		return
	}
	inc := Result{
		Findings:       m.res.Findings[m.sentF:],
		Assets:         m.res.Assets[m.sentA:],
		Logs:           m.res.Logs[m.sentL:],
		Traffic:        m.res.Traffic[m.sentT:],
		Knowledge:      m.res.Knowledge[m.sentK:],
		FindingUpdates: m.updatedLocked(),
	}
	m.mu.Unlock()
	if err := m.onFlush(ctx, m.brief, inc); err != nil {
		return
	}
	m.mu.Lock()
	m.lastFlush = time.Now()
	m.sentF += len(inc.Findings)
	m.sentA += len(inc.Assets)
	m.sentL += len(inc.Logs)
	m.sentT += len(inc.Traffic)
	m.sentK += len(inc.Knowledge)
	// 上报期间又有新增 → 仍待发
	m.inflight = m.sentF != len(m.res.Findings) || m.sentA != len(m.res.Assets) ||
		m.sentL != len(m.res.Logs) || m.sentT != len(m.res.Traffic) ||
		m.sentK != len(m.res.Knowledge)
	m.mu.Unlock()
}

// ---- tools.Reporter 接口实现 ----

func (m *memReporter) SaveAsset(_ context.Context, typ, value string, meta map[string]any) {
	detail := ""
	if meta != nil {
		if s, ok := meta["detail"].(string); ok {
			detail = s
		}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.res.Assets = append(m.res.Assets, Asset{Type: typ, Value: value, Detail: detail})
	m.flushLocked()
}

func (m *memReporter) SaveFinding(_ context.Context, f tools.Finding) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	// 同名同目标在本地即合并（server 侧按同一键落库）：返回的本地编号始终指向
	// 该发现的规范条目，后续 finding_step / update_finding 才落到 server 上那一条。
	// 并入时只补空字段，不覆盖已有的更详细信息。
	for i := range m.res.Findings {
		e := &m.res.Findings[i]
		if e.Name != f.Name || e.Target != f.Target {
			continue
		}
		if e.Detail == "" {
			e.Detail = f.Detail
		}
		if e.Evidence == "" {
			e.Evidence = f.Evidence
		}
		if e.PoC == "" {
			e.PoC = f.PoC
		}
		if e.Severity == "" {
			e.Severity = f.Severity
		}
		e.Steps = append(e.Steps, f.Steps...)
		m.markDirtyLocked(int64(i + 1))
		m.flushLocked()
		return int64(i + 1), nil
	}
	m.res.Findings = append(m.res.Findings, Finding{
		Name: f.Name, Severity: f.Severity, Target: f.Target, Detail: f.Detail,
		Evidence: f.Evidence, PoC: f.PoC, Status: f.Status, Steps: f.Steps,
	})
	m.flushLocked()
	return int64(len(m.res.Findings)), nil // 1 起的本地编号
}

// UpdateFinding 更新已有发现。patch 键：status / detail / evidence / poc（覆盖）、
// note（验证说明，附在详情末尾）、step（追加一步利用链）、steps（整体替换）。
// 更新过的发现标脏，随下次增量上报同步到 server——原先只改内存，而发现通常
// 在创建后几秒内就已上报，之后的「确认为真 / 误报」与补充的步骤 server 永远
// 收不到。
func (m *memReporter) UpdateFinding(_ context.Context, id int64, patch map[string]any) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if id < 1 || int(id) > len(m.res.Findings) {
		return fmt.Errorf("finding #%d 不存在", id)
	}
	f := &m.res.Findings[id-1]
	if s, ok := patch["status"].(string); ok {
		f.Status = s
	}
	if s, ok := patch["detail"].(string); ok {
		f.Detail = s
	}
	if s, ok := patch["evidence"].(string); ok {
		f.Evidence = s
	}
	if s, ok := patch["poc"].(string); ok {
		f.PoC = s
	}
	if note, ok := patch["note"].(string); ok && strings.TrimSpace(note) != "" {
		tag := "核验说明"
		switch f.Status {
		case "confirmed":
			tag = "核验确认"
		case "false_positive":
			tag = "误报判定"
		}
		f.Detail = strings.TrimRight(f.Detail, " \n") + fmt.Sprintf("\n\n【%s】%s", tag, note)
	}
	if st, ok := patch["step"].(tools.FindingStep); ok {
		f.Steps = append(f.Steps, st)
	}
	if ss, ok := patch["steps"].([]tools.FindingStep); ok {
		f.Steps = ss
	}
	m.markDirtyLocked(id)
	m.flushLocked()
	return nil
}

// markDirtyLocked 记下被更新过的发现（持锁调用）。
func (m *memReporter) markDirtyLocked(id int64) {
	if m.dirtySet == nil {
		m.dirtySet = map[int64]bool{}
	}
	if !m.dirtySet[id] {
		m.dirtySet[id] = true
		m.dirtyIDs = append(m.dirtyIDs, id)
	}
}

// updatedLocked 取自上次上报以来被更新过的发现（最新状态）并清空脏标记。
// 尽力而为：这一路丢了也不要紧——任务收尾的最终结果会全量对账。
func (m *memReporter) updatedLocked() []Finding {
	if len(m.dirtyIDs) == 0 {
		return nil
	}
	out := make([]Finding, 0, len(m.dirtyIDs))
	for _, id := range m.dirtyIDs {
		out = append(out, m.res.Findings[id-1])
	}
	m.dirtyIDs, m.dirtySet = nil, nil
	return out
}

func (m *memReporter) SaveEvidence(_ context.Context, typ, content string, meta map[string]any) {
	detail := typ
	if meta != nil {
		if s, ok := meta["detail"].(string); ok && s != "" {
			detail = s
		}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.res.Logs = append(m.res.Logs, LogItem{Stage: "evidence", Tool: "evidence",
		Content: detail + ": " + tools.Truncate(content, 2000)})
	m.flushLocked()
}

// SaveTraffic 结构化流量录制（蓝本 record_traffic 落 TrafficLog，节点回传 server）。
func (m *memReporter) SaveTraffic(_ context.Context, method, rawURL, reqBody string,
	status int, snippet, sourceTool string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.res.Traffic = append(m.res.Traffic, TrafficItem{
		Method: method, URL: rawURL, RequestBody: tools.Truncate(reqBody, 4000),
		Status: status, ResponseSnippet: tools.Truncate(snippet, 4000),
		SourceTool: sourceTool,
	})
	m.flushLocked()
}

// SaveSession 会话上报（复用 assets 通道 type=session，零迁移；server 侧
// ReplayTraffic 查最新会话附 cookie——pull 架构下重放带认证的唯一途径）。
func (m *memReporter) SaveSession(ctx context.Context, baseURL, user string, cookies map[string]string) {
	detail, _ := json.Marshal(map[string]any{"user": user, "cookies": cookies})
	m.SaveAsset(ctx, "session", baseURL, map[string]any{
		"detail": string(detail), "source": "web_login",
	})
}

// SaveKnowledge 沉淀经验：入会话知识（供本任务内 SearchKnowledge），并经增量
// 通道结构化回传 server 落知识库（api.SaveKnowledgeAuto：去重、标来源与适用
// 范围）。原先只写一条日志行、server 从不入库——任务一结束经验就丢了。
func (m *memReporter) SaveKnowledge(_ context.Context, k tools.Knowledge) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.kSeq++
	m.knowledge = append(m.knowledge, knowledgeEntry{
		id: fmt.Sprintf("k%d", m.kSeq), title: k.Title, content: k.Content})
	m.res.Knowledge = append(m.res.Knowledge, k)
	m.res.Logs = append(m.res.Logs, LogItem{Stage: "knowledge", Tool: "knowledge_save",
		Content: "📘 已沉淀到知识库：" + k.Title})
	m.flushLocked()
	return nil
}

// SearchKnowledge 会话内知识检索（本任务沉淀的条目，BM25，标题加权于正文；
// 与 server 侧知识库同一套打分）。跨任务的知识库由 server 排序后以索引形式
// 随任务书注入，全文用 knowledge_get 拉取。
func (m *memReporter) SearchKnowledge(_ context.Context, query string, limit int) []map[string]any {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.knowledge) == 0 || strings.TrimSpace(query) == "" {
		return nil
	}
	if limit <= 0 {
		limit = 5
	}
	byID := map[string]knowledgeEntry{}
	docs := make([]rank.Doc, 0, len(m.knowledge))
	for _, kv := range m.knowledge {
		byID[kv.id] = kv
		docs = append(docs, rank.Doc{ID: kv.id, Text: rank.Weighted(kv.title, "", "", kv.content)})
	}
	hits := rank.New(docs).Search(query, limit)
	res := make([]map[string]any, 0, len(hits))
	for _, h := range hits {
		kv := byID[h.ID]
		res = append(res, map[string]any{
			"id": kv.id, "snippet": tools.Truncate(kv.title+"\n"+kv.content, 600),
			"score": h.Score,
		})
	}
	return res
}

// knowledgeEntry 会话内知识条目。
type knowledgeEntry struct {
	id, title, content string
}

func (m *memReporter) Log(_ context.Context, actor, stage, message string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.res.Logs = append(m.res.Logs, LogItem{Stage: stage, Tool: actor, Content: message})
	m.flushLocked()
}

func (m *memReporter) LLMDesc() string {
	return modelDesc(m.brief.LLM)
}

// AssetCount 会话内已发现资产数（自适应步数预算用）。必须导出：agent 循环
// 用类型断言找 AssetCount()，原先只有未导出的 assetCount，断言永远不成立，
// 运行中的预算上调因此是死代码。
func (m *memReporter) AssetCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.res.Assets)
}

// FindingCount 会话内发现数（收工前盲区审查用）。
func (m *memReporter) FindingCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.res.Findings)
}
