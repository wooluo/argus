// Package pipeline 移植自 AutoPentest core/pipeline.py —— 任务执行流水线。
// 节点侧运行：Poll 领任务 → 组装 Brief → Run() 执行（staged/autonomous）
// → Result 经 /api/nodes/result 回传 server 落库。
package pipeline

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/wooluo/argus/internal/agent"
	"github.com/wooluo/argus/internal/llm"
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
	Knowledge   string       `json:"knowledge"`   // server 注入的知识库块（跨任务经验）
	Scope       []scope.Rule `json:"scope"`
	AllowHosts  []string     `json:"allow_hosts"`
	LLM         llm.Config   `json:"llm"`
	// HITL 审批门：名单由 server Poll 下发，门实现由节点注入（HTTP 回连）。
	ApprovalsRequire []string           `json:"approvals_require"`
	ApprovalGate     agent.ApprovalGate `json:"-"`
}

// Finding / Asset / LogItem 与 server ReportResult 请求体字段一一对应。
type Finding struct {
	Name     string `json:"name"`
	Severity string `json:"severity"`
	Target   string `json:"target"`
	Detail   string `json:"detail"`
	Evidence string `json:"evidence"`
	PoC      string `json:"poc"`
	Status   string `json:"status"` // 本地状态（pending/confirmed/false_positive），回传时丢弃
	Steps    []string
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
	Status   string    `json:"status"` // done | failed
	Message  string    `json:"message"`
	Findings []Finding `json:"findings"`
	Assets   []Asset   `json:"assets"`
	Logs     []LogItem `json:"logs"`
	Report   string    `json:"report"`
	Tokens   map[string]int64 `json:"tokens,omitempty"`
}

// memReporter 缓冲式 Reporter：工具产出先攒在内存（阶段间 _data_summary 直接
// 读缓冲，替代原版查库），flush 回调把新增条目增量推给 server（长任务可见进度）。
type memReporter struct {
	mu      sync.Mutex
	res     *Result
	sentF   int
	sentA   int
	sentL   int
	onFlush   func(Brief, Result) // 可选：增量上报（只带新增条目）
	brief     Brief
	knowledge []knowledgeEntry // 会话内知识（SaveKnowledge 入此，供 SearchKnowledge）
	kSeq      int
}

func (m *memReporter) flushLocked() {
	if m.onFlush == nil {
		return
	}
	inc := Result{
		Findings: m.res.Findings[m.sentF:],
		Assets:   m.res.Assets[m.sentA:],
		Logs:     m.res.Logs[m.sentL:],
	}
	if len(inc.Findings) == 0 && len(inc.Assets) == 0 && len(inc.Logs) == 0 {
		return
	}
	m.sentF, m.sentA, m.sentL = len(m.res.Findings), len(m.res.Assets), len(m.res.Logs)
	go m.onFlush(m.brief, inc)
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
	m.res.Findings = append(m.res.Findings, Finding{
		Name: f.Name, Severity: f.Severity, Target: f.Target, Detail: f.Detail,
		Evidence: f.Evidence, PoC: f.PoC, Status: f.Status,
	})
	m.flushLocked()
	return int64(len(m.res.Findings)), nil // 1 起的本地编号
}

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
	if ss, ok := patch["steps"].([]string); ok {
		f.Steps = ss
	}
	return nil
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

// SaveKnowledge 沉淀经验：经增量日志通道回传（server 侧可入库 knowledge）。
func (m *memReporter) SaveKnowledge(_ context.Context, title, content string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.kSeq++
	m.knowledge = append(m.knowledge, knowledgeEntry{
		id: fmt.Sprintf("k%d", m.kSeq), title: title, content: content})
	m.res.Logs = append(m.res.Logs, LogItem{Stage: "knowledge", Tool: "knowledge_save",
		Content: title + "\n" + tools.Truncate(content, 4000)})
	m.flushLocked()
	return nil
}

// SearchKnowledge 会话内知识检索（本任务沉淀的条目，BM25 简化打分：
// 词频×逆文档频率；跨任务知识由 server 在任务书注入 Brief，不走此路径）。
func (m *memReporter) SearchKnowledge(_ context.Context, query string, limit int) []map[string]any {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.knowledge) == 0 || strings.TrimSpace(query) == "" {
		return nil
	}
	if limit <= 0 {
		limit = 5
	}
	// 分词：英文词 + 中文单字 bigram（与原版 BM25 一致）
	tokens := tokenize(query)
	type scored struct {
		s   float64
		kv  knowledgeEntry
	}
	var out []scored
	for _, kv := range m.knowledge {
		docT := tokenize(kv.title + " " + kv.content)
		tf := map[string]int{}
		for _, t := range docT {
			tf[t]++
		}
		score := 0.0
		for _, q := range tokens {
			if c, ok := tf[q]; ok && c > 0 {
				idf := 1.0 + float64(len(m.knowledge))/float64(c+1)
				score += idf * float64(c)
			}
		}
		if score > 0 {
			out = append(out, scored{score, kv})
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].s > out[j].s })
	if len(out) > limit {
		out = out[:limit]
	}
	res := make([]map[string]any, 0, len(out))
	for _, o := range out {
		res = append(res, map[string]any{
			"id": o.kv.id, "snippet": tools.Truncate(o.kv.title+"\n"+o.kv.content, 600),
			"score": o.s,
		})
	}
	return res
}

// knowledgeEntry 会话内知识条目。
type knowledgeEntry struct {
	id, title, content string
}

// tokenize 中英混合分词：>=2 字符的英数词 + 相邻汉字 bigram。
func tokenize(s string) []string {
	var toks []string
	var word []rune
	flush := func() {
		if len(word) >= 2 {
			toks = append(toks, string(word))
		}
		word = word[:0]
	}
	for _, r := range strings.ToLower(s) {
		switch {
		case r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '_':
			word = append(word, r)
		default:
			flush()
		}
	}
	flush()
	// 汉字 bigram
	runes := []rune(s)
	for i := 0; i+1 < len(runes); i++ {
		if isHan(runes[i]) && isHan(runes[i+1]) {
			toks = append(toks, string(runes[i:i+2]))
		}
	}
	return toks
}

func isHan(r rune) bool { return r >= 0x4e00 && r <= 0x9fff }

func (m *memReporter) Log(_ context.Context, actor, stage, message string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.res.Logs = append(m.res.Logs, LogItem{Stage: stage, Tool: actor, Content: message})
	m.flushLocked()
}

func (m *memReporter) LLMDesc() string {
	host := m.brief.LLM.BaseURL
	if i := strings.Index(host, "://"); i >= 0 {
		host = host[i+3:]
	}
	if i := strings.Index(host, "/"); i >= 0 {
		host = host[:i]
	}
	if host == "" {
		host = "?"
	}
	return m.brief.LLM.Model + " @ " + host
}

// assetCount 会话内已发现资产数（自适应步数预算用）。
func (m *memReporter) assetCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.res.Assets)
}
