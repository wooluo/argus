// Package rank 轻量文本检索：中英混合分词 + BM25。知识库共用一套打分——
// 节点侧的会话内知识（pipeline 的 SearchKnowledge）与 server 侧的持久知识库
// （api 的 KnowledgeIndexFor）同一实现。纯标准库，无外部依赖。
package rank

import (
	"math"
	"sort"
	"strings"
)

// Tokens 中英混合分词：≥2 字符的英数词 + 相邻汉字 bigram。
func Tokens(s string) []string {
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
	runes := []rune(s)
	for i := 0; i+1 < len(runes); i++ {
		if isHan(runes[i]) && isHan(runes[i+1]) {
			toks = append(toks, string(runes[i:i+2]))
		}
	}
	return toks
}

func isHan(r rune) bool { return r >= 0x4e00 && r <= 0x9fff }

// Doc 待检索文档。Text 用 Weighted 拼各字段即可获得字段加权。
type Doc struct {
	ID   string
	Text string
}

// Scored 命中结果。
type Scored struct {
	ID    string
	Score float64
}

// Index BM25 索引（k1=1.5 / b=0.75：词频饱和 + 文档长度归一）。
type Index struct {
	ids   []string
	tfs   []map[string]int
	dls   []float64
	avgdl float64
	df    map[string]int
}

// New 建索引：预计算各文档词频、长度与全局文档频率。
func New(docs []Doc) *Index {
	ix := &Index{df: map[string]int{}}
	for _, d := range docs {
		toks := Tokens(d.Text)
		tf := map[string]int{}
		for _, t := range toks {
			tf[t]++
			if tf[t] == 1 {
				ix.df[t]++
			}
		}
		ix.ids = append(ix.ids, d.ID)
		ix.tfs = append(ix.tfs, tf)
		ix.dls = append(ix.dls, float64(len(toks)))
		ix.avgdl += float64(len(toks))
	}
	if n := float64(len(docs)); n > 0 {
		ix.avgdl /= n
	}
	if ix.avgdl < 1 {
		ix.avgdl = 1
	}
	return ix
}

// Search 返回得分 > 0 的文档，按得分降序（同分保持录入顺序），最多 limit 条。
func (ix *Index) Search(query string, limit int) []Scored {
	if ix == nil {
		return nil
	}
	tokens := Tokens(query)
	if len(ix.ids) == 0 || len(tokens) == 0 {
		return nil
	}
	const k1, b = 1.5, 0.75
	n := float64(len(ix.ids))
	out := make([]Scored, 0, len(ix.ids))
	for i := range ix.ids {
		score := 0.0
		for _, q := range tokens {
			c := ix.tfs[i][q]
			if c == 0 {
				continue
			}
			// idf: ln(1 + (N - df + 0.5) / (df + 0.5))
			idf := math.Log(1 + (n-float64(ix.df[q])+0.5)/(float64(ix.df[q])+0.5))
			norm := 1 - b + b*ix.dls[i]/ix.avgdl
			score += idf * float64(c) * (k1 + 1) / (float64(c) + k1*norm)
		}
		if score > 0 {
			out = append(out, Scored{ID: ix.ids[i], Score: score})
		}
	}
	if len(out) == 0 {
		return nil
	}
	sort.SliceStable(out, func(a, b int) bool { return out[a].Score > out[b].Score })
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}

// Weighted 字段加权：标题重复 3 次、说明与标签各 2 次后拼接正文——BM25 的
// 词频项随即给这些字段加权（标题命中比正文命中更相关）。
func Weighted(title, summary, tags, content string) string {
	return strings.Repeat(title+" ", 3) + strings.Repeat(summary+" ", 2) +
		strings.Repeat(tags+" ", 2) + content
}
