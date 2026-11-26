package pipeline

import (
	"strings"
	"testing"
)

// 报告中的证据必须脱敏（Cookie / Authorization / token / secret）。
func TestRedactEvidence(t *testing.T) {
	cases := map[string]string{
		`正常文本`:                         `正常文本`,
		`Cookie: abc123`:               `Cookie: ***`,
		`Authorization: Bearer tok123`: `Authorization: ***`,
		`url?token=abc&id=1`:           `token=***`,
		`secret=my-secret-key`:         `secret=***`,
		`api_key=sk-test123`:           `api_key=***`,
	}
	for input, expected := range cases {
		got := redactEvidence(input)
		if !strings.Contains(got, expected) {
			t.Errorf("redactEvidence(%q) → %q，未包含预期 %q", input, got, expected)
		}
	}
}

// pending 发现不应出现在确认漏洞列表里——genReport 会在 facts 里
// 把它们放在"待核实"节。
func TestFindingSplitByStatus(t *testing.T) {
	findings := []struct {
		name   string
		status string
		isConf bool
		isPen  bool
		isFP   bool
	}{
		{"已确认", "confirmed", true, false, false},
		{"已验证", "verified", true, false, false},
		{"待核实", "pending", false, true, false},
		{"待核实2", "", false, true, false},
		{"误报", "false_positive", false, false, true},
	}
	for _, f := range findings {
		s := f.status
		isConf := s != "pending" && s != "" && s != "false_positive"
		isPen := s == "pending" || s == ""
		isFP := s == "false_positive"
		if isConf != f.isConf || isPen != f.isPen || isFP != f.isFP {
			t.Errorf("finding %q status=%q → conf=%v pen=%v fp=%v，期待 conf=%v pen=%v fp=%v",
				f.name, f.status, isConf, isPen, isFP, f.isConf, f.isPen, f.isFP)
		}
	}
}
