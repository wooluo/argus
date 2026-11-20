// 覆盖率严格测度（对齐原 core/coverage.py）：
// 每个资产（url/host/domain/ip）为一个测试等价类，
// 覆盖率 = 被本任务审计日志（思考/调用/结果）触及的等价类 / 全部等价类。
package store

import (
	"database/sql"
	"math"
	"strconv"
	"strings"
)

// CoverageStats: 覆盖率统计（供任务书/提醒注入）。
// taskID<=0 时统计项目全部任务的日志。
func CoverageStats(db *sql.DB, projectID, taskID int64) (total, tested int, untested []string) {
	rows, err := db.Query(`SELECT value FROM assets
		WHERE project_id=? AND type IN ('url','host','domain','ip')`, projectID)
	if err != nil {
		return 0, 0, nil
	}
	var values []string
	for rows.Next() {
		var v string
		if rows.Scan(&v) == nil && v != "" {
			values = append(values, v)
		}
	}
	rows.Close()

	logQ := `SELECT content,result_summary FROM agent_logs WHERE task_id=?`
	var args []any
	args = append(args, taskID)
	if taskID <= 0 {
		logQ = `SELECT l.content,l.result_summary FROM agent_logs l
			JOIN tasks t ON t.id=l.task_id WHERE t.project_id=?`
		args = args[:0]
		args = append(args, projectID)
	}
	lrows, err := db.Query(logQ, args...)
	if err != nil {
		return len(values), 0, values
	}
	var blob strings.Builder
	for lrows.Next() {
		var c, s sql.NullString
		if lrows.Scan(&c, &s) == nil {
			blob.WriteString(c.String)
			blob.WriteString("\n")
			blob.WriteString(s.String)
		}
	}
	lrows.Close()
	b := blob.String()

	testedSet := map[string]bool{}
	for _, v := range values {
		base := strings.SplitN(v, "?", 2)[0]
		if strings.Contains(b, v) || (base != v && strings.Contains(b, base)) {
			testedSet[v] = true
		}
	}
	for _, v := range values {
		if !testedSet[v] {
			untested = append(untested, v)
		}
	}
	return len(values), len(testedSet), untested
}

// CoverageDescribe: 人话摘要行（注入提醒/复盘）。
func CoverageDescribe(db *sql.DB, projectID, taskID int64) string {
	total, tested, untested := CoverageStats(db, projectID, taskID)
	if total == 0 {
		return "覆盖率: 暂无资产等价类"
	}
	ratio := float64(tested) / float64(total)
	if math.IsNaN(ratio) {
		ratio = 0
	}
	sample := untested
	if len(sample) > 4 {
		sample = sample[:4]
	}
	s := "（无）"
	if len(sample) > 0 {
		s = strings.Join(sample, ", ")
	}
	return "覆盖率 " + strconv.Itoa(int(math.Round(ratio*100))) + "%（已触及 " + strconv.Itoa(tested) + "/" + strconv.Itoa(total) +
		" 个资产等价类）；未测样例: " + s
}
