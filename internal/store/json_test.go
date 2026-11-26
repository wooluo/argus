package store

import (
	"encoding/json"
	"path/filepath"
	"testing"
)

func TestNormalizeJSON(t *testing.T) {
	cases := map[string]string{
		"":                "{}",
		"   ":             "{}",
		`{"a":1}`:         `{"a":1}`,
		`[1,2]`:           `[1,2]`,
		"not json":        `{"_raw":"not json"}`,
		`{"broken": true`: `{"_raw":"{\"broken\": true"}`,
	}
	for in, want := range cases {
		if got := NormalizeJSON(in); got != want {
			t.Errorf("NormalizeJSON(%q) = %q，应为 %q", in, got, want)
		}
	}
}

// 一条不合法的 RawJSON 曾让整份响应体为空（状态码仍是 200）：资产中心因此
// 整页空白。序列化永远要成功。
func TestRawJSONMarshalNeverBreaksResponse(t *testing.T) {
	cases := map[string]string{
		"":           `{"d":null}`,
		"  ":         `{"d":null}`,
		`{"a":1}`:    `{"d":{"a":1}}`,
		`[1]`:        `{"d":[1]}`,
		"garbage":    `{"d":{"_invalid":"garbage"}}`,
		`{"x": true`: `{"d":{"_invalid":"{\"x\": true"}}`,
	}
	for in, want := range cases {
		b, err := json.Marshal(struct {
			D RawJSON `json:"d"`
		}{RawJSON(in)})
		if err != nil || string(b) != want {
			t.Errorf("RawJSON(%q) → %s, %v，应为 %s", in, b, err, want)
		}
	}
}

// 老库里的资产 detail 是空串：启动时修成 {}。
func TestOpenFixesEmptyAssetDetail(t *testing.T) {
	path := filepath.Join(t.TempDir(), "argus.db")
	db, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO projects(id,name,scope,authorized) VALUES(1,'甲','[]',1),
		(2,'乙','[]',1)`); err != nil {
		t.Fatal(err)
	}
	// 绕过 NormalizeJSON 直接写，模拟修复上线前入库的旧数据
	if _, err := db.Exec(`INSERT INTO assets(project_id,type,value,detail) VALUES
		(1,'domain','a.test',''),(1,'url','https://a.test','{"status_code":200}'),(2,'ip','1.1.1.1','')`); err != nil {
		t.Fatal(err)
	}
	db.Close()

	db, err = Open(path)
	if err != nil {
		t.Fatalf("重新打开: %v", err)
	}
	defer db.Close()
	var bad int
	if err := db.QueryRow(`SELECT COUNT(*) FROM assets WHERE NOT json_valid(detail)`).Scan(&bad); err != nil || bad != 0 {
		t.Fatalf("重新打开后仍有 %d 条 detail 不合法（%v）", bad, err)
	}
	var d string
	if err := db.QueryRow(`SELECT detail FROM assets WHERE value='a.test'`).Scan(&d); err != nil || d != "{}" {
		t.Fatalf("空串应修成 {}: %q %v", d, err)
	}
	if err := db.QueryRow(`SELECT detail FROM assets WHERE value='https://a.test'`).Scan(&d); err != nil || d != `{"status_code":200}` {
		t.Fatalf("合法的不应被改动: %q %v", d, err)
	}
}
