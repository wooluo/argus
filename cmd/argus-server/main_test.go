package main

import (
	"os"
	"path/filepath"
	"testing"
)

// 日志文件打不开不能挡住启动；设 off 就不建文件。
func TestOpenLogFile(t *testing.T) {
	dir := t.TempDir()
	def := filepath.Join(dir, "argus-server.log")
	f, path := openLogFile(dir)
	if f == nil || path != def {
		t.Fatalf("默认日志文件 = %v, %q，应为 %s", f, path, def)
	}
	f.Close()
	if _, err := os.Stat(def); err != nil {
		t.Fatalf("日志文件没建出来: %v", err)
	}

	custom := filepath.Join(dir, "sub", "x.log")
	if err := os.MkdirAll(filepath.Dir(custom), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ARGUS_LOG", custom)
	f, path = openLogFile(dir)
	if f == nil || path != custom {
		t.Fatalf("ARGUS_LOG 指定后 = %v, %q，应为 %s", f, path, custom)
	}
	f.Close()

	t.Setenv("ARGUS_LOG", "off")
	if f, _ = openLogFile(dir); f != nil {
		f.Close()
		t.Fatal("ARGUS_LOG=off 时不应打开日志文件")
	}

	t.Setenv("ARGUS_LOG", filepath.Join(dir, "missing-dir", "x.log"))
	if f, _ = openLogFile(dir); f != nil {
		f.Close()
		t.Fatal("目录不存在时应返回 nil，让 server 照常启动")
	}
}
