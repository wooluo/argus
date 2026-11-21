package api

// docx_test.go: Markdown → docx 渲染回归（防死循环/结构缺失）。

import (
	"archive/zip"
	"bytes"
	"io"
	"strings"
	"testing"
	"time"
)

func TestRenderDocx(t *testing.T) {
	md := "# 标题一\n\n正文 **加粗** 与 `代码`。\n\n" +
		"| 名称 | 级别 |\n|---|---|\n| SQL注入 | 高 |\n\n" +
		"> 引用行\n\n- 列表项\n\n```\ncode block\nline2\n```\n"
	done := make(chan []byte, 1)
	go func() { done <- renderDocx(md) }()
	var b []byte
	select {
	case b = <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("renderDocx 死循环（超时 3s）")
	}
	// zip 魔数 + 解压读 document.xml
	if len(b) < 4 || b[0] != 'P' || b[1] != 'K' {
		t.Fatalf("非 zip 输出: %x", b[:4])
	}
	zr, err := zip.NewReader(bytes.NewReader(b), int64(len(b)))
	if err != nil {
		t.Fatalf("zip 打开失败: %v", err)
	}
	var doc string
	for _, f := range zr.File {
		if f.Name == "word/document.xml" {
			rc, _ := f.Open()
			raw, _ := io.ReadAll(rc)
			rc.Close()
			doc = string(raw)
		}
	}
	if doc == "" {
		t.Fatal("zip 中无 word/document.xml")
	}
	for _, want := range []string{"<w:tbl>", "<w:b/>", "Consolas", "标题一", "SQL注入"} {
		if !strings.Contains(doc, want) {
			t.Fatalf("document.xml 缺少 %q", want)
		}
	}
}
