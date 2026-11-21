package api

// docx.go: Markdown → Word（.docx）导出，移植蓝本 core/report.py render_docx。
// 零第三方依赖：手写最小 OOXML（zip: [Content_Types].xml + document.xml +
// _rels/.rels + word/_rels/document.xml.rels），标题/段落/表格/代码块/加粗/行内代码。
// 中文等宽：代码块用等宽字体段落 + 灰底省略（shading 需 styles.xml，从简）。

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io"
	"strings"
)

// renderDocx 把 Markdown 渲染为 .docx 字节流。
func renderDocx(md string) []byte {
	var doc strings.Builder
	doc.WriteString(`<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body>`)

	lines := strings.Split(md, "\n")
	i := 0
	for i < len(lines) {
		line := lines[i]
		trimmed := strings.TrimSpace(line)
		switch {
		case trimmed == "":
			i++
		case strings.HasPrefix(trimmed, "```"):
			// 代码块：等宽小字号逐行
			i++
			var code []string
			for i < len(lines) && !strings.HasPrefix(strings.TrimSpace(lines[i]), "```") {
				code = append(code, lines[i])
				i++
			}
			if i < len(lines) {
				i++ // 跳过收尾 ```
			}
			for _, cl := range code {
				doc.WriteString(docxPara(xmlEscape(cl), docxRunOpts{mono: true, size: 18}))
			}
		case strings.HasPrefix(trimmed, "|") && i+1 < len(lines) &&
			strings.HasPrefix(strings.TrimSpace(lines[i+1]), "|"):
			// 表格：| a | b |（下一行是 |---|---| 分隔）
			var rows [][]string
			for i < len(lines) && strings.HasPrefix(strings.TrimSpace(lines[i]), "|") {
				cells := splitTableRow(strings.TrimSpace(lines[i]))
				if !isTableDivider(cells) {
					rows = append(rows, cells)
				}
				i++
			}
			doc.WriteString(docxTable(rows))
		default:
			// 标题 / 引用 / 列表 / 正文——单行渲染
			switch {
			case strings.HasPrefix(trimmed, "#"):
				level := 0
				for level < len(trimmed) && trimmed[level] == '#' {
					level++
				}
				if level > 4 {
					level = 4
				}
				doc.WriteString(docxHeading(xmlEscape(strings.TrimSpace(trimmed[level:])), level))
			case strings.HasPrefix(trimmed, ">"):
				doc.WriteString(docxPara(inlineRuns(strings.TrimSpace(strings.TrimPrefix(trimmed, ">"))),
					docxRunOpts{italic: true, size: 20}))
			case strings.HasPrefix(trimmed, "- ") || strings.HasPrefix(trimmed, "* "):
				doc.WriteString(docxPara("• "+inlineRuns(strings.TrimSpace(trimmed[2:])), docxRunOpts{}))
			default:
				doc.WriteString(docxPara(inlineRuns(trimmed), docxRunOpts{}))
			}
			i++
		}
	}
	doc.WriteString(`</w:body></w:document>`)

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	files := map[string]string{
		"[Content_Types].xml": `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
<Default Extension="xml" ContentType="application/xml"/>
<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
</Types>`,
		"_rels/.rels": `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
</Relationships>`,
		"word/_rels/document.xml.rels": `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>
</Relationships>`,
		"word/styles.xml": `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:styles xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
<w:docDefaults><w:rPrDefault><w:rPr>
<w:rFonts w:ascii="Calibri" w:eastAsia="Microsoft YaHei" w:hAnsi="Calibri"/>
<w:sz w:val="22"/>
</w:rPr></w:rPrDefault></w:docDefaults>
</w:styles>`,
		"word/document.xml": doc.String(),
	}
	for name, content := range files {
		f, _ := zw.Create(name)
		_, _ = io.WriteString(f, content)
	}
	_ = zw.Close()
	return buf.Bytes()
}

type docxRunOpts struct {
	mono   bool
	italic bool
	size   int // 半磅；0=默认 22（11pt）
}

func (o docxRunOpts) rPr() string {
	font, sz := "Calibri", 22
	if o.mono {
		font, sz = "Consolas", 18
	}
	if o.size > 0 {
		sz = o.size
	}
	rpr := fmt.Sprintf(`<w:rPr><w:rFonts w:ascii="%s" w:eastAsia="%s" w:hAnsi="%s"/><w:sz w:val="%d"/>`,
		font, font, font, sz)
	if o.italic {
		rpr += `<w:i/>`
	}
	return rpr + `</w:rPr>`
}

func docxPara(runsXML string, opts docxRunOpts) string {
	return `<w:p><w:pPr><w:spacing w:after="120"/></w:pPr>` +
		`<w:r>` + opts.rPr() + `<w:t xml:space="preserve">` + runsXML + `</w:t></w:r></w:p>`
}

func docxHeading(text string, level int) string {
	size := 40 - level*6 // H1=34半磅(17pt) H2=28 H3=22 H4=16... 至少 18
	if size < 18 {
		size = 18
	}
	opts := docxRunOpts{size: size}
	return `<w:p><w:pPr><w:spacing w:before="240" w:after="120"/></w:pPr>` +
		`<w:r><w:rPr><w:b/>` + strings.TrimPrefix(strings.TrimSuffix(opts.rPr(), "</w:rPr>"), "<w:rPr>") +
		`</w:rPr><w:t xml:space="preserve">` + text + `</w:t></w:r></w:p>`
}

func docxTable(rows [][]string) string {
	if len(rows) == 0 {
		return ""
	}
	cols := 0
	for _, r := range rows {
		if len(r) > cols {
			cols = len(r)
		}
	}
	var b strings.Builder
	b.WriteString(`<w:tbl><w:tblPr><w:tblBorders>`)
	for _, side := range []string{"top", "left", "bottom", "right", "insideH", "insideV"} {
		b.WriteString(fmt.Sprintf(
			`<w:%s w:val="single" w:sz="4" w:color="999999"/>`, side))
	}
	b.WriteString(`</w:tblBorders></w:tblPr>`)
	for ri, r := range rows {
		b.WriteString(`<w:tr>`)
		for ci := 0; ci < cols; ci++ {
			cell := ""
			if ci < len(r) {
				cell = r[ci]
			}
			b.WriteString(`<w:tc><w:tcPr>`)
			if ri == 0 {
				b.WriteString(`<w:shd w:val="clear" w:fill="EEEEEE"/>`)
			}
			b.WriteString(`</w:tcPr>`)
			opts := docxRunOpts{}
			if ri == 0 {
				opts = docxRunOpts{size: 20}
				b.WriteString(docxPara(xmlEscape(cell), opts))
			} else {
				b.WriteString(docxPara(xmlEscape(cell), opts))
			}
			b.WriteString(`</w:tc>`)
		}
		b.WriteString(`</w:tr>`)
	}
	b.WriteString(`</w:tbl>`)
	return b.String()
}

// inlineRuns 行内标记：**加粗**、`代码`（转义 + 分段 run）。
func inlineRuns(s string) string {
	var out strings.Builder
	rest := s
	for rest != "" {
		bIdx, cIdx := strings.Index(rest, "**"), strings.Index(rest, "`")
		switch {
		case bIdx >= 0 && (cIdx < 0 || bIdx < cIdx):
			out.WriteString(xmlEscape(rest[:bIdx]))
			end := strings.Index(rest[bIdx+2:], "**")
			if end < 0 {
				out.WriteString(xmlEscape(rest[bIdx:]))
				return out.String()
			}
			out.WriteString(`</w:t></w:r><w:r><w:rPr><w:b/></w:rPr><w:t xml:space="preserve">`)
			out.WriteString(xmlEscape(rest[bIdx+2 : bIdx+2+end]))
			out.WriteString(`</w:t></w:r><w:r><w:t xml:space="preserve">`)
			rest = rest[bIdx+2+end+2:]
		case cIdx >= 0:
			out.WriteString(xmlEscape(rest[:cIdx]))
			end := strings.Index(rest[cIdx+1:], "`")
			if end < 0 {
				out.WriteString(xmlEscape(rest[cIdx:]))
				return out.String()
			}
			out.WriteString(`</w:t></w:r><w:r><w:rPr><w:rFonts w:ascii="Consolas" w:eastAsia="Consolas" w:hAnsi="Consolas"/><w:sz w:val="20"/></w:rPr><w:t xml:space="preserve">`)
			out.WriteString(xmlEscape(rest[cIdx+1 : cIdx+1+end]))
			out.WriteString(`</w:t></w:r><w:r><w:t xml:space="preserve">`)
			rest = rest[cIdx+1+end+1:]
		default:
			out.WriteString(xmlEscape(rest))
			return out.String()
		}
	}
	return out.String()
}

func splitTableRow(line string) []string {
	line = strings.TrimPrefix(line, "|")
	line = strings.TrimSuffix(line, "|")
	parts := strings.Split(line, "|")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		out = append(out, strings.TrimSpace(p))
	}
	return out
}

func isTableDivider(cells []string) bool {
	for _, c := range cells {
		c = strings.ReplaceAll(strings.ReplaceAll(c, "-", ""), ":", "")
		if strings.TrimSpace(c) != "" {
			return false
		}
	}
	return true
}

func xmlEscape(s string) string {
	r := strings.NewReplacer(
		"&", "&amp;", "<", "&lt;", ">", "&gt;",
		`"`, "&quot;", "'", "&apos;",
	)
	return r.Replace(s)
}
