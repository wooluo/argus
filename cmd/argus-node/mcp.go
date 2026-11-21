// mcp.go: MCP（Model Context Protocol）动态工具注入（移植蓝本 core/mcp_tools.py）。
// server 经 Poll 下发启用的 MCP 服务器配置 → 节点 initialize + tools/list →
// 每个远端工具包装为本地 tools.Tool（命名 mcp_<server>_<tool>）注册进全局
// Registry，agent 即可直接调用。协议：Streamable HTTP + JSON-RPC（Bearer）。
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/wooluo/argus/internal/tools"
)

// mcpServer Poll 下发的 MCP 服务器配置（settings.mcp 中 enabled 的条目）。
type mcpServer struct {
	ID      string `json:"id"`
	URL     string `json:"url"`
	Token   string `json:"token"`
	Timeout int    `json:"timeout"` // 秒，0=默认 30
}

var mcpHTTP = &http.Client{Timeout: 30 * time.Second}

// mcpToolEntry 远端工具清单条目。
type mcpToolEntry struct {
	Name   string         `json:"name"`
	Desc   string         `json:"description"`
	Schema map[string]any `json:"inputSchema"`
}

// registerMCPTools 拉取远端工具清单并注册为本地工具；单个服务器失败不致命。
func registerMCPTools(servers []mcpServer) int {
	n := 0
	for _, s := range servers {
		if strings.TrimSpace(s.URL) == "" {
			continue
		}
		list, err := mcpToolsList(s)
		if err != nil {
			log.Printf("[mcp] %s 工具清单获取失败: %v（跳过）", s.ID, err)
			continue
		}
		for _, t := range list {
			tools.Register(&mcpTool{srv: s, name: t.Name, desc: t.Desc, schema: t.Schema})
			n++
		}
		log.Printf("[mcp] %s 注入 %d 个工具", s.ID, len(list))
	}
	return n
}

// mcpTool 远端 MCP 工具的本地包装。
type mcpTool struct {
	srv    mcpServer
	name   string
	desc   string
	schema map[string]any
}

func (t *mcpTool) Name() string { return "mcp_" + t.srv.ID + "_" + t.name }

func (t *mcpTool) Description() string {
	d := t.desc
	if len(d) > 300 {
		d = d[:300]
	}
	return fmt.Sprintf("[MCP:%s] %s", t.srv.ID, d)
}

func (t *mcpTool) Parameters() map[string]any {
	if t.schema != nil {
		return t.schema
	}
	return map[string]any{"type": "object"}
}

func (t *mcpTool) Execute(ctx context.Context, args map[string]any, _ *tools.Context) (string, error) {
	timeout := 60 * time.Second
	if t.srv.Timeout > 0 {
		timeout = time.Duration(t.srv.Timeout) * time.Second
	}
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	body, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": "tools/call",
		"params": map[string]any{"name": t.name, "arguments": args},
	})
	req, err := http.NewRequestWithContext(cctx, http.MethodPost, t.srv.URL, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	if t.srv.Token != "" {
		req.Header.Set("Authorization", "Bearer "+t.srv.Token)
	}
	resp, err := mcpHTTP.Do(req)
	if err != nil {
		return "", tools.Errorf("MCP 调用失败: %v", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != 200 {
		return "", tools.Errorf("MCP HTTP %d: %s", resp.StatusCode, tools.Truncate(string(raw), 300))
	}
	// Streamable HTTP 可能回 SSE 帧（data: {...}）——取首个 JSON 对象
	payload := mcpUnframe(raw)
	var out struct {
		Result struct {
			Content []struct {
				Type string `json:"type"`
				Text string `json:"text"`
			} `json:"content"`
			IsError bool `json:"isError"`
		} `json:"result"`
		Error *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(payload, &out); err != nil {
		return "", tools.Errorf("MCP 响应解析失败: %v", err)
	}
	if out.Error != nil {
		return "", tools.Errorf("MCP 错误: %s", out.Error.Message)
	}
	var texts []string
	for _, c := range out.Result.Content {
		if c.Type == "text" || c.Type == "" {
			texts = append(texts, c.Text)
		} else {
			texts = append(texts, fmt.Sprintf("[%s]", c.Type))
		}
	}
	res := strings.Join(texts, "\n")
	if out.Result.IsError {
		return "", tools.Errorf("MCP 工具执行错误: %s", tools.Truncate(res, 400))
	}
	return tools.Truncate(res, 6000), nil
}

// mcpToolsList initialize + tools/list，返回远端工具清单。
func mcpToolsList(s mcpServer) ([]mcpToolEntry, error) {
	timeout := 15 * time.Second
	if s.Timeout > 0 {
		timeout = time.Duration(s.Timeout) * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	var none []mcpToolEntry
	// initialize（结果丢弃，仅握手）
	initBody, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": "initialize",
		"params": map[string]any{
			"protocolVersion": "2024-11-05",
			"capabilities":    map[string]any{},
			"clientInfo":      map[string]any{"name": "argus-node", "version": "1.0"},
		},
	})
	if _, err := mcpPost(ctx, s, initBody); err != nil {
		return none, fmt.Errorf("initialize: %w", err)
	}
	listBody, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": map[string]any{}})
	raw, err := mcpPost(ctx, s, listBody)
	if err != nil {
		return none, fmt.Errorf("tools/list: %w", err)
	}
	var out struct {
		Result struct {
			Tools []mcpToolEntry `json:"tools"`
		} `json:"result"`
	}
	if err := json.Unmarshal(mcpUnframe(raw), &out); err != nil {
		return none, fmt.Errorf("响应解析: %w", err)
	}
	return out.Result.Tools, nil
}

func mcpPost(ctx context.Context, s mcpServer, body []byte) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.URL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	if s.Token != "" {
		req.Header.Set("Authorization", "Bearer "+s.Token)
	}
	resp, err := mcpHTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("HTTP %d: %.200s", resp.StatusCode, string(raw))
	}
	return raw, nil
}

// mcpUnframe SSE 帧（data: 行）取首个 JSON；纯 JSON 原样返回。
func mcpUnframe(raw []byte) []byte {
	s := string(raw)
	if !strings.Contains(s, "data:") {
		return raw
	}
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "data:") {
			payload := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
			if payload != "" && payload[0] == '{' {
				return []byte(payload)
			}
		}
	}
	return raw
}
