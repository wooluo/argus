// Package auth: Bearer Token 鉴权（与原 core/auth.py 语义一致）。
// Token 为空 = 本地模式放行全部请求（与原项目行为对齐）。
package auth

import (
	"crypto/subtle"
	"net/http"
	"strings"
	"sync"
)

type Middleware struct {
	mu    sync.RWMutex
	token string // 内存热更新（settings 表）
}

func New(token string) *Middleware {
	return &Middleware{token: token}
}

func (m *Middleware) SetToken(t string) {
	m.mu.Lock()
	m.token = t
	m.mu.Unlock()
}

// Token 当前管理 token（节点部署时下发给 argus-node 做注册凭证；
// 空串 = 本地模式，注册端点放行，节点任意 token 均可）。
func (m *Middleware) Token() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.token
}

func (m *Middleware) Enabled() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.token != ""
}

func (m *Middleware) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m.mu.RLock()
		tok := m.token
		m.mu.RUnlock()
		if tok == "" {
			next.ServeHTTP(w, r) // 本地模式
			return
		}
		// /api/auth/* 与健康检查豁免；节点注册同样需要管理 token（防开放注册）
		p := r.URL.Path
		if strings.HasPrefix(p, "/api/auth/") || p == "/healthz" {
			next.ServeHTTP(w, r)
			return
		}
		got := ""
		if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer ") {
			got = strings.TrimPrefix(h, "Bearer ")
		} else if q := r.URL.Query().Get("token"); q != "" { // SSE 兼容（EventSource 不能带 header）
			got = q
		}
		if subtle.ConstantTimeCompare([]byte(got), []byte(tok)) == 1 {
			next.ServeHTTP(w, r)
			return
		}
		w.Header().Set("WWW-Authenticate", `Bearer realm="argus"`)
		http.Error(w, `{"detail":"unauthorized"}`, http.StatusUnauthorized)
	})
}

// NodeAuth: 节点 Bearer 校验（节点 token 与管理 token 分离）。
type NodeAuth struct {
	mu     sync.RWMutex
	tokens map[string]int64 // token -> node id
}

func NewNodeAuth() *NodeAuth {
	return &NodeAuth{tokens: map[string]int64{}}
}

func (n *NodeAuth) Set(token string, nodeID int64) {
	n.mu.Lock()
	n.tokens[token] = nodeID
	n.mu.Unlock()
}

func (n *NodeAuth) Remove(token string) {
	n.mu.Lock()
	delete(n.tokens, token)
	n.mu.Unlock()
}

// Check 返回 nodeID；未注册返回 0。
func (n *NodeAuth) Check(r *http.Request) int64 {
	h := r.Header.Get("Authorization")
	if !strings.HasPrefix(h, "Bearer ") {
		return 0
	}
	tok := strings.TrimPrefix(h, "Bearer ")
	n.mu.RLock()
	id, ok := n.tokens[tok]
	n.mu.RUnlock()
	if !ok {
		return 0
	}
	return id
}
