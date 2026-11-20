package server

import (
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"github.com/wooluo/argus/internal/api"
	"github.com/wooluo/argus/internal/auth"
	"github.com/wooluo/argus/internal/events"
	"github.com/wooluo/argus/internal/ui"
)

// NewRouter: 组装全部路由。
func NewRouter(a *api.API, bus *events.Bus, am *auth.Middleware, nodeAuth *auth.NodeAuth, nodeAPI *NodeAPI, staticDir string) http.Handler {
	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Recoverer)

	r.Get("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		_, _ = w.Write([]byte("ok"))
	})

	r.Group(func(apig chi.Router) {
		apig.Use(am.Handler)

		// SSE 事件流
		apig.Get("/api/stream", bus.ServeSSE)

		// Projects
		apig.Route("/api/projects", func(pr chi.Router) {
			pr.Get("/", a.ListProjects)
			pr.Post("/", a.CreateProject)
			pr.Route("/{id}", func(prr chi.Router) {
				prr.Get("/", a.GetProject)
				prr.Put("/", a.UpdateProject)
				prr.Delete("/", a.DeleteProject)
				prr.Post("/tasks", a.StartTask)
				prr.Post("/findings", a.CreateFinding)
				// Reports（报告域）
				prr.Get("/report", a.GetProjectReport)
				prr.Get("/report/export", a.ExportReport)
				prr.Get("/report/preview", a.PreviewReport)
				prr.Post("/report/generate", a.GenerateReport)
			})
		})

		// Tasks
		apig.Route("/api/tasks", func(tr chi.Router) {
			tr.Get("/", a.ListTasks)
			tr.Route("/{id}", func(trr chi.Router) {
				trr.Get("/", a.GetTask)
				trr.Post("/stop", a.StopTask)
			})
		})

		// Assets / Findings / Logs
		apig.Get("/api/assets", a.ListAssets)
		apig.Get("/api/findings", a.ListFindings)
		apig.Get("/api/reports", a.ListReports)
		apig.Patch("/api/findings/{id}", a.UpdateFindingStatus)
		apig.Get("/api/agent-logs", a.ListAgentLogs)

		// Settings（设置页；auth 写后热更新）
		apig.Get("/api/settings", a.GetSettings)
		apig.Put("/api/settings/llm", a.PutLLM)
		apig.Put("/api/settings/proxy", a.PutProxy)
		apig.Put("/api/settings/target-proxy", a.PutTargetProxy)
		apig.Put("/api/settings/tools", a.PutTools)
		apig.Put("/api/settings/limits", a.PutLimits)
		apig.Get("/api/settings/auth", a.GetAuth)
		apig.Put("/api/settings/auth", a.PutAuth)
		apig.Post("/api/settings/auth/generate", a.GenerateAuth)
		apig.Post("/api/settings/llm/test", a.TestLLM)
		apig.Get("/api/settings/llm/models", a.LLMModels)
		apig.Get("/api/settings/llm/preset-keys", a.GetPresetKeys)
		apig.Put("/api/settings/llm/preset-keys", a.PutPresetKey)
		apig.Get("/api/tools", a.ToolsStatus)

		// Extension 域（蓝本 api/extension.py）
		apig.Get("/api/agents", a.ListAgents)
		apig.Get("/api/agents/builtin-prompt", a.BuiltinAgentPrompt)
		apig.Put("/api/agents/{agent_id}", a.PutAgent)
		apig.Get("/api/mcp", a.ListMCP)
		apig.Put("/api/mcp", a.PutMCP)
		apig.Delete("/api/mcp/{server_id}", a.DeleteMCP)
		apig.Post("/api/mcp/{server_id}/test", a.TestMCP)
		apig.Get("/api/skills", a.ListSkills)
		apig.Post("/api/skills", a.CreateSkill)
		apig.Put("/api/skills/{skill_id}", a.UpdateSkill)
		apig.Get("/api/skills/{skill_id}/content", a.SkillContent)
		apig.Delete("/api/skills/{skill_id}", a.DeleteSkill)
		apig.Get("/api/notify/config", a.GetNotifyConfig)
		apig.Put("/api/notify/config", a.PutNotifyConfig)
		apig.Post("/api/notify/test", a.TestNotify)
		apig.Get("/api/repeater/logs", a.RepeaterLogs)
		apig.Post("/api/repeater/send", a.RepeaterSend)
		apig.Get("/api/poclib", a.PoclibStats)
		apig.Put("/api/poclib/repos", a.PutPocRepos)
		apig.Post("/api/poclib/sync", a.PoclibSync)
	})

	// 节点面 API（独立鉴权域；注册需管理 token 防开放注册）
	r.Route("/api/nodes", func(nr chi.Router) {
		nr.Group(func(rg chi.Router) {
			rg.Use(am.Handler)
			rg.Post("/register", nodeAPI.Register)
			rg.Get("/", nodeAPI.ListNodes)
		})
		nr.Group(func(ng chi.Router) {
			ng.Use(nodeAuthHandler(nodeAuth))
			ng.Post("/heartbeat", nodeAPI.Heartbeat)
			ng.Get("/poll", nodeAPI.Poll)
			ng.Post("/result", nodeAPI.ReportResult)
			ng.Post("/progress", nodeAPI.Progress)
		})
	})

	serveStatic(r, staticDir)
	return r
}

func nodeAuthHandler(na *auth.NodeAuth) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if na.Check(r) == 0 {
				w.Header().Set("Content-Type", "application/json")
				http.Error(w, `{"detail":"unknown node"}`, http.StatusUnauthorized)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// serveStatic: 优先磁盘目录（ARGUS_STATIC），否则内嵌 dist。
func serveStatic(r *chi.Mux, staticDir string) {
	if staticDir != "" {
		abs, err := filepath.Abs(staticDir)
		if err == nil {
			if st, err2 := os.Stat(abs); err2 == nil && st.IsDir() {
				r.Get("/*", spaHandler(http.Dir(abs), abs+"/index.html"))
				return
			}
		}
	}
	sub, _ := fs.Sub(ui.Dist, "dist")
	r.Get("/*", spaHandler(http.FS(sub), ""))
}

// spaHandler: 存在则发文件，否则回退 index.html（前端路由）。
func spaHandler(fsys http.FileSystem, diskIndex string) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		p := strings.TrimPrefix(req.URL.Path, "/")
		if p == "" {
			p = "index.html"
		}
		if f, err := fsys.Open(p); err == nil {
			f.Close()
			http.FileServer(fsys).ServeHTTP(w, req)
			return
		}
		if diskIndex != "" {
			http.ServeFile(w, req, diskIndex)
			return
		}
		index, err := fs.ReadFile(ui.Dist, "dist/index.html")
		if err != nil {
			http.NotFound(w, req)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(index)
	}
}
