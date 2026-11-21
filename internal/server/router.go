package server

import (
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
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

		// SSE 事件流（全局 + 单任务）
		apig.Get("/api/stream", bus.ServeSSE)
		apig.Get("/api/stream/{task_id}", func(w http.ResponseWriter, r *http.Request) {
			id, err := strconv.ParseInt(chi.URLParam(r, "task_id"), 10, 64)
			if err != nil || id <= 0 {
				http.Error(w, `{"detail":"invalid task_id"}`, 422)
				return
			}
			bus.ServeSSETask(w, r, id)
		})

		// withPID 项目子路由 → 全局列表 handler 的 project_id 查询参数桥接
		withPID := func(h http.HandlerFunc) http.HandlerFunc {
			return func(w http.ResponseWriter, r *http.Request) {
				q := r.URL.Query()
				if q.Get("project_id") == "" {
					q.Set("project_id", chi.URLParam(r, "id"))
					r.URL.RawQuery = q.Encode()
				}
				h(w, r)
			}
		}

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
				// 项目维度子列表（蓝本 /projects/{id}/tasks|assets|findings|traffic）
				prr.Get("/tasks", withPID(a.ListTasks))
				prr.Get("/assets", withPID(a.ListAssets))
				prr.Get("/findings", withPID(a.ListFindings))
				prr.Get("/traffic", withPID(a.ListTraffic))
				// 项目情报库（跨任务持久）
				prr.Get("/intel", a.GetProjectIntel)
				prr.Post("/intel", a.AddProjectIntel)
				// 资产覆盖图（蓝本 asset_graph）
				prr.Get("/graph", a.GetGraph)
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
				trr.Post("/intel", a.SubmitIntel) // 运行中情报注入
				trr.Get("/tree", a.DecisionTree)
				trr.Get("/exploration", a.ExplorationGraph)
			})
		})

		// Assets / Findings / Logs / Traffic
		apig.Get("/api/assets", a.ListAssets)
		apig.Get("/api/findings", a.ListFindings)
		apig.Get("/api/reports", a.ListReports)
		apig.Get("/api/traffic", a.ListTraffic)
		apig.Patch("/api/findings/{id}", a.UpdateFindingStatus)
		apig.Post("/api/findings/{id}/retest", a.RetestFinding)
		apig.Post("/api/findings/read-all", a.MarkAllFindingsRead)
		apig.Post("/api/findings/{id}/read", a.MarkFindingRead)
		apig.Get("/api/findings/{id}/evidence", a.FindingEvidence)
		apig.Get("/api/findings/{id}/steps", a.FindingSteps)
		apig.Delete("/api/findings/{id}", a.DeleteFinding)
		apig.Post("/api/traffic/{id}/replay", a.ReplayTraffic)
		apig.Get("/api/knowledge", a.ListKnowledge)
		apig.Post("/api/knowledge", a.CreateKnowledge)
		apig.Get("/api/knowledge/github-config", a.GetGithubConfig)
		apig.Put("/api/knowledge/github-config", a.PutGithubConfig)
		apig.Get("/api/knowledge/{kid}/content", a.KnowledgeContent)
		apig.Put("/api/knowledge/{kid}", a.UpdateKnowledge)
		apig.Delete("/api/knowledge/{kid}", a.DeleteKnowledge)
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
		apig.Get("/api/settings/fofa", a.GetFofaConfig)
		apig.Put("/api/settings/fofa", a.PutFofaConfig)
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

		// Dashboard 域（蓝本 api/dashboard.py）
		apig.Get("/api/dashboard/stats", a.GetDashboard)
		apig.Get("/api/dashboard/sources", a.GetSources)
		apig.Put("/api/dashboard/sources", a.PutSources)
		apig.Get("/api/system/logs", a.SystemLogs)

		// Approvals 域（蓝本 api/approvals.py：高危工具调用审批）
		apig.Route("/api/approvals", func(ar chi.Router) {
			ar.Get("/", a.ListApprovals)
			ar.Get("/config", a.GetApprovalConfig)
			ar.Put("/config", a.PutApprovalConfig)
			ar.Post("/{id}/decide", a.DecideApproval)
		})

		// SSH 引导式节点部署（管理面；节点网 register/heartbeat 在下方独立鉴权域）
		apig.Post("/api/nodes/deploy", nodeAPI.DeployNode)

		// Kali 域（蓝本 api/kali.py）
		apig.Get("/api/kali/hosts", a.ListKaliHosts)
		apig.Put("/api/kali/hosts", a.PutKaliHosts)
		apig.Post("/api/kali/hosts/test", a.TestKaliHost)
		apig.Get("/api/kali/hosts/{host_id}/metrics", a.KaliHostMetrics)
		apig.Get("/api/kali/hosts/{host_id}/activity", a.KaliHostActivity)
		apig.Delete("/api/kali/hosts/{host_id}", a.DeleteKaliHost)

		// Nodes 域（dnslog 节点 CRUD；/api/nodes 的节点网 register/heartbeat 已在下方独立挂载，
		// 与蓝本前缀冲突，故 dnslog 配置面挂 /api/nodes 下的 GET/PUT/test）
		apig.Get("/api/nodes", a.ListNodes)
		apig.Put("/api/nodes", a.PutNodes)
		apig.Post("/api/nodes/test", a.TestNode)

		// ScopeSentry 域（蓝本 api/scopesentry.py）
		apig.Get("/api/scopesentry/config", a.GetScopeSentryConfig)
		apig.Put("/api/scopesentry/config", a.PutScopeSentryConfig)
		apig.Post("/api/scopesentry/test", a.ScopeSentryTest)
		apig.Post("/api/scopesentry/projects/{project_id}/import", a.ScopeSentryImport)

		// Templates 域（蓝本 api/templates.py）
		apig.Get("/api/templates", a.ListTemplates)
		apig.Post("/api/templates/upload", a.UploadTemplate)
		apig.Get("/api/templates/{template_id}/content", a.GetTemplateContent)
		apig.Delete("/api/templates/{template_id}", a.DeleteTemplate)

		// Toolbox 域（蓝本 api/toolbox.py）
		apig.Get("/api/toolbox", a.GetToolbox)
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
			// HITL 审批门：节点写 pending + 轮询决定（管理面 /api/approvals 决策）
			ng.Post("/approvals", nodeAPI.CreateApproval)
			ng.Get("/approvals/{id}", nodeAPI.GetApproval)
			// 运行中情报：节点轮询拉取操作员提交的情报
			ng.Get("/intel", nodeAPI.NodeIntel)
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
