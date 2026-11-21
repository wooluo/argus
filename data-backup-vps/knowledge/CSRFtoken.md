# 自动化测试中会话保持与 CSRF token 处理的通用策略

- 来源：任务 #34 自动复盘（自我迭代）
- 保存时间：2026-11-19 12:39

**结论**：在自动化渗透测试中，遇到需要 CSRF token 保护的页面（如登录、上传、配置修改），必须实现“先获取 token 再提交”的原子操作，并建立会话失效自动重连机制，否则测试流程会因重定向到登录页而中断。

**适用场景**：任何使用 CSRF token 的 Web 应用（如 DVWA、WordPress、Joomla），以及需要保持登录状态的连续测试流程。

**具体做法**：
1. **会话管理**：使用持久化 Cookie 容器（如 Python requests.Session 对象），自动保存和发送 Set-Cookie。
2. **CSRF token 提取**：
   - 对每个需要 token 的页面，先 GET 该页面，从 HTML 中正则匹配 `name="user_token" value="([^"]+)"` 或类似模式。
   - 注意 token 可能隐藏在 JavaScript 变量或 meta 标签中，需根据页面结构调整提取逻辑。
3. **原子提交**：将 token 作为 POST 参数与业务数据一起提交，避免 token 过期（通常 token 单次有效）。
4. **会话失效检测**：每次请求后检查响应状态码或页面内容是否包含登录表单特征（如“Login”关键字、`<input name='username'>`），若检测到则立即执行重新登录流程：
   - 重新获取登录页的 token → 提交凭据 → 更新 Cookie → 重试原请求。
5. **断点续测**：在自动化脚本中记录当前测试的模块和等级，当会话恢复后，从断点继续而非从头开始。

**注意事项**：
- 某些应用（如 DVWA high 等级）的 token 可能通过 session 变量传递，需先访问特定端点（如 session-input.php）获取。
- 避免并发请求导致 token 被消耗：在单线程中顺序执行。
- 如果 token 绑定 IP 或 User-Agent，需保持这些属性一致。