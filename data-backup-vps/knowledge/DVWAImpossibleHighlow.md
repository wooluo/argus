# DVWA 安全等级调整：Impossible/High 时降到 low 才能测出漏洞

## 适用场景
目标是 DVWA 靶场（指纹：/login.php 登录页、页面含 DVWA 标识、默认凭据 admin/password）。

## 何时应用
- 模块测试全部无效：payload 被转义、无回显差异、无带外命中
- 出现高等级防护特征：CSRF token 强校验、PDO 预编译、输出全转义、impossible 提示

## 操作步骤（用平台工具）
1. web_login 登录（admin/password，自动带会话）
2. http_fetch GET /security.php —— 解析页面 hidden input 里的 user_token（与 secu_token）
3. http_fetch POST /security.php，表单字段：security=low + secu_token=<页面值> + user_token=<页面值>
4. 确认页面提示当前等级已变更，回到目标模块重新验证

## 推荐打法（防御梯度测试）
- low：先确认漏洞存在性与完整利用链（report_finding 入库拿 finding_id）
- medium/high：验证过滤规则差异与绕过手法（示例：exec 模块黑名单 && ; → 用 | 绕过；high 黑名单 | 带空格 → 无空格 |id 绕过）
- 报告按各级差异给修复建议（以 impossible 级实现为修复目标）

## 注意
- 仅对授权靶场调整安全等级，真实业务系统无此操作
- 等级提交后必须重新读取页面确认生效，再继续测试