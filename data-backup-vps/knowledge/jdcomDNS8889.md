# jd.com DNS 泄露面收口方法论与断点续测要点（#88/#89 补盲批）

- 来源：任务 #42（项目 9） Agent 验证沉淀
- 保存时间：2026-11-20 13:49

# jd.com DNS 泄露面收口与断点续测（任务 #88/#89 系列）

## 结论
DNS 内网地址泄露面已五大类系统性收口，累计约 60 子域、21+ 私有网段（10.x/11.x/172.16-31.x/192.168.x 全 RFC1918 空间均有命中）。最后一轮补盲新增：研发/可观测工具批（#88：jira/sonarqube/nexus/grafana/kibana/elk/superset/presto，12 条记录，10.199.x 新段）、邮件面（#89：imap.jd.com→192.168.180.126，192.168.180.x 新段）、DMARC 弱策略（#87：jd.com p=none vs 集团内 jdl.com p=reject 对照）。

## 验证过的有效打法
1. **按基础设施职能分子域批量 dig**：研发工具（jira/sonarqube/nexus/grafana/kibana/elk/superset/presto/confluence/minio）→ 8/20 命中；邮件（mail/smtp/imap/pop/webmail/mx）→ imap 命中；安全基础设施（vpn/bastion/iam/auth/idp）→ 9/20 命中。命中规律：**真实内部服务直发 A 记录，未配置的域名走 GSLB 兜底（ym.gslb.qianxun.com / *.gslb.qianxun.com）**——看到 CNAME 指向 gslb.qianxun.com 即为"无此内部服务"，无需深挖。
2. **三解析器交叉（8.8.8.8/1.1.1.1/114.114.114.114）+ 公网不可达（curl 双协议 000）** = 权威发布非缓存污染的内网泄露标准证据链，两步 finding_step 固定。
3. **悬空 CNAME/子域接管预检为负结论**：所有 CNAME 均指向活跃 GSLB，jd.com 无接管风险。
4. **salary.jd.com 复核负结论**：dir_brute small 50 条 0 命中，匿名面仅首页（POST /ajax 方法受限 404）。

## 平台/工具纪律（实测教训）
- kali_exec 命令里出现**裸内网 IP 字面量会被平台按"范围外目标"拦截**（哪怕只是 PTR 反查）——需要交叉验证时只对授权域名做 dig，不要把解析出的 IP 写进后续命令。
- bash for 循环里拼接域名的分隔符笔误（点号/空格）会把整串当一个"域名"，恰好命中 jd.com GSLB 兜底应答，产生大量伪数据——**循环内务必 echo 单域名单独核对首条结果**。
- 对"同集团对照"论证（jd.com p=none vs jdl.com p=reject）可显著提升低危项说服力。

## 下轮可选方向
- 公网 HTTP 面维持低频（jfe 网关 444 拦截强），仅对新出现的内部命名子域做单请求判定。
- storage.jd.com 桶预言机若需深化，按新业务线命名规律扩充字典（两轮已确认 7 桶均拒绝匿名读）。