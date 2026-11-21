# 自动化SQL注入测试中识别并绕过LIMIT截断

- 来源：任务 #34 自动复盘（自我迭代）
- 保存时间：2026-11-19 12:25

结论先行：当UNION SELECT注入返回结果仅显示一行时，很可能原始查询存在LIMIT 1限制，导致UNION SELECT的结果被截断，此时需要调整payload以绕过。适用场景：任何使用UNION SELECT注入且目标查询有LIMIT子句的场景（如DVWA high等级SQL注入、分页查询等）。具体做法：在UNION SELECT后添加`LIMIT 1,1`来跳过第一行，或者使用子查询如`UNION SELECT 1,2 FROM (SELECT 1,2 UNION SELECT 3,4) AS tmp`来避免直接受外层LIMIT影响。自动化工具（如sqlmap）可通过`--prefix`和`--suffix`参数添加绕过，或手动修改payload。注意事项：需确认原始查询的LIMIT值，有时是`LIMIT 0,1`，可尝试`LIMIT 1,1`或`OFFSET 1`；另外注意数据库语法差异（MySQL支持LIMIT，其他数据库可能不同）；若仍无效，可尝试使用`UNION ALL SELECT`或盲注方式验证。