#!/usr/bin/env python3
# AutoPentest(Python) → Argus(Go) 数据迁移
# 用法：python3 scripts/migrate-from-python.py [python_data_dir] [argus_db]
# 迁移：projects/tasks/assets/findings/agent_logs/reports/project_intel/
#       finding_steps/traffic_logs/repeater_logs（保留原 ID 关联）+
#       knowledge/skills 文件 + settings（llm/fofa/kali_hosts/skills/...）
# 注意：会清空 argus.db 里的业务表（保留 nodes/settings 的 auth 等运行配置）
import json
import shutil
import sqlite3
import sys
from pathlib import Path

PY_DATA = Path(sys.argv[1] if len(sys.argv) > 1 else Path.home() / "DEV/AutoPentest/data")
GO_DB = Path(sys.argv[2] if len(sys.argv) > 2 else Path.home() / "DEV/argus/data/argus.db")
GO_DATA = GO_DB.parent

TABLES = ["projects", "tasks", "assets", "findings", "agent_logs", "reports",
          "project_intel", "finding_steps", "traffic_logs", "repeater_logs"]

py = sqlite3.connect(f"file:{PY_DATA/'autopentest.db'}?mode=ro", uri=True)
go = sqlite3.connect(GO_DB)

# ── 0. 备份 ──
bak = GO_DB.with_suffix(".db.bak-migrate")
shutil.copy(GO_DB, bak)
print(f"✓ 已备份 {bak.name}")

# ── 1. 业务表迁移（清 Go 侧测试数据 → 按列交集拷贝，保留原 ID）──
total = 0
for t in TABLES:
    go.execute(f"DELETE FROM {t}")
    py_cols = [r[1] for r in py.execute(f"PRAGMA table_info({t})")]
    go_cols = [r[1] for r in go.execute(f"PRAGMA table_info({t})")]
    common = [c for c in go_cols if c in py_cols]  # 保持 Go 列序（缺列走默认值）
    rows = py.execute(f"SELECT {','.join(common)} FROM {t}").fetchall()
    if rows:
        ph = ",".join("?" * len(common))
        go.executemany(f"INSERT INTO {t} ({','.join(common)}) VALUES ({ph})", rows)
    print(f"  {t}: {len(rows)} 行")
    total += len(rows)

# 修正自增序列（保留原 ID 后 seq 需对齐）
for t in TABLES:
    m = go.execute(f"SELECT MAX(id) FROM {t}").fetchone()[0] or 0
    go.execute(f"UPDATE sqlite_sequence SET seq=? WHERE name=?", (m, t))
go.commit()

# ── 2. knowledge / skills 文件 ──
for sub in ("knowledge", "skills"):
    src, dst = PY_DATA / sub, GO_DATA / sub
    if src.is_dir():
        dst.mkdir(parents=True, exist_ok=True)
        n = 0
        for f in src.iterdir():
            if f.is_file():
                shutil.copy2(f, dst / f.name)
                n += 1
        print(f"  文件 {sub}/: {n} 个")

# ── 3. settings（键名映射；运行类键 auth/node 不动）──
try:
    ps = json.loads((PY_DATA / "settings.json").read_text())
except FileNotFoundError:
    ps = {}
keymap = {"llm": "llm", "tools": "tools", "limits": "limits", "proxy": "proxy",
          "target_proxy": "target_proxy", "kali_hosts": "kali_hosts",
          "skills": "skills", "knowledge": "knowledge",
          "custom_nuclei_repo": "custom_nuclei_repo", "intel_dir": "intel_dir",
          "github_token": "github_token", "llm_preset_keys": "llm_preset_keys",
          "poc_repos": "poc_repos"}
for pk, gk in keymap.items():
    v = ps.get(pk)
    if v in (None, "", [], {}):
        continue
    go.execute("INSERT INTO settings(key,value) VALUES(?,?) "
               "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
               (gk, json.dumps(v, ensure_ascii=False)))
# fofa 对象 → 两键
fofa = ps.get("fofa") or {}
if fofa.get("email"):
    go.execute("INSERT INTO settings(key,value) VALUES('fofa_email',?) "
               "ON CONFLICT(key) DO UPDATE SET value=excluded.value", (fofa["email"],))
if fofa.get("key"):
    go.execute("INSERT INTO settings(key,value) VALUES('fofa_key',?) "
               "ON CONFLICT(key) DO UPDATE SET value=excluded.value", (fofa["key"],))
go.commit()
print(f"  settings: {sum(1 for k in keymap if ps.get(k) not in (None, '', [], {}))} 键 + fofa")

print(f"\n✅ 迁移完成：{total} 行业务数据 + 知识/技能文件 + 设置")
print(f"   回滚：cp {bak.name} argus.db")
