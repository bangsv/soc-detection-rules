"""Smoke-test the SOC Atlas API surface. Usage: python tools/smoke_api.py [base_url]"""
from __future__ import annotations

import json
import sys
import urllib.request

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8000"
FAILURES: list[str] = []


def check(name: str, condition: bool, detail: str = "") -> None:
    print(f"[{'ok' if condition else 'FAIL'}] {name}{(' — ' + detail) if detail and not condition else ''}")
    if not condition:
        FAILURES.append(name)


def get(path: str, expect_json: bool = True):
    with urllib.request.urlopen(BASE + path, timeout=30) as response:
        raw = response.read()
        if not expect_json:
            return response.status, raw, response.headers
        return response.status, json.loads(raw.decode("utf-8")), response.headers


status, meta, _ = get("/api/meta")
check("/api/meta status", status == 200)
counts = meta["counts"]
check("attacks == 6", counts["attacks"] == 6, json.dumps(counts))
check("ioc total > 30", counts["iocs"] > 30, json.dumps(counts))
check("materials > 100", counts["materials"] > 100, json.dumps(counts))
check("filters have categories", bool(meta["filters"]["categories"]))
check("filters have tactics", bool(meta["filters"]["tactics"]))

status, items, _ = get("/api/attacks")
check("/api/attacks returns list", isinstance(items, list) and len(items) == 6)
check("every attack has severity", all(item["severity"] for item in items))
check("first attack is critical", items[0]["severity"] == "Критично", items[0]["id"])
check("rules counted on cards", sum(item.get("rules_count", 0) for item in items) >= 40, str(sum(item.get("rules_count", 0) for item in items)))

for item in items:
    status, detail, _ = get(f"/api/attacks/{urllib.parse.quote(item['id'])}")
    groups = {group["type"]: group["items"] for group in detail["ioc_groups"]}
    real_rows = [row for rows in groups.values() for row in rows if not row.get("placeholder")]
    issues = []
    if status != 200:
        issues.append("status")
    if not detail["materials"]:
        issues.append("no materials")
    if not detail["vector"]:
        issues.append("no vector")
    if not detail["lab"]:
        issues.append("no lab rows from IOC")
    if not detail["references"]:
        issues.append("no cross-references from IOC")
    if len(real_rows) != item["ioc_count"]:
        issues.append(f"ioc count mismatch: {len(real_rows)} != {item['ioc_count']}")
    triage = detail.get("triage") or {}
    if not triage.get("total"):
        issues.append("no triage materials")
    if not (detail.get("rules") or {}).get("total"):
        issues.append("no detection rules")
    check(f"detail {item['id']}", not issues, ", ".join(issues))
    for group in detail["ioc_groups"]:
        for indicator in group["items"]:
            if indicator.get("placeholder"):
                continue
            if not indicator["detected_type"]:
                check(f"indicator type {indicator['value']}", False)

# Данные об атаках должны приходить из файла IOC.
check("ioc source is the IOC file", meta.get("ioc_source") == "IOC", str(meta.get("ioc_source")))
check("lab read from IOC", len(meta.get("lab", [])) == 4, str(len(meta.get("lab", []))))
check(
    "lab nodes have address and role",
    all(node.get("address") and node.get("role") for node in meta.get("lab", [])),
    str([(node.get("tag"), node.get("address")) for node in meta.get("lab", [])]),
)
check(
    "lab does not list scenarios",
    all("scenarios" not in node for node in meta.get("lab", [])),
    str([node for node in meta.get("lab", []) if "scenarios" in node]),
)
check("threat intelligence from IOC", len(meta.get("sources", [])) >= 4, str(len(meta.get("sources", []))))
check("no catalogue issues", not meta.get("issues"), "; ".join(meta.get("issues", [])))

# Правила детектирования: список отдаётся с деталями, содержимое — по отдельному запросу.
status, rules, _ = get("/api/attacks/CVE-2017-0143_EternalBlue/rules")
check("rules list has groups", bool(rules["groups"]), str(rules.get("total")))
check("rules list has files", rules["total"] >= 5, str(rules["total"]))
rule_path = rules["groups"][0]["items"][0]["path"]
status, rule, _ = get("/api/attacks/CVE-2017-0143_EternalBlue/rule?path=" + urllib.parse.quote(rule_path))
check("rule content served", bool(rule["content"].strip()), rule_path)
check("rule content has language", bool(rule.get("language")), str(rule.get("language")))

status, tray, _ = get("/api/attacks/DCSync/tray")
check("tray count matches", tray["count"] == 7, str(tray["count"]))
check("tray rows have type", all(row["type"] for row in tray["items"]))

status, csv_bytes, headers = get("/api/attacks/DCSync/tray?format=csv", expect_json=False)
check("csv export", status == 200 and b"value,group,type" in csv_bytes)
check("csv is attachment", "attachment" in headers.get("Content-Disposition", ""))

status, zip_bytes, headers = get("/api/attacks/DCSync/bundle", expect_json=False)
check("zip bundle", status == 200 and zip_bytes[:2] == b"PK", str(len(zip_bytes)))
check("zip is attachment", "attachment" in headers.get("Content-Disposition", ""))

status, search, _ = get("/api/search?q=EfsRpcOpenFileRaw")
check(
    "search finds EfsRpcOpenFileRaw",
    any("EfsRpcOpenFileRaw" in r["ioc"] for r in search["results"])
    or any("EfsRpcOpenFileRaw" in row["value"] for row in search["fragments"]),
    json.dumps(search["results"][:1], ensure_ascii=False),
)
check("search fragments not empty", bool(search["fragments"]))

status, readme, _ = get("/api/readme?path=" + urllib.parse.quote("CVE-2017-0143_EternalBlue/README.md"))
check("readme html", "<h" in readme["html"])
check("readme toc", bool(readme["toc"]))
check("readme attack", readme["attack"] == "CVE-2017-0143_EternalBlue")

status, shortcuts, _ = get("/api/shortcuts")
check("shortcuts", len(shortcuts) >= 6)

status, summary, _ = get("/api/summary")
check("summary attacks", summary["attacks"] == 6)

print()
print(f"{len(FAILURES)} failure(s)" if FAILURES else "all checks passed")
sys.exit(1 if FAILURES else 0)
