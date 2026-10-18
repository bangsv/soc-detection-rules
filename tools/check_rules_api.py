"""Проверка API правил: список по типам и загрузка содержимого."""
from __future__ import annotations

import json
import sys
import urllib.parse
import urllib.request

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8010"
failures: list[str] = []


def check(label: str, ok: bool, detail: str = "") -> None:
    print(f"[{'ok' if ok else 'FAIL'}] {label}{'' if ok else ' — ' + detail}")
    if not ok:
        failures.append(label)


def get(path: str) -> dict:
    with urllib.request.urlopen(BASE + path, timeout=30) as response:
        return json.loads(response.read().decode("utf-8"))


items = get("/api/attacks")
total = 0
for item in items:
    detail = get(f"/api/attacks/{urllib.parse.quote(item['id'])}")
    rules = detail.get("rules") or {}
    count = rules.get("total", 0)
    total += count
    kinds = ", ".join(f"{group['title']}={group['count']}" for group in rules.get("groups", []))
    print(f"{item['id']}: правил {count} → {kinds or '—'}")

check("правила есть у большинства сценариев", total >= 40, str(total))

# Правила одного сценария: список, типы и содержимое по ленивому запросу.
BASE_ATTACK = "CVE-2017-0143_EternalBlue"
detail = get("/api/attacks/" + urllib.parse.quote(BASE_ATTACK))
rules = detail["rules"]
titles = {group["title"] for group in rules["groups"]}
check("Sigma найдена", any("Sigma" in title for title in titles), str(titles))
check("Suricata найдена", any("Suricata" in title for title in titles), str(titles))
check("XP-правила найдены", any("XP" in title for title in titles), str(titles))
check("ELK-правила из detection_rule/elk_rules найдены", any("ELK" in title for title in titles), str(titles))

listing = get("/api/attacks/" + urllib.parse.quote(BASE_ATTACK) + "/rules")
check("отдельный эндпоинт списка правил", listing["total"] == rules["total"], f"{listing['total']} != {rules['total']}")

first = rules["groups"][0]["items"][0]
rule = get(f"/api/attacks/{BASE_ATTACK}/rule?path=" + urllib.parse.quote(first["path"]))
check("содержимое правила отдаётся", bool(rule["content"].strip()), rule["path"])
check("у правила есть язык подсветки", bool(rule.get("language")), str(rule.get("language")))
check("у правила есть число строк", rule.get("lines", 0) > 0, str(rule.get("lines")))

# Правила читаются из detection_rule новой раскладки.
check("правило лежит в detection_rule", all("detection_rule" in row["path"] for group in rules["groups"] for row in group["items"]),
      str([row["path"] for group in rules["groups"] for row in group["items"]][:3]))

# Служебные файлы не должны попадать в список правил.
names = {row["name"].casefold() for group in rules["groups"] for row in group["items"]}
check("metainfo.yaml исключён", "metainfo.yaml" not in names, str(sorted(names)))
check("i18n исключён", not any(name.startswith("i18n_") for name in names), str(sorted(names)))
check("материалы триажа исключены", not any("triage" in row["path"] for group in rules["groups"] for row in group["items"]))

# ---------------------------------------------------------------- triage
triage = detail["triage"]
print()
print(f"triage {BASE_ATTACK}: {triage['total']} файлов, группы: " +
      ", ".join(f"{g['title']}={g['count']}" for g in triage["groups"]))
check("triage собран из папки triage", triage["total"] > 0, str(triage["total"]))
check("triage: есть дампы Wireshark", any(g["kind"] == "wireshark" for g in triage["groups"]),
      str([g["kind"] for g in triage["groups"]]))
check("triage: есть журналы Suricata", any(g["kind"] == "suricata_logs" for g in triage["groups"]),
      str([g["kind"] for g in triage["groups"]]))
check("triage: файлы только из triage", all("/triage/" in row["path"] for g in triage["groups"] for row in g["items"]))
check("triage: у файлов есть ссылка на скачивание",
      all(row["download"].endswith(row["path"].replace(" ", "%20")) or row["download"].startswith("/api/")
          for g in triage["groups"] for row in g["items"]))

listing = get(f"/api/attacks/{BASE_ATTACK}/triage")
check("отдельный эндпоинт списка triage", listing["total"] == triage["total"], f"{listing['total']} != {triage['total']}")

# Материалы отдаются на скачивание вложением, содержимое в интерфейсе не показываем.
dump = next((row for g in triage["groups"] for row in g["items"] if row["ext"] == ".pcapng"), None)
if dump:
    with urllib.request.urlopen(BASE + dump["download"], timeout=60) as response:
        disposition = response.headers.get("Content-Disposition", "")
    check("дамп скачивается вложением", "attachment" in disposition, disposition)

# Защита доступа: чужой файл вне папки сценария читать нельзя.
try:
    get("/api/attacks/DCSync/rule?path=" + urllib.parse.quote("app/main.py"))
    check("чужой путь запрещён", False, "файл вне папки сценария был прочитан")
except urllib.error.HTTPError as error:
    check("чужой путь запрещён", error.code == 404, f"код {error.code}")

try:
    get("/api/attacks/DCSync/triage/file?path=" + urllib.parse.quote("DCSync/README.md"))
    check("вне triage читать нельзя", False, "README был прочитан как triage")
except urllib.error.HTTPError as error:
    check("вне triage читать нельзя", error.code == 404, f"код {error.code}")

print()
print(f"{len(failures)} failure(s)" if failures else "правила и triage собираются корректно")
sys.exit(1 if failures else 0)
