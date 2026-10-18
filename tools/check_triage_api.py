"""Проверка панели triage: карточки, подписи, ссылки на скачивание и группа Zerologon."""
from __future__ import annotations

import importlib
import json
import os
import sys
import urllib.parse
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
os.environ["RULES_DIR"] = str(ROOT)
sys.path.insert(0, str(ROOT / "app"))
main = importlib.import_module("main")

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8017"
failures: list[str] = []


def check(label: str, ok: bool, detail: str = "") -> None:
    print(f"[{'ok' if ok else 'FAIL'}] {label}{'' if ok else ' — ' + detail}")
    if not ok:
        failures.append(label)


def get(path: str) -> dict:
    with urllib.request.urlopen(BASE + path, timeout=30) as response:
        return json.loads(response.read().decode("utf-8"))


for attack_id in main.catalog()["attacks"]:
    payload = main.triage_payload(attack_id)
    print(f"\n{attack_id}: {payload['total']} файлов, {round(payload['size'] / 1024)} КБ")
    for group in payload["groups"]:
        names = ", ".join(row["name"] for row in group["items"][:3])
        print(f"   {group['title']:<14} {group['count']:>2} → {names}")

# Zerologon: логи разложены по инструментам — подпись сценария обязательна.
zer = main.triage_payload("CVE-2020-1472_Zerologon")
suricata = next((g for g in zer["groups"] if g["kind"] == "suricata_logs"), None)
check("Zerologon: есть логи по инструментам", bool(suricata), str([g["kind"] for g in zer["groups"]]))
if suricata:
    labels = {row["scenario"] for row in suricata["items"]}
    check("Zerologon: подписаны инструменты", labels == {"Metasploit", "Mimikatz"}, str(labels))
    eve = [row for row in suricata["items"] if row["name"] == "eve.json"]
    check("Zerologon: два eve.json различимы", len({row["scenario"] for row in eve}) == 2,
          str([r["scenario"] for r in eve]))

# Каждая карточка имеет всё, что нужно для понятного скачивания.
detail = get("/api/attacks/" + urllib.parse.quote("DCSync"))
triage = detail["triage"]
items = [row for group in triage["groups"] for row in group["items"]]
check("у каждого файла есть ссылка на скачивание", all(row["download"].startswith("/api/attacks/DCSync/triage/file") for row in items))
check("у каждого файла есть тип", all(row["type_title"] for row in items))
check("у каждого файла есть программа открытия", all(row["tool"] for row in items))
check("у каждого файла есть подпись", all(row["description"] for row in items))
check("есть ссылка на ZIP", triage["bundle"].endswith("/bundle"), triage["bundle"])
check("сортировка: провал раньше неуказанных", triage["groups"][0]["items"][0]["result"] == "fail",
      triage["groups"][0]["items"][0]["name"])
check("типы файлов подписаны по папке",
      any(row["type_title"] == "Сетевой дамп" for row in items) and any(row["type_title"] == "Журнал Windows" for row in items),
      str({row["type_title"] for row in items}))

# Скачивание отдаёт файл вложением, а не страницу.
dump = next(row for row in items if row["ext"] == ".pcapng")
with urllib.request.urlopen(BASE + dump["download"], timeout=60) as response:
    disposition = response.headers.get("Content-Disposition", "")
    payload_bytes = response.read(4)
check("скачивание помечено как вложение", "attachment" in disposition, disposition)
check("скачивается именно файл", payload_bytes[:1] == b"\x0a" or len(payload_bytes) == 4, str(payload_bytes))

# Доступ ограничен папкой triage своего сценария.
for bad in ("DCSync/README.md", "app/main.py"):
    try:
        urllib.request.urlopen(BASE + "/api/attacks/DCSync/triage/file?path=" + urllib.parse.quote(bad), timeout=20)
        check(f"запрещено: {bad}", False, "файл был отдан")
    except urllib.error.HTTPError as error:
        check(f"запрещено: {bad}", error.code == 404, f"код {error.code}")

print()
print(f"{len(failures)} failure(s)" if failures else "материалы triage готовы к скачиванию")
sys.exit(1 if failures else 0)
