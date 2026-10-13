"""Сверка: все сведения об атаках формируются из файла IOC.

Запуск: python tools/check_ioc_source.py
Сравнивает каталог приложения со снимком tools/ioc-migration.json (состояние до переезда):
метаданные, техники с тактиками, стенд, ссылки и текст индикаторов. Дополнительно
проверяет, что в коде и разметке не осталось зашитых сведений об атаках.
"""
from __future__ import annotations

import importlib
import json
import os
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SNAPSHOT = ROOT / "tools" / "ioc-migration.json"
os.environ["RULES_DIR"] = str(ROOT)
sys.path.insert(0, str(ROOT / "app"))

main = importlib.import_module("main")
failures: list[str] = []


def norm(value: str) -> str:
    return re.sub(r"\s+", " ", str(value or "")).strip()


snapshot = json.loads(SNAPSHOT.read_text(encoding="utf-8"))
expected = snapshot["attacks"]
catalog = main.catalog()

print(f"сценариев: {len(catalog['attacks'])} (в снимке {len(expected)})")
if set(catalog["attacks"]) != set(expected):
    failures.append(f"состав сценариев отличается: {sorted(set(catalog['attacks']) ^ set(expected))}")

for attack_id, want in expected.items():
    attack = catalog["attacks"].get(attack_id)
    if not attack:
        failures.append(f"{attack_id}: сценарий не построен из файла IOC")
        continue
    pub = main.public_attack(attack)
    info = main.attack_meta(attack)

    for field in ("short", "cve", "severity", "category", "tagline"):
        if norm(pub[field]) != norm(want[field]):
            failures.append(f"{attack_id}: {field} «{pub[field]}» ≠ «{want[field]}»")
    if (pub["cvss"] or None) != (want["cvss"] or None):
        failures.append(f"{attack_id}: cvss {pub['cvss']} ≠ {want['cvss']}")
    if main.platform_label(info["platform"]) != want["platform"]:
        failures.append(f"{attack_id}: platform «{info['platform']}» ≠ «{want['platform']}»")
    if info["surface"] != want["surface"]:
        failures.append(f"{attack_id}: surface «{info['surface']}» ≠ «{want['surface']}»")
    for field in ("vector", "focus"):
        if norm(info[field]) != norm(want[field]):
            failures.append(f"{attack_id}: {field} отличается от снимка")

    got_techniques = {item["id"]: item["tactic"] for item in pub["attack"]}
    want_techniques = {item["id"]: item["tactic"] for item in want["techniques"]}
    if got_techniques != want_techniques:
        failures.append(f"{attack_id}: техники {got_techniques} ≠ {want_techniques}")

    for group, key in (("Host IOC", "host_iocs"), ("Network IOC", "network_iocs")):
        got = [
            (norm(row["value"]), norm(row["description"]), bool(row["important"]))
            for row in attack["ioc_groups"][group]
            if not row.get("placeholder")
        ]
        wanted = [
            (norm(row["value"]), norm(row["description"]), bool(row["important"]))
            for row in want[key]
            if not row.get("placeholder")
        ]
        if got != wanted:
            failures.append(f"{attack_id} / {group}: индикаторы отличаются ({len(got)} против {len(wanted)})")
            for index, (left, right) in enumerate(zip(got, wanted)):
                if left != right:
                    failures.append(f"    #{index + 1}: «{left[0]}» ≠ «{right[0]}»")
                    if left[1] != right[1]:
                        failures.append(f"        описание: «{left[1][:70]}…» ≠ «{right[1][:70]}…»")
                    break
    if not attack.get("lab"):
        failures.append(f"{attack_id}: не заполнен блок LAB")
    if not attack.get("references"):
        failures.append(f"{attack_id}: не заполнен блок REFERENCES")
    if not info["techniques"] and want["techniques"]:
        failures.append(f"{attack_id}: техники не разобраны")

total = sum(main.public_attack(item)["ioc_count"] for item in catalog["attacks"].values())
wanted_total = sum(
    len([row for row in attack["host_iocs"] + attack["network_iocs"] if not row.get("placeholder")])
    for attack in expected.values()
)
print(f"индикаторов: {total} (в снимке {wanted_total})")
if total != wanted_total:
    failures.append(f"итог индикаторов {total} ≠ {wanted_total}")

print(f"замечаний каталога: {len(catalog['issues'])}")
for issue in catalog["issues"]:
    failures.append(f"замечание: {issue}")
if not catalog["lab"]:
    failures.append("раздел ## LAB не прочитан")
if not catalog["sources"]:
    failures.append("раздел ## THREAT INTELLIGENCE не прочитан")

# В коде и разметке не должно остаться сведений об атаках.
BACKEND_MARKERS = ("ATTACK_META", "IOC_ATTACK_MAP", "MITRE_TACTICS", "CVE-20")
FRONTEND_MARKERS = ("EternalBlue", "Zerologon", "PetitPotam", "DCSync", "Nginx UI", "Copy Fail")

backend = (ROOT / "app" / "main.py").read_text(encoding="utf-8")
for marker in BACKEND_MARKERS:
    if marker in backend:
        failures.append(f"app/main.py: остались зашитые сведения «{marker}»")

for relative in ("app/static/js/attacks.js", "app/static/js/app.js", "app/static/index.html"):
    path = ROOT / relative
    if not path.is_file():
        continue
    text = path.read_text(encoding="utf-8")
    for marker in FRONTEND_MARKERS:
        if marker in text:
            failures.append(f"{relative}: зашитое название сценария «{marker}»")
    if re.search(r"CVE-\d{4}-\d{4,7}", text):
        failures.append(f"{relative}: зашитый идентификатор CVE")

print()
if failures:
    print(f"{len(failures)} failure(s)")
    for failure in failures:
        print(f"FAIL {failure}")
else:
    print("все сведения об атаках приходят из файла IOC и совпадают со снимком")
sys.exit(1 if failures else 0)
