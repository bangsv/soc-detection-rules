"""Быстрая проверка правок: BOM в CSV, регистр платформы, текст стенда."""
from __future__ import annotations

import json
import sys
import urllib.request

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8000"
failures: list[str] = []


def check(label: str, ok: bool, detail: str = "") -> None:
    print(f"[{'ok' if ok else 'FAIL'}] {label}{'' if ok else ' — ' + detail}")
    if not ok:
        failures.append(label)


raw = urllib.request.urlopen(f"{BASE}/api/attacks/CVE-2017-0143_EternalBlue/tray?format=csv").read()
check("CSV начинается с UTF-8 BOM", raw[:3] == b"\xef\xbb\xbf", raw[:8].hex())
text = raw.decode("utf-8-sig")
lines = text.splitlines()
check("CSV: заголовок на месте", lines[0] == "value,group,type,important,comment", lines[0])
check("CSV: кириллица читается", "Сетевой вход" in text, text[60:120])
check("CSV: CRLF для Excel", "\r\n" in text)
check("CSV: 8 индикаторов", len(lines) - 1 == 8, str(len(lines) - 1))

items = json.load(urllib.request.urlopen(f"{BASE}/api/attacks"))
platforms = sorted({item["platform"] for item in items})
check("Платформа «Linux / Контейнер»", "Linux / Контейнер" in platforms, "; ".join(platforms))
check("Нет «Linux / контейнер»", "Linux / контейнер" not in platforms)

meta = json.load(urllib.request.urlopen(f"{BASE}/api/meta"))
filters = meta["filters"]["platforms"]
check("Фильтр платформ с заглавной", "Контейнер" in filters and "контейнер" not in filters, "; ".join(filters))

labs = {item["short"]: item for item in items}
detail = json.load(urllib.request.urlopen(f"{BASE}/api/attacks/CVE-2017-0143_EternalBlue"))
check("Стенд EternalBlue: Windows 10", "Windows 10" in detail["lab"], detail["lab"])
check("Стенд EternalBlue: Kali Linux", "Kali Linux" in detail["lab"], detail["lab"])

petitpotam = json.load(urllib.request.urlopen(f"{BASE}/api/attacks/CVE-2021-36942_PetitPotam"))
check("Стенд PetitPotam: Windows 10", "Windows 10" in petitpotam["lab"], petitpotam["lab"])
check("Стенд PetitPotam: Kali Linux", "Kali Linux" in petitpotam["lab"], petitpotam["lab"])

print()
print(f"{len(failures)} failure(s)" if failures else "все проверки пройдены")
sys.exit(1 if failures else 0)
