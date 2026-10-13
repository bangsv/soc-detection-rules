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

detail = json.load(urllib.request.urlopen(f"{BASE}/api/attacks/CVE-2017-0143_EternalBlue"))
lab_rows = " ".join(f"{row.get('address', '')} {row.get('notes', '')} {row.get('role', '')}" for row in detail["lab"])
check("Стенд EternalBlue: Windows 10", "Windows 10" in lab_rows, lab_rows[:140])
check("Стенд EternalBlue: Kali Linux", "Kali Linux" in lab_rows, lab_rows[:140])
check("Стенд приходит таблицей", isinstance(detail["lab"], list) and len(detail["lab"]) == 2, str(type(detail["lab"])))
check("Ссылки REFERENCES приходят из IOC", len(detail["references"]) >= 5, str(len(detail["references"])))

petitpotam = json.load(urllib.request.urlopen(f"{BASE}/api/attacks/CVE-2021-36942_PetitPotam"))
petitpotam_lab = " ".join(str(row) for row in petitpotam["lab"])
check("Стенд PetitPotam: Windows 10", "Windows 10" in petitpotam_lab, petitpotam_lab[:140])
check("Стенд PetitPotam: Kali Linux", "Kali Linux" in petitpotam_lab, petitpotam_lab[:140])

print()
print(f"{len(failures)} failure(s)" if failures else "все проверки пройдены")
sys.exit(1 if failures else 0)
