from __future__ import annotations

import io
import json
import os
import re
import zipfile
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path

import markdown
from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import FileResponse, Response
from fastapi.staticfiles import StaticFiles

ROOT = Path(os.getenv("RULES_DIR", Path(__file__).resolve().parents[1])).resolve()
SKIP_DIRS = {".git", "app", "__pycache__", ".venv", "node_modules"}
EXCLUDED_CATALOG_FOLDERS = {"help_file", "Legitimate_Activity"}
XP_RULE_DIR = "XP_rule_(eXtraction and Processing)"
ALLOWED_XP_RULE_FILES = {"rule.co", "formula.xp", "normalization_event.txt"}
IOC_SOURCE = ROOT / "IOC"
IOC_ATTACK_MAP = {
    "eternalblue": "CVE-2017-0143_EternalBlue",
    "zerologon": "CVE-2020-1472_Zerologon",
    "petitpotam": "CVE-2021-36942_PetitPotam",
    "dcsync": "DCSync",
    "nginx ui": "CVE-2026-27944_Nginx UI",
    "cve-2025-33073": "CVE-2025-33073",
    "copy fail": "CVE-2026-31431_Copy fail",
}

# Hand-curated scenario metadata: keeps the catalog readable without touching the rule files.
ATTACK_META: dict[str, dict] = {
    "CVE-2017-0143_EternalBlue": {
        "short": "EternalBlue",
        "cve": "CVE-2017-0143",
        "tagline": "SMBv1 remote code execution на устаревших Windows-хостах.",
        "severity": "Критично",
        "cvss": 9.8,
        "platform": "Windows",
        "surface": "Сеть / SMB",
        "category": "Удалённое выполнение кода",
        "attack": ["T1210", "T1569.002", "T1055"],
        "vector": "Специально сформированные SMB-пакеты в SMBv1 приводят к переполнению и удалённому выполнению кода.",
        "focus": "Связка аномальной фрагментации NT Transact / Trans2 с последующим необычным исходящим соединением процесса.",
        "lab": "192.168.0.30 (Kali Linux) → 192.168.0.15 (Windows 10), SMB TCP/445",
    },
    "CVE-2020-1472_Zerologon": {
        "short": "Zerologon",
        "cve": "CVE-2020-1472",
        "tagline": "Криптографический дефект Netlogon: сброс пароля компьютерной учётной записи DC.",
        "severity": "Критично",
        "cvss": 10.0,
        "platform": "Windows",
        "surface": "RPC / MS-NRPC",
        "category": "Повышение привилегий",
        "attack": ["T1068", "T1078.002"],
        "vector": "Перебор NetrServerAuthenticate3 с нулевым ClientCredential и последующий NetrServerPasswordSet2.",
        "focus": "Цикл Opnum 4 → Opnum 26 с нулевыми challenge/credential и финальным STATUS_SUCCESS перед сменой пароля.",
        "lab": "192.168.0.30 (Kali Linux) → 192.168.0.10 (dc01), MS-NRPC TCP/135 + динамический RPC",
    },
    "CVE-2021-36942_PetitPotam": {
        "short": "PetitPotam",
        "cve": "CVE-2021-36942",
        "tagline": "Принудительная аутентификация через EFSRPC с последующим NTLM Relay.",
        "severity": "Высоко",
        "cvss": 8.1,
        "platform": "Windows",
        "surface": "RPC / MS-EFSRPC",
        "category": "Принуждение к аутентификации",
        "attack": ["T1187", "T1557.001", "T1021.002"],
        "vector": "EfsRpcOpenFileRaw с UNC-путём на контролируемый узел заставляет DC инициировать NTLM-аутентификацию.",
        "focus": "Входящий SMB на DC (Initiated=false) и следующий за ним исходящий SMB от DC (Initiated=true) на TCP/445.",
        "lab": "192.168.0.30 (Kali Linux, relay) → 192.168.0.10 (dc01) → 192.168.0.15 (Windows 10)",
    },
    "CVE-2026-27944_Nginx UI": {
        "short": "Nginx UI",
        "cve": "CVE-2026-27944",
        "tagline": "Неавторизованное скачивание резервной копии конфигурации через API Nginx UI.",
        "severity": "Высоко",
        "cvss": 7.5,
        "platform": "Linux / Контейнер",
        "surface": "HTTP / API",
        "category": "Утечка данных",
        "attack": ["T1190", "T1552.001"],
        "vector": "GET /api/backup до версии 2.3.3 возвращает архив с секретами без аутентификации.",
        "focus": "HTTP 200 на /api/backup вместе с заголовком X-Backup-Security, включая нормализованные варианты пути.",
        "lab": "Внешний сканер → Nginx UI 2.x, HTTP/HTTPS",
    },
    "CVE-2026-31431_Copy fail": {
        "short": "Copy Fail",
        "cve": "CVE-2026-31431",
        "tagline": "Локальное повышение привилегий через перезапись page cache SUID-файла.",
        "severity": "Критично",
        "cvss": 8.8,
        "platform": "Linux",
        "surface": "Ядро / AF_ALG",
        "category": "Повышение привилегий",
        "attack": ["T1068", "T1548"],
        "vector": "Цикл splice в AF_ALG перезаписывает страничный кэш /usr/bin/su распакованным пейлоадом.",
        "focus": "Прогрессия exit=4, 8, 12 … 160 в парных splice и запуск su с euid=root без событий PAM.",
        "lab": "Локальный пользователь → ядро Linux, системные вызовы socket/bind/splice",
    },
    "DCSync": {
        "short": "DCSync",
        "cve": "T1003.006",
        "tagline": "Извлечение секретов Active Directory через злоупотребление репликацией каталога.",
        "severity": "Критично",
        "cvss": 9.0,
        "platform": "Windows",
        "surface": "DRSUAPI / LDAP",
        "category": "Кража учётных данных",
        "attack": ["T1003.006"],
        "vector": "DRSGetNCChanges от узла, не являющегося контроллером домена, выгружает хеши учётных записей.",
        "focus": "Событие 4662 с AccessMask=0x100 и GUID Replicating Directory Changes All от не-DC источника.",
        "lab": "192.168.0.30 (Kali Linux, Impacket) → 192.168.0.10 (dc01), MS-DRSR",
    },
    "CVE-2025-33073": {
        "short": "CVE-2025-33073",
        "cve": "CVE-2025-33073",
        "tagline": "Лабораторный сценарий с набором материалов и правил детектирования.",
        "severity": "Средне",
        "cvss": None,
        "platform": "Windows",
        "surface": "SMB",
        "category": "Лабораторный сценарий",
        "attack": [],
        "vector": "Материалы и правила сценария используются для отработки триажа.",
        "focus": "Сценарий входит в атлас как заготовка и дополняется по мере появления материалов.",
        "lab": "Лабораторный стенд SOC",
    },
}

SEVERITY_ORDER = {"Критично": 0, "Высоко": 1, "Средне": 2, "Низко": 3}

HASH_RE = re.compile(r"\b[a-fA-F0-9]{32}(?:[a-fA-F0-9]{8})?(?:[a-fA-F0-9]{32})?\b")
STATUS_PREFIX_RE = re.compile(r"\b(?:STATUS_|WERR_|ERROR_|NT_)[A-Z0-9_]+", re.I)
UUID_RE = re.compile(r"\b[a-f0-9]{8}-(?:[a-f0-9]{4}-){3}[a-f0-9]{12}\b", re.I)
STATUS_CODE_RE = re.compile(r"\b0x[a-f0-9]{6,8}\b", re.I)
LIST_MARKER_RE = re.compile(r"^(?:•|\*|-|\d+\.)\s+")
SPLIT_RE = re.compile(r"[,\s]+(?![^()`]*`)|;\s*")
RPC_METHOD_RE = re.compile(r"\b(?:DRS|DRSGetNCChanges|DRSBind|Netr|EfsRpc|DRSCrackNames|DRSDomainControllerInfo)[A-Za-z0-9]*")
PROCESS_RE = re.compile(r"\b[a-z0-9_.-]+\.exe\b", re.I)
EVENT_LABEL_RE = re.compile(
    r"(?:Sysmon|Security|SMBClient|SMBServer|NETLOGON|Linux Audit|Linux|Audit)\s*(?:Event ID|Event ID:|:)?\s*([0-9]{3,5})",
    re.I,
)
QUOTED_RE = re.compile(r"`([^`\n]{2,120})`")
HTTP_RE = re.compile(r"\b(?:GET|POST|HEAD|PUT)\s+(/\S*)")
HOST_RE = re.compile(r"\b(?:[a-z0-9-]+\.)+(?:com|net|org|ru|local|io|gov|edu)\b", re.I)
HASH_LIKE_RE = re.compile(r"\b[a-f0-9]{32,64}\b", re.I)
OPNUM_RE = re.compile(r"\bOpnum\s*[=:]?\s*([0-9]{1,3})\b", re.I)
PATH_RE = re.compile(r"(?<![\w])/(?:usr|bin|etc|var|api|tmp|opt|home)[\w./-]*")

EVENT_SOURCES = {
    "sysmon": "Sysmon",
    "security": "Windows Security",
    "smbclient": "SMBClient",
    "smbserver": "SMBServer",
    "netlogon": "NETLOGON",
    "linux audit": "Linux Audit",
    "audit": "Linux Audit",
    "linux": "Linux Audit",
}

MITRE_TACTICS = {
    "T1187": "Credential Access",
    "T1003.006": "Credential Access",
    "T1557.001": "Credential Access",
    "T1552.001": "Credential Access",
    "T1068": "Privilege Escalation",
    "T1548": "Privilege Escalation",
    "T1078.002": "Privilege Escalation",
    "T1210": "Lateral Movement",
    "T1021.002": "Lateral Movement",
    "T1190": "Initial Access",
    "T1569.002": "Execution",
    "T1055": "Defense Evasion",
}

SHORTCUTS = [
    {"keys": ["Ctrl", "K"], "label": "Командная палитра: поиск по всему атласу"},
    {"keys": ["/"], "label": "Фокус в поле поиска индикаторов"},
    {"keys": ["1"], "label": "Раздел «Индикаторы»"},
    {"keys": ["2"], "label": "Раздел «Атаки»"},
    {"keys": ["3"], "label": "Раздел «Документация»"},
    {"keys": ["T"], "label": "Переключить светлую и тёмную тему"},
    {"keys": ["C"], "label": "Скопировать весь набор индикаторов сценария"},
    {"keys": ["Esc"], "label": "Закрыть панель, палитру или поиск"},
    {"keys": ["↑", "↓"], "label": "Навигация внутри палитры"},
]

app = FastAPI(title="SOC Atlas", docs_url=None, redoc_url=None)
app.mount("/static", StaticFiles(directory=Path(__file__).parent / "static"), name="static")


def readable(path: Path) -> str:
    for encoding in ("utf-8", "utf-8-sig", "cp1251"):
        try:
            return path.read_text(encoding=encoding)
        except UnicodeDecodeError:
            continue
    return path.read_text(encoding="utf-8", errors="replace")


def attack_name(folder: str) -> str:
    return folder.replace("_", " ")


def attack_from_readme(parts: tuple[str, ...]) -> tuple[str, str] | None:
    """Map each README to its attack; support AD CS ESC as independent scenarios."""
    if len(parts) < 2 or parts[0] in EXCLUDED_CATALOG_FOLDERS:
        return None
    if parts[0] == "AD_CS_ESC":
        return None  # Hidden until the group is complete and linked from the main README.
    return parts[0], attack_name(parts[0])


def classify_ioc(value: str) -> str | None:
    """Return a useful IOC category; discard prose accidentally wrapped in code."""
    if re.fullmatch(r"CVE-\d{4}-\d{4,7}", value, re.I):
        return "CVE"
    if re.fullmatch(r"T\d{4}(?:\.\d{3})?", value, re.I):
        return "MITRE ATT&CK"
    if HASH_RE.fullmatch(value):
        return "Хеш"
    if re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", value):
        return "IP-адрес"
    if re.fullmatch(r"(?:[a-f0-9]{2}:){5}[a-f0-9]{2}", value, re.I):
        return "MAC-адрес"
    if re.fullmatch(r"[a-f0-9]{8}-(?:[a-f0-9]{4}-){3}[a-f0-9]{12}", value, re.I):
        return "UUID"
    if re.fullmatch(r"0x[a-f0-9]{6,}", value, re.I):
        return "Код статуса"
    if re.fullmatch(r"/(?:api|v\d+|wp-[a-z-]+|admin|cgi-bin|usr|bin|etc|var)(?:/[a-z0-9_.-]+)*", value, re.I):
        return "HTTP-путь"
    if re.fullmatch(r"(?:[\w-]+\.)+(?:com|net|org|ru|local|io|gov|edu)", value, re.I):
        return "Домен"
    if re.fullmatch(r"\d{3,6}", value):
        return "Event ID"
    # Named rules, RPC methods and status labels: no spaces or full sentences.
    if re.fullmatch(r"[A-Za-z][A-Za-z0-9_.:-]{3,80}", value) and (
        any(c.isupper() for c in value[1:]) or "_" in value or "." in value
    ):
        return "Именованный индикатор"
    return None


# ---------------------------------------------------------------- IOC extraction


def _clean_fragment(value: str) -> str:
    value = value.replace("\u00a0", " ")
    value = re.sub(r"\s+", " ", value)
    return value.strip(" :;,.—–-`*_|")


def _add_fragment(store: dict, raw: str, kind: str, attach_to: str | None = None) -> None:
    value = _clean_fragment(raw)
    if not value or value.startswith("•") or len(value) < 2:
        return
    if value.casefold() in {"и", "или", "далее", "например"}:
        return
    entry = store.setdefault(value.casefold(), {"value": value, "kind": kind, "attach": attach_to, "count": 0})
    entry["count"] += 1
    if attach_to and not entry.get("attach"):
        entry["attach"] = attach_to


def extract_fragments(text: str) -> dict:
    """Pull concrete technical artefacts out of mixed Russian/English prose."""
    store: dict = {}
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        marker = bool(LIST_MARKER_RE.match(stripped))
        anchors: list[tuple[int, str]] = []
        for match in EVENT_LABEL_RE.finditer(stripped):
            source = EVENT_SOURCES.get(match.group(0).split("Event")[0].strip().casefold(), "")
            if source:
                value = f"{source} Event ID {match.group(1)}"
                _add_fragment(store, value, "Event ID", value)
                anchors.append((match.start(), value))
        for match in QUOTED_RE.finditer(stripped):
            inner = match.group(1)
            _add_fragment(store, inner, "Значение", anchors[0][1] if anchors else None)
            for uuid in UUID_RE.findall(inner):
                _add_fragment(store, uuid, "UUID", inner)
            for opnum in OPNUM_RE.finditer(inner):
                _add_fragment(store, f"Opnum {opnum.group(1)}", "Opnum", inner)
        for match in HTTP_RE.finditer(stripped):
            _add_fragment(store, f"{match.group(1)}", "HTTP-путь", anchors[0][1] if anchors else None)
        for match in STATUS_CODE_RE.finditer(stripped):
            _add_fragment(store, match.group(0), "Код статуса", anchors[0][1] if anchors else None)
        for match in STATUS_PREFIX_RE.finditer(stripped):
            _add_fragment(store, match.group(0), "Код статуса", anchors[0][1] if anchors else None)
        for match in RPC_METHOD_RE.finditer(stripped):
            _add_fragment(store, match.group(0), "RPC-метод", anchors[0][1] if anchors else None)
        for match in PROCESS_RE.finditer(stripped):
            _add_fragment(store, match.group(0), "Процесс", anchors[0][1] if anchors else None)
        for match in PATH_RE.finditer(stripped):
            _add_fragment(store, match.group(0), "Путь", anchors[0][1] if anchors else None)
        for match in HOST_RE.finditer(stripped):
            _add_fragment(store, match.group(0), "Домен", anchors[0][1] if anchors else None)
        for match in HASH_LIKE_RE.finditer(stripped):
            _add_fragment(store, match.group(0), "Хеш", anchors[0][1] if anchors else None)
        if not stripped.startswith("`"):
            for chunk in SPLIT_RE.split(re.sub(r"^-+\s*", "", stripped)):
                token = _clean_fragment(chunk)
                if 3 <= len(token) <= 48 and re.search(r"[A-Za-zА-Яа-я]", token) and not token.endswith((".", "!", "?")):
                    _add_fragment(store, token, "Ключ", anchors[0][1] if anchors else None)
    return store


# --------------------------------------------------------------- IOC catalogue


def load_iocs_from_source(attacks: dict, iocs: dict) -> None:
    """The manually curated IOC file is the single authoritative IOC source."""
    if not IOC_SOURCE.is_file():
        return
    source = readable(IOC_SOURCE)
    sections = re.split(r"(?m)^###\s+", source)
    for section in sections[1:]:
        heading, _, body = section.partition("\n")
        attack_id = IOC_ATTACK_MAP.get(heading.strip().casefold())
        attack = attacks.get(attack_id)
        if attack_id == "CVE-2025-33073" and not attack:
            attack = attacks[attack_id] = {
                "id": attack_id,
                "title": "CVE-2025-33073 · лабораторный сценарий",
                "files": 0,
                "readmes": [],
                "iocs": {},
                "ioc_groups": {"Host IOC": [], "Network IOC": []},
            }
        if not attack:
            continue
        group_parts = re.split(
            r"(?im)^\*\*(Host IOC|Network\s*/\s*HTTP IOC|Network IOC)\*\*\s*$",
            body,
        )
        run_fragments: dict = {}
        for label, group_body in zip(group_parts[1::2], group_parts[2::2]):
            category = "Host IOC" if label.casefold().startswith("host") else "Network IOC"
            entries = []
            current = []
            for line in group_body.splitlines():
                numbered = re.match(r"^\s*\d+\.\s+(.*)", line)
                if numbered:
                    if current:
                        entries.append(current)
                    current = [numbered.group(1)]
                elif current:
                    current.append(line)
            if current:
                entries.append(current)

            for lines in entries:
                first_line = lines[0].strip()
                delimiter = re.search(r"\s(?:—|–|-)\s", first_line)
                if delimiter:
                    label_text = first_line[:delimiter.start()]
                    detail_text = first_line[delimiter.end():].strip()
                else:
                    label_text = first_line
                    detail_text = ""

                code_label = re.search(r"`([^`\n]+)`", label_text)
                value = code_label.group(1) if code_label and delimiter else re.sub(r"[`*_❗]", "", label_text)
                value = re.sub(r"\s+", " ", value).strip(" :—–-")
                if not value:
                    continue

                details = [detail_text] if detail_text else []
                for continuation in lines[1:]:
                    nested = continuation.strip()
                    if nested:
                        nested = re.sub(r"^(?:\*|-|\d+\.)\s+", "", nested)
                        details.append(f"• {nested}")
                description = "\n".join(details).strip() or first_line
                indicator = {
                    "value": value,
                    "type": category,
                    "description": description,
                    "important": "❗" in "\n".join(lines),
                }
                attack["ioc_groups"][category].append(indicator)
                key = value.casefold()
                attack["iocs"].setdefault(key, indicator)
                record = iocs.setdefault(key, {**indicator, "attacks": set()})
                record["attacks"].add(attack_id)
                run_fragments.update(extract_fragments("\n".join(lines)))
        if run_fragments:
            attack["fragments"] = run_fragments


@lru_cache(maxsize=1)
def catalog() -> dict:
    attacks: dict[str, dict] = {}
    iocs: dict[str, dict] = {}
    readmes = []
    excluded_dirs = SKIP_DIRS | EXCLUDED_CATALOG_FOLDERS | {"AD_CS_ESC"}
    for current, directories, filenames in os.walk(ROOT):
        directories[:] = [name for name in directories if name not in excluded_dirs]
        folder = Path(current)
        for filename in filenames:
            if filename.lower() != "readme.md":
                continue
            file = folder / filename
            rel = file.relative_to(ROOT).as_posix()
            parts = file.relative_to(ROOT).parts
            attack_info = attack_from_readme(parts)
            if attack_info:
                attack_id, title = attack_info
                attack = attacks.setdefault(attack_id, {
                    "id": attack_id, "title": title, "files": 0, "readmes": [], "iocs": {},
                    "ioc_groups": {"Host IOC": [], "Network IOC": []},
                })
                attack["files"] += 1
                attack["readmes"].append(rel)
                readmes.append({"path": rel, "attack": attack_id, "title": attack["title"]})
            elif len(parts) == 1:
                readmes.append({"path": rel, "attack": "", "title": "Обзор репозитория"})
    load_iocs_from_source(attacks, iocs)
    # The catalog order stays deterministic: severity first, then name.
    ordered = sorted(
        attacks.values(),
        key=lambda item: (SEVERITY_ORDER.get(meta(item["id"])["severity"], 9), item["id"].casefold()),
    )
    attacks = {item["id"]: item for item in ordered}
    return {"attacks": attacks, "iocs": iocs, "readmes": readmes}


def meta(attack_id: str) -> dict:
    base = {
        "short": attack_name(attack_id),
        "cve": "",
        "tagline": "",
        "severity": "Средне",
        "cvss": None,
        "platform": "—",
        "surface": "—",
        "category": "Сценарий",
        "attack": [],
        "vector": "",
        "focus": "",
        "lab": "",
    }
    base.update(ATTACK_META.get(attack_id, {}))
    return base


def platform_label(value: str) -> str:
    """Платформа всегда с заглавной буквы: «Linux / контейнер» → «Linux / Контейнер»."""
    return " / ".join(part.strip().capitalize() if part.strip() else part for part in value.split("/"))


def public_attack(item: dict) -> dict:
    info = meta(item["id"])
    return {
        "id": item["id"],
        "title": item["title"],
        "short": info["short"],
        "cve": info["cve"],
        "files": item["files"],
        "ioc_count": sum(len(group) for group in item["ioc_groups"].values()),
        "host_count": len(item["ioc_groups"]["Host IOC"]),
        "network_count": len(item["ioc_groups"]["Network IOC"]),
        "readmes": item["readmes"],
        "severity": info["severity"],
        "cvss": info["cvss"],
        "platform": platform_label(info["platform"]),
        "surface": info["surface"],
        "category": info["category"],
        "tagline": info["tagline"],
        "attack": [{"id": tid, "tactic": MITRE_TACTICS.get(tid, "—")} for tid in info["attack"]],
    }


def attack_fragments(attack: dict) -> list[dict]:
    """Structured, copy-friendly artefacts extracted from the triage notes."""
    store = attack.get("fragments") or {}
    rows = sorted(store.values(), key=lambda row: (-row["count"], row["value"].casefold()))
    return [
        {"value": row["value"], "kind": row["kind"], "attach": row.get("attach") or ""}
        for row in rows
    ]


def attack_directory(attack_id: str) -> Path:
    """Every public download must stay inside the folder of its attack."""
    return (ROOT / attack_id).resolve()


def is_allowed_material(path: Path, base: Path) -> bool:
    """Keep the XP rule bundle limited to the three approved files only."""
    rel_parts = path.relative_to(base).parts
    if not rel_parts or rel_parts[0] != XP_RULE_DIR:
        return True
    return path.name in ALLOWED_XP_RULE_FILES


def material_files(attack_id: str) -> list[dict]:
    base = attack_directory(attack_id)
    if ROOT not in base.parents or not base.is_dir():
        return []
    materials = []
    for source in base.rglob("*"):
        if not source.is_file() or any(part in SKIP_DIRS for part in source.relative_to(ROOT).parts):
            continue
        if not is_allowed_material(source, base):
            continue
        rel = source.relative_to(ROOT).as_posix()
        materials.append({
            "path": rel,
            "name": source.name,
            "kind": source.suffix.lstrip(".").upper() or "FILE",
            "size": source.stat().st_size,
        })
    return sorted(materials, key=lambda x: x["path"].casefold())


def material_kinds(materials: list[dict]) -> list[str]:
    seen: list[str] = []
    for item in materials:
        if item["kind"] not in seen:
            seen.append(item["kind"])
    return seen


def response_headers() -> dict:
    return {"Cache-Control": "no-store"}


def details(item: dict) -> dict:
    info = meta(item["id"])
    materials = material_files(item["id"])
    groups = []
    for name in ("Host IOC", "Network IOC"):
        indicators = []
        for raw in item["ioc_groups"][name]:
            detected = classify_ioc(raw["value"].strip())
            indicators.append({**raw, "detected_type": detected or name.split()[0]})
        groups.append({"type": name, "items": indicators})
    cve = info["cve"] if info["cve"].startswith("CVE-") else ""
    return {
        **public_attack(item),
        "materials": materials,
        "material_kinds": material_kinds(materials),
        "ioc_groups": groups,
        "fragments": attack_fragments(item),
        "vector": info["vector"],
        "focus": info["focus"],
        "lab": info["lab"],
        "tactics": sorted({MITRE_TACTICS.get(tid, "") for tid in info["attack"]} - {""}),
        "sources": (
            [{"label": "NVD", "url": f"https://nvd.nist.gov/vuln/detail/{cve}"}] if cve else []
        ) + [{"label": f"MITRE {tid}", "url": f"https://attack.mitre.org/techniques/{tid.split('.')[0]}/{tid.split('.')[1] + '/' if '.' in tid else ''}"} for tid in info["attack"] if tid.startswith("T")],
    }


# ----------------------------------------------------------------------- routes


@app.get("/", response_class=FileResponse)
def home():
    return FileResponse(Path(__file__).parent / "static" / "index.html", headers=response_headers())


@app.get("/about", response_class=FileResponse)
def about():
    return FileResponse(Path(__file__).parent / "static" / "about.html", headers=response_headers())


@app.get("/api/health")
def health():
    return {"ok": True, "root": str(ROOT), "generated_at": datetime.now(timezone.utc).isoformat()}


@app.get("/api/meta")
def site_meta():
    data = catalog()
    items = [public_attack(x) for x in data["attacks"].values()]
    materials = [f for item in data["attacks"].values() for f in material_files(item["id"])]
    categories = sorted({item["category"] for item in items})
    platforms = sorted({platform_label(p).strip() for item in items for p in re.split(r"\s*/\s*", item["platform"]) if p and p != "—"})
    tactics = sorted({t["tactic"] for item in items for t in item["attack"] if t["tactic"] != "—"})
    return {
        "counts": {
            "attacks": len(items),
            "iocs": sum(item["ioc_count"] for item in items),
            "host_iocs": sum(item["host_count"] for item in items),
            "network_iocs": sum(item["network_count"] for item in items),
            "readmes": len(data["readmes"]),
            "materials": len(materials),
            "bytes": sum(item["size"] for item in materials),
            "critical": sum(1 for item in items if item["severity"] == "Критично"),
        },
        "filters": {"categories": categories, "platforms": platforms, "tactics": tactics, "severities": list(SEVERITY_ORDER)},
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }


@app.get("/api/summary")
def summary():
    data = catalog()
    return {
        "attacks": len(data["attacks"]),
        "iocs": len(data["iocs"]),
        "readmes": len(data["readmes"]),
        "items": [public_attack(x) for x in data["attacks"].values()],
        "readme_items": data["readmes"],
    }


@app.get("/api/shortcuts")
def shortcuts():
    return SHORTCUTS


@app.get("/api/attacks")
def attacks():
    return [public_attack(x) for x in catalog()["attacks"].values()]


@app.get("/api/attacks/{attack_id}")
def attack_detail(attack_id: str):
    item = catalog()["attacks"].get(attack_id)
    if not item:
        raise HTTPException(404, "Attack not found")
    return details(item)


@app.get("/api/attacks/{attack_id}/tray")
def attack_tray(attack_id: str, format: str = Query("json", pattern="^(json|text|csv)$")):
    """Analyst hand-off: one click yields a paste-ready indicator list."""
    item = catalog()["attacks"].get(attack_id)
    if not item:
        raise HTTPException(404, "Attack not found")
    rows = []
    for name in ("Host IOC", "Network IOC"):
        for raw in item["ioc_groups"][name]:
            detected = classify_ioc(raw["value"].strip()) or name.split()[0]
            rows.append({
                "value": raw["value"],
                "group": name,
                "type": detected,
                "important": bool(raw.get("important")),
                "comment": re.sub(r"\s+", " ", raw.get("description", "")).strip(),
            })
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    if format == "text":
        lines = [
            f"# SOC Atlas · {item['title']} · экспорт {stamp}",
            f"# Индикаторов: {len(rows)}",
            "",
        ]
        for group in ("Host IOC", "Network IOC"):
            subset = [r for r in rows if r["group"] == group]
            if not subset:
                continue
            lines.append(f"## {group}")
            for row in subset:
                flag = "[!]" if row["important"] else "[ ]"
                lines.append(f"{flag} {row['value']}\t{row['type']}")
            lines.append("")
        body = "\n".join(lines).strip() + "\n"
        return Response(
            body,
            media_type="text/plain; charset=utf-8",
            headers={"Content-Disposition": f'attachment; filename="{attack_id}-iocs.txt"'},
        )
    if format == "csv":
        import csv as csv_module

        buffer = io.StringIO()
        writer = csv_module.DictWriter(buffer, fieldnames=["value", "group", "type", "important", "comment"], lineterminator="\r\n")
        writer.writeheader()
        writer.writerows(rows)
        # UTF-8 BOM: без него Excel открывает кириллицу как «РЎРµС‚РµРІРѕР№ РІС…РѕРґ».
        body = "\ufeff" + buffer.getvalue()
        return Response(
            body,
            media_type="text/csv; charset=utf-8",
            headers={"Content-Disposition": f'attachment; filename="{attack_id}-iocs.csv"'},
        )
    return {"attack": public_attack(item), "count": len(rows), "items": rows}


@app.get("/api/download")
def download(path: str):
    target = (ROOT / path).resolve()
    if not target.is_file() or ROOT not in target.parents:
        raise HTTPException(404, "File not found")

    for attack_id in catalog()["attacks"]:
        base = attack_directory(attack_id)
        try:
            rel = target.relative_to(base)
        except ValueError:
            continue
        if rel.parts and rel.parts[0] == XP_RULE_DIR and target.name not in ALLOWED_XP_RULE_FILES:
            raise HTTPException(404, "File not found")
        return FileResponse(target, filename=target.name, content_disposition_type="attachment")

    raise HTTPException(404, "File not found")


@app.get("/api/attacks/{attack_id}/bundle")
def bundle(attack_id: str):
    """Download one scenario as a single ZIP archive."""
    item = catalog()["attacks"].get(attack_id)
    if not item:
        raise HTTPException(404, "Attack not found")
    materials = material_files(attack_id)
    base = attack_directory(attack_id)
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for material in materials:
            source = (ROOT / material["path"]).resolve()
            if not source.is_file():
                continue
            archive.write(source, source.relative_to(base).as_posix())
        payload = attack_tray(attack_id)  # returns the structured indicator list
        archive.writestr(
            "_SOC_ATLAS_iocs.json",
            json.dumps(payload, ensure_ascii=False, indent=2),
        )
    safe_name = re.sub(r"[^\w.\-]+", "_", attack_id)
    return Response(
        buffer.getvalue(),
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="{safe_name}.zip"'},
    )


@app.get("/api/readmes")
def readmes():
    return catalog()["readmes"]


@app.get("/api/readme")
def readme(path: str):
    target = (ROOT / path).resolve()
    if ROOT not in target.parents or target.name.lower() != "readme.md" or not target.is_file():
        raise HTTPException(404, "README not found")
    source = readable(target)
    rendered = markdown.markdown(source, extensions=["fenced_code", "tables", "toc", "sane_lists", "codehilite"])
    headings = re.findall(r"<h([23])[^>]*>(.*?)</h\1>", rendered, re.S)
    toc = [
        {"level": int(level), "text": re.sub(r"<[^>]+>", "", text).strip()}
        for level, text in headings
        if re.sub(r"<[^>]+>", "", text).strip()
    ]
    return {"path": path, "html": rendered, "source": source, "toc": toc[:24], "attack": path.split("/")[0] if "/" in path else ""}


@app.get("/api/search")
def search(q: str = Query(min_length=1, max_length=200)):
    needle = q.lower().strip()
    data = catalog()
    matches = []
    for key, record in data["iocs"].items():
        if needle in key or needle in record.get("description", "").casefold():
            matches.append({
                "ioc": record["value"], "type": record["type"],
                "attacks": [public_attack(data["attacks"][x]) for x in sorted(record["attacks"])],
            })
    attack_matches = [
        public_attack(a) for a in data["attacks"].values()
        if needle in a["title"].casefold() or needle in a["id"].casefold()
    ]
    fragment_matches = []
    for attack in data["attacks"].values():
        for record in attack.get("fragments", {}).values():
            if needle in record["value"].casefold():
                fragment_matches.append({
                    "value": record["value"], "kind": record["kind"],
                    "attach": record.get("attach") or "",
                    "attack": public_attack(attack),
                })
    fragment_matches.sort(key=lambda item: (not item["value"].casefold().startswith(needle), item["value"].casefold()))
    return {
        "query": q,
        "attacks": attack_matches,
        "results": sorted(matches, key=lambda x: (not x["ioc"].casefold().startswith(needle), x["ioc"].casefold()))[:80],
        "fragments": fragment_matches[:40],
    }


@app.post("/api/reindex")
def reindex():
    catalog.cache_clear()
    return {"ok": True, "summary": summary()}
