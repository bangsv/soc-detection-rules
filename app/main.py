from __future__ import annotations

import io
import json
import os
import re
import zipfile
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path
from urllib.parse import quote

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
# Сведения об атаках, их индикаторы, стенды и ссылки живут только в файле IOC.
# Имя блока — только слова и слэши, поэтому «## LAB — описание» читается как LAB.
BLOCK_MARKER = re.compile(r"(?m)^\s*##\s*(?P<name>[A-Za-zА-Яа-я /]+?)\s*(?:—|::|$)", re.M)

SEVERITY_ORDER = {"Критично": 0, "Высоко": 1, "Средне": 2, "Низко": 3}


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


def _add_quoted_value(store: dict, raw: str, attach_to: str | None = None) -> None:
    """Значение из `обратных кавычек`: только похожее на реальный технический артефакт.

    Файл IOC — это проза, поэтому без фильтра в список попадают обрывки фраз. Правила:
    одно слово (или токен с путём), без предложений, без чистых чисел вроде 61111.
    """
    value = _clean_fragment(raw)
    if not value or len(value) < 3 or len(value) > 80:
        return
    if re.search(r"\.\s|,\s|;\s|:\s|[!?]\s", value):
        return
    if "(" in value and ")" not in value:
        return
    if " " in value and not re.search(r"[\\/:]", value):
        return
    if re.fullmatch(r"[\d\s.,:]+", value):
        return
    if value.isdigit():
        return
    # То, что уже попадает в отдельные категории, в «Значения» не дублируем.
    if STATUS_CODE_RE.search(value) or UUID_RE.search(value) or HTTP_RE.search(value) or "=" in value:
        return
    _add_fragment(store, value, "Значение", attach_to)


def extract_fragments(text: str) -> dict:
    """Достаёт из описаний IOC конкретные артефакты: ID событий, коды, RPC-методы.

    Используется поиском и командной палитрой: обрывки фраз не собираем, иначе подсказки
    превращаются в мусор.
    """
    store: dict = {}
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        anchors: list[tuple[int, str]] = []
        for match in EVENT_LABEL_RE.finditer(stripped):
            source = EVENT_SOURCES.get(match.group(0).split("Event")[0].strip().casefold(), "")
            if source:
                value = f"{source} Event ID {match.group(1)}"
                _add_fragment(store, value, "Event ID", value)
                anchors.append((match.start(), value))
        for match in QUOTED_RE.finditer(stripped):
            inner = match.group(1)
            _add_quoted_value(store, inner, anchors[0][1] if anchors else None)
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
    return store




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



# --------------------------------------------------------------------- helpers


def clean_text(value: str) -> str:
    """Убирает markdown-разметку из значения, сохраняя текст как есть."""
    value = (value or "").replace("\u00a0", " ")
    value = re.sub(r"\*\*(.+?)\*\*", r"\1", value)
    value = re.sub(r"(?<!\w)\*(?!\s)(.+?)(?<!\s)\*(?!\w)", r"\1", value)
    return value.strip()


def fingerprint(value: str) -> str:
    return re.sub(r"[\s`*_]+", " ", (value or "").casefold()).strip()


def parse_fields(block: str) -> dict[str, str]:
    """Пары `ключ: значение`, включая многострочные значения с отступом."""
    data: dict[str, str] = {}
    key: str | None = None
    for raw in block.splitlines():
        line = raw.rstrip()
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if line[:1] in {" ", "\t"} and key:
            data[key] = clean_text(f"{data[key]} {stripped}")
            continue
        if ":" in stripped:
            name, _, value = stripped.partition(":")
            key = name.strip().casefold()
            data[key] = clean_text(value)
    return data


TECHNIQUE_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")


def parse_techniques(block: str) -> list[dict[str, str]]:
    """`T1210 = Lateral Movement`, `T1210 (Lateral Movement)` или просто `T1210`.

    Поле `techniques:` может быть однострочным списком; продолжения на строках с
    отступом тоже учитываются, поэтому техники удобно дописывать вручную.
    """
    techniques: list[dict[str, str]] = []
    for raw in block.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.casefold().startswith("techniques:"):
            line = line.split(":", 1)[1].strip()
        line = line.lstrip("-*").strip()
        if not line:
            continue
        for chunk in re.split(r",|;", line):
            match = TECHNIQUE_RE.search(chunk)
            if not match:
                continue
            tid = match.group(0).upper()
            tactic = ""
            if "=" in chunk:
                tactic = chunk.split("=", 1)[1].strip()
            else:
                found = re.search(r"\(([^)]+)\)", chunk)
                if found:
                    tactic = found.group(1).strip()
            if not any(item["id"] == tid for item in techniques):
                techniques.append({"id": tid, "tactic": tactic or "—"})
    return techniques


def parse_blocks(body: str) -> list[tuple[str, str]]:
    """Делит тело сценария на блоки по ключевым словам (ATTACK, LAB, HOST IOC…).

    Всё, что стоит до первого ключевого слова, относится к блоку ATTACK: так поля
    `name`, `severity`, `techniques` читаются, даже если слово ATTACK не написано.
    """
    markers = ("ATTACK", "LAB", "HOST IOC", "NETWORK IOC", "REFERENCES", "SKIP RULES")
    pattern = re.compile(r"(?mi)^\s*(?P<name>" + "|".join(re.escape(m) for m in markers) + r")\s*$")
    found = list(pattern.finditer(body))
    blocks: list[tuple[str, str]] = []
    if not found:
        return [("ATTACK", body)]
    head = body[: found[0].start()]
    if head.strip():
        blocks.append(("ATTACK", head))
    for index, match in enumerate(found):
        start = match.end()
        end = found[index + 1].start() if index + 1 < len(found) else len(body)
        blocks.append((match.group("name").upper(), body[start:end]))
    merged: list[tuple[str, str]] = []
    for name, chunk in blocks:
        if merged and merged[-1][0] == name:
            merged[-1] = (name, merged[-1][1] + chunk)
        else:
            merged.append((name, chunk))
    return merged


def parse_stanzas(block: str) -> list[list[str]]:
    """Строки вида `a :: b :: c` → список разобранных полей (пустые пропускаются)."""
    rows: list[list[str]] = []
    for raw in block.splitlines():
        line = raw.strip().lstrip("-").strip()
        if not line or line.startswith("#") or line == "---":
            continue
        if set(line) <= {"═", "─", "—", "-", " "}:
            continue
        if "::" not in line:
            continue
        rows.append([clean_text(part) for part in line.split("::")])
    return rows


PLACEHOLDER_RE = re.compile(r"индикатор\w*\s+(?:нет|отсутству|не\s+описан)", re.I)


def is_placeholder(value: str) -> bool:
    return bool(PLACEHOLDER_RE.search(value or ""))


def parse_indicators(block: str) -> list[dict[str, Any]]:
    """Индикаторы: `- значение :: пояснение`, `- значение — пояснение` или таблица.

    Оформление специально нестрогое: файл ведётся вручную, поэтому принимаются оба
    разделителя, нумерованные пункты и markdown-таблица с колонками «индикатор/описание».
    """
    items: list[dict[str, Any]] = []
    for raw in block.splitlines():
        if not raw.strip() or raw.strip().startswith("#"):
            continue
        stripped = raw.lstrip()
        if stripped.startswith(("- ", "* ")) or re.match(r"^\d+\.\s", stripped):
            text = re.sub(r"^(?:- |\* |\d+\.\s+)", "", stripped).strip()
            important = "❗" in text
            text = text.replace("❗", "").strip()
            if not text:
                continue
            if "::" in text:
                value, _, description = text.partition("::")
            else:
                delimiter = re.search(r"\s+(?:—|–)\s+", text)
                if delimiter:
                    value, description = text[: delimiter.start()], text[delimiter.end():]
                else:
                    value, description = text, ""
            value = value.strip().strip("`").strip()
            description = description.strip()
            if not value:
                continue
            if is_placeholder(value):
                items.append({"value": value, "description": "", "important": False, "placeholder": True})
                continue
            items.append({"value": value, "description": description, "important": important})
        elif items and raw[:1] in {" ", "\t"} and not items[-1].get("placeholder"):
            continuation = stripped.strip()
            if not continuation or continuation == "---" or is_placeholder(continuation):
                continue
            previous = items[-1]["description"]
            items[-1]["description"] = (previous + " " + continuation).strip() if previous else continuation
    return items or parse_indicator_table(block)


def parse_indicator_table(block: str) -> list[dict[str, Any]]:
    """Запасной вариант: таблица `| Индикатор | Тип | Описание |` для ручного ввода."""
    rows: list[dict[str, Any]] = []
    headers: list[str] = []
    for raw in block.splitlines():
        line = raw.strip()
        if not line.startswith("|"):
            continue
        cells = [clean_text(cell) for cell in line.strip("|").split("|")]
        if not headers:
            headers = [cell.casefold() for cell in cells]
            continue
        if all(set(cell) <= {"-", ":", " "} for cell in cells):
            continue
        record = dict(zip(headers, cells))
        value = (record.get("индикатор") or record.get("значение") or record.get("value") or "").strip()
        if not value:
            continue
        description = (record.get("описание") or record.get("пояснение") or record.get("description") or "").strip()
        important = "❗" in value or (record.get("ключевой", "").casefold() in {"да", "yes", "true", "1"})
        rows.append({"value": value.replace("❗", "").strip(), "description": description, "important": important})
    return rows


def parse_cvss(value: str) -> float | None:
    match = re.search(r"\d+(?:[.,]\d+)?", value or "")
    if not match:
        return None
    try:
        return float(match.group(0).replace(",", "."))
    except ValueError:
        return None


# ------------------------------------------------------------------ IOC loader


def parse_scenario(body: str) -> dict[str, Any]:
    """Разбирает блок «АТАКА»: сведения, стенд, индикаторы, ссылки и служебные правила."""
    attack: dict[str, str] = {}
    technique_block = ""
    groups: dict[str, list[dict[str, Any]]] = {"Host IOC": [], "Network IOC": []}
    lab: list[dict[str, str]] = []
    references: list[dict[str, str]] = []
    skip: list[str] = []

    for name, block in parse_blocks(body):
        if name == "ATTACK":
            attack = parse_fields(block)
            technique_block = "\n".join(
                line for line in block.splitlines() if line.strip().casefold().startswith("techniques:")
                or line[:1] in {" ", "\t"}
            )
        elif name == "LAB":
            for row in parse_stanzas(block):
                row += [""] * (4 - len(row))
                lab.append({"source": row[0], "address": row[1], "role": row[2], "notes": row[3]})
        elif name == "HOST IOC":
            groups["Host IOC"] = parse_indicators(block)
        elif name == "NETWORK IOC":
            groups["Network IOC"] = parse_indicators(block)
        elif name == "REFERENCES":
            for row in parse_stanzas(block):
                row += [""] * (3 - len(row))
                references.append({"type": row[0], "value": row[1], "description": row[2]})
        elif name == "SKIP RULES":
            skip = [row[0] for row in parse_stanzas(block) if row and row[0]]

    return {
        "meta": {
            "short": attack.get("name") or "",
            "folder": attack.get("folder") or "",
            "cve": "" if attack.get("cve", "-") in {"", "-"} else attack["cve"],
            "severity": attack.get("severity") or "Средне",
            "cvss": parse_cvss(attack.get("cvss", "")),
            "platform": attack.get("platform") or "—",
            "surface": attack.get("surface") or "—",
            "category": attack.get("category") or "Сценарий",
            "tagline": attack.get("tagline") or "",
            "vector": attack.get("vector") or "",
            "focus": attack.get("focus") or "",
            "techniques": parse_techniques(technique_block),
        },
        "ioc_groups": groups,
        "lab": lab,
        "references": references,
        "skip": skip,
    }


def parse_global_section(name: str, block: str, settings: dict[str, Any]) -> None:
    """Разбирает общие разделы файла: стенд, площадки TI и список исключений."""
    if name == "LAB":
        settings["lab"] = [
            {"tag": row[0], "address": row[1] if len(row) > 1 else "", "role": row[2] if len(row) > 2 else "", "notes": row[3] if len(row) > 3 else ""}
            for row in (row + [""] * (4 - len(row)) for row in parse_stanzas(block))
        ]
    elif name == "THREAT INTELLIGENCE":
        settings["sources"] = [
            {"label": row[0], "url": row[1] if len(row) > 1 else "", "note": row[2] if len(row) > 2 else ""}
            for row in (row + [""] * (3 - len(row)) for row in parse_stanzas(block))
        ]
    elif name == "SKIP":
        # В разделе SKIP пишут просто имена папок — по одному в строке.
        entries: list[str] = []
        for raw in block.splitlines():
            line = raw.strip().lstrip("-").strip()
            if not line or line.startswith("#") or "::" in line:
                continue
            if set(line) <= {"═", "─", "—", "-", " "}:
                continue
            entries.append(line)
        settings["skip"] = entries


GLOBAL_BLOCK_RE = re.compile(r"(?mi)^\s*(?:#+\s*)?(?P<name>LAB|THREAT INTELLIGENCE|SKIP)\s*(?:$|—|::)")
ATTACK_RE = re.compile(r"(?mi)^\s*(?:#+\s*)?ATTACK\s*$")


def is_global_section(line: str, in_attack: bool = False) -> str:
    """Имя общего раздела файла (`LAB`, `THREAT INTELLIGENCE`, `SKIP`) или пустая строка.

    Внутри блока атаки слово `LAB` относится к стенду сценария, поэтому контекст важен.
    """
    match = GLOBAL_BLOCK_RE.match(line)
    if not match:
        return ""
    name = match.group("name").upper()
    if in_attack and name == "LAB":
        return ""
    return name


def parse_ioc_document(text: str) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Читает файл IOC: общие разделы и блоки «АТАКА» в порядке следования.

    Разделы можно писать и как `ATTACK`, и как `## ATTACK` — обе формы равнозначны.
    Баннеры из тире и комментарии-инструкции игнорируются.
    """
    settings: dict[str, Any] = {"lab": [], "sources": [], "skip": []}
    scenarios: list[dict[str, Any]] = []
    mode = "global"
    current = ""
    buffer: list[str] = []
    attack_bodies: list[str] = []
    header_lines: list[str] = []

    def flush() -> None:
        nonlocal buffer
        body = "\n".join(buffer)
        if current:
            if current == "ATTACK":
                attack_bodies.append(body)
            else:
                parse_global_section(current, body, settings)
        buffer = []

    for raw in text.splitlines():
        stripped = raw.strip()
        if stripped and set(stripped) <= {"═", "─", "—", "-", " "}:
            continue  # декоративный баннер
        if mode == "attack":
            # Внутри блока атаки ключевые слова относятся к сценарию, а не к файлу.
            if ATTACK_RE.match(raw):
                flush()
                current = "ATTACK"
                continue
            buffer.append(raw)
            continue
        if ATTACK_RE.match(raw):
            flush()
            mode = "attack"
            current = "ATTACK"
            continue
        header_lines.append(raw)
        section = is_global_section(raw, in_attack=False)
        if section:
            flush()
            current = section
        else:
            buffer.append(raw)
    flush()

    for body in attack_bodies:
        scenario = parse_scenario(body)
        if scenario["meta"]["short"] or scenario["meta"]["folder"]:
            scenarios.append(scenario)

    # Общие разделы ищем только в шапке файла: в блоках атак LAB означает стенд сценария.
    header = "\n".join(header_lines)
    if not settings["lab"] and not settings["sources"]:
        for section, body in parse_global_blocks(header):
            parse_global_section(section, body, settings)
    if not settings["skip"]:
        for section, body in parse_global_blocks(header, names=("SKIP",)):
            parse_global_section(section, body, settings)
    settings["skip"] = [
        row for row in settings["skip"]
        if row and row.casefold() not in {"end", "attack"} and not set(row) <= {"─", "—", "-"}
    ]
    return settings, scenarios


def parse_global_blocks(text: str, names: tuple[str, ...] = ("LAB", "THREAT INTELLIGENCE", "SKIP")) -> list[tuple[str, str]]:
    """Выделяет общие разделы (LAB / THREAT INTELLIGENCE / SKIP) из шапки файла.

    Блоки атак не рассматриваются: внутри них `LAB` — это стенд конкретного сценария.
    """
    header = ATTACK_RE.split(text)[0]
    pattern = re.compile(
        r"(?mi)^\s*(?:#+\s*)?(?P<name>" + "|".join(re.escape(name) for name in names) + r")\s*(?:$|—|::)"
    )
    found = list(pattern.finditer(header))
    blocks: list[tuple[str, str]] = []
    for index, match in enumerate(found):
        start = match.end()
        end = found[index + 1].start() if index + 1 < len(found) else len(header)
        blocks.append((match.group("name").upper(), header[start:end]))
    return blocks


def resolve_folder(scenario: dict[str, Any], folders: list[str]) -> str:
    """Папка сценария: явное поле `folder`, иначе поиск по CVE, затем по имени."""
    meta = scenario["meta"]
    explicit = meta.get("folder") or ""
    if explicit and explicit in folders:
        return explicit
    cve = (meta.get("cve") or "").upper()
    if cve:
        match = next((folder for folder in folders if folder.upper().startswith(cve)), None)
        if match:
            return match
    key = fingerprint(meta.get("short") or "").replace(" ", "")
    if key:
        match = next((folder for folder in folders if fingerprint(folder).replace(" ", "") == key), None)
        if match:
            return match
    return ""


def real_indicators(attack: dict, category: str) -> list[dict]:
    """Индикаторы без строк-заглушек: их не считаем и не отдаём в экспорт."""
    return [row for row in attack["ioc_groups"][category] if not row.get("placeholder")]


def lab_text(item: dict) -> str:
    parts = []
    for entry in item.get("lab", []):
        address = entry.get("address", "")
        role = entry.get("role", "")
        parts.append(f"{address} — {role}" if role else address)
    return " → ".join(part for part in parts if part)


@lru_cache(maxsize=1)
def catalog() -> dict:
    """Каталог атак целиком строится из файла IOC."""
    issues: list[str] = []
    lab: list[dict[str, str]] = []
    ti_sources: list[dict[str, str]] = []
    scenarios: list[dict[str, Any]] = []
    skipped: set[str] = set()
    folders: list[str] = sorted(
        entry.name
        for entry in ROOT.iterdir()
        if entry.is_dir() and entry.name not in SKIP_DIRS and not entry.name.startswith(".")
    )
    if IOC_SOURCE.is_file():
        settings, scenarios = parse_ioc_document(readable(IOC_SOURCE))
        lab = settings["lab"]
        ti_sources = settings["sources"]
        skipped = set(settings["skip"])
    else:
        issues.append("Файл IOC не найден: каталог атак пуст")

    attacks: dict[str, dict[str, Any]] = {}
    iocs: dict[str, dict[str, Any]] = {}
    readmes: list[dict[str, str]] = []
    for scenario in scenarios:
        attack_id = resolve_folder(scenario, folders)
        if not attack_id:
            issues.append(
                f"Сценарий «{scenario['meta']['short']}» не привязан к папке: укажите `folder` в блоке ATTACK"
            )
            continue
        attack = {
            "id": attack_id,
            "title": attack_id.replace("_", " "),
            "files": 0,
            "readmes": [],
            "iocs": {},
            "ioc_groups": {"Host IOC": [], "Network IOC": []},
            "meta": scenario["meta"],
            "lab": scenario["lab"],
            "references": scenario["references"],
            "skip": scenario["skip"],
            "fragments": {},
        }
        for category in ("Host IOC", "Network IOC"):
            for row in scenario["ioc_groups"][category]:
                placeholder = bool(row.get("placeholder"))
                indicator = {
                    "value": row["value"],
                    "type": category,
                    "description": "" if placeholder else (row["description"] or row["value"]),
                    "important": bool(row["important"]),
                    "placeholder": placeholder,
                }
                attack["ioc_groups"][category].append(indicator)
                if placeholder:
                    continue
                key = indicator["value"].casefold()
                attack["iocs"].setdefault(key, indicator)
                record = iocs.setdefault(key, {**indicator, "attacks": set()})
                record["attacks"].add(attack_id)
                attack["fragments"].update(extract_fragments(f"{indicator['value']} — {indicator['description']}"))
        attacks[attack_id] = attack

    excluded = SKIP_DIRS | EXCLUDED_CATALOG_FOLDERS | skipped
    unlisted: set[str] = set()
    for current, directories, filenames in os.walk(ROOT):
        directories[:] = [name for name in directories if name not in excluded]
        folder = Path(current)
        for filename in filenames:
            if filename.lower() != "readme.md":
                continue
            file = folder / filename
            rel = file.relative_to(ROOT).as_posix()
            parts = file.relative_to(ROOT).parts
            if len(parts) == 1:
                readmes.append({"path": rel, "attack": "", "title": "Обзор репозитория"})
                continue
            attack = attacks.get(parts[0])
            if attack:
                attack["files"] += 1
                attack["readmes"].append(rel)
                readmes.append({"path": rel, "attack": attack["id"], "title": attack["title"]})
            else:
                unlisted.add(parts[0])

    for folder in sorted(unlisted):
        count = len(list((ROOT / folder).rglob("README.md")))
        issues.append(
            f"Папка «{folder}» не описана в файле IOC: {count} README вне каталога. "
            "Добавьте блок АТАКА или пометьте папку в разделе ## SKIP."
        )

    ordered = sorted(
        attacks.values(),
        key=lambda item: (SEVERITY_ORDER.get(item["meta"]["severity"], 9), item["id"].casefold()),
    )
    unique: list[str] = []
    for issue in issues:
        if issue not in unique:
            unique.append(issue)
    return {
        "attacks": {item["id"]: item for item in ordered},
        "iocs": iocs,
        "readmes": readmes,
        "lab": lab,
        "sources": ti_sources,
        "issues": unique,
    }


def attack_meta(attack: dict) -> dict:
    return attack.get("meta") or {
        "short": attack["id"],
        "cve": "",
        "severity": "Средне",
        "cvss": None,
        "platform": "—",
        "surface": "—",
        "category": "Сценарий",
        "tagline": "",
        "vector": "",
        "focus": "",
        "techniques": [],
    }


# ------------------------------------------------------------------- templates


def platform_label(value: str) -> str:
    """Платформа всегда с заглавной буквы: «Linux / контейнер» → «Linux / Контейнер»."""
    return " / ".join(part.strip().capitalize() if part.strip() else part for part in (value or "").split("/"))


def public_attack(item: dict) -> dict:
    info = attack_meta(item)
    host = real_indicators(item, "Host IOC")
    network = real_indicators(item, "Network IOC")
    return {
        "id": item["id"],
        "title": item["title"],
        "short": info["short"],
        "cve": info["cve"],
        "files": item["files"],
        "ioc_count": len(host) + len(network),
        "host_count": len(host),
        "network_count": len(network),
        "rules_count": rules_payload(item["id"])["total"],
        "readmes": item["readmes"],
        "severity": info["severity"],
        "cvss": info["cvss"],
        "platform": platform_label(info["platform"]),
        "surface": info["surface"],
        "category": info["category"],
        "tagline": info["tagline"],
        "attack": info["techniques"],
        "lab": item.get("lab", []),
        "references": item.get("references", []),
    }


def attack_fragments(attack: dict) -> list[dict]:
    store = attack.get("fragments") or {}
    rows = sorted(store.values(), key=lambda row: (-row["count"], row["value"].casefold()))
    return [{"value": row["value"], "kind": row["kind"], "attach": row.get("attach") or ""} for row in rows]


# ------------------------------------------------- правила детектирования (SIEM/NDR/EDR)

# Тип правила определяется папкой и именем файла: папки сценариев можно раскладывать
# привычным образом (Sigma_rules, suricata_rules, audit.rules, XP_rule/...).
# Порядок важен: частные признаки (normalization, correlation) идут раньше общих (sysmon).
RULE_KINDS: list[tuple[str, str, tuple[str, ...]]] = [
    ("sigma", "Sigma", ("sigma",)),
    ("suricata", "Suricata", ("suricata",)),
    ("auditd", "auditd", ("audit.rules", "auditd", "audit_rule")),
    ("xp-normalization", "XP · нормализация", ("normalization_rule",)),
    ("sysmon", "Sysmon", ("sysmon",)),
    ("xp-correlation", "XP · корреляция", ("correlation_rule", "correlation")),
    ("xp-rule", "XP · правило", ("rule.co", "formula.xp")),
    ("elastic", "ELK / Elastic", ("elastic", "elk", "elastalert", "eql", "ndjson")),
    ("kaspersky", "Kaspersky KUMA", (".kuma.", "kuma_", "kuma/")),
    ("maxpatrol", "MaxPatrol SIEM", ("maxpatrol", "pt_siem")),
    ("wazuh", "Wazuh", ("wazuh", "ossec")),
    ("splunk", "Splunk", ("splunk", ".spl")),
]

RULE_LANGUAGES = {
    "sigma": "yaml",
    "suricata": "suricata",
    "sysmon": "xml",
    "auditd": "ini",
    "xp-normalization": "text",
    "xp-correlation": "text",
    "xp-rule": "text",
    "elastic": "json",
}

# Где лежат правила: папка detection_rule (новая раскладка) и привычные имена папок.
RULE_ROOT_DIR = "detection_rule"
RULE_ROOT_MARKERS = ("detection_rule", "sigma", "suricata", "sysmon", "audit", "elk_rules",
                     "normalization_rule", "correlation_rule", "kuma", "wazuh", "splunk")

# Что не показываем в правилах: материалы триажа, переводы, тесты и служебные метафайлы.
RULE_EXCLUDE = re.compile(
    r"triage/|/i18n/|/tests?/|\.pcapng$|\.evtx$|\.(png|jpg|jpeg|gif|ico|pdf|zip)$|"
    r"eve\.json$|stats\.log$|suricata\.log$|readme\.md$|\.pyc$|__pycache__",
    re.I,
)
# Служебные файлы правил: без них список остаётся списком самих правил.
# normalization_event.txt — это примеры нормализованных событий, а не правило.
RULE_EXCLUDED_NAMES = {"metainfo.yaml", "metainfo.yml", "normalized_success.json", "normalization_event.txt"}
RULE_EXTENSIONS = {".rules", ".yml", ".yaml", ".xml", ".conf", ".co", ".xp", ".json", ".txt",
                   ".py", ".ps1", ".rb", ".spl", ".ndjson"}


def is_rule_candidate(path: Path, attack_id: str) -> bool:
    """Файл лежит в правилах: внутри detection_rule или в папке с признаком системы."""
    try:
        parts = path.relative_to(ROOT / attack_id).parts
    except ValueError:
        return False
    if RULE_ROOT_DIR in parts:
        return True
    return any(any(marker in part.casefold() for marker in RULE_ROOT_MARKERS) for part in parts[:-1])


def classify_rule(path: Path, attack_id: str) -> tuple[str, str] | None:
    """Определяет тип правила по пути и имени файла; None — не правило."""
    rel = path.relative_to(ROOT).as_posix()
    inner = rel[len(attack_id) + 1:]
    if RULE_EXCLUDE.search(inner) or path.suffix.lower() not in RULE_EXTENSIONS:
        return None
    if path.name.casefold() in RULE_EXCLUDED_NAMES:
        return None
    haystack = f"{inner} {path.name}".casefold()
    for kind, title, markers in RULE_KINDS:
        if any(marker.casefold() in haystack for marker in markers):
            return kind, title
    # Одиночный файл Sigma-формата (`sigma.yml` вне папки sigma_rules).
    if path.suffix.lower() in {".yml", ".yaml"}:
        head = path.read_text(encoding="utf-8", errors="replace")[:2000]
        if re.search(r"title:|logsource:|detection:", head):
            return "sigma", "Sigma"
    return None


@lru_cache(maxsize=256)
def attack_rules(attack_id: str) -> tuple[dict, ...]:
    """Список правил сценария: тип, файл, размер. Содержимое отдаётся отдельным запросом."""
    base = attack_directory(attack_id)
    if ROOT not in base.parents or not base.is_dir():
        return ()
    found: dict[str, dict] = {}
    for source in sorted(base.rglob("*"), key=lambda item: item.as_posix().casefold()):
        if not source.is_file() or any(part in SKIP_DIRS for part in source.relative_to(ROOT).parts):
            continue
        if not is_rule_candidate(source, attack_id):
            continue
        classified = classify_rule(source, attack_id)
        if not classified:
            continue
        kind, title = classified
        rel = source.relative_to(ROOT).as_posix()
        folder = source.parent.relative_to(base).as_posix()
        found[rel] = {
            "id": rel,
            "name": source.name,
            "path": rel,
            "folder": "" if folder == "." else folder,
            "kind": kind,
            "kind_title": title,
            "size": source.stat().st_size,
        }
    return tuple(found.values())


def rules_payload(attack_id: str) -> dict:
    """Сгруппированный по типам список правил: компактно для интерфейса."""
    rows = list(attack_rules(attack_id))
    groups: list[dict] = []
    for kind, title, _ in RULE_KINDS:
        subset = [row for row in rows if row["kind"] == kind]
        if not subset:
            continue
        groups.append({
            "kind": kind,
            "title": title,
            "count": len(subset),
            "size": sum(row["size"] for row in subset),
            "items": subset,
        })
    # Типы, которых нет в префиксном списке (нестандартные имена файлов).
    known = {kind for kind, _, _ in RULE_KINDS}
    rest = [row for row in rows if row["kind"] not in known]
    if rest:
        groups.append({
            "kind": "other",
            "title": "Прочие правила",
            "count": len(rest),
            "size": sum(row["size"] for row in rest),
            "items": rest,
        })
    return {"total": len(rows), "groups": groups}


def read_rule_content(attack_id: str, rule_id: str) -> dict:
    """Читает содержимое правила; доступ ограничен папкой сценария."""
    base = attack_directory(attack_id)
    target = (ROOT / rule_id).resolve()
    if ROOT not in target.parents or base not in target.parents or not target.is_file():
        raise HTTPException(404, "Rule not found")
    text = readable(target)
    lines = text.count("\n") + 1
    classified = classify_rule(target, attack_id) or ("text", "Правило")
    return {
        "id": rule_id,
        "name": target.name,
        "path": target.relative_to(ROOT).as_posix(),
        "kind": classified[0],
        "kind_title": classified[1],
        "language": RULE_LANGUAGES.get(classified[0], "text"),
        "size": target.stat().st_size,
        "lines": lines,
        "content": text,
    }


# ------------------------------------------------------ материалы триажа (triage)

# Группы материалов триажа: подпись, как в файлах называется результат, что это.
TRIAGE_KINDS: list[tuple[str, str, str, tuple[str, ...]]] = [
    ("wireshark", "Wireshark", "Сетевые дампы (PCAPNG): разбор трафика по этапам атаки",
     ("wireshark", "pcap", "dump")),
    ("windows_logs", "Windows", "Журналы Windows: EVTX и выгрузки Sysmon",
     ("windows_logs", "windows", "evtx", "sysmon")),
    ("linux_logs", "Linux / auditd", "Журналы Linux и auditd",
     ("linux_logs", "linux_log", "audit_log")),
    ("suricata_logs", "Suricata", "Логи IDS Suricata: eve.json, fast.log, stats.log",
     ("suricata",)),
    ("cli", "Вывод PoC", "Вывод эксплойта из терминала: успешный и неуспешный запуск",
     ("output_cli", "cli", "poc", "script")),
    ("hash", "Хеши", "НTLM-хеши и учётные данные, полученные на стенде",
     ("hash", "ntlm", "credential")),
]

# Как в именах файлов помечают результат эксперимента.
# Порядок важен: `not_success` — это провал, поэтому проверки провала идут раньше успеха.
TRIAGE_RESULTS: list[tuple[str, str, str]] = [
    ("fail", "провал", r"not_success|not_not_success|nоt_success|fail|error|ошибк|_bad"),
    ("legit", "легитимное", r"legit|normal|baseline|легитим|репликац|ввод_контрол"),
    ("success", "успех", r"success|succeess|успех|_ok|good"),
    ("test", "тест правила", r"test"),
]

TRIAGE_RESULT_LABELS = {
    "success": "Успешная атака",
    "fail": "Неуспешная атака",
    "legit": "Легитимная активность",
    "test": "Проверка правила",
    "": "Результат не указан",
}

# Чем открывать файл: подсказка рядом с кнопкой скачивания.
TRIAGE_TOOLS = {
    ".pcapng": "Wireshark",
    ".pcap": "Wireshark",
    ".evtx": "Просмотр событий Windows",
    ".json": "Текстовый редактор",
    ".ndjson": "Текстовый редактор",
    ".log": "Текстовый редактор",
    ".txt": "Текстовый редактор",
    ".xml": "Просмотр событий / редактор",
    ".csv": "Excel",
    ".md": "Просмотр markdown",
}

# Что такое файл — по папке, в которой он лежит.
TRIAGE_FILE_TYPES = {
    "wireshark": "Сетевой дамп",
    "windows_logs": "Журнал Windows",
    "linux_logs": "Журнал Linux",
    "suricata_logs": "Лог IDS",
    "output_cli": "Вывод эксплойта",
}

TRIAGE_KIND_TITLES = {".pcapng": "PCAPNG", ".evtx": "EVTX", ".json": "JSON", ".txt": "TXT",
                      ".log": "LOG", ".xml": "XML", ".md": "MD", ".zip": "ZIP"}


def triage_result(name: str) -> str:
    """Успех, провал или легитимная активность — по имени файла."""
    haystack = name.casefold()
    for key, _, pattern in TRIAGE_RESULTS:
        if re.search(pattern, haystack):
            return key
    return ""


def triage_scenario_label(name: str, folder: str) -> str:
    """Сценарий внутри прогона: `metasploit`, `mimikatz`, `legitimate_activity`.

    В Zerologon логи разложены по подпапкам инструментов, и без этой подписи
    `eve.json` из metasploit не отличить от `eve.json` из mimikatz.
    """
    parts = [part for part in folder.split("/") if part and part.casefold() != "triage"]
    skip = {"wireshark", "windows_logs", "linux_logs", "suricata_logs", "output_cli_poc", "output_cli"}
    variants = [part for part in parts[1:] if part.casefold() not in skip]
    if not variants:
        return ""
    label = " / ".join(variants).replace("_", " ").strip()
    return label.capitalize() if label else ""


def triage_description(name: str, result_key: str, file_type: str) -> str:
    """Короткая подпись: что это за файл, без пересказа содержимого."""
    if result_key:
        return f"{file_type} · {TRIAGE_RESULT_LABELS[result_key].lower()}"
    if file_type:
        return file_type
    return "Файл материала"


@lru_cache(maxsize=256)
def attack_triage(attack_id: str) -> tuple[dict, ...]:
    """Файлы для разбора инцидента: дампы, журналы, вывод PoC. Только из папки triage."""
    base = attack_directory(attack_id)
    if ROOT not in base.parents or not base.is_dir():
        return ()
    found: dict[str, dict] = {}
    for source in sorted(base.rglob("*"), key=lambda item: item.as_posix().casefold()):
        if not source.is_file() or any(part in SKIP_DIRS for part in source.relative_to(ROOT).parts):
            continue
        inside = source.relative_to(base)
        if "triage" not in [part.casefold() for part in inside.parts[:-1]]:
            continue
        if source.suffix.lower() in {".pyc"} or "__pycache__" in inside.parts:
            continue
        rel = source.relative_to(ROOT).as_posix()
        folder = "" if inside.parent.as_posix() == "." else inside.parent.as_posix()
        ext = source.suffix.lower()
        result = triage_result(source.name)
        file_type = next(
            (label for key, label in TRIAGE_FILE_TYPES.items() if key in folder.casefold()), "Материал"
        )
        found[rel] = {
            "id": rel,
            "name": source.name,
            "path": rel,
            "folder": folder,
            "ext": ext,
            "kind": TRIAGE_KIND_TITLES.get(ext, ext.lstrip(".").upper() or "FILE"),
            "result": result,
            "result_title": TRIAGE_RESULT_LABELS.get(result, ""),
            "scenario": triage_scenario_label(source.name, folder),
            "type_title": file_type,
            "description": triage_description(source.name, result, file_type),
            "tool": TRIAGE_TOOLS.get(ext, "Текстовый редактор"),
            "download": f"/api/attacks/{attack_id}/triage/file?path={quote(rel)}",
            "size": source.stat().st_size,
        }
    return tuple(found.values())


def triage_group_of(row: dict) -> str:
    """Определяет группу материала по папке, в которой он лежит (первый уровень)."""
    folder = row["folder"].casefold()
    name = row["name"].casefold()
    for kind, _, _, markers in TRIAGE_KINDS:
        if any(marker in folder for marker in markers):
            return kind
    for kind, _, _, markers in TRIAGE_KINDS:
        if any(marker in name for marker in markers):
            return kind
    return "other"


def triage_payload(attack_id: str) -> dict:
    """Сгруппированный список материалов триажа с готовыми ссылками на скачивание."""
    rows = list(attack_triage(attack_id))
    order = {key: index for index, (key, _, _) in enumerate(TRIAGE_RESULTS)}

    def sort_key(row: dict) -> tuple:
        # Успех, провал, легитимное, прочее — внутри группы по имени.
        return (order.get(row["result"], 99), (row.get("scenario") or "").casefold(), row["name"].casefold())

    groups: list[dict] = []
    for kind, title, note, _ in TRIAGE_KINDS:
        subset = [row for row in rows if triage_group_of(row) == kind]
        if not subset:
            continue
        subset.sort(key=sort_key)
        groups.append({
            "kind": kind,
            "title": title,
            "note": note,
            "count": len(subset),
            "size": sum(row["size"] for row in subset),
            "bundle": f"/api/attacks/{attack_id}/bundle",
            "items": subset,
        })
    rest = [row for row in rows if triage_group_of(row) == "other"]
    if rest:
        rest.sort(key=sort_key)
        groups.append({
            "kind": "other",
            "title": "Прочее",
            "note": "Дополнительные материалы: скрипты, хеши, README",
            "count": len(rest),
            "size": sum(row["size"] for row in rest),
            "bundle": f"/api/attacks/{attack_id}/bundle",
            "items": rest,
        })
    by_result = {key: sum(1 for row in rows if row["result"] == key) for key, _, _ in TRIAGE_RESULTS}
    return {
        "total": len(rows),
        "size": sum(row["size"] for row in rows),
        "results": by_result,
        "bundle": f"/api/attacks/{attack_id}/bundle",
        "groups": groups,
    }


def read_triage_content(attack_id: str, path_id: str) -> dict:
    """Отдаёт материал триажа файлом на скачивание.

    Содержимое в интерфейсе не показываем: дампы и журналы открывают в Wireshark
    и Просмотрщике событий, поэтому единственное действие — скачать.
    """
    base = attack_directory(attack_id)
    target = (ROOT / path_id).resolve()
    if ROOT not in target.parents or base not in target.parents or not target.is_file():
        raise HTTPException(404, "File not found")
    if "triage" not in [part.casefold() for part in target.relative_to(base).parts[:-1]]:
        raise HTTPException(404, "File not found")
    return {
        "id": path_id,
        "name": target.name,
        "path": target.relative_to(ROOT).as_posix(),
        "download": f"/api/attacks/{attack_id}/triage/file?path={quote(target.relative_to(ROOT).as_posix())}",
        "size": target.stat().st_size,
    }


def lab_matrix() -> list[dict]:
    """Узлы стенда из раздела ## LAB: только то, что задано в файле IOC."""
    return [{**row} for row in catalog()["lab"]]


def details(item: dict) -> dict:
    info = attack_meta(item)
    materials = material_files(item["id"])
    groups = []
    for name in ("Host IOC", "Network IOC"):
        indicators = []
        for raw in item["ioc_groups"][name]:
            detected = None if raw.get("placeholder") else classify_ioc(raw["value"].strip())
            indicators.append({**raw, "detected_type": detected or name.split()[0]})
        groups.append({"type": name, "items": indicators})
    return {
        **public_attack(item),
        "materials": materials,
        "material_kinds": material_kinds(materials),
        "ioc_groups": groups,
        "fragments": attack_fragments(item),
        "vector": info["vector"],
        "focus": info["focus"],
        "lab": item.get("lab", []),
        "lab_text": lab_text(item),
        "references": item.get("references", []),
        "tactics": sorted({entry["tactic"] for entry in info["techniques"] if entry.get("tactic") and entry["tactic"] != "—"}),
        "rules": rules_payload(item["id"]),
        "triage": triage_payload(item["id"]),
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
        "lab": lab_matrix(),
        "sources": data["sources"],
        "issues": data["issues"],
        "ioc_source": IOC_SOURCE.name,
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


@app.get("/api/attacks/{attack_id}/rules")
def attack_rules_list(attack_id: str):
    """Список правил сценария по типам: Sigma, Suricata, Sysmon, auditd, XP и другие."""
    item = catalog()["attacks"].get(attack_id)
    if not item:
        raise HTTPException(404, "Attack not found")
    return rules_payload(attack_id)


@app.get("/api/attacks/{attack_id}/rule")
def attack_rule_content(attack_id: str, path: str = Query(min_length=1)):
    """Содержимое одного правила: загружается только при открытии в интерфейсе."""
    if attack_id not in catalog()["attacks"]:
        raise HTTPException(404, "Attack not found")
    return read_rule_content(attack_id, path)


@app.get("/api/attacks/{attack_id}/triage")
def attack_triage_list(attack_id: str):
    """Материалы для разбора инцидента: дампы, журналы, вывод PoC."""
    item = catalog()["attacks"].get(attack_id)
    if not item:
        raise HTTPException(404, "Attack not found")
    return triage_payload(attack_id)


@app.get("/api/attacks/{attack_id}/triage/file")
def attack_triage_content(attack_id: str, path: str = Query(min_length=1)):
    """Материал триажа на скачивание: дампы и журналы открывают в своих программах."""
    if attack_id not in catalog()["attacks"]:
        raise HTTPException(404, "Attack not found")
    read_triage_content(attack_id, path)
    target = (ROOT / path).resolve()
    return FileResponse(
        target,
        filename=target.name,
        media_type="application/octet-stream",
        content_disposition_type="attachment",
    )


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
    """Скачать сценарий одним ZIP-архивом."""
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
    body = buffer.getvalue()
    return Response(
        body,
        media_type="application/zip",
        headers={
            "Content-Disposition": f'attachment; filename="{safe_name}.zip"',
            # Браузер не должен гадать по типу: это всегда архив, а не страница.
            "Content-Type": "application/zip",
            "X-Content-Type-Options": "nosniff",
            "Content-Length": str(len(body)),
            "Cache-Control": "no-store",
        },
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
