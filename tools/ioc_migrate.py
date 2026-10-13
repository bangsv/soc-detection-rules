"""Миграция данных об атаках в файл IOC: снимок, сборка нового IOC и новый бэкенд.

Шаги (можно запускать по отдельности):
    python tools/ioc_migrate.py snapshot   # снимок текущих данных в tools/ioc-migration.json
    python tools/ioc_migrate.py build      # собрать IOC.new из снимка
    python tools/ioc_migrate.py backend    # собрать app/main.py.new (чтение только из IOC)
    python tools/ioc_migrate.py apply      # подменить IOC и app/main.py (с бэкапами)
"""
from __future__ import annotations

import importlib
import json
import os
import re
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BASELINE = ROOT / "tools" / "ioc-migration.json"
IOC = ROOT / "IOC"
MAIN = ROOT / "app" / "main.py"


# ------------------------------------------------------------------ шаг 1: снимок


def parse_legacy_ioc(text: str) -> dict[str, dict[str, list[dict]]]:
    """Читает прежний формат: `**Host IOC**` и нумерованные пункты."""
    result: dict[str, dict[str, list[dict]]] = {}
    for section in re.split(r"(?m)^###\s+", text)[1:]:
        heading, _, body = section.partition("\n")
        name = heading.strip()
        groups: dict[str, list[dict]] = {"Host IOC": [], "Network IOC": []}
        parts = re.split(r"(?im)^\*\*(Host IOC|Network\s*/\s*HTTP IOC|Network IOC)\*\*\s*$", body)
        for label, group_body in zip(parts[1::2], parts[2::2]):
            key = "Host IOC" if label.casefold().startswith("host") else "Network IOC"
            for raw in re.split(r"(?m)^\s*\d+\.\s+", group_body)[1:]:
                lines = [line.strip() for line in raw.splitlines() if line.strip() and line.strip() != "---"]
                if not lines:
                    continue
                first = lines[0]
                important = "❗" in first
                clean = first.replace("❗", "").strip()
                delimiter = re.search(r"\s(?:—|–)\s", clean)
                if delimiter:
                    value = clean[: delimiter.start()].strip()
                    description = clean[delimiter.end():].strip()
                else:
                    value, description = clean, ""
                value = value.strip("`").strip()
                if "индикаторы отсутствуют" in value:
                    groups[key].append({"value": value, "description": "", "important": False, "placeholder": True})
                    continue
                extra = [re.sub(r"^(?:\*|-|\d+\.)\s+", "", line) for line in lines[1:]]
                if extra:
                    description = " ".join([description, *extra]).strip()
                groups[key].append({"value": value, "description": description, "important": important})
        result[name] = groups
    return result


def snapshot() -> int:
    os.environ["RULES_DIR"] = str(ROOT)
    sys.path.insert(0, str(ROOT / "app"))
    main = importlib.import_module("main")

    legacy = parse_legacy_ioc(main.readable(main.IOC_SOURCE))
    catalog = main.catalog()

    payload: dict = {"attacks": {}, "order": [], "tactics": dict(main.MITRE_TACTICS)}
    for attack_id, item in catalog["attacks"].items():
        info = main.meta(attack_id)
        section = next(
            (name for name in legacy if name.casefold() in {info["short"].casefold(), attack_id.casefold()}),
            None,
        )
        groups = legacy.get(section, {"Host IOC": [], "Network IOC": []})
        payload["order"].append(attack_id)
        payload["attacks"][attack_id] = {
            "section": section,
            "short": info["short"],
            "cve": info["cve"],
            "severity": info["severity"],
            "cvss": info["cvss"],
            "platform": info["platform"],
            "surface": info["surface"],
            "category": info["category"],
            "tagline": info["tagline"],
            "vector": info["vector"],
            "focus": info["focus"],
            "lab": info["lab"],
            "techniques": [{"id": tid, "tactic": main.MITRE_TACTICS.get(tid, "—")} for tid in info["attack"]],
            "host_iocs": [{**row, "type": main.classify_ioc(row["value"].strip()) or "Host"} for row in groups["Host IOC"]],
            "network_iocs": [{**row, "type": main.classify_ioc(row["value"].strip()) or "Network"} for row in groups["Network IOC"]],
        }

    BASELINE.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    total = sum(
        sum(1 for row in attack["host_iocs"] + attack["network_iocs"] if not row.get("placeholder"))
        for attack in payload["attacks"].values()
    )
    print(f"снимок: {BASELINE.name} — сценариев {len(payload['attacks'])}, индикаторов {total}")
    for attack_id in payload["order"]:
        attack = payload["attacks"][attack_id]
        print(f"  {attack['short']:<12} host={len(attack['host_iocs'])} network={len(attack['network_iocs'])}")
    return 0


# --------------------------------------------------- шаг 2: сборка нового IOC

LAB_NODES = [
    ("dc01", "192.168.0.10", "контроллер домена (primary)", "события 4624/4662, DRSUAPI; Windows Server"),
    ("dc02", "192.168.0.100", "контроллер домена (secondary)", "реплика домена"),
    ("workstation", "192.168.0.15", "рабочая станция (Windows 10)", "точка входа клиентских атак"),
    ("attacker", "192.168.0.30", "атакующий хост (Kali Linux)", "Impacket, Responder, Mimikatz"),
]

THREAT_INTEL = [
    ("Kaspersky Threat Intelligence", "https://www.kaspersky.ru/enterprise-security/threat-intelligence", "APT-отчёты и TI-фиды"),
    ("PT ESC Threat Intelligence", "https://ptsecurity.com/research/pt-esc-threat-intelligence/", "исследования Positive Technologies"),
    ("F6 Research Hub", "https://www.f6.ru/resources/research-hub/", "исследования F6"),
    ("BI.ZONE Research", "https://bi.zone/expertise/research/", "аналитика и отчёты BI.ZONE"),
]

LAB_STANDS: dict[str, list[tuple[str, str, str, str]]] = {
    "CVE-2017-0143_EternalBlue": [
        ("attacker", "192.168.0.30 · Kali Linux", "запуск PoC EternalBlue", "TCP/445, SMBv1"),
        ("target", "192.168.0.15 · Windows 10", "SMB-сервер с уязвимым SMBv1", "Sysmon 3, Security 4624"),
    ],
    "CVE-2020-1472_Zerologon": [
        ("attacker", "192.168.0.30 · Kali Linux", "перебор NetrServerAuthenticate3", "TCP/135 + динамический RPC"),
        ("target", "192.168.0.10 · dc01", "уязвимый Netlogon контроллера домена", "сброс пароля учётной записи DC"),
    ],
    "CVE-2021-36942_PetitPotam": [
        ("attacker", "192.168.0.30 · Kali Linux", "EFSRPC-вызов и NTLM Relay", "listener на TCP/445"),
        ("coercion target", "192.168.0.10 · dc01", "принуждение к NTLM-аутентификации", "ответ через EFSRPC"),
        ("relay target", "192.168.0.15 · Windows 10", "приём ретранслированной аутентификации", "LogonType=3, учётная запись DC01$"),
    ],
    "CVE-2026-27944_Nginx UI": [
        ("scanner", "внешний узел", "запрос GET /api/backup", "Nginx UI до 2.3.3, HTTP/HTTPS"),
        ("target", "Nginx UI 2.x", "выдача резервной копии с секретами", "200 OK + X-Backup-Security"),
    ],
    "CVE-2026-31431_Copy fail": [
        ("attacker", "локальный пользователь", "эксплуатация через AF_ALG и splice", "без сетевого трафика"),
        ("target", "ядро Linux", "перезапись page cache /usr/bin/su", "euid=root без событий PAM"),
    ],
    "DCSync": [
        ("attacker", "192.168.0.30 · Kali Linux", "Impacket secretsdump", "MS-DRSR, DRSUAPI"),
        ("target", "192.168.0.10 · dc01", "выдача изменений каталога", "событие 4662, AccessMask=0x100"),
    ],
}

REFERENCES: dict[str, list[tuple[str, str, str]]] = {
    "CVE-2017-0143_EternalBlue": [
        ("NVD", "https://nvd.nist.gov/vuln/detail/CVE-2017-0143", "SMBv1 remote code execution (EternalBlue)"),
        ("BDU FSTEC", "https://bdu.fstec.ru/vul/2017-01100", "карточка в банке данных угроз"),
        ("MITRE ATT&CK", "https://attack.mitre.org/techniques/T1210/", "T1210 Exploitation of Remote Services"),
        ("MITRE ATT&CK", "https://attack.mitre.org/techniques/T1569/002/", "T1569.002 Service Execution"),
        ("MITRE ATT&CK", "https://attack.mitre.org/techniques/T1055/", "T1055 Process Injection"),
        ("MS17-010", "https://learn.microsoft.com/ru-ru/security-updates/securitybulletins/2017/ms17-010", "бюллетень с исправлением"),
        ("Habr", "https://habr.com/ru/companies/k2tech/articles/892202/", "разбор атаки и детектирования"),
    ],
    "CVE-2020-1472_Zerologon": [
        ("NVD", "https://nvd.nist.gov/vuln/detail/CVE-2020-1472", "Netlogon elevation of privilege (Zerologon)"),
        ("BDU FSTEC", "https://bdu.fstec.ru/vul/2020-03700", "карточка в банке данных угроз"),
        ("MITRE ATT&CK", "https://attack.mitre.org/techniques/T1068/", "T1068 Exploitation for Privilege Escalation"),
        ("MITRE ATT&CK", "https://attack.mitre.org/techniques/T1078/002/", "T1078.002 Domain Accounts"),
        ("Habr", "https://habr.com/ru/companies/bizone/articles/526168/", "разбор Zerologon"),
        ("Habr", "https://habr.com/ru/companies/rvision/articles/743142/", "детектирование Zerologon"),
    ],
    "CVE-2021-36942_PetitPotam": [
        ("NVD", "https://nvd.nist.gov/vuln/detail/CVE-2021-36942", "Windows EFS RPC spoofing (PetitPotam)"),
        ("BDU FSTEC", "https://bdu.fstec.ru/vul/2021-03260", "карточка в банке данных угроз"),
        ("MITRE ATT&CK", "https://attack.mitre.org/techniques/T1187/", "T1187 Forced Authentication"),
        ("MITRE ATT&CK", "https://attack.mitre.org/techniques/T1557/001/", "T1557.001 SMB Relay"),
        ("MITRE ATT&CK", "https://attack.mitre.org/techniques/T1021/002/", "T1021.002 SMB/Windows Admin Shares"),
        ("Habr", "https://habr.com/ru/companies/ussc/articles/688682/", "PetitPotam и NTLM Relay"),
        ("Hackndo", "https://en.hackndo.com/ntlm-relay/", "практика NTLM Relay"),
    ],
    "CVE-2026-27944_Nginx UI": [
        ("NVD", "https://nvd.nist.gov/vuln/detail/CVE-2026-27944", "Nginx UI backup disclosure"),
        ("MITRE ATT&CK", "https://attack.mitre.org/techniques/T1190/", "T1190 Exploit Public-Facing Application"),
        ("MITRE ATT&CK", "https://attack.mitre.org/techniques/T1552/001/", "T1552.001 Credentials In Files"),
    ],
    "CVE-2026-31431_Copy fail": [
        ("NVD", "https://nvd.nist.gov/vuln/detail/CVE-2026-31431", "Copy Fail: LPE в ядре Linux"),
        ("MITRE ATT&CK", "https://attack.mitre.org/techniques/T1068/", "T1068 Exploitation for Privilege Escalation"),
        ("MITRE ATT&CK", "https://attack.mitre.org/techniques/T1548/", "T1548 Abuse Elevation Control Mechanism"),
    ],
    "DCSync": [
        ("MITRE ATT&CK", "https://attack.mitre.org/techniques/T1003/006/", "T1003.006 DCSync"),
        ("BDU FSTEC", "https://bdu.fstec.ru/threat/ubi-2021-01079", "описание техники в банке данных угроз"),
        ("Habr", "https://habr.com/ru/companies/rvision/articles/709866/", "разбор DCSync"),
        ("Habr", "https://habr.com/ru/companies/rvision/articles/709942/", "детектирование DCSync"),
    ],
}

SKIP_RULES: dict[str, str] = {
    "CVE-2017-0143_EternalBlue": "normalization, correlation",
    "CVE-2020-1472_Zerologon": "normalization, correlation",
    "CVE-2021-36942_PetitPotam": "normalization, correlation, sigma, script",
    "CVE-2026-27944_Nginx UI": "normalization, correlation",
    "CVE-2026-31431_Copy fail": "normalization, correlation",
    "DCSync": "normalization, correlation",
}

HEADER = """# ══════════════════════════════════════════════════════════════════════════════
#  SOC Detection Rules · IOC BASE
#  Единственный источник сведений об атаках: и метаданные, и индикаторы, и ссылки.
#  Приложение (app/main.py) читает только этот файл и ничего не хранит в коде.
# ══════════════════════════════════════════════════════════════════════════════
#
#  КАК ДОБАВИТЬ ИЛИ ПОПРАВИТЬ АТАКУ
#  ─────────────────────────────────────────────────────────────────────────
#  1. Скопируйте любой блок «АТАКА» целиком и вставьте ниже.
#  2. Заполните поля. Обязательные: name, folder, severity, tagline.
#     • folder — имя папки с материалами атаки (по ней подтянутся README,
#       PCAP, EVTX и правила); можно не указывать, если папка называется
#       так же, как `name` с заменой пробелов на подчёркивания.
#     • cve — идентификатор уязвимости, если он есть.
#     • cvss — число (9.8) или «-», если оценка неизвестна.
#     • severity — одно из: Критично | Высоко | Средне | Низко.
#     • techniques — по одной технике в строке, можно без тактики:
#           T1210 = Lateral Movement
#           T1210 (Lateral Movement)
#  3. Индикаторы пишутся строками «- значение :: пояснение».
#     • разделитель — двойное двоеточие, поэтому тире внутри текста не мешают;
#     • `❗` в начале строки помечает ключевой признак;
#     • пояснение можно писать в несколько строк с отступом;
#     • если у сценария нет сетевых индикаторов, оставьте пустой раздел
#       NETWORK IOC — атлас сам покажет, что их нет.
#  4. Сохраните файл и нажмите ↻ в шапке атласа — данные перечитаются.
#
#  РАЗДЕЛЫ ФАЙЛА
#  ─────────────────────────────────────────────────────────────────────────
#    ## LAB                     общий стенд: узлы и их роли
#    ## THREAT INTELLIGENCE     площадки с отчётами (используются в разделе новостей)
#    ## SKIP                    папки, которые не показывать в атласе
#    ── АТАКА ──                блок сценария ниже
#
#  Порядок блоков «АТАКА» задаёт порядок сценариев в атласе.
# ══════════════════════════════════════════════════════════════════════════════


# ─────────────────────────────────────────────────────────────────────────────
## LAB — лабораторный стенд
# ─────────────────────────────────────────────────────────────────────────────
#  формат: tag :: address :: role :: notes
# ─────────────────────────────────────────────────────────────────────────────
LAB
"""


def build() -> int:
    payload = json.loads(BASELINE.read_text(encoding="utf-8"))
    parts: list[str] = [HEADER]
    parts.extend(f"{tag} :: {address} :: {role} :: {notes}" for tag, address, role, notes in LAB_NODES)
    parts.extend([
        "",
        "",
        "# ─────────────────────────────────────────────────────────────────────────────",
        "## THREAT INTELLIGENCE — площадки с отчётами и исследованиями",
        "# ─────────────────────────────────────────────────────────────────────────────",
        "#  формат: название :: url :: чем полезно",
        "# ─────────────────────────────────────────────────────────────────────────────",
    ])
    parts.extend(f"{name} :: {url} :: {note}" for name, url, note in THREAT_INTEL)
    parts.extend([
        "",
        "",
        "# ─────────────────────────────────────────────────────────────────────────────",
        "## SKIP — папки, которые не попадают в каталог атласа",
        "# ─────────────────────────────────────────────────────────────────────────────",
        "AD_CS_ESC",
        "",
    ])

    for attack_id in payload["order"]:
        attack = payload["attacks"][attack_id]
        techniques = attack["techniques"] or []
        parts.append("")
        parts.append("# ═════════════════════════════════════════════════════════════════════════════")
        parts.append("── АТАКА ─────────────────────────────────────────────────────────────────────")
        parts.append("# ═════════════════════════════════════════════════════════════════════════════")
        parts.append("ATTACK")
        parts.append(f"name: {attack['short']}")
        parts.append(f"folder: {attack_id}")
        parts.append(f"cve: {attack['cve'] or '-'}")
        parts.append(f"severity: {attack['severity']}")
        parts.append(f"cvss: {'-' if attack['cvss'] is None else attack['cvss']}")
        parts.append(f"platform: {attack['platform']}")
        parts.append(f"surface: {attack['surface']}")
        parts.append(f"category: {attack['category']}")
        parts.append(f"tagline: {attack['tagline']}")
        parts.append(f"vector: {attack['vector']}")
        parts.append(f"focus: {attack['focus']}")
        if techniques:
            parts.append(f"techniques: {techniques[0]['id']} = {techniques[0]['tactic']}")
            for technique in techniques[1:]:
                parts.append(f"  {technique['id']} = {technique['tactic']}")
        else:
            parts.append("techniques:")

        parts.append("")
        parts.append("LAB")
        for source, address, role, notes in LAB_STANDS.get(attack_id, []):
            parts.append(f"{source} :: {address} :: {role} :: {notes}")
        if not LAB_STANDS.get(attack_id):
            parts.append(f"lab :: {attack['lab']} :: лабораторный стенд :: -")

        parts.append("")
        parts.append("HOST IOC")
        for row in attack["host_iocs"]:
            marker = "❗ " if row["important"] else ""
            description = " ".join(row["description"].split())
            parts.append(f"- {marker}{row['value']} :: {description}")
        parts.append("")
        parts.append("NETWORK IOC")
        for row in attack["network_iocs"]:
            marker = "❗ " if row["important"] else ""
            description = " ".join(row["description"].split())
            parts.append(f"- {marker}{row['value']} :: {description}")

        parts.append("")
        parts.append("REFERENCES")
        for kind, value, note in REFERENCES.get(attack_id, []):
            parts.append(f"{kind} :: {value} :: {note}")

        parts.append("")
        parts.append("SKIP RULES")
        for rule in re.split(r"[,\s]+", SKIP_RULES.get(attack_id, "")):
            if rule:
                parts.append(rule)
        parts.append("")
        parts.append("END")
        parts.append("")

    (ROOT / "IOC.new").write_text("\n".join(parts), encoding="utf-8")
    print(f"IOC.new собран: {len(payload['order'])} сценариев")
    return 0


# ------------------------------------------------- шаг 3: новый бэкенд

BACKEND_CODE = r'''
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


def lab_matrix() -> list[dict]:
    """Узлы стенда из раздела ## LAB с привязкой к сценариям."""
    data = catalog()
    nodes: list[dict] = []
    for row in data["lab"]:
        address = row.get("address", "")
        ip = address.split("·")[0].strip()
        scenarios: list[str] = []
        if ip:
            for attack in data["attacks"].values():
                for entry in attack.get("lab", []):
                    if re.search(rf"(?<![\d.]){re.escape(ip)}(?![\d.])", entry.get("address", "")) and attack["id"] not in scenarios:
                        scenarios.append(attack["id"])
        nodes.append({**row, "scenarios": scenarios})
    return nodes


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
    }
'''

CONSTANTS = '''# Сведения об атаках, их индикаторы, стенды и ссылки живут только в файле IOC.
# Имя блока — только слова и слэши, поэтому «## LAB — описание» читается как LAB.
BLOCK_MARKER = re.compile(r"(?m)^\\s*##\\s*(?P<name>[A-Za-zА-Яа-я /]+?)\\s*(?:—|::|$)", re.M)

SEVERITY_ORDER = {"Критично": 0, "Высоко": 1, "Средне": 2, "Низко": 3}

'''


def replace_block(text: str, start_marker: str, end_marker: str, replacement: str) -> str:
    start = text.index(start_marker)
    end = text.index(end_marker, start)
    return text[:start] + replacement.lstrip("\n") + "\n" + text[end:]


def backend() -> int:
    text = MAIN.read_text(encoding="utf-8")

    regex_block = text[text.index("HASH_RE = re.compile"):text.index("MITRE_TACTICS = {")].rstrip() + "\n"
    fragments_block = (
        text[text.index("# ---------------------------------------------------------------- IOC extraction"):
             text.index("# --------------------------------------------------------------- IOC catalogue")].rstrip() + "\n"
    )
    # Файловые помощники не зависят от источника данных: сохраняем их без изменений.
    files_block = (
        text[text.index("def attack_directory(attack_id: str) -> Path:"):
             text.index("# ----------------------------------------------------------------------- routes")].rstrip() + "\n"
    )
    helpers = regex_block + "\n\n" + fragments_block + "\n\n" + files_block

    text = replace_block(text, "IOC_ATTACK_MAP = {", "SHORTCUTS = [", CONSTANTS)
    text = replace_block(
        text,
        "# ---------------------------------------------------------------- IOC extraction",
        "# ----------------------------------------------------------------------- routes",
        helpers + "\n\n" + BACKEND_CODE,
    )
    text = text.replace(
        '        "filters": {"categories": categories, "platforms": platforms, "tactics": tactics, "severities": list(SEVERITY_ORDER)},',
        '        "filters": {"categories": categories, "platforms": platforms, "tactics": tactics, "severities": list(SEVERITY_ORDER)},\n'
        '        "lab": lab_matrix(),\n'
        '        "sources": data["sources"],\n'
        '        "issues": data["issues"],\n'
        '        "ioc_source": IOC_SOURCE.name,',
    )
    # Тактики берутся из блока ATTACK, словарь MITRE_TACTICS больше не нужен.
    text = text.replace(
        '        "tactics": sorted({MITRE_TACTICS.get(tid, "") for tid in info["attack"]} - {""}),\n',
        "",
    )
    text = text.replace("IOC_SECTION_MARKER", "BLOCK_MARKER").replace("IOC_BLOCK_MARKER", "BLOCK_MARKER")

    (ROOT / "app" / "main.py.new").write_text(text, encoding="utf-8")
    print(f"app/main.py.new собран ({len(text)} символов)")
    for marker in ("ATTACK_META", "IOC_ATTACK_MAP", "MITRE_TACTICS"):
        print(f"  {marker}: {'ОСТАЛСЯ' if marker in text else 'удалён'}")
    return 0


def apply() -> int:
    shutil.copy(MAIN, ROOT / "app" / "main.py.legacy")
    shutil.copy(IOC, ROOT / "IOC.legacy")
    shutil.copy(ROOT / "app" / "main.py.new", MAIN)
    shutil.copy(ROOT / "IOC.new", IOC)
    print("IOC и app/main.py обновлены; прежние версии: IOC.legacy, app/main.py.legacy")
    return 0


ACTIONS = {"snapshot": snapshot, "build": build, "backend": backend, "apply": apply}


if __name__ == "__main__":
    action = sys.argv[1] if len(sys.argv) > 1 else "snapshot"
    raise SystemExit(ACTIONS[action]())
