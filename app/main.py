from __future__ import annotations

import os
import re
from functools import lru_cache
from pathlib import Path

import markdown
from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

ROOT = Path(os.getenv("RULES_DIR", Path(__file__).resolve().parents[1])).resolve()
TEXT_EXTENSIONS = {".md", ".txt", ".yml", ".yaml", ".rules", ".xp", ".co", ".json", ".xml", ".log", ".js", ".ps1", ".rb"}
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
}
IOC_RE = re.compile(
    r"\bCVE-\d{4}-\d{4,7}\b|\bT\d{4}(?:\.\d{3})?\b|"
    r"\b(?:\d{1,3}\.){3}\d{1,3}\b|\b(?:[a-f0-9]{2}:){5}[a-f0-9]{2}\b|"
    r"\b[a-f0-9]{8}-(?:[a-f0-9]{4}-){3}[a-f0-9]{12}\b|"
    r"\b0x[a-f0-9]{6,}\b|/(?:[\w.~-]+/?){1,}|"
    r"\b(?:[\w-]+\.)+[a-z]{2,}\b",
    re.IGNORECASE,
)
HASH_RE = re.compile(r"\b[a-fA-F0-9]{32}(?:[a-fA-F0-9]{8})?(?:[a-fA-F0-9]{32})?\b")

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
    if re.fullmatch(r"/(?:api|v\d+|wp-[a-z-]+|admin|cgi-bin)(?:/[a-z0-9_.-]+)*", value, re.I):
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
    return {"attacks": attacks, "iocs": iocs, "readmes": readmes}


def public_attack(item: dict) -> dict:
    return {"id": item["id"], "title": item["title"], "files": item["files"], "ioc_count": sum(len(group) for group in item["ioc_groups"].values()), "readmes": item["readmes"]}


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


@app.get("/", response_class=FileResponse)
def home():
    return FileResponse(Path(__file__).parent / "static" / "index.html")


@app.get("/about", response_class=FileResponse)
def about():
    return FileResponse(Path(__file__).parent / "static" / "about.html")


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
    attack_matches = [public_attack(a) for a in data["attacks"].values() if needle in a["title"].casefold() or needle in a["id"].casefold()]
    return {"query": q, "attacks": attack_matches, "results": sorted(matches, key=lambda x: (not x["ioc"].casefold().startswith(needle), x["ioc"].casefold()))[:80]}


@app.get("/api/attacks")
def attacks():
    return [public_attack(x) for x in catalog()["attacks"].values()]


@app.get("/api/attacks/{attack_id}")
def attack_detail(attack_id: str):
    item = catalog()["attacks"].get(attack_id)
    if not item:
        raise HTTPException(404, "Attack not found")
    materials = material_files(attack_id)
    return {
        **public_attack(item),
        "materials": materials,
        "ioc_groups": [
            {"type": name, "items": item["ioc_groups"][name]}
            for name in ("Host IOC", "Network IOC")
        ],
    }


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
    return {"path": path, "html": rendered, "source": source}


@app.post("/api/reindex")
def reindex():
    catalog.cache_clear()
    return {"ok": True, "summary": summary()}
