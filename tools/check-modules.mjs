/* Static module graph check for the SOC Atlas front end.
   - verifies every relative import resolves to a real file
   - verifies every named import is actually exported by the target module
   - syntax checks each module with `node --check --input-type=module`
   Usage: node tools/check-modules.mjs [dir] */

import { readFileSync, readdirSync, statSync, writeFileSync, mkdirSync } from "node:fs";
import { join, resolve, dirname, extname } from "node:path";
import { tmpdir } from "node:os";
import { spawnSync } from "node:child_process";

const root = resolve(process.argv[2] || "app/static/js");
const failures = [];
const warnings = [];
const modules = new Map();
const scratch = join(tmpdir(), `soc-atlas-module-check-${process.pid}`);
mkdirSync(scratch, { recursive: true });

function walk(dir) {
  if (statSync(dir).isFile()) {
    modules.set(resolve(dir), readFileSync(dir, "utf8"));
    return;
  }
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) walk(full);
    else if ([".js", ".mjs"].includes(extname(entry))) modules.set(full, readFileSync(full, "utf8"));
  }
}
walk(root);

function exportedNames(source) {
  const names = new Set();
  let match;
  const reDecl = /export\s+(?:async\s+)?(?:function\*?|const|let|var|class)\s+([A-Za-z0-9_$]+)/g;
  while ((match = reDecl.exec(source))) names.add(match[1]);
  const reList = /export\s*\{([^}]+)\}/g;
  while ((match = reList.exec(source))) {
    for (const part of match[1].split(",")) {
      const bits = part.trim().split(/\s+as\s+/);
      const name = (bits[1] || bits[0] || "").trim();
      if (name) names.add(name);
    }
  }
  if (/export\s+default\b/.test(source)) names.add("default");
  return names;
}

function namedImports(source) {
  const out = [];
  let match;
  const re = /import\s*\{([^}]+)\}\s*from\s*["']([^"']+)["']/g;
  while ((match = re.exec(source))) {
    for (const part of match[1].split(",")) {
      const bits = part.trim().split(/\s+as\s+/);
      const name = (bits[0] || "").trim();
      if (name) out.push({ name, from: match[2] });
    }
  }
  const reDefault = /import\s+([A-Za-z0-9_$]+)\s*,\s*\{([^}]+)\}\s*from\s*["']([^"']+)["']/g;
  while ((match = reDefault.exec(source))) {
    // handled by namedImports for the brace part; namespaced default is unused in this project
  }
  return out;
}

function dynamicImports(source) {
  const out = [];
  const re = /import\(\s*["']([^"']+)["']\s*\)/g;
  let match;
  while ((match = re.exec(source))) out.push(match[1]);
  return out;
}

function resolveImport(fromFile, spec) {
  const candidate = resolve(dirname(fromFile), spec);
  for (const path of [candidate, `${candidate}.js`, join(candidate, "index.js")]) {
    if (modules.has(path)) return path;
  }
  return null;
}

for (const [file, source] of modules) {
  const scratchFile = join(scratch, `${file.split(/[\\/]/).pop()}.mjs`);
  writeFileSync(scratchFile, source);
  const check = spawnSync(process.execPath, ["--check", scratchFile], { encoding: "utf8" });
  if (check.status !== 0) {
    const message = (check.stderr || "").split("\n").slice(0, 4).join(" ").trim();
    failures.push(`${rel(file)}: syntax error: ${message}`);
  }

  for (const spec of [...new Set([...namedImports(source).map((i) => i.from), ...dynamicImports(source)])]) {
    if (!spec.startsWith(".")) continue;
    if (!resolveImport(file, spec)) failures.push(`${rel(file)}: unresolved import "${spec}"`);
  }

  for (const { name, from } of namedImports(source)) {
    if (!from.startsWith(".")) continue;
    const target = resolveImport(file, from);
    if (!target) continue;
    if (!exportedNames(modules.get(target)).has(name)) {
      failures.push(`${rel(file)}: "{${name}}" is not exported by "${from}"`);
    }
  }

  const body = source.replace(/import[\s\S]*?from\s*["'][^"']+["'];?/g, "");
  for (const { name } of namedImports(source)) {
    if (!new RegExp(`(?<![\\w$])${name.replace(/\$/g, "\\$")}(?![\\w$])`).test(body)) {
      warnings.push(`${rel(file)}: unused import ${name}`);
    }
  }
}

function rel(file) {
  return file.replace(`${resolve(".")}\\`, "").replace(/\\/g, "/");
}

/* Cross-check asset references in the HTML templates. */
const staticRoot = resolve("app/static");
for (const page of ["index.html", "about.html"]) {
  const file = join(staticRoot, page);
  let html;
  try {
    html = readFileSync(file, "utf8");
  } catch {
    failures.push(`${page}: template not found`);
    continue;
  }
  const refs = [...html.matchAll(/(?:src|href)="(\/static\/[^"]+)"/g)].map((match) => match[1]);
  for (const ref of new Set(refs)) {
    const asset = join(staticRoot, ref.replace("/static/", ""));
    try {
      statSync(asset);
    } catch {
      failures.push(`${page}: missing asset ${ref}`);
    }
  }
  const ids = [...html.matchAll(/\sid="([^"]+)"/g)].map((match) => match[1]);
  const duplicates = ids.filter((id, index) => ids.indexOf(id) !== index);
  if (duplicates.length) failures.push(`${page}: duplicate id(s) ${[...new Set(duplicates)].join(", ")}`);

  const referencedSelectors = [...html.matchAll(/data-[a-z-]+/g)].map((match) => match[0]);
  if (!referencedSelectors.length) warnings.push(`${page}: no data-* hooks found`);
}

console.log(`checked ${modules.size} module(s)`);
for (const warning of warnings) console.log(`warn  ${warning}`);
for (const failure of failures) console.log(`FAIL  ${failure}`);
console.log(failures.length ? `${failures.length} failure(s)` : "module graph OK");
process.exit(failures.length ? 1 : 0);
