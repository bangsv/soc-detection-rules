/* Правила детектирования сценария: Sigma, Suricata, Sysmon, auditd, XP-правила.
   Список типов и файлов приходит вместе с деталями сценария (компактно), содержимое
   правила запрашивается только при открытии — интерфейс не нагружается. */

import { $, api, copyText, esc, fileSize, toast } from "./utils.js";

const state = {
  attackId: "",
  rules: { total: 0, groups: [] },
  activeKind: "all",
  activePath: "",
  cache: new Map(),
  seq: 0,
};

function groups() {
  return state.rules?.groups || [];
}

function total() {
  return state.rules?.total || 0;
}

function kindTabs() {
  const all = `<button class="rule-tab" type="button" data-rule-kind="all" aria-selected="${state.activeKind === "all"}">
      Все <small>${total()}</small>
    </button>`;
  return (
    all +
    groups()
      .map(
        (group) => `<button class="rule-tab" type="button" data-rule-kind="${esc(group.kind)}" aria-selected="${state.activeKind === group.kind}">
      ${esc(group.title)} <small>${group.count}</small>
    </button>`,
      )
      .join("")
  );
}

function visibleItems() {
  if (state.activeKind === "all") return groups().flatMap((group) => group.items);
  return groups().find((group) => group.kind === state.activeKind)?.items || [];
}

function fileList() {
  const items = visibleItems();
  if (!items.length) {
    return `<p class="rule-hint">Для этого типа правила в сценарии не найдены.</p>`;
  }
  return items
    .map(
      (item) => `
      <button class="rule-file" type="button" data-rule-open="${esc(item.path)}" aria-current="${state.activePath === item.path}" title="${esc(item.path)}">
        <span class="rule-file__kind">${esc(item.kind_title)}</span>
        <span class="rule-file__text">
          <span class="rule-file__name">${esc(item.name)}</span>
          ${item.folder ? `<span class="rule-file__folder">${esc(item.folder)}</span>` : ""}
        </span>
        <span class="rule-file__size">${fileSize(item.size)}</span>
      </button>`,
    )
    .join("");
}

function viewerTemplate() {
  if (!state.activePath) {
    return `<div class="rule-viewer rule-viewer--empty">
        <span class="badge badge--plain">Правило</span>
        <p>Выберите файл слева — содержимое загрузится по запросу и не утяжеляет страницу.</p>
      </div>`;
  }
  const rule = state.cache.get(state.activePath);
  if (!rule) {
    return `<div class="rule-viewer"><div class="loader">Загрузка правила…</div></div>`;
  }
  return `
    <div class="rule-viewer">
      <div class="rule-viewer__head">
        <div class="rule-viewer__meta">
          <span class="badge badge--accent">${esc(rule.kind_title)}</span>
          <span class="rule-viewer__path" title="${esc(rule.path)}">${esc(rule.path)}</span>
          <span class="text-2xs mono dim">${rule.lines} строк · ${fileSize(rule.size)}</span>
        </div>
        <div class="cluster" style="gap:6px">
          <button class="btn btn--ghost btn--sm" type="button" data-rule-copy>Копировать</button>
          <a class="btn btn--ghost btn--sm" href="/api/download?path=${encodeURIComponent(rule.path)}" download>Скачать</a>
        </div>
      </div>
      <pre class="rule-code" data-language="${esc(rule.language)}"><code>${esc(rule.content)}</code></pre>
    </div>`;
}

function render() {
  const host = $("#attack-rules");
  if (!host) return;
  if (!total()) {
    host.innerHTML = `
      <div class="rules">
        <div class="rules__head"><h4>Правила детектирования</h4></div>
        <p class="rule-hint">В папке сценария правила не найдены. Положите файлы в подпапки
        <code>Sigma_rules</code>, <code>suricata_rules</code>, <code>audit.rules</code>, <code>sysmon.xml</code>
        или <code>XP_rule (…)</code> — они появятся здесь автоматически.</p>
      </div>`;
    return;
  }
  const visible = visibleItems().length;
  host.innerHTML = `
    <div class="rules">
      <div class="rules__head">
        <h4>Правила детектирования</h4>
        <span class="text-2xs mono dim">${total()} файлов · ${groups().length} типов</span>
      </div>
      <div class="rule-tabs" role="tablist" aria-label="Типы правил">${kindTabs()}</div>
      <div class="rule-actions">
        <span class="text-2xs dim">Показано файлов: ${visible}</span>
        <button class="btn btn--quiet btn--sm" type="button" data-rule-copy-group>Копировать весь набор</button>
      </div>
      <div class="rules__body">
        <div class="rule-files" role="list">${fileList()}</div>
        ${viewerTemplate()}
      </div>
    </div>`;
}

/* «Копировать весь набор» — выгрузка правил активного типа одним текстом. */
async function copyVisibleRules() {
  const items = visibleItems();
  if (!items.length) return;
  const chunks = [];
  for (const item of items) {
    if (!state.cache.has(item.path)) {
      try {
        state.cache.set(item.path, await api(`/api/attacks/${encodeURIComponent(state.attackId)}/rule?path=${encodeURIComponent(item.path)}`));
      } catch {
        continue;
      }
    }
    const rule = state.cache.get(item.path);
    chunks.push(`# ${rule.path}\n${rule.content.trim()}`);
  }
  copyText(chunks.join("\n\n"), `Скопировано правил: ${chunks.length}`);
}

async function openRule(path) {
  if (state.activePath === path && state.cache.has(path)) return;
  state.activePath = path;
  const seq = ++state.seq;
  if (!state.cache.has(path)) {
    render();
    try {
      const data = await api(`/api/attacks/${encodeURIComponent(state.attackId)}/rule?path=${encodeURIComponent(path)}`);
      state.cache.set(path, data);
    } catch {
      toast("Не удалось загрузить правило", "warn");
    }
    if (seq !== state.seq) return;
  }
  render();
}

/* Панель монтируется в карточку сценария: делегирование, поэтому слушатели не теряются. */
export function initRules() {
  document.addEventListener("click", (event) => {
    if (!event.target.closest("#attack-rules")) return;
    const tab = event.target.closest("[data-rule-kind]");
    if (tab) {
      state.activeKind = tab.dataset.ruleKind;
      state.activePath = "";
      render();
      return;
    }
    const open = event.target.closest("[data-rule-open]");
    if (open) {
      openRule(open.dataset.ruleOpen);
      return;
    }
    if (event.target.closest("[data-rule-copy-group]")) {
      copyVisibleRules();
      return;
    }
    if (event.target.closest("[data-rule-copy]")) {
      const rule = state.cache.get(state.activePath);
      if (rule) copyText(rule.content, `Скопировано: ${rule.name}`);
    }
  });
}

export function mountRules(detail) {
  state.rules = detail.rules || { total: 0, groups: [] };
  state.attackId = detail.id;
  state.activeKind = state.rules.groups?.[0]?.kind || "all";
  state.activePath = "";
  state.cache.clear();
  state.seq += 1;
  render();
}
