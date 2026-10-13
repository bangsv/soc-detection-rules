/* Attack catalog: filters, scenario cards, detail console and exports. */

import { $, $$, api, copyText, countLabel, esc, fileSize, highlight, normalize, severityBadge, toast } from "./utils.js";
import { addToTray } from "./tray.js";

const state = {
  items: [],
  meta: null,
  query: "",
  severities: new Set(),
  platforms: new Set(),
  tactics: new Set(),
  current: null,
};

const FRAGMENT_KINDS = ["Event ID", "Код статуса", "RPC-метод", "Opnum", "HTTP-путь", "UUID"];

function matches(item) {
  const term = normalize(state.query);
  if (term) {
    const haystack = normalize(
      [item.title, item.id, item.short, item.cve, item.tagline, item.category, item.surface].join(" "),
    );
    if (!haystack.includes(term)) return false;
  }
  if (state.severities.size && !state.severities.has(item.severity)) return false;
  if (state.platforms.size && !state.platforms.has(item.platform)) return false;
  if (state.tactics.size && !item.attack.some((entry) => state.tactics.has(entry.tactic))) return false;
  return true;
}

function chip(filter, value, active) {
  return `<button class="chip chip--select" type="button" data-filter="${filter}" data-value="${esc(value)}" aria-pressed="${active}">${esc(value)}</button>`;
}

function renderFilters() {
  const { filters } = state.meta;
  $("#filter-severity").innerHTML = filters.severities
    .map((value) => chip("severity", value, state.severities.has(value)))
    .join("");
  $("#filter-platform").innerHTML = filters.platforms
    .map((value) => chip("platform", value, state.platforms.has(value)))
    .join("");
  $("#filter-tactic").innerHTML = filters.tactics
    .map((value) => chip("tactic", value, state.tactics.has(value)))
    .join("");
}

function distribution() {
  const max = Math.max(1, ...state.items.map((item) => item.ioc_count));
  $("#ioc-distribution").innerHTML = state.items
    .slice()
    .sort((a, b) => b.ioc_count - a.ioc_count)
    .map(
      (item) => `
      <div class="stack stack--sm">
        <div class="cluster cluster--between">
          <button class="btn btn--quiet btn--sm" type="button" data-open-attack="${esc(item.id)}" style="padding:0">${esc(item.short)}</button>
          <span class="text-2xs mono dim">${item.ioc_count}</span>
        </div>
        <div class="scenario__meter"><i style="width:${Math.round((item.ioc_count / max) * 100)}%"></i></div>
      </div>`,
    )
    .join("");
}

function scenarioCard(item) {
  const max = Math.max(1, ...state.items.map((entry) => entry.ioc_count));
  const tactics = item.attack.slice(0, 3);
  return `
    <article class="scenario" data-scenario="${esc(item.id)}" aria-current="${state.current === item.id}" tabindex="0" role="button"
             aria-label="Сценарий ${esc(item.title)}: ${item.ioc_count} индикаторов">
      <div class="scenario__top">
        ${severityBadge(item.severity)}
        <span class="badge badge--plain">${esc(item.platform)}</span>
      </div>
      <h3 class="scenario__title">${highlight(esc(item.title), state.query)}</h3>
      <p class="scenario__tagline">${esc(item.tagline)}</p>
      <div class="scenario__stats">
        <span><b>${item.ioc_count}</b> IOC</span>
        <span><b>${item.host_count}</b> host</span>
        <span><b>${item.network_count}</b> net</span>
        <span><b>${item.files}</b> README</span>
      </div>
      <div class="scenario__meter"><i style="width:${Math.round((item.ioc_count / max) * 100)}%"></i></div>
      <div class="scenario__tactics">
        ${
          tactics.length
            ? tactics.map((entry) => `<span class="badge badge--violet">${esc(entry.id)}</span>`).join("")
            : `<span class="badge badge--plain">лабораторный сценарий</span>`
        }
      </div>
      <div class="scenario__foot">
        <span>Открыть индикаторы</span>
        <span aria-hidden="true">→</span>
      </div>
    </article>`;
}

function renderGrid() {
  const visible = state.items.filter(matches);
  const host = $("#attacks");
  $("#attack-count").textContent = String(visible.length);
  $("#attack-total").textContent = String(state.items.length);
  host.innerHTML = visible.length
    ? visible.map(scenarioCard).join("")
    : `<div class="result result--empty">Под выбранные фильтры сценариев нет. Сбросьте фильтры или измените запрос.</div>`;
}

function fragmentRow(value, kind) {
  return `<div class="cluster" style="gap:8px">
      <span class="badge badge--plain">${esc(kind)}</span>
      <code class="result__value" data-copy-value="${esc(value)}" title="Нажмите, чтобы скопировать">${esc(value)}</code>
      <button class="icon-btn" type="button" data-collect="${esc(value)}" data-collect-type="${esc(kind)}" title="В набор IOC" aria-label="Добавить ${esc(value)}">＋</button>
    </div>`;
}

function fragmentsBlock(detail) {
  const fragments = detail.fragments || [];
  const shown = fragments.filter((fragment) => FRAGMENT_KINDS.includes(fragment.kind)).slice(0, 18);
  if (!shown.length) return "";
  const hidden = fragments.length - shown.length;
  return `
    <details class="materials">
      <summary><span>Технические фрагменты из триаж-заметок</span><small>${fragments.length}</small></summary>
      <div class="stack stack--sm" style="padding:14px 16px">
        <p class="text-xs dim">Автоматически извлечённые значения из пояснений: удобно копировать в правила и запросы SIEM.</p>
        ${shown.map((fragment) => fragmentRow(fragment.value, fragment.kind)).join("")}
        ${hidden > 0 ? `<p class="text-2xs dim">Ещё ${hidden} фрагментов скрыто — используйте поиск по индикаторам.</p>` : ""}
      </div>
    </details>`;
}

function iocRow(indicator, index, group) {
  return `
    <div class="ioc-row" data-important="${Boolean(indicator.important)}">
      <span class="ioc-row__index">${String(index + 1).padStart(2, "0")}</span>
      <div class="ioc-row__body">
        <div class="cluster" style="gap:8px">
          <code class="ioc-row__value" data-copy-value="${esc(indicator.value)}" title="Нажмите, чтобы скопировать">${esc(indicator.value)}</code>
          <span class="badge ${indicator.important ? "badge--high" : "badge--plain"}">${esc(indicator.detected_type)}</span>
          ${indicator.important ? `<span class="badge badge--critical">ключевой</span>` : ""}
        </div>
        ${indicator.description ? `<div class="ioc-row__desc">${rich(indicator.description)}</div>` : ""}
      </div>
      <div class="ioc-row__side">
        <div class="ioc-row__tools">
          <button class="icon-btn" type="button" data-copy-value="${esc(indicator.value)}" title="Скопировать" aria-label="Скопировать ${esc(indicator.value)}">⧉</button>
          <button class="icon-btn" type="button" data-collect="${esc(indicator.value)}" data-collect-type="${esc(indicator.detected_type)}" title="В набор IOC" aria-label="Добавить ${esc(indicator.value)} в набор">＋</button>
        </div>
        <span class="text-2xs mono dim">${esc(group.replace(" IOC", ""))}</span>
      </div>
    </div>`;
}

function rich(text) {
  return esc(text)
    .replace(/`([^`\n]+)`/g, "<code>$1</code>")
    .replace(/\*\*(.+?)\*\*/g, "<strong>$1</strong>")
    .split("\n")
    .filter((line) => line.trim())
    .map((line) => `<span>${line.replace(/^\s*[•*\-]\s*/, "• ")}</span>`)
    .join("");
}

function labTable(rows) {
  if (!rows?.length) return "";
  return `
    <div class="lab-table">
      <table>
        <thead>
          <tr><th>Source</th><th>Address</th><th>Role</th><th>Notes</th></tr>
        </thead>
        <tbody>
          ${rows
            .map(
              (row) =>
                `<tr><td><code>${esc(row.source || "—")}</code></td><td>${esc(row.address || "—")}</td><td>${esc(row.role || "—")}</td><td class="dim">${esc(row.notes || "—")}</td></tr>`,
            )
            .join("")}
        </tbody>
      </table>
    </div>`;
}

function referencesRow(rows) {
  if (!rows?.length) return "";
  return `<div class="cluster">
      ${rows
        .map((row) => {
          const label = `${esc(row.type)}${row.value ? ` · ${esc(row.value.replace(/^https?:\/\//, "").slice(0, 60))}` : ""}`;
          const title = esc(row.description || row.value || row.type);
          return /^https?:/.test(row.value || "")
            ? `<a class="chip chip--link" href="${esc(row.value)}" target="_blank" rel="noreferrer" title="${title}">${label} ↗</a>`
            : `<span class="chip" title="${title}">${label}</span>`;
        })
        .join("")}
    </div>`;
}

function detailTemplate(detail) {
  const groups = detail.ioc_groups.map((group) => ({ ...group, key: group.type.startsWith("Host") ? "host" : "network" }));
  const total = groups.reduce((sum, group) => sum + group.items.length, 0);
  return `
    <div class="detail__head">
      <div>
        <div class="cluster">
          ${severityBadge(detail.severity)}
          ${detail.cve ? `<span class="badge badge--accent">${esc(detail.cve)}</span>` : ""}
          ${detail.cvss ? `<span class="badge badge--plain">CVSS ${detail.cvss}</span>` : ""}
          <span class="badge badge--plain">${esc(detail.platform)}</span>
          <span class="badge badge--plain">${esc(detail.surface)}</span>
        </div>
        <h3 class="detail__title">${esc(detail.title)}</h3>
        <p class="text-sm muted">${esc(detail.tagline)}</p>
      </div>
      <button class="icon-btn" type="button" data-detail-close aria-label="Закрыть панель">×</button>
    </div>

    <div class="detail__grid">
      <div class="detail__block"><h4>Вектор атаки</h4><p>${esc(detail.vector)}</p></div>
      <div class="detail__block"><h4>На что смотреть в логах</h4><p>${esc(detail.focus)}</p></div>
      <div class="detail__block"><h4>Стенд воспроизведения</h4><p>${esc(detail.lab_text || "описан в таблице ниже")}</p></div>
    </div>

    ${labTable(detail.lab)}

    <div class="detail__actions">
      <button class="btn btn--primary btn--sm" type="button" data-tray-add-attack="${esc(detail.id)}">Добавить все IOC в набор</button>
      <button class="btn btn--ghost btn--sm" type="button" data-copy-attack="${esc(detail.id)}" data-mode="text">Копировать списком</button>
      <a class="btn btn--ghost btn--sm" href="/api/attacks/${encodeURIComponent(detail.id)}/tray?format=csv">CSV</a>
      <a class="btn btn--ghost btn--sm" href="/api/attacks/${encodeURIComponent(detail.id)}/bundle">ZIP с материалами</a>
      <span class="detail__count">${countLabel(total, ["индикатор", "индикатора", "индикаторов"])} · ${countLabel(detail.materials.length, ["материал", "материала", "материалов"])}</span>
    </div>

    ${referencesRow(detail.references)}

    <div class="ioc">
      <div class="ioc__tabs" role="tablist" aria-label="Группы индикаторов">
        <button class="tab" role="tab" type="button" data-ioc-tab="all" aria-selected="true">Все <small>${total}</small></button>
        ${groups
          .map(
            (group) =>
              `<button class="tab" role="tab" type="button" data-ioc-tab="${group.key}" aria-selected="false">${esc(group.type)} <small>${group.items.length}</small></button>`,
          )
          .join("")}
      </div>
      <div class="ioc__panels">
        ${groups
          .map(
            (group) => `
          <section class="ioc__panel" data-panel="${group.key}">
            <div class="ioc__panel-head">
              <span class="ioc__panel-title">${esc(group.type)}</span>
              <button class="btn btn--quiet btn--sm" type="button" data-copy-group="${esc(group.key)}">Копировать группу</button>
            </div>
            ${
              group.items.length
                ? `<div class="ioc__list">${group.items.map((indicator, index) => iocRow(indicator, index, group.type)).join("")}</div>`
                : `<p class="ioc-empty">Для этой группы индикаторы не описаны — например, атака полностью локальная и не создаёт сетевого трафика.</p>`
            }
          </section>`,
          )
          .join("")}
      </div>
    </div>

    ${fragmentsBlock(detail)}

    <details class="materials">
      <summary><span>Материалы сценария</span><small>${detail.materials.length} файлов · ${detail.material_kinds.join(", ")}</small></summary>
      <div class="materials__list">
        ${detail.materials
          .map(
            (material) => `
          <a class="material" href="/api/download?path=${encodeURIComponent(material.path)}" download>
            <span class="material__kind">${esc(material.kind)}</span>
            <span class="material__name" title="${esc(material.path)}">${esc(material.path)}</span>
            <span class="material__size">${fileSize(material.size)}</span>
            <b aria-hidden="true">↓</b>
          </a>`,
          )
          .join("")}
      </div>
    </details>

    ${
      detail.readmes.length
        ? `<div class="cluster">
             ${detail.readmes
               .map(
                 (path) =>
                   `<button class="doc-link" type="button" data-readme="${esc(path)}">Открыть документацию: ${esc(path.split("/").slice(-2, -1)[0] || "README")} <span aria-hidden="true">→</span></button>`,
               )
               .join("")}
           </div>`
        : ""
    }`;
}

export async function showAttack(attackId, { scroll = true } = {}) {
  const panel = $("#attack-detail");
  if (!panel) return;
  panel.hidden = false;
  panel.innerHTML = `<div class="loader">Загрузка сценария…</div>`;
  try {
    const detail = await api(`/api/attacks/${encodeURIComponent(attackId)}`);
    panel.innerHTML = detailTemplate(detail);
    state.current = attackId;
    $$("#attacks [data-scenario]").forEach((card) =>
      card.setAttribute("aria-current", String(card.dataset.scenario === attackId)),
    );
    if (scroll) panel.scrollIntoView({ behavior: "smooth", block: "start" });
    if (location.hash !== `#attack-${encodeURIComponent(attackId)}`) {
      history.replaceState(null, "", `#attack-${encodeURIComponent(attackId)}`);
    }
  } catch {
    panel.innerHTML = `<div class="result result--empty">Не удалось загрузить сценарий: сервер недоступен.</div>`;
  }
}

function currentGroupItems(key) {
  const panel = $(`#attack-detail [data-panel="${key}"]`);
  if (!panel) return [];
  return $$(".ioc-row__value", panel).map((node) => node.dataset.copyValue);
}

export async function collectAttack(attackId) {
  try {
    const detail = await api(`/api/attacks/${encodeURIComponent(attackId)}/tray`);
    let added = 0;
    for (const row of detail.items) {
      if (addToTray({ value: row.value, type: row.type, context: detail.attack.short })) added += 1;
    }
    toast(added ? `Добавлено индикаторов: ${added}` : "Все индикаторы уже в наборе");
  } catch {
    toast("Не удалось получить список индикаторов", "warn");
  }
}

async function copyAttack(attackId) {
  try {
    const response = await fetch(`/api/attacks/${encodeURIComponent(attackId)}/tray?format=text`);
    const text = await response.text();
    copyText(text, "Список IOC скопирован");
  } catch {
    toast("Не удалось скопировать список", "warn");
  }
}

function syncCollapsibleGroups() {
  const narrow = window.matchMedia("(max-width: 960px)").matches;
  $$("details[data-mobile-collapse]").forEach((group) => {
    if (narrow) group.removeAttribute("open");
    else group.setAttribute("open", "");
  });
}

export function initAttacks(items, meta) {
  state.items = items;
  state.meta = meta;
  renderFilters();
  renderGrid();
  distribution();
  syncCollapsibleGroups();
  window.matchMedia("(max-width: 960px)").addEventListener?.("change", syncCollapsibleGroups);
  $("#attack-search")?.addEventListener("input", (event) => {
    state.query = event.target.value;
    renderGrid();
  });

  $("#filter-reset")?.addEventListener("click", () => {
    state.query = "";
    state.severities.clear();
    state.platforms.clear();
    state.tactics.clear();
    const input = $("#attack-search");
    if (input) input.value = "";
    renderFilters();
    renderGrid();
  });

  document.addEventListener("click", (event) => {
    const filter = event.target.closest("[data-filter]");
    if (filter) {
      const bucket = { severity: state.severities, platform: state.platforms, tactic: state.tactics }[filter.dataset.filter];
      if (!bucket) return;
      const value = filter.dataset.value;
      if (bucket.has(value)) bucket.delete(value);
      else bucket.add(value);
      renderFilters();
      renderGrid();
      return;
    }

    const card = event.target.closest("[data-scenario]");
    if (card) {
      showAttack(card.dataset.scenario);
      return;
    }

    const open = event.target.closest("[data-open-attack]");
    if (open) {
      showAttack(open.dataset.openAttack);
      document.querySelector("#attacks-map")?.scrollIntoView({ behavior: "smooth", block: "start" });
      return;
    }

    if (event.target.closest("[data-detail-close]")) {
      const panel = $("#attack-detail");
      panel.hidden = true;
      panel.innerHTML = "";
      state.current = null;
      $$("#attacks [data-scenario]").forEach((node) => node.setAttribute("aria-current", "false"));
      history.replaceState(null, "", location.pathname + location.search);
      return;
    }

    const tab = event.target.closest("[data-ioc-tab]");
    if (tab) {
      const key = tab.dataset.iocTab;
      $$("#attack-detail [data-ioc-tab]").forEach((node) =>
        node.setAttribute("aria-selected", String(node.dataset.iocTab === key)),
      );
      $$("#attack-detail [data-panel]").forEach((panel) => {
        panel.hidden = key !== "all" && panel.dataset.panel !== key;
      });
      return;
    }

    const copyGroup = event.target.closest("[data-copy-group]");
    if (copyGroup) {
      const values = currentGroupItems(copyGroup.dataset.copyGroup);
      copyText(values.join("\n"), `Скопировано индикаторов: ${values.length}`);
      return;
    }

    const trayAttack = event.target.closest("[data-tray-add-attack]");
    if (trayAttack) {
      collectAttack(trayAttack.dataset.trayAddAttack);
      return;
    }

    const copyAttackBtn = event.target.closest("[data-copy-attack]");
    if (copyAttackBtn) {
      copyAttack(copyAttackBtn.dataset.copyAttack);
      return;
    }

    const copy = event.target.closest("#attack-detail [data-copy-value]");
    if (copy) {
      copyText(copy.dataset.copyValue, `Скопировано: ${copy.dataset.copyValue}`);
      return;
    }

    const collect = event.target.closest("#attack-detail [data-collect]");
    if (collect) {
      addToTray({
        value: collect.dataset.collect,
        type: collect.dataset.collectType || "IOC",
        context: state.current || "",
      });
    }
  });

  document.addEventListener("keydown", (event) => {
    if (event.key !== "Enter" && event.key !== " ") return;
    const card = event.target.closest?.("[data-scenario]");
    if (card) {
      event.preventDefault();
      showAttack(card.dataset.scenario);
    }
  });

  window.addEventListener("hashchange", () => {
    const match = location.hash.match(/^#attack-(.+)$/);
    if (match) showAttack(decodeURIComponent(match[1]), { scroll: false });
  });

  const initial = location.hash.match(/^#attack-(.+)$/);
  if (initial) showAttack(decodeURIComponent(initial[1]));

  return state;
}
