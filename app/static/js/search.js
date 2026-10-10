/* IOC explorer: indexed search with quick filters, type facets and evidence tray. */

import { $, api, copyText, debounce, esc, highlight, normalize } from "./utils.js";
import { addToTray } from "./tray.js";

const state = {
  query: "",
  quick: new Set(),
  facets: new Set(),
  last: null,
  seq: 0,
};

const QUICK_MATCHERS = {
  "CVE-": (row) => /^CVE-/i.test(row.value),
  "Event ID": (row) => /\bEvent ID\b/i.test(row.value) || row.type === "Event ID",
  "0x": (row) => /^0x/i.test(row.value),
  "EfsRpc": (row) => /EfsRpc/i.test(row.value),
  "Opnum": (row) => /Opnum/i.test(row.value),
  "/api/": (row) => /\/api\//i.test(row.value),
  "splice": (row) => /splice|AF_ALG|page cache|Audit/i.test(row.value),
};

const EMPTY_HINT =
  "Введите минимум один символ: поиск идёт по индексу IOC, фрагментам из README, названиям сценариев и описаниям индикаторов.";

function collected() {
  const rows = [];
  for (const result of state.last?.results || []) {
    rows.push({
      value: result.ioc,
      type: result.type,
      context: (result.attacks || []).map((attack) => attack.short || attack.title).join(" · "),
      attacks: result.attacks || [],
      source: "ioc",
    });
  }
  for (const fragment of state.last?.fragments || []) {
    rows.push({
      value: fragment.value,
      type: fragment.kind,
      context: fragment.attach
        ? `${fragment.attack?.short || ""} · ${fragment.attach}`
        : fragment.attack?.short || "",
      attacks: fragment.attack ? [fragment.attack] : [],
      source: "fragment",
    });
  }
  return rows;
}

function matchesQuick(row) {
  if (!state.quick.size) return true;
  return Array.from(state.quick).some((key) =>
    QUICK_MATCHERS[key] ? QUICK_MATCHERS[key](row) : normalize(row.value).includes(normalize(key)),
  );
}

function visibleRows() {
  return collected().filter((row) => matchesQuick(row) && (!state.facets.size || state.facets.has(row.type)));
}

function rowsTemplate(rows, query) {
  return rows
    .map(
      (row) => `
      <div class="result">
        <div class="result__main">
          <code class="result__value" data-copy-value="${esc(row.value)}" title="Нажмите, чтобы скопировать">${highlight(esc(row.value), query)}</code>
          <div class="result__context">
            <span class="badge badge--plain">${esc(row.type)}</span>
            ${row.context ? `<span>${esc(row.context)}</span>` : ""}
          </div>
        </div>
        <div class="result__side">
          ${row.attacks.length ? `<button class="btn btn--quiet btn--sm" type="button" data-open-attack="${esc(row.attacks[0].id)}">Сценарий →</button>` : ""}
          <button class="icon-btn" type="button" data-collect="${esc(row.value)}" title="Добавить в набор IOC" aria-label="Добавить ${esc(row.value)} в набор">＋</button>
        </div>
      </div>`,
    )
    .join("");
}

function quickBar() {
  return `<div class="cluster">
      <span class="rail__label">Быстрые фильтры</span>
      ${Object.keys(QUICK_MATCHERS)
        .map(
          (key) =>
            `<button class="chip chip--select" type="button" data-quick="${esc(key)}" aria-pressed="${state.quick.has(key)}">${esc(key === "splice" ? "Linux Audit" : key === "0x" ? "Коды статусов" : key)}</button>`,
        )
        .join("")}
      <button class="btn btn--quiet btn--sm" type="button" id="search-reset">Сбросить</button>
    </div>`;
}

function facetBar(rows) {
  const counts = new Map();
  for (const row of rows) counts.set(row.type, (counts.get(row.type) || 0) + 1);
  if (counts.size < 2) return "";
  return `<div class="cluster">
      <span class="rail__label">Тип</span>
      ${[...counts.entries()]
        .sort((a, b) => b[1] - a[1])
        .map(
          ([type, count]) =>
            `<button class="chip chip--select" type="button" data-type="${esc(type)}" aria-pressed="${state.facets.has(type)}">${esc(type)} <span class="chip__mono">${count}</span></button>`,
        )
        .join("")}
    </div>`;
}

function facetsHost() {
  return $("#search-facets");
}

function render() {
  const host = $("#results");
  const stateNode = $("#search-state");
  const facets = facetsHost();
  const data = state.last;
  const query = state.query.trim();

  if (!data) {
    host.innerHTML = `<div class="result result--empty">${EMPTY_HINT}</div>`;
    stateNode.textContent = EMPTY_HINT;
    facets.innerHTML = "";
    return;
  }

  const rows = collected();
  const visible = visibleRows();
  const visibleIocs = visible.filter((row) => row.source === "ioc");
  const visibleFragments = visible.filter((row) => row.source === "fragment");
  const term = normalize(query);
  const attacks = (data.attacks || []).filter(
    (attack) => !term || normalize(attack.title).includes(term) || normalize(attack.id).includes(term),
  );

  const blocks = [];
  if (attacks.length) {
    blocks.push(`<div class="stack stack--sm">
      <p class="results__group-title">Сценарии · ${attacks.length}</p>
      ${attacks
        .map(
          (attack) => `
        <div class="result">
          <div class="result__main">
            <span class="result__value">${highlight(esc(attack.title), query)}</span>
            <div class="result__context">
              <span class="badge badge--plain">${esc(attack.severity)}</span>
              <span>${attack.ioc_count} индикаторов · ${attack.host_count} host / ${attack.network_count} network</span>
            </div>
          </div>
          <div class="result__side">
            <button class="btn btn--ghost btn--sm" type="button" data-open-attack="${esc(attack.id)}">Открыть сценарий →</button>
          </div>
        </div>`,
        )
        .join("")}
    </div>`);
  }
  if (visibleIocs.length) {
    blocks.push(`<div class="stack stack--sm">
      <p class="results__group-title">Индикаторы базы · ${visibleIocs.length}</p>
      ${rowsTemplate(visibleIocs, query)}
    </div>`);
  }
  if (visibleFragments.length) {
    blocks.push(`<div class="stack stack--sm">
      <p class="results__group-title">Технические фрагменты из README · ${visibleFragments.length}</p>
      ${rowsTemplate(visibleFragments, query)}
    </div>`);
  }

  const total = visible.length + attacks.length;
  stateNode.innerHTML = total
    ? `Найдено <b class="result-count">${total}</b> · индекс IOC, фрагменты README, каталог сценариев`
    : `По запросу «${esc(query)}» совпадений нет. Попробуйте CVE, Opnum, имя RPC-метода или код статуса.`;

  facets.innerHTML = `${quickBar()}${facetBar(rows)}`;
  host.innerHTML = blocks.join("") || `<div class="result result--empty">Совпадений нет. Уберите быстрые фильтры или измените запрос.</div>`;
}

export async function runSearch(query = state.query) {
  state.query = query;
  const term = query.trim();
  if (!term) {
    state.last = null;
    state.quick.clear();
    state.facets.clear();
    render();
    return;
  }
  const seq = ++state.seq;
  $("#search-state").innerHTML = `<span class="loader">Поиск в индексе индикаторов…</span>`;
  try {
    const data = await api(`/api/search?q=${encodeURIComponent(term)}`);
    if (seq !== state.seq) return;
    state.last = data;
    state.facets.clear();
    render();
  } catch {
    if (seq === state.seq) $("#search-state").innerHTML = "Не удалось выполнить поиск: сервер недоступен.";
  }
}

export function focusSearch() {
  const input = $("#ioc-search");
  if (!input) return;
  input.focus();
  input.scrollIntoView({ behavior: "smooth", block: "center" });
}

export function setSearchQuery(query, { run = true } = {}) {
  const input = $("#ioc-search");
  if (input) input.value = query;
  state.query = query;
  if (run) runSearch(query);
}

export function initSearch() {
  const input = $("#ioc-search");
  if (!input) return;
  const debounced = debounce((value) => runSearch(value), 200);
  input.addEventListener("input", (event) => debounced(event.target.value));
  input.addEventListener("keydown", (event) => {
    if (event.key === "Enter") {
      event.preventDefault();
      debounced.cancel();
      runSearch(input.value);
    }
  });

  $("#search-reset")?.addEventListener("click", (event) => {
    event.preventDefault();
    setSearchQuery("");
    input.focus();
  });

  // Quick filters and type facets are re-rendered on every search, so they are wired by delegation.
  facetsHost()?.addEventListener("click", (event) => {
    if (event.target.closest("#search-reset")) {
      setSearchQuery("");
      input.focus();
      return;
    }
    const quick = event.target.closest("[data-quick]");
    if (quick) {
      const key = quick.dataset.quick;
      if (state.quick.has(key)) state.quick.delete(key);
      else state.quick.add(key);
      render();
      return;
    }
    const facet = event.target.closest("[data-type]");
    if (facet) {
      const value = facet.dataset.type;
      if (state.facets.has(value)) state.facets.delete(value);
      else state.facets.add(value);
      render();
    }
  });

  document.addEventListener("click", (event) => {
    const copy = event.target.closest("#results [data-copy-value]");
    if (copy) {
      copyText(copy.dataset.copyValue, `Скопировано: ${copy.dataset.copyValue}`);
      return;
    }
    const collect = event.target.closest("#results [data-collect]");
    if (collect) {
      const row = collected().find((item) => item.value === collect.dataset.collect);
      if (row) addToTray({ value: row.value, type: row.type, context: row.context });
    }
  });

  render();
}
