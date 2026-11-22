/* Страница «Инструменты»: база blue-team материалов.
   Поиск и фильтры вынесены в закреплённую колонку слева; результат виден
   в трёх местах — строка состояния под поиском, счётчик в липкой панели
   списка и активные условия отдельными чипами. */

import { $, $$, esc, escapeRegExp, normalize } from "./utils.js";
import { initTheme, toggleTheme } from "./theme.js";
import { FORMATS, GROUPS, GROUP_ALIASES, PLATFORMS, SOURCES, TOOLS } from "./tools-data.js";

const state = {
  query: "",
  group: new Set(),
  format: new Set(),
  platform: new Set(),
  source: new Set(),
};

/* Фасеты фильтрации: порядок задаёт порядок блоков в колонке. */
const FACETS = [
  {
    kind: "group",
    label: "Задача",
    open: true,
    items: () => GROUPS.map((group) => ({ value: group.id, label: group.title })),
    has: (tool, value) => tool.group === value,
  },
  {
    kind: "format",
    label: "Формат",
    open: true,
    items: () => FORMATS.map((format) => ({ value: format.id, label: format.title })),
    has: (tool, value) => tool.format === value,
  },
  {
    kind: "platform",
    label: "Платформа",
    open: true,
    items: () => PLATFORMS.map((platform) => ({ value: platform, label: platform })),
    has: (tool, value) => tool.platforms.includes(value),
  },
  {
    kind: "source",
    label: "Источник",
    open: false,
    items: () => Object.values(SOURCES).map((source) => ({ value: source.id, label: source.title })),
    has: (tool, value) => tool.source === value,
  },
];

const facetById = (kind) => FACETS.find((facet) => facet.kind === kind);
const groupById = (id) => GROUPS.find((group) => group.id === id);
const formatById = (id) => FORMATS.find((format) => format.id === id);

function haystack(tool) {
  return normalize([tool.name, tool.summary, tool.why, tool.note, tool.url, ...tool.platforms].join(" "));
}

/** Проходит ли запись фильтры; `skip` исключает один фасет (для счётчиков). */
function passes(tool, skip) {
  for (const facet of FACETS) {
    if (facet.kind === skip) continue;
    const selected = state[facet.kind];
    if (!selected.size) continue;
    let hit = false;
    for (const value of selected) {
      if (facet.has(tool, value)) {
        hit = true;
        break;
      }
    }
    if (!hit) return false;
  }
  if (skip !== "query" && state.query) return haystack(tool).includes(normalize(state.query));
  return true;
}

const activeCount = () => FACETS.reduce((sum, facet) => sum + state[facet.kind].size, 0) + (state.query ? 1 : 0);
const visibleTools = () => TOOLS.filter((tool) => passes(tool, null));

/** Сколько записей даст значение фасета при текущих остальных условиях. */
function facetCount(facet, value) {
  return TOOLS.filter((tool) => passes(tool, facet.kind) && facet.has(tool, value)).length;
}

function toggleIn(set, value) {
  if (set.has(value)) set.delete(value);
  else set.add(value);
}

/* ------------------------------------------------------------- подсветка */

function queryTokens() {
  return normalize(state.query)
    .split(/\s+/)
    .filter((token) => token.length >= 2)
    .sort((a, b) => b.length - a.length);
}

/** Помечает найденные фрагменты; текст предварительно экранируется. */
function mark(text) {
  const value = esc(text);
  const tokens = queryTokens();
  if (!tokens.length) return value;
  const pattern = new RegExp(`(${tokens.map(escapeRegExp).join("|")})`, "gi");
  return value.replace(pattern, "<mark>$1</mark>");
}

/* ---------------------------------------------------------------- фильтры */

function facetRow(facet, item, count) {
  const active = state[facet.kind].has(item.value);
  const empty = count === 0 && !active;
  const hint = `${item.label}: ${count} ${pluralize(count)}`;
  return `<button class="tool-facet" type="button"
      data-filter="${facet.kind}" data-value="${esc(item.value)}"
      aria-pressed="${active}" title="${esc(hint)}" ${empty ? "disabled" : ""}>
      <span class="tool-facet__label">${esc(item.label)}</span>
      <span class="tool-facet__count">${count}</span>
    </button>`;
}

function renderFilters() {
  const host = $("#tools-filters");
  if (!host) return;
  host.innerHTML = FACETS.map((facet) => {
    const rows = facet
      .items()
      .map((item) => ({ ...item, count: facetCount(facet, item.value) }))
      .filter((item) => item.count > 0 || state[facet.kind].has(item.value));
    if (!rows.length) return "";
    const summary = `<summary class="tools-facet__head">${esc(facet.label)}${
      state[facet.kind].size ? ` <span class="tools-facet__picked">${state[facet.kind].size}</span>` : ""
    }</summary>`;
    return `<details class="tools-facet" ${facet.open || state[facet.kind].size ? "open" : ""}>
        ${summary}
        <div class="tools-facet__list">${rows.map((item) => facetRow(facet, item, item.count)).join("")}</div>
      </details>`;
  }).join("");
}

/* ---------------------------------------------------------------- статусы */

function setInputEmptyState(empty) {
  const input = $("#tools-search");
  if (!input) return;
  input.toggleAttribute("aria-invalid", empty);
  input.classList.toggle("is-empty", empty);
}

function renderStatus() {
  const total = TOOLS.length;
  const found = visibleTools().length;
  const conditions = activeCount();
  const query = state.query.trim();

  const status = $("#tools-status");
  if (status) {
    if (!conditions) {
      status.dataset.state = "all";
      status.textContent = `Показаны все ${total} записи`;
    } else if (found) {
      status.dataset.state = "found";
      status.textContent = `Найдено ${found} из ${total}`;
    } else {
      status.dataset.state = "empty";
      status.textContent = query
        ? `По запросу «${query}» ничего нет`
        : "Под выбранные фильтры ничего нет";
    }
  }

  const compact = $("#tools-side-state");
  if (compact) compact.textContent = conditions ? `${found} из ${total}` : `${total}`;

  const counter = $("#tools-count");
  if (counter) counter.textContent = conditions ? `найдено ${found} из ${total}` : `все ${total}`;

  const toolbar = $("#tools-toolbar-hint");
  if (toolbar) toolbar.textContent = "";

  const chips = $("#tools-active");
  if (chips) {
    const items = [];
    if (query) items.push({ kind: "query", value: "", label: `поиск: «${query}»` });
    for (const facet of FACETS) {
      for (const value of state[facet.kind]) {
        const label = facet.items().find((item) => item.value === value)?.label || value;
        items.push({ kind: facet.kind, value, label });
      }
    }
    chips.innerHTML = items.length
      ? items
          .map(
            (item) => `<button class="tools-active-chip" type="button" data-chip-remove="${item.kind}" data-chip-value="${esc(
              item.value,
            )}" title="Снять условие">${esc(item.label)}<span aria-hidden="true">×</span></button>`,
          )
          .join("")
      : "";
  }

  const badge = $("[data-active-filters]");
  if (badge) {
    badge.textContent = String(conditions);
    badge.toggleAttribute("hidden", conditions === 0);
  }

  setInputEmptyState(Boolean(query) && found === 0);
}

/* ------------------------------------------------------------------ список */

function toolRow(tool) {
  const format = formatById(tool.format);
  const source = SOURCES[tool.source];
  return `
    <a class="tool-row" href="${esc(tool.url)}" target="_blank" rel="noreferrer" data-format="${esc(tool.format)}">
      <span class="tool-row__head">
        <span class="tool-row__name">${mark(tool.name)}</span>
        <span class="tool-row__format">${esc(format?.title || "")}</span>
        <span class="tool-row__arrow" aria-hidden="true">↗</span>
      </span>
      <span class="tool-row__summary">${mark(tool.summary)}</span>
      <span class="tool-row__why"><b>Зачем:</b> ${mark(tool.why)}</span>
      <span class="tool-row__tags">
        ${tool.platforms.map((platform) => `<span class="tool-tag">${mark(platform)}</span>`).join("")}
        ${tool.source !== "mine" ? `<span class="tool-tag tool-tag--source">${esc(source.title)}</span>` : ""}
      </span>
      ${tool.note ? `<span class="tool-row__note">${esc(tool.note)}</span>` : ""}
    </a>`;
}

function emptyState() {
  const query = state.query.trim();
  const conditions = activeCount();
  return `<div class="tool-empty">
      <p class="tool-empty__title">Ничего не найдено</p>
      <p class="tool-empty__text">${
        query
          ? `Запрос «${esc(query)}» не совпал ни с названием, ни с описанием, ни с платформой записи.`
          : "Ни одна запись не отвечает всем выбранным условиям одновременно."
      }</p>
      <div class="tool-empty__actions">
        ${query ? `<button class="btn btn--ghost btn--sm" type="button" data-clear-query>Очистить поиск</button>` : ""}
        ${conditions ? `<button class="btn btn--ghost btn--sm" type="button" data-tools-reset>Сбросить фильтры</button>` : ""}
      </div>
    </div>`;
}

function renderList() {
  const host = $("#tools-list");
  if (!host) return;
  const visible = visibleTools();
  if (!visible.length) {
    host.innerHTML = emptyState();
    return;
  }
  host.innerHTML = GROUPS.map((group) => {
    const items = visible.filter((tool) => tool.group === group.id);
    if (!items.length) return "";
    return `
      <section class="tools-group" aria-labelledby="tools-group-${group.id}">
        <div class="tools-group__head">
          <h2 id="tools-group-${group.id}">${esc(group.title)}</h2>
          <span class="tools-group__note">${esc(group.note)}</span>
          <span class="tools-group__count">${items.length}</span>
        </div>
        <div class="tools-rows">${items.map(toolRow).join("")}</div>
      </section>`;
  }).join("");
}

/* -------------------------------------------------------------- адресная строка */

function syncHash() {
  const params = new URLSearchParams();
  if (state.query) params.set("q", state.query);
  if (state.group.size) params.set("task", [...state.group].join(","));
  if (state.format.size) params.set("format", [...state.format].join(","));
  if (state.platform.size) params.set("platform", [...state.platform].join(","));
  if (state.source.size) params.set("source", [...state.source].join(","));
  const query = params.toString();
  history.replaceState(null, "", `${location.pathname}${query ? `?${query}` : ""}`);
}

function renderAll(withHash = true) {
  renderFilters();
  renderStatus();
  renderList();
  if (withHash) syncHash();
}

function resetAll() {
  state.query = "";
  for (const facet of FACETS) state[facet.kind].clear();
  const search = $("#tools-search");
  if (search) search.value = "";
  renderAll();
}

function readHash() {
  const params = new URLSearchParams(location.search);
  const read = (key) => (params.get(key) || "").split(",").filter(Boolean);
  state.query = params.get("q") || "";
  // Старые ссылки хранят прежние id разделов — переводим их в новую таксономию.
  state.group = new Set(read("task").map((value) => GROUP_ALIASES[value] || value));
  state.format = new Set(read("format"));
  state.platform = new Set(read("platform"));
  state.source = new Set(read("source"));
  const search = $("#tools-search");
  if (search) search.value = state.query;
}

/* ------------------------------------------------------------------ события */

function initEvents() {
  document.addEventListener("click", (event) => {
    if (event.target.closest("[data-tools-reset]")) {
      resetAll();
      return;
    }
    if (event.target.closest("[data-clear-query]")) {
      state.query = "";
      const search = $("#tools-search");
      if (search) {
        search.value = "";
        search.focus();
      }
      renderAll();
      return;
    }
    const remove = event.target.closest("[data-chip-remove]");
    if (remove) {
      const kind = remove.dataset.chipRemove;
      const value = remove.dataset.chipValue;
      if (kind === "query") {
        state.query = "";
        const search = $("#tools-search");
        if (search) search.value = "";
      } else if (kind === "group") state.group.delete(value);
      else if (kind === "format") state.format.delete(value);
      else if (kind === "platform") state.platform.delete(value);
      else if (kind === "source") state.source.delete(value);
      renderAll();
      return;
    }
    const filter = event.target.closest("[data-filter]");
    if (filter && !filter.disabled) {
      const facet = facetById(filter.dataset.filter);
      if (facet) toggleIn(state[facet.kind], filter.dataset.value);
      renderAll();
      return;
    }
    const toggle = event.target.closest("[data-filters-toggle]");
    if (toggle) {
      const side = $("#tools-side");
      const collapsed = side?.dataset.collapsed === "true";
      if (side) side.dataset.collapsed = String(!collapsed);
      toggle.setAttribute("aria-expanded", String(collapsed));
    }
  });

  let timer;
  document.addEventListener("input", (event) => {
    const search = event.target.closest?.("#tools-search");
    if (!search) return;
    state.query = search.value;
    clearTimeout(timer);
    timer = setTimeout(() => {
      renderFilters();
      renderStatus();
      renderList();
      syncHash();
    }, 90);
  });

  document.addEventListener("keydown", (event) => {
    if (event.target?.id !== "tools-search") return;
    if (event.key === "Escape" && state.query) {
      event.preventDefault();
      state.query = "";
      event.target.value = "";
      renderAll();
    }
  });
}

/* -------------------------------------------------------------- оформление */

function initReveal() {
  const nodes = $$(".reveal");
  if (!nodes.length) return;
  if (window.matchMedia("(prefers-reduced-motion: reduce)").matches || !("IntersectionObserver" in window)) {
    nodes.forEach((node) => node.classList.add("is-visible"));
    return;
  }
  const observer = new IntersectionObserver(
    (entries) => {
      for (const entry of entries) {
        if (!entry.isIntersecting) continue;
        entry.target.classList.add("is-visible");
        observer.unobserve(entry.target);
      }
    },
    { rootMargin: "0px 0px -10% 0px" },
  );
  nodes.forEach((node) => observer.observe(node));
}

function initHeader() {
  const header = $("#site-header");
  const nav = $("#nav");
  const toggle = $("#nav-toggle");
  const onScroll = () => header?.setAttribute("data-stuck", String(window.scrollY > 8));
  onScroll();
  window.addEventListener("scroll", onScroll, { passive: true });

  toggle?.addEventListener("click", () => {
    const open = nav?.dataset.open === "true";
    if (nav) nav.dataset.open = String(!open);
    toggle.setAttribute("aria-expanded", String(!open));
    toggle.setAttribute("aria-label", open ? "Открыть меню" : "Закрыть меню");
  });

  document.addEventListener("click", (event) => {
    document.querySelectorAll(".nav-more[open]").forEach((menu) => {
      if (!menu.contains(event.target)) menu.removeAttribute("open");
    });
  });

  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape") document.querySelectorAll(".nav-more[open]").forEach((menu) => menu.removeAttribute("open"));
  });
  nav?.addEventListener("click", (event) => {
    if (event.target.closest("a") && window.matchMedia("(max-width: 860px)").matches) {
      nav.dataset.open = "false";
      toggle?.setAttribute("aria-expanded", "false");
    }
  });
}

/* На узких экранах колонка свёрнута: список виден сразу.
   Состояние пересчитывается при изменении ширины окна. */
function initSidebarState() {
  const side = $("#tools-side");
  const toggle = $("[data-filters-toggle]");
  if (!side || !toggle) return;
  const query = window.matchMedia("(max-width: 1100px)");
  const apply = (narrow) => {
    side.dataset.collapsed = String(narrow);
    toggle.setAttribute("aria-expanded", String(!narrow));
  };
  apply(query.matches);
  const onChange = (event) => apply(event.matches);
  if (typeof query.addEventListener === "function") query.addEventListener("change", onChange);
  else query.addListener?.(onChange);
}

document.addEventListener("keydown", (event) => {
  const typing = ["INPUT", "TEXTAREA"].includes(event.target?.tagName);
  if (typing || event.altKey || event.ctrlKey || event.metaKey) return;
  if (event.key.toLowerCase() === "t") toggleTheme();
  if (event.key === "/") {
    event.preventDefault();
    $("#tools-search")?.focus();
  }
});

function pluralize(count) {
  const mod10 = count % 10;
  const mod100 = count % 100;
  if (mod10 === 1 && mod100 !== 11) return `${count} запись`;
  if (mod10 >= 2 && mod10 <= 4 && (mod100 < 10 || mod100 >= 20)) return `${count} записи`;
  return `${count} записей`;
}

function applyCounts() {
  // Числа в статическом тексте берутся из данных: при добавлении записей они не расходятся.
  const label = pluralize(TOOLS.length);
  for (const node of $$("[data-tools-count]")) node.textContent = label;
  for (const node of $$("[data-tools-total]")) node.textContent = String(TOOLS.length);
  for (const node of $$("[data-tools-groups]")) node.textContent = String(GROUPS.length);
  for (const node of $$("[data-tools-sources]")) node.textContent = String(Object.values(SOURCES).filter((source) => source.id !== "mine").length);
}

initTheme();
initHeader();
initSidebarState();
initReveal();
readHash();
applyCounts();
renderAll(false);
initEvents();
