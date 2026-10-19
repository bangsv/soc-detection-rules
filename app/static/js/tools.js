/* Страница «Инструменты»: единая база blue-team материалов с фильтрами и поиском. */

import { $, $$, esc, normalize } from "./utils.js";
import { initTheme, toggleTheme } from "./theme.js";
import { FORMATS, GROUPS, GROUP_ALIASES, PLATFORMS, SOURCES, TOOLS } from "./tools-data.js";

const state = {
  query: "",
  groups: new Set(),
  formats: new Set(),
  platforms: new Set(),
  sources: new Set(),
};

const groupById = (id) => GROUPS.find((group) => group.id === id);
const formatById = (id) => FORMATS.find((format) => format.id === id);

function matches(tool) {
  if (state.groups.size && !state.groups.has(tool.group)) return false;
  if (state.formats.size && !state.formats.has(tool.format)) return false;
  if (state.sources.size && !state.sources.has(tool.source)) return false;
  if (state.platforms.size && !tool.platforms.some((platform) => state.platforms.has(platform))) return false;
  if (!state.query) return true;
  const haystack = normalize([tool.name, tool.summary, tool.why, tool.note, tool.url, ...tool.platforms].join(" "));
  return haystack.includes(normalize(state.query));
}

function toggleIn(set, value) {
  if (set.has(value)) set.delete(value);
  else set.add(value);
}

function chip(kind, value, label, count, active) {
  return `<button class="tool-chip" type="button" data-filter="${kind}" data-value="${esc(value)}" aria-pressed="${active}">
    ${esc(label)}${count !== undefined ? ` <small>${count}</small>` : ""}
  </button>`;
}

function renderFilters() {
  const host = $("#tools-filters");
  if (!host) return;
  const byGroup = (id) => TOOLS.filter((tool) => tool.group === id).length;
  const byFormat = (id) => TOOLS.filter((tool) => tool.format === id).length;
  const byPlatform = (id) => TOOLS.filter((tool) => tool.platforms.includes(id)).length;
  const bySource = (id) => TOOLS.filter((tool) => tool.source === id).length;

  host.innerHTML = `
    <div class="tools-filter-block">
      <span class="tools-filter-label">Задача</span>
      <div class="tools-chips">
        ${GROUPS.filter((group) => byGroup(group.id)).map((group) => chip("group", group.id, group.title, byGroup(group.id), state.groups.has(group.id))).join("")}
      </div>
    </div>
    <div class="tools-filter-block">
      <span class="tools-filter-label">Формат</span>
      <div class="tools-chips">
        ${FORMATS.map((format) => chip("format", format.id, format.title, byFormat(format.id), state.formats.has(format.id))).join("")}
      </div>
    </div>
    <div class="tools-filter-block">
      <span class="tools-filter-label">Платформа</span>
      <div class="tools-chips">
        ${PLATFORMS.map((platform) => chip("platform", platform, platform, byPlatform(platform), state.platforms.has(platform))).join("")}
      </div>
    </div>
    <div class="tools-filter-block">
      <span class="tools-filter-label">Источник</span>
      <div class="tools-chips">
        ${Object.values(SOURCES).map((source) => chip("source", source.id, source.title, bySource(source.id), state.sources.has(source.id))).join("")}
      </div>
    </div>`;
}

function toolRow(tool) {
  const format = formatById(tool.format);
  const source = SOURCES[tool.source];
  return `
    <a class="tool-row" href="${esc(tool.url)}" target="_blank" rel="noreferrer" data-format="${esc(tool.format)}">
      <span class="tool-row__head">
        <span class="tool-row__name">${esc(tool.name)}</span>
        <span class="tool-row__format">${esc(format?.title || "")}</span>
        <span class="tool-row__arrow" aria-hidden="true">↗</span>
      </span>
      <span class="tool-row__summary">${esc(tool.summary)}</span>
      <span class="tool-row__why"><b>Зачем:</b> ${esc(tool.why)}</span>
      <span class="tool-row__tags">
        ${tool.platforms.map((platform) => `<span class="tool-tag">${esc(platform)}</span>`).join("")}
        ${tool.source !== "mine" ? `<span class="tool-tag tool-tag--source">${esc(source.title)}</span>` : ""}
      </span>
      ${tool.note ? `<span class="tool-row__note">${esc(tool.note)}</span>` : ""}
    </a>`;
}

function renderList() {
  const host = $("#tools-list");
  if (!host) return;
  const visible = TOOLS.filter(matches);
  const counter = $("#tools-count");
  if (counter) counter.textContent = visible.length === TOOLS.length ? `все ${TOOLS.length}` : `найдено ${visible.length}`;

  if (!visible.length) {
    host.innerHTML = `<div class="tool-empty">
        <p>Под выбранные условия ничего нет.</p>
        <button class="btn btn--ghost btn--sm" type="button" data-tools-reset>Сбросить фильтры</button>
      </div>`;
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

function syncHash() {
  const params = new URLSearchParams();
  if (state.query) params.set("q", state.query);
  if (state.groups.size) params.set("task", [...state.groups].join(","));
  if (state.formats.size) params.set("format", [...state.formats].join(","));
  if (state.platforms.size) params.set("platform", [...state.platforms].join(","));
  if (state.sources.size) params.set("source", [...state.sources].join(","));
  const query = params.toString();
  history.replaceState(null, "", `${location.pathname}${query ? `?${query}` : ""}`);
}

function renderAll(withHash = true) {
  renderFilters();
  renderList();
  if (withHash) syncHash();
}

function readHash() {
  const params = new URLSearchParams(location.search);
  const read = (key) => (params.get(key) || "").split(",").filter(Boolean);
  state.query = params.get("q") || "";
  // Старые ссылки хранят прежние id разделов — переводим их в новую таксономию.
  state.groups = new Set(read("task").map((value) => GROUP_ALIASES[value] || value));
  state.formats = new Set(read("format"));
  state.platforms = new Set(read("platform"));
  state.sources = new Set(read("source"));
  const search = $("#tools-search");
  if (search) search.value = state.query;
}function initEvents() {
  document.addEventListener("click", (event) => {
    if (event.target.closest("[data-tools-reset]")) {
      state.query = "";
      state.groups.clear();
      state.formats.clear();
      state.platforms.clear();
      state.sources.clear();
      const search = $("#tools-search");
      if (search) search.value = "";
      renderAll();
      return;
    }
    const filter = event.target.closest("[data-filter]");
    if (filter) {
      const { filter: kind, value } = filter.dataset;
      if (kind === "group") toggleIn(state.groups, value);
      if (kind === "format") toggleIn(state.formats, value);
      if (kind === "platform") toggleIn(state.platforms, value);
      if (kind === "source") toggleIn(state.sources, value);
      renderAll();
    }
  });

  document.addEventListener("input", (event) => {
    const search = event.target.closest?.("#tools-search");
    if (!search) return;
    state.query = search.value;
    renderList();
    syncHash();
  });
}

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

  nav?.addEventListener("click", (event) => {
    if (event.target.closest("a") && window.matchMedia("(max-width: 860px)").matches) {
      nav.dataset.open = "false";
      toggle?.setAttribute("aria-expanded", "false");
    }
  });
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
initReveal();
readHash();
applyCounts();
renderAll(false);
initEvents();
