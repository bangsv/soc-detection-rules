/* Command palette (Ctrl+K): one entry point for scenarios, indicators, docs and actions. */

import { $, api, copyText, debounce, esc, highlight, normalize, toast } from "./utils.js";
import { setSearchQuery, focusSearch } from "./search.js";
import { showAttack, collectAttack } from "./attacks.js";
import { loadDocument } from "./docs.js";
import { toggleTheme } from "./theme.js";
import { catalogData, loadCatalog } from "./store.js";

const state = { items: [], active: 0, query: "", seq: 0 };

function commandItems() {
  return [
    { kind: "Разделы", icon: "⌗", title: "Индикаторы: поиск по IOC", subtitle: "Раздел explorer", run: () => scrollTo("#explorer") },
    { kind: "Разделы", icon: "⌗", title: "Карта сценариев атак", subtitle: "Раздел attacks", run: () => scrollTo("#attacks-map") },
    { kind: "Разделы", icon: "⌗", title: "База знаний: README", subtitle: "Раздел knowledge", run: () => scrollTo("#knowledge") },
    { kind: "Разделы", icon: "◈", title: "Профиль автора", subtitle: "Страница /about", run: () => (location.href = "/about") },
    { kind: "Действия", icon: "☾", title: "Переключить тему", subtitle: "Тёмная и светлая", run: () => toggleTheme() },
    { kind: "Действия", icon: "↻", title: "Переиндексировать базу", subtitle: "Перечитать README и IOC", run: () => reindex() },
    { kind: "Действия", icon: "⌕", title: "Фокус в поиск IOC", subtitle: "Клавиша /", run: () => focusSearch() },
  ];
}

function scrollTo(hash) {
  document.querySelector(hash)?.scrollIntoView({ behavior: "smooth", block: "start" });
  close();
}

async function reindex() {
  try {
    await api("/api/reindex", { method: "POST" });
    toast("Индекс обновлён");
    location.reload();
  } catch {
    toast("Не удалось обновить индекс", "warn");
  }
}

async function dataset() {
  if (!catalogData().ready) {
    try {
      await loadCatalog();
    } catch {
      /* fall back to commands only */
    }
  }
  return catalogData();
}

function staticItems() {
  const { attacks, readmes } = catalogData();
  const items = [];
  for (const attack of attacks) {
    items.push({
      kind: "Сценарии",
      icon: "◈",
      title: attack.title,
      subtitle: `${attack.severity} · ${attack.ioc_count} IOC · ${attack.surface}`,
      run: () => {
        close();
        showAttack(attack.id);
        document.querySelector("#attacks-map")?.scrollIntoView({ behavior: "smooth", block: "start" });
      },
    });
    items.push({
      kind: "Действия",
      icon: "＋",
      title: `Собрать все IOC: ${attack.short}`,
      subtitle: "Добавить индикаторы сценария в набор",
      run: () => {
        close();
        collectAttack(attack.id);
      },
    });
  }
  for (const doc of readmes) {
    items.push({
      kind: "Документы",
      icon: "▤",
      title: doc.title || doc.path,
      subtitle: doc.path,
      run: () => {
        close();
        loadDocument(doc.path);
      },
    });
  }
  return [...commandItems(), ...items];
}

function render() {
  const host = $("#palette-results");
  const status = $("#palette-status");
  const items = state.items;
  if (!items.length) {
    host.innerHTML = `<p class="palette__empty">Ничего не найдено. Попробуйте другое значение или нажмите Esc.</p>`;
    status.textContent = "Совпадений: 0";
    return;
  }
  let lastKind = "";
  const rows = items
    .map((item, index) => {
      const group = item.kind !== lastKind ? `<p class="palette__group">${esc(item.kind)}</p>` : "";
      lastKind = item.kind;
      return `${group}
        <button class="palette__item" type="button" role="option" data-index="${index}" data-active="${index === state.active}" aria-selected="${index === state.active}">
          <span class="palette__icon" aria-hidden="true">${item.icon}</span>
          <span class="palette__text">
            <b>${highlight(esc(item.title), state.query)}</b>
            <small>${esc(item.subtitle || "")}</small>
          </span>
          <span class="text-2xs mono dim">${index === state.active ? "Enter" : ""}</span>
        </button>`;
    })
    .join("");
  host.innerHTML = rows;
  status.textContent = `Совпадений: ${items.length}`;
  host.querySelector('[data-active="true"]')?.scrollIntoView({ block: "nearest" });
}

async function search(query) {
  state.query = query;
  const term = query.trim();
  const staticList = staticItems();
  if (!term) {
    state.items = filterStatic(staticList, "");
    state.active = 0;
    render();
    return;
  }
  const seq = ++state.seq;
  const local = filterStatic(staticList, term);
  state.items = local;
  state.active = 0;
  render();
  try {
    const data = await api(`/api/search?q=${encodeURIComponent(term)}`);
    if (seq !== state.seq) return;
    const dynamic = [];
    for (const result of data.results || []) {
      dynamic.push({
        kind: "Индикаторы",
        icon: "⌗",
        title: result.ioc,
        subtitle: `${result.type} · ${(result.attacks || []).map((a) => a.short).join(", ")}`,
        run: () => {
          close();
          setSearchQuery(result.ioc);
          focusSearch();
        },
      });
    }
    for (const fragment of (data.fragments || []).slice(0, 12)) {
      dynamic.push({
        kind: "Фрагменты README",
        icon: "≡",
        title: fragment.value,
        subtitle: `${fragment.kind}${fragment.attach ? " · " + fragment.attach : ""}`,
        run: () => {
          close();
          copyText(fragment.value, `Скопировано: ${fragment.value}`);
        },
      });
    }
    for (const attack of data.attacks || []) {
      dynamic.push({
        kind: "Сценарии",
        icon: "◈",
        title: attack.title,
        subtitle: `${attack.severity} · ${attack.ioc_count} IOC`,
        run: () => {
          close();
          showAttack(attack.id);
        },
      });
    }
    state.items = [...dynamic, ...local];
    state.active = 0;
    render();
  } catch {
    status.textContent = "Поиск недоступен: сервер не отвечает";
  }
}

function filterStatic(items, term) {
  const needle = normalize(term);
  if (!needle) return items;
  return items.filter((item) => normalize(item.title).includes(needle) || normalize(item.subtitle).includes(needle));
}

export function open() {
  const dialog = $("#palette");
  if (!dialog || dialog.open) return;
  dialog.showModal();
  const input = $("#palette-input");
  input.value = "";
  state.query = "";
  state.active = 0;
  state.items = filterStatic(staticItems(), "");
  render();
  input.focus();
  dataset().then(() => {
    state.items = filterStatic(staticItems(), state.query);
    render();
  });
}

export function close() {
  const dialog = $("#palette");
  if (dialog?.open) dialog.close();
}

export function initPalette() {
  const dialog = $("#palette");
  const input = $("#palette-input");
  if (!dialog || !input) return;

  const debounced = debounce((value) => search(value), 170);
  input.addEventListener("input", (event) => {
    debounced.cancel();
    state.query = event.target.value;
    // Instant local filtering keeps typing responsive; the API fills in matches right after.
    search(event.target.value);
  });

  input.addEventListener("keydown", (event) => {
    if (event.key === "ArrowDown" || event.key === "ArrowUp") {
      event.preventDefault();
      if (!state.items.length) return;
      const delta = event.key === "ArrowDown" ? 1 : -1;
      state.active = (state.active + delta + state.items.length) % state.items.length;
      render();
      return;
    }
    if (event.key === "Enter") {
      event.preventDefault();
      state.items[state.active]?.run();
    }
  });

  $("#palette-close")?.addEventListener("click", close);

  dialog.addEventListener("close", () => {
    const host = $("#palette-results");
    if (host) host.innerHTML = "";
  });

  document.addEventListener("click", (event) => {
    const item = event.target.closest("#palette-results [data-index]");
    if (!item) return;
    state.items[Number(item.dataset.index)]?.run();
  });

  document.addEventListener("click", (event) => {
    if (event.target.closest("#palette-open")) {
      event.preventDefault();
      open();
    }
  });
}
