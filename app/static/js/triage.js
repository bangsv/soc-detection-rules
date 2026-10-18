/* Материалы triage: дампы, журналы и вывод PoC. Содержимое не показываем — задача
   панели в том, чтобы было понятно, что скачиваешь. Список приходит вместе с деталями
   сценария, ссылки на скачивание готовы на сервере. */

import { $, esc, fileSize } from "./utils.js";

const state = {
  attackId: "",
  triage: { total: 0, groups: [] },
  activeKind: "all",
  query: "",
};

function groups() {
  return state.triage?.groups || [];
}

function total() {
  return state.triage?.total || 0;
}

function tabs() {
  const all = `<button class="rule-tab" type="button" data-triage-kind="all" aria-selected="${state.activeKind === "all"}">
      Все <small>${total()}</small>
    </button>`;
  return (
    all +
    groups()
      .map(
        (group) => `<button class="rule-tab" type="button" data-triage-kind="${esc(group.kind)}" aria-selected="${state.activeKind === group.kind}">
      ${esc(group.title)} <small>${group.count}</small>
    </button>`,
      )
      .join("")
  );
}

function matches(item) {
  if (!state.query) return true;
  const haystack = [item.name, item.scenario, item.type_title, item.result_title, item.folder]
    .join(" ")
    .toLowerCase();
  return haystack.includes(state.query);
}

function visibleItems() {
  const pool = state.activeKind === "all" ? groups().flatMap((group) => group.items) : groups().find((group) => group.kind === state.activeKind)?.items || [];
  return pool.filter(matches);
}

function activeGroup() {
  return groups().find((group) => group.kind === state.activeKind) || null;
}

function fileCard(item) {
  return `
    <a class="triage-card" href="${esc(item.download)}" download="${esc(item.name)}" data-result="${esc(item.result || "none")}" title="Скачать ${esc(item.name)}">
      <span class="triage-card__top">
        <span class="triage-card__ext">${esc(item.kind)}</span>
        ${item.result ? `<span class="triage-result triage-result--${esc(item.result)}">${esc(item.result_title)}</span>` : ""}
        <span class="triage-card__size">${fileSize(item.size)}</span>
      </span>
      <span class="triage-card__name">${esc(item.name)}</span>
      <span class="triage-card__meta">
        ${item.scenario ? `<span class="triage-card__tag">${esc(item.scenario)}</span>` : ""}
        <span class="triage-card__type">${esc(item.type_title)}</span>
      </span>
      <span class="triage-card__foot">
        <span class="triage-card__tool">Открыть в: ${esc(item.tool)}</span>
        <span class="triage-card__download" aria-hidden="true">Скачать ↓</span>
      </span>
    </a>`;
}

function render() {
  const host = $("#attack-triage");
  if (!host) return;
  if (!total()) {
    host.innerHTML = "";
    return;
  }
  const items = visibleItems();
  const group = activeGroup();
  host.innerHTML = `
    <section class="triage">
      <div class="rules__head">
        <h4>Материалы triage</h4>
        <span class="text-2xs mono dim">${total()} файлов · ${fileSize(state.triage.size || 0)}</span>
      </div>

      <div class="rule-tabs" role="tablist" aria-label="Типы материалов">${tabs()}</div>

      <div class="triage-bar">
        <label class="triage-bar__search">
          <span class="visually-hidden">Фильтр по имени файла</span>
          <input type="search" data-triage-search value="${esc(state.query)}" placeholder="Фильтр по имени: secretsdump, mimikatz…" autocomplete="off">
        </label>
        <span class="triage-bar__count">${items.length === total() ? "все файлы" : `найдено ${items.length}`}</span>
        <a class="btn btn--primary btn--sm" href="${esc(state.triage.bundle)}" download>Скачать всё ZIP</a>
      </div>

      <p class="triage-note">${esc(group?.note || "Дампы, журналы и вывод PoC: нажмите на карточку, чтобы скачать файл")}</p>

      <div class="triage-grid">
        ${items.length ? items.map(fileCard).join("") : `<p class="rule-hint">По запросу «${esc(state.query)}» файлов нет. <button class="btn btn--quiet btn--sm" type="button" data-triage-reset>Сбросить</button></p>`}
      </div>
    </section>`;
}

export function initTriage() {
  document.addEventListener("click", (event) => {
    if (!event.target.closest("#attack-triage")) return;
    const tab = event.target.closest("[data-triage-kind]");
    if (tab) {
      state.activeKind = tab.dataset.triageKind;
      render();
      return;
    }
    if (event.target.closest("[data-triage-reset]")) {
      state.query = "";
      render();
    }
  });

  document.addEventListener("input", (event) => {
    const search = event.target.closest?.("[data-triage-search]");
    if (!search) return;
    state.query = search.value.trim().toLowerCase();
    render();
    const input = document.querySelector("[data-triage-search]");
    if (input) {
      input.focus();
      input.setSelectionRange(input.value.length, input.value.length);
    }
  });
}

export function mountTriage(detail) {
  state.triage = detail.triage || { total: 0, groups: [] };
  state.attackId = detail.id;
  state.activeKind = state.triage.groups?.[0]?.kind || "all";
  state.query = "";
  render();
}
