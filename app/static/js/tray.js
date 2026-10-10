/* Evidence tray: collect indicators across search and scenarios, then export them. */

import { $, copyText, downloadText, esc, toast } from "./utils.js";

const STORAGE_KEY = "soc-atlas-tray";
const listeners = new Set();
let items = load();

function load() {
  try {
    const raw = JSON.parse(localStorage.getItem(STORAGE_KEY) || "[]");
    return Array.isArray(raw) ? raw.filter((item) => item && item.value) : [];
  } catch {
    return [];
  }
}

function persist() {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(items));
  } catch {
    /* storage may be unavailable in private mode: the tray still works in memory */
  }
}

function notify() {
  render();
  for (const listener of listeners) listener(items);
}

export function subscribe(listener) {
  listeners.add(listener);
  listener(items);
}

export function trayItems() {
  return [...items];
}

export function isCollected(value) {
  return items.some((item) => item.value === value);
}

export function addToTray({ value, type = "IOC", context = "" }) {
  const clean = String(value || "").trim();
  if (!clean) return false;
  if (isCollected(clean)) {
    toast(`Уже в наборе: ${clean}`);
    return false;
  }
  items = [{ value: clean, type, context }, ...items].slice(0, 300);
  persist();
  notify();
  toast(`Добавлено в набор: ${clean}`);
  return true;
}

export function removeFromTray(value) {
  items = items.filter((item) => item.value !== value);
  persist();
  notify();
}

export function clearTray() {
  items = [];
  persist();
  notify();
}

export function trayAsText({ grouped = false } = {}) {
  if (!items.length) return "";
  if (!grouped) return items.map((item) => item.value).join("\n");
  const buckets = new Map();
  for (const item of items) {
    if (!buckets.has(item.type)) buckets.set(item.type, []);
    buckets.get(item.type).push(item.value);
  }
  return [...buckets.entries()]
    .map(([type, values]) => `# ${type}\n${values.join("\n")}`)
    .join("\n\n");
}

function render() {
  const host = $("#tray");
  if (!host) return;
  const count = $("#tray-count");
  if (count) count.textContent = String(items.length);
  const preview = $("#tray-preview");
  if (preview) preview.textContent = items.length ? items[0].value : "";
  const list = $("#tray-list");
  if (list) {
    list.innerHTML = items.length
      ? items
          .map(
            (item) =>
              `<span class="tray__chip" title="${esc(item.context || item.type)}"><span>${esc(item.value)}</span><button type="button" data-tray-remove="${esc(item.value)}" aria-label="Убрать ${esc(item.value)}">×</button></span>`,
          )
          .join("")
      : `<span class="text-xs dim">Набор пуст: добавляйте индикаторы кнопкой ＋ в поиске или в карточке сценария.</span>`;
  }
  host.hidden = items.length === 0;
  if (host.hidden) collapseTray();
}

function expandTray() {
  const panel = $("#tray-panel");
  const toggle = $("#tray-toggle");
  if (!panel || !toggle) return;
  panel.hidden = false;
  toggle.setAttribute("aria-expanded", "true");
}

function collapseTray() {
  const panel = $("#tray-panel");
  const toggle = $("#tray-toggle");
  if (!panel || !toggle) return;
  panel.hidden = true;
  toggle.setAttribute("aria-expanded", "false");
}

export function initTray() {
  render();
  $("#tray-toggle")?.addEventListener("click", () => {
    const expanded = $("#tray-toggle").getAttribute("aria-expanded") === "true";
    if (expanded) collapseTray();
    else expandTray();
  });
  $("#tray-close")?.addEventListener("click", () => {
    clearTray();
    toast("Набор очищен");
  });
  $("#tray-copy")?.addEventListener("click", () => {
    if (!items.length) return;
    copyText(trayAsText({ grouped: true }), `Скопировано индикаторов: ${items.length}`);
  });
  $("#tray-download")?.addEventListener("click", () => {
    if (!items.length) return;
    downloadText("soc-atlas-iocs.txt", `# SOC Atlas · набор индикаторов (${items.length})\n\n${trayAsText({ grouped: true })}\n`);
  });
  document.addEventListener("click", (event) => {
    const remove = event.target.closest("[data-tray-remove]");
    if (remove) removeFromTray(remove.dataset.trayRemove);
  });
  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape") collapseTray();
  });
}
