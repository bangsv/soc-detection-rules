/* Theme controller: dark by default, remembers the analyst's choice. */

import { $ } from "./utils.js";

const STORAGE_KEY = "soc-atlas-theme";
const MEDIA = window.matchMedia("(prefers-color-scheme: light)");

function preferred() {
  const saved = localStorage.getItem(STORAGE_KEY);
  if (saved === "light" || saved === "dark") return saved;
  return MEDIA.matches ? "light" : "dark";
}

export function applyTheme(theme) {
  const next = theme === "light" ? "light" : "dark";
  document.documentElement.dataset.theme = next;
  const meta = $('meta[name="theme-color"]');
  if (meta) meta.setAttribute("content", next === "light" ? "#f7faf9" : "#070d11");
  const icon = document.querySelector("[data-theme-icon]");
  if (icon) icon.textContent = next === "light" ? "☀" : "☾";
  const button = $("#theme-toggle");
  if (button) {
    button.setAttribute("aria-label", next === "light" ? "Включить тёмную тему" : "Включить светлую тему");
    button.title = `${next === "light" ? "Тёмная" : "Светлая"} тема (T)`;
  }
  window.dispatchEvent(new CustomEvent("themechange", { detail: { theme: next } }));
  return next;
}

export function currentTheme() {
  return document.documentElement.dataset.theme === "light" ? "light" : "dark";
}

export function toggleTheme() {
  const next = currentTheme() === "light" ? "dark" : "light";
  localStorage.setItem(STORAGE_KEY, next);
  return applyTheme(next);
}

export function initTheme() {
  applyTheme(preferred());
  $("#theme-toggle")?.addEventListener("click", () => toggleTheme());
  MEDIA.addEventListener?.("change", () => {
    if (!localStorage.getItem(STORAGE_KEY)) applyTheme(preferred());
  });
}
