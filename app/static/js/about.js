/* About page bootstrap: theme control, mobile navigation, scroll effects. */

import { $, $$, api } from "./utils.js";
import { initTheme, toggleTheme } from "./theme.js";

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

document.addEventListener("keydown", (event) => {
  const typing = ["INPUT", "TEXTAREA"].includes(event.target?.tagName);
  if (typing || event.altKey || event.ctrlKey || event.metaKey) return;
  if (event.key.toLowerCase() === "t") toggleTheme();
});

/* Числа проекта берутся из API: при изменении базы они не расходятся со статичным текстом. */
async function fillAtlasStats() {
  const target = $("[data-atlas-note]");
  if (!target) return;
  try {
    const meta = await api("/api/meta");
    const counts = meta.counts;
    target.textContent = `${counts.attacks} сценариев · ${counts.iocs} индикаторов · ${counts.readmes} документов`;
  } catch {
    target.textContent = "";
  }
}

initTheme();
initHeader();
initReveal();
fillAtlasStats();
