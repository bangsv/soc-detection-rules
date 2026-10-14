/* SOC Atlas · application shell: bootstrap, header behaviour, metrics, shortcuts. */

import { $, $$, api, esc, formatDate, isTyping, onIdle, toast } from "./utils.js";
import { initTheme, toggleTheme } from "./theme.js";
import { initTray } from "./tray.js";
import { initSearch, focusSearch, setSearchQuery } from "./search.js";
import { initAttacks } from "./attacks.js";
import { initRules } from "./rules.js";
import { initDocs } from "./docs.js";
import { initPalette, open as openPalette } from "./palette.js";
import { catalogData, loadCatalog } from "./store.js";

const SECTIONS = ["explorer", "attacks-map", "knowledge"];

function metricTile(value, label, note, variant = "") {
  return `
    <div class="stat ${variant}">
      <span class="stat__value">${value}</span>
      <span class="stat__label">${label}</span>
      ${note ? `<span class="stat__note">${note}</span>` : ""}
    </div>`;
}

function shortName(attackId) {
  const attack = catalogData().attacks.find((item) => item.id === attackId);
  return attack?.short || attackId;
}

/* Стенд в шапке строится из раздела ## LAB файла IOC — в разметке данных нет. */
function renderLabCard(meta) {
  const host = $("#lab-card");
  if (!host) return;
  const rows = meta.lab || [];
  if (!rows.length) {
    host.innerHTML = `<div class="info-list__row"><dt>Стенд</dt><dd>не описан в файле IOC</dd></div>`;
    return;
  }
  host.innerHTML = rows
    .map(
      (row) => `
      <div class="info-list__row">
        <dt>${esc(row.tag || "node")}</dt>
        <dd>
          ${esc(row.address || "—")}
          ${row.role ? `<span class="lab-role">${esc(row.role)}</span>` : ""}
          ${row.scenarios?.length ? `<span class="lab-scenarios">${row.scenarios.map((id) => esc(shortName(id))).join(", ")}</span>` : ""}
        </dd>
      </div>`,
    )
    .join("");
}

async function renderMetrics(meta, items) {
  const host = $("#metrics-band");
  if (!host) return;
  const counts = meta.counts;
  host.innerHTML = [
    metricTile(counts.attacks, "сценариев", `${counts.critical} критичных · ${meta.filters.platforms.length} платформ`),
    metricTile(counts.iocs, "индикаторов", `${counts.host_iocs} host · ${counts.network_iocs} network`, "stat--accent"),
    metricTile(
      counts.readmes,
      "документов",
      `${counts.materials} файлов · ${(counts.bytes / 1024 / 1024).toFixed(1)} МБ`,
    ),
    metricTile(meta.filters.tactics.length, "тактик ATT&CK", "маппинг техник по сценариям", "stat--warn"),
  ].join("");

  const footer = $("#footer-updated");
  if (footer) footer.textContent = `индекс: ${formatDate(meta.generated_at)}`;
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

  $("#reindex")?.addEventListener("click", async (event) => {
    const button = event.currentTarget;
    button.classList.add("spin");
    try {
      await api("/api/reindex", { method: "POST" });
      toast("Индекс пересобран");
      window.location.reload();
    } catch {
      toast("Сервер не отвечает", "warn");
    } finally {
      button.classList.remove("spin");
    }
  });
}

function initScrollSpy() {
  const links = $$("[data-nav]");
  if (!links.length || !("IntersectionObserver" in window)) return;
  const observer = new IntersectionObserver(
    (entries) => {
      for (const entry of entries) {
        if (!entry.isIntersecting) continue;
        links.forEach((link) => link.setAttribute("aria-current", String(link.dataset.nav === entry.target.id)));
      }
    },
    { rootMargin: "-45% 0px -50% 0px" },
  );
  for (const id of SECTIONS) {
    const section = document.getElementById(id);
    if (section) observer.observe(section);
  }
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
    { rootMargin: "0px 0px -8% 0px" },
  );
  nodes.forEach((node) => observer.observe(node));
}

function initShortcuts() {
  document.addEventListener("keydown", (event) => {
    const typing = isTyping(event.target);

    if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "k") {
      event.preventDefault();
      openPalette();
      return;
    }

    if (event.key === "Escape") {
      const search = $("#ioc-search");
      if (document.activeElement === search) {
        search.value = "";
        setSearchQuery("");
        search.blur();
      }
      document.querySelector("#nav")?.setAttribute("data-open", "false");
      return;
    }

    if (typing || event.altKey || event.ctrlKey || event.metaKey) return;

    if (event.key === "/") {
      event.preventDefault();
      focusSearch();
      return;
    }
    if (event.key.toLowerCase() === "t") {
      toggleTheme();
      return;
    }
    const index = Number(event.key);
    if (index >= 1 && index <= SECTIONS.length) {
      document.getElementById(SECTIONS[index - 1])?.scrollIntoView({ behavior: "smooth", block: "start" });
    }
  });
}

async function boot() {
  initTheme();
  initHeader();
  initTray();
  initSearch();
  initPalette();
  initRules();
  initScrollSpy();
  initReveal();
  initShortcuts();

  try {
    const store = await loadCatalog();
    const meta = store.meta;
    const items = store.attacks;
    renderLabCard(meta);
    await renderMetrics(meta, items);
    initAttacks(items, meta);
    initDocs(store.readmes);
    onIdle(() => {
      // Warm the search index so the first query answers without a round trip.
      fetch("/api/search?q=a").catch(() => {});
    });
  } catch {
    toast("Не удалось загрузить каталог: проверьте, что сервер запущен", "warn");
    const host = $("#attacks");
    if (host) host.innerHTML = `<div class="result result--empty">Каталог недоступен. Запустите сервер и обновите страницу.</div>`;
  }
}

boot();
