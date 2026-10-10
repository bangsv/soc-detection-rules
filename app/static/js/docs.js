/* Knowledge base: document navigation, rendered README, table of contents, image lightbox. */

import { $, api, copyText, debounce, esc, normalize } from "./utils.js";

const state = { items: [], current: null, filter: "" };

function slugify(text) {
  const slug = normalize(text)
    .replace(/[^\p{L}\p{N}\s-]/gu, "")
    .trim()
    .replace(/\s+/g, "-")
    .slice(0, 60);
  return slug || "section";
}

function decorate(html) {
  const holder = document.createElement("div");
  holder.innerHTML = html;
  const used = new Map();
  const toc = [];

  holder.querySelectorAll("h1, h2, h3").forEach((heading) => {
    const base = slugify(heading.textContent || "");
    const count = used.get(base) || 0;
    used.set(base, count + 1);
    const id = count ? `${base}-${count}` : base;
    heading.id = id;
    if (heading.tagName !== "H1") {
      toc.push({ id, level: heading.tagName === "H2" ? 2 : 3, text: heading.textContent.trim() });
    }
  });

  holder.querySelectorAll("pre").forEach((pre) => {
    if (pre.querySelector(".doc-copy")) return;
    pre.style.position = "relative";
    const button = document.createElement("button");
    button.type = "button";
    button.className = "icon-btn doc-copy";
    button.textContent = "⧉";
    button.title = "Скопировать листинг";
    button.setAttribute("aria-label", "Скопировать листинг");
    button.style.position = "absolute";
    button.style.top = "8px";
    button.style.right = "8px";
    pre.append(button);
  });

  holder.querySelectorAll("img").forEach((image) => {
    image.loading = "lazy";
    image.decoding = "async";
    image.tabIndex = 0;
    image.setAttribute("role", "button");
    image.setAttribute("aria-label", `Увеличить изображение: ${image.alt || "скриншот из документа"}`);
  });

  holder.querySelectorAll("a[href]").forEach((link) => {
    const href = decodeURIComponent(link.getAttribute("href"));
    const match = href.match(/([\w .\-()]+\.md)/i);
    if (!match) return;
    const name = match[1].toLowerCase();
    const exists = state.items.find((item) => item.path.toLowerCase().endsWith(name));
    if (exists) {
      link.href = "#knowledge";
      link.dataset.readme = exists.path;
    }
  });

  return { html: holder.innerHTML, toc };
}

function renderNav() {
  const term = normalize(state.filter);
  const filtered = state.items.filter(
    (item) => !term || normalize(item.title).includes(term) || normalize(item.path).includes(term),
  );
  const counter = $("#doc-count");
  if (counter) counter.textContent = String(state.items.length);
  const nav = $("#readme-nav");
  if (!nav) return;
  nav.innerHTML = filtered.length
    ? filtered
        .map((item) => {
          const parts = item.path.split("/");
          const isPrimary = Boolean(item.attack) && parts.length === 2;
          const label = !item.attack
            ? "корень репозитория"
            : isPrimary
              ? "основной README"
              : parts
                  .slice(1, -1)
                  .join(" · ")
                  .replace(/[_-]+/g, " ")
                  .trim() || "триаж-материалы";
          return `
        <button type="button" data-readme="${esc(item.path)}" aria-current="${state.current === item.path}">
          <small>${esc(item.title)}${isPrimary || !item.attack ? "" : " · триаж"}</small>
          <span>${esc(label)}</span>
        </button>`;
        })
        .join("")
    : `<p class="text-xs dim" style="padding:12px">Документы не найдены.</p>`;
}

function tocTemplate(toc) {
  if (!toc.length) return `<p class="text-xs dim" style="padding:4px 16px 14px">В документе нет заголовков для навигации.</p>`;
  return toc
    .map((entry) => `<a href="#knowledge" data-toc="${esc(entry.id)}" data-level="${entry.level}">${esc(entry.text)}</a>`)
    .join("");
}

function renderToc(toc) {
  const slot = $("#doc-toc");
  if (!slot) return;
  slot.innerHTML = tocTemplate(toc);
  const counter = $("#toc-count");
  if (counter) counter.textContent = String(toc.length);
  slot.scrollTop = 0;
  observeHeadings(toc);
}

/* Highlight the section the analyst is currently reading. */
let tocObserver = null;

function setActiveToc(id) {
  const slot = $("#doc-toc");
  if (!slot) return;
  slot.querySelectorAll("[data-toc]").forEach((link) => {
    const active = link.dataset.toc === id;
    link.setAttribute("aria-current", String(active));
    if (active) link.scrollIntoView({ block: "nearest" });
  });
}

function observeHeadings(toc) {
  tocObserver?.disconnect();
  tocObserver = null;
  const slot = $("#doc-toc");
  if (!slot || !toc.length || !("IntersectionObserver" in window)) return;

  tocObserver = new IntersectionObserver(
    (entries) => {
      const visible = entries
        .filter((entry) => entry.isIntersecting)
        .sort((a, b) => a.boundingClientRect.top - b.boundingClientRect.top);
      if (visible.length) setActiveToc(visible[0].target.id);
    },
    { rootMargin: "-10% 0px -70% 0px", threshold: 0 },
  );

  for (const entry of toc) {
    const heading = document.getElementById(entry.id);
    if (heading) tocObserver.observe(heading);
  }
}

export async function loadDocument(path, { scroll = true } = {}) {
  const doc = $("#document");
  if (!doc) return;
  state.current = path;
  renderNav();
  doc.innerHTML = `<div class="loader">Загрузка документа…</div>`;
  try {
    const data = await api(`/api/readme?path=${encodeURIComponent(path)}`);
    const { html, toc } = decorate(data.html);
    renderToc(toc);
    doc.innerHTML = `
      <div class="doc__path">
        <span class="badge badge--accent">README</span>
        <span>${esc(data.path)}</span>
        ${data.attack ? `<button class="btn btn--quiet btn--sm" type="button" data-open-attack="${esc(data.attack)}">Сценарий →</button>` : ""}
      </div>
      ${html}`;
    if (scroll) doc.scrollIntoView({ behavior: "smooth", block: "start" });
    if (location.hash !== "#knowledge") history.replaceState(null, "", "#knowledge");
  } catch {
    doc.innerHTML = `<div class="doc-empty"><strong>Документ не найден</strong><p class="text-sm muted">Проверьте путь или обновите индекс кнопкой ↻ в шапке.</p></div>`;
  }
}

export function openLightbox(image) {
  const viewer = $("#image-viewer");
  if (!viewer) return;
  const target = viewer.querySelector("img");
  target.src = image.currentSrc || image.src;
  target.alt = image.alt || "Увеличенное изображение";
  viewer.querySelector(".lightbox__caption").textContent =
    image.alt || "Нажмите вне изображения или Esc, чтобы закрыть.";
  viewer.showModal();
}

export function initDocs(items) {
  state.items = items;
  renderNav();
  renderToc([]);

  $("#doc-search")?.addEventListener(
    "input",
    debounce((event) => {
      state.filter = event.target.value;
      renderNav();
    }, 160),
  );

  document.addEventListener("click", (event) => {
    const open = event.target.closest("[data-readme]");
    if (open?.dataset.readme) {
      event.preventDefault();
      loadDocument(decodeURIComponent(open.dataset.readme));
      return;
    }
    const tocLink = event.target.closest("[data-toc]");
    if (tocLink) {
      event.preventDefault();
      const target = document.getElementById(tocLink.dataset.toc);
      if (target) {
        target.scrollIntoView({ behavior: "smooth", block: "start" });
        setActiveToc(tocLink.dataset.toc);
      }
      return;
    }
    if (event.target.closest(".doc-copy")) {
      const pre = event.target.closest("pre");
      const text = pre?.querySelector("code")?.textContent ?? pre?.textContent ?? "";
      copyText(text.trim(), "Листинг скопирован");
      return;
    }
    const image = event.target.closest("#document img");
    if (image) openLightbox(image);
  });

  document.addEventListener("keydown", (event) => {
    if ((event.key === "Enter" || event.key === " ") && event.target.matches?.("#document img")) {
      event.preventDefault();
      openLightbox(event.target);
    }
  });

  const viewer = $("#image-viewer");
  viewer?.addEventListener("click", (event) => {
    if (event.target === viewer || event.target.closest("#lightbox-close")) viewer.close();
  });
  viewer?.addEventListener("close", () => {
    const image = viewer.querySelector("img");
    image.removeAttribute("src");
    image.alt = "";
    viewer.querySelector(".lightbox__caption").textContent = "";
  });

  const preferred = items.find((item) => item.attack) || items[0];
  if (preferred) loadDocument(preferred.path, { scroll: false });
}
