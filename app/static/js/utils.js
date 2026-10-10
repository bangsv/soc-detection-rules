/* Shared helpers: DOM, escaping, formatting, API access, clipboard, toasts. */

export const $ = (selector, scope = document) => scope.querySelector(selector);
export const $$ = (selector, scope = document) => Array.from(scope.querySelectorAll(selector));

export const esc = (value) =>
  String(value ?? "").replace(/[&<>"']/g, (char) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;",
  }[char]));

export const escapeRegExp = (value) => String(value).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

/** Wrap every case-insensitive occurrence of `needle` in <mark>. Input must be escaped already. */
export function highlight(escapedText, needle) {
  const term = String(needle || "").trim();
  if (!term) return escapedText;
  const pattern = new RegExp(escapeRegExp(term), "gi");
  return escapedText.replace(pattern, (match) => `<mark>${match}</mark>`);
}

export function normalize(value) {
  return String(value ?? "").toLocaleLowerCase("ru").trim();
}

export function debounce(fn, delay = 200) {
  let timer;
  const wrapped = (...args) => {
    clearTimeout(timer);
    timer = setTimeout(() => fn(...args), delay);
  };
  wrapped.cancel = () => clearTimeout(timer);
  return wrapped;
}

export async function api(path, options) {
  const response = await fetch(path, options);
  if (!response.ok) throw new Error(`${response.status} ${response.statusText}`);
  return response.json();
}

export function fileSize(bytes) {
  if (!Number.isFinite(bytes)) return "—";
  if (bytes < 1024) return `${bytes} Б`;
  const units = ["КБ", "МБ", "ГБ"];
  let value = bytes / 1024;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit += 1;
  }
  return `${value.toFixed(value >= 10 ? 0 : 1)} ${units[unit]}`;
}

export function formatDate(iso) {
  if (!iso) return "—";
  try {
    return new Intl.DateTimeFormat("ru-RU", { dateStyle: "medium", timeStyle: "short" }).format(new Date(iso));
  } catch {
    return iso;
  }
}

/** Russian plural forms: plural(3, ["индикатор", "индикатора", "индикаторов"]). */
export function plural(count, forms) {
  const value = Math.abs(Number(count) || 0) % 100;
  const tail = value % 10;
  if (value > 10 && value < 20) return forms[2];
  if (tail > 1 && tail < 5) return forms[1];
  if (tail === 1) return forms[0];
  return forms[2];
}

export function countLabel(count, forms) {
  return `${count} ${plural(count, forms)}`;
}

const SEVERITY_CLASS = {
  "Критично": "badge--critical",
  "Высоко": "badge--high",
  "Средне": "badge--medium",
  "Низко": "badge--plain",
};

export function severityClass(severity) {
  return SEVERITY_CLASS[severity] || "badge--plain";
}

export function severityBadge(severity) {
  return `<span class="badge ${severityClass(severity)}">${esc(severity)}</span>`;
}

/** Markdown-lite renderer for indicator explanations coming from the IOC base. */
export function richText(text) {
  return esc(text)
    .replace(/`([^`\n]+)`/g, "<code>$1</code>")
    .replace(/\*\*(.+?)\*\*/g, "<strong>$1</strong>")
    .replace(/(?:^|\n)\s*•\s*/g, "\n• ")
    .split("\n")
    .map((line) => (line.trim() ? `<span>${line.replace(/^•\s*/, "• ")}</span>` : ""))
    .join("");
}

/* ------------------------------------------------------------------ toasts */

let toastHost;

export function toast(message, kind = "info", timeout = 2600) {
  toastHost ??= $("#toasts");
  if (!toastHost) return;
  const node = document.createElement("div");
  node.className = "toast";
  node.dataset.kind = kind;
  node.innerHTML = `<span aria-hidden="true">${kind === "warn" ? "!" : "✓"}</span>${esc(message)}`;
  toastHost.append(node);
  setTimeout(() => {
    node.style.transition = "opacity 200ms ease, transform 200ms ease";
    node.style.opacity = "0";
    node.style.transform = "translateY(8px)";
    setTimeout(() => node.remove(), 220);
  }, timeout);
}

/* --------------------------------------------------------------- clipboard */

export async function copyText(text, label = "Скопировано") {
  const value = String(text ?? "");
  if (!value) return false;
  try {
    await navigator.clipboard.writeText(value);
    toast(label);
    return true;
  } catch {
    const area = document.createElement("textarea");
    area.value = value;
    area.setAttribute("readonly", "");
    area.style.position = "fixed";
    area.style.opacity = "0";
    document.body.append(area);
    area.select();
    const ok = document.execCommand?.("copy");
    area.remove();
    toast(ok ? label : "Не удалось скопировать", ok ? "info" : "warn");
    return Boolean(ok);
  }
}

export function downloadText(filename, text) {
  const blob = new Blob([text], { type: "text/plain;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  document.body.append(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

/* ------------------------------------------------------------- focus guard */

export function isTyping(target) {
  if (!target) return false;
  const tag = target.tagName;
  return tag === "INPUT" || tag === "TEXTAREA" || tag === "SELECT" || target.isContentEditable;
}

export function onIdle(fn) {
  if ("requestIdleCallback" in window) {
    window.requestIdleCallback(fn, { timeout: 900 });
  } else {
    setTimeout(fn, 120);
  }
}
