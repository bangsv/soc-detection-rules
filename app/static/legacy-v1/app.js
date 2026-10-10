const $ = (s) => document.querySelector(s);
let timer;
let activeIocPopover = null;
const esc = (s) => String(s).replace(/[&<>"']/g, x => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[x]));

async function api(url, opts) { const r = await fetch(url, opts); if (!r.ok) throw new Error('Request failed'); return r.json(); }
function metric(n, label) { return `<div><strong>${n}</strong><span>${label}</span></div>`; }
function fileSize(bytes) { if (bytes < 1024) return `${bytes} Б`; const units = ['КБ', 'МБ', 'ГБ']; let value = bytes / 1024, unit = 0; while (value >= 1024 && unit < units.length - 1) { value /= 1024; unit++; } return `${value.toFixed(value >= 10 ? 0 : 1)} ${units[unit]}`; }
function renderAttack(a) { return `<button class="attack-card" data-attack="${encodeURIComponent(a.id)}"><span class="card-top"><em>◈</em><small>${a.files} README</small></span><h3>${esc(a.title)}</h3><p>${a.ioc_count} индикаторов</p><span class="card-arrow">Смотреть IOC →</span></button>`; }
function attackBadge(a) { return `<span class="attack-badge">${esc(a.title)}</span>`; }
function renderIocHelp(text) {
  return esc(text)
    .replace(/`([^`\n]+)`/g, '<code>$1</code>')
    .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
    .replace(/(?:^|\n)•\s*/g, '<br><span class="ioc-help-bullet">•</span> ')
    .replace(/\n/g, '<br>');
}

function closeIocPopover() {
  if (!activeIocPopover) return;
  activeIocPopover.popover.hidden = true;
  activeIocPopover.trigger.setAttribute('aria-expanded', 'false');
  activeIocPopover.item.classList.remove('popover-below', 'popover-align-right');
  activeIocPopover = null;
}

function positionIocPopover() {
  if (!activeIocPopover) return;
  const {item, trigger, popover} = activeIocPopover;
  const anchor = trigger.getBoundingClientRect();
  const viewportHeight = window.visualViewport?.height || window.innerHeight;
  const viewportWidth = window.visualViewport?.width || window.innerWidth;
  if (anchor.bottom <= 0 || anchor.top >= viewportHeight || anchor.right <= 0 || anchor.left >= viewportWidth) {
    closeIocPopover();
    return;
  }

  const edge = 12;
  const gap = 10;
  const availableAbove = Math.max(0, anchor.top - edge - gap);
  const availableBelow = Math.max(0, viewportHeight - anchor.bottom - edge - gap);
  const showAbove = availableAbove >= availableBelow;
  const availableHeight = Math.max(96, showAbove ? availableAbove : availableBelow);
  popover.style.maxHeight = `${availableHeight}px`;
  const bounds = popover.getBoundingClientRect();
  const left = Math.max(edge, Math.min(anchor.left, viewportWidth - bounds.width - edge));
  const top = showAbove
    ? Math.max(edge, anchor.top - bounds.height - gap)
    : Math.min(viewportHeight - bounds.height - edge, anchor.bottom + gap);

  popover.style.left = `${left}px`;
  popover.style.top = `${top}px`;
  popover.style.setProperty('--ioc-arrow-x', `${Math.max(18, Math.min(anchor.left + 18 - left, bounds.width - 18))}px`);
  item.classList.toggle('popover-below', !showAbove);
  item.classList.toggle('popover-align-right', anchor.left + bounds.width > viewportWidth - edge);
}

async function showAttack(id) {
  const panel = $('#attack-detail'); panel.innerHTML = '<div class="loader">Загрузка индикаторов…</div>'; panel.hidden = false;
  const data = await api('/api/attacks/' + encodeURIComponent(id));
  panel.innerHTML = `<div class="intel-title"><div><p class="eyebrow">IOC INVENTORY</p><h3>${esc(data.title)}</h3><p>${data.ioc_count} индикаторов · Host IOC и Network IOC</p></div><button class="close-intel" aria-label="Закрыть">×</button></div><p class="ioc-hint"><span>i</span> Нажмите на индикатор, чтобы открыть пояснение из базы IOC.</p><div class="ioc-groups">${data.ioc_groups.map(g => `<section class="ioc-group"><h4>${esc(g.type)} <span>${g.items.length}</span></h4>${g.items.length ? `<div class="ioc-list">${g.items.map(i => `<div class="ioc-item"><div class="ioc-popover" role="tooltip" hidden><span class="ioc-popover-kicker">СПРАВКА ПО IOC</span><p>${renderIocHelp(i.description)}</p></div><button type="button" class="ioc-trigger${i.important ? ' is-important' : ''}" aria-label="Показать справку: ${esc(i.value)}" aria-expanded="false" data-description="${esc(i.description)}"><code>${esc(i.value)}</code><span class="ioc-info" aria-hidden="true">i</span></button></div>`).join('')}</div>` : '<p class="ioc-empty">Для этого типа индикаторы не указаны.</p>'}</section>`).join('')}</div><details class="materials"><summary><span>Материалы сценария</span><small>${data.materials.length} файлов</small></summary><div class="material-list">${data.materials.map(f => `<a href="/api/download?path=${encodeURIComponent(f.path)}" class="material" download><span class="file-kind">${esc(f.kind)}</span><span class="file-name" title="${esc(f.path)}">${esc(f.path)}</span><small>${fileSize(f.size)}</small><b>↓</b></a>`).join('')}</div></details>${data.readmes[0] ? `<button class="open-doc" data-readme="${encodeURIComponent(data.readmes[0])}">Открыть документацию атаки →</button>` : ''}`;
  panel.scrollIntoView({behavior: 'smooth', block: 'nearest'});
}

async function loadDocument(path) {
  const doc = $('#document'); doc.innerHTML = '<div class="loader">Загрузка документа…</div>';
  try {
    const data = await api('/api/readme?path=' + encodeURIComponent(path));
    doc.innerHTML = `<div class="doc-path">${esc(data.path)}</div>${data.html}`;
    doc.querySelectorAll('img').forEach(image => {
      image.classList.add('document-image');
      image.loading = 'lazy';
      image.decoding = 'async';
      image.tabIndex = 0;
      image.setAttribute('role', 'button');
      image.setAttribute('aria-label', `Увеличить изображение: ${image.alt || 'Скриншот из документа'}`);
    });
    history.replaceState(null, '', '#knowledge'); doc.scrollIntoView({behavior:'smooth', block:'start'});
  }
  catch { doc.innerHTML = '<div class="document-empty"><h3>Документ не найден</h3></div>'; }
}

function openImageViewer(image) {
  const viewer = $('#image-viewer');
  const enlarged = viewer.querySelector('img');
  enlarged.src = image.currentSrc || image.src;
  enlarged.alt = image.alt || 'Увеличенное изображение';
  viewer.querySelector('p').textContent = image.alt || 'Нажмите вне изображения или Esc, чтобы закрыть.';
  viewer.showModal();
}

async function search(q) {
  const out = $('#results'), state = $('#search-state');
  if (!q.trim()) { out.innerHTML = ''; state.textContent = 'Поиск по CVE, IOC, хешам и названиям угроз.'; return; }
  state.textContent = 'Поиск в индексе индикаторов…';
  const data = await api('/api/search?q=' + encodeURIComponent(q));
  if (!data.results.length && !data.attacks.length) { state.innerHTML = `Для <b>${esc(q)}</b> совпадений не найдено.`; out.innerHTML = ''; return; }
  state.textContent = `Совпадений: ${data.results.length + data.attacks.length}`;
  out.innerHTML = `${data.attacks.map(a => `<div class="result threat-result"><span class="result-type">УГРОЗА</span><strong>${esc(a.title)}</strong><button class="result-open" data-attack="${encodeURIComponent(a.id)}">Все IOC →</button></div>`).join('')}${data.results.map(r => `<div class="result"><div class="indicator"><code>${esc(r.ioc)}</code><span class="result-type">${esc(r.type)}</span></div><div class="found-in"><span>Обнаружен в:</span>${r.attacks.map(attackBadge).join('')}</div></div>`).join('')}`;
}

async function init() {
  const data = await api('/api/summary');
  $('#metrics').innerHTML = metric(data.attacks,'сценариев') + metric(data.iocs,'IOC в индексе') + metric(data.readmes,'README');
  $('#attacks').innerHTML = data.items.sort((a,b) => a.title.localeCompare(b.title)).map(renderAttack).join('');
  const docs = data.readme_items;
  $('#readme-nav').innerHTML = `<p>ДОКУМЕНТЫ <span>${docs.length}</span></p>` + docs.map(d => `<button data-readme="${encodeURIComponent(d.path)}"><small>${esc(d.title)}</small><span>${esc(d.path.split('/').slice(1,-1).join(' / ') || 'Общее')}</span></button>`).join('');
}
document.addEventListener('click', e => {
  if (e.target.matches('#document img')) return openImageViewer(e.target);
  if (e.target.closest('.image-viewer-close')) return $('#image-viewer').close();
  if (e.target.matches('#image-viewer')) return $('#image-viewer').close();
  const iocTrigger = e.target.closest('.ioc-trigger');
  if (iocTrigger) {
    const item = iocTrigger.closest('.ioc-item');
    const wasOpen = !item.querySelector('.ioc-popover').hidden;
    closeIocPopover();
    if (!wasOpen) {
      const popover = item.querySelector('.ioc-popover');
      popover.hidden = false;
      iocTrigger.setAttribute('aria-expanded', 'true');
      activeIocPopover = {item, trigger: iocTrigger, popover};
      positionIocPopover();
    }
    return;
  }
  if (!e.target.closest('.ioc-item')) {
    closeIocPopover();
  }
  const readme = e.target.closest('[data-readme]'); if (readme?.dataset.readme) return loadDocument(decodeURIComponent(readme.dataset.readme));
  const attack = e.target.closest('[data-attack]'); if (attack?.dataset.attack) return showAttack(decodeURIComponent(attack.dataset.attack));
  if (e.target.closest('.close-intel')) $('#attack-detail').hidden = true;
});
document.addEventListener('keydown', e => {
  if ((e.key === 'Enter' || e.key === ' ') && e.target.matches('#document img')) {
    e.preventDefault();
    openImageViewer(e.target);
  }
});
$('#image-viewer').addEventListener('close', () => {
  const image = $('#image-viewer img');
  image.removeAttribute('src');
  image.alt = '';
  $('#image-viewer p').textContent = '';
});
$('#ioc-search').addEventListener('input', e => { clearTimeout(timer); timer = setTimeout(() => search(e.target.value), 220); });
document.addEventListener('keydown', e => { if (e.key === 'Escape') { closeIocPopover(); $('#ioc-search').value = ''; $('#ioc-search').blur(); search(''); } });
document.addEventListener('scroll', positionIocPopover, {capture: true, passive: true});
window.addEventListener('resize', positionIocPopover, {passive: true});
window.visualViewport?.addEventListener('resize', positionIocPopover, {passive: true});
window.visualViewport?.addEventListener('scroll', positionIocPopover, {passive: true});
$('#reindex').addEventListener('click', async () => { $('#reindex').classList.add('spin'); await api('/api/reindex', {method:'POST'}); $('#reindex').classList.remove('spin'); init(); });
init();
