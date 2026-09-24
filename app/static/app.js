const $ = (s) => document.querySelector(s);
let timer;
const esc = (s) => String(s).replace(/[&<>"']/g, x => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[x]));

async function api(url, opts) { const r = await fetch(url, opts); if (!r.ok) throw new Error('Request failed'); return r.json(); }
function metric(n, label) { return `<div><strong>${n}</strong><span>${label}</span></div>`; }
function fileSize(bytes) { if (bytes < 1024) return `${bytes} Б`; const units = ['КБ', 'МБ', 'ГБ']; let value = bytes / 1024, unit = 0; while (value >= 1024 && unit < units.length - 1) { value /= 1024; unit++; } return `${value.toFixed(value >= 10 ? 0 : 1)} ${units[unit]}`; }
function renderAttack(a) { return `<button class="attack-card" data-attack="${encodeURIComponent(a.id)}"><span class="card-top"><em>◈</em><small>${a.files} README</small></span><h3>${esc(a.title)}</h3><p>${a.ioc_count} индикаторов</p><span class="card-arrow">Смотреть IOC →</span></button>`; }
function attackBadge(a) { return `<span class="attack-badge">${esc(a.title)}</span>`; }

async function showAttack(id) {
  const panel = $('#attack-detail'); panel.innerHTML = '<div class="loader">Загрузка индикаторов…</div>'; panel.hidden = false;
  const data = await api('/api/attacks/' + encodeURIComponent(id));
  panel.innerHTML = `<div class="intel-title"><div><p class="eyebrow">IOC INVENTORY</p><h3>${esc(data.title)}</h3><p>${data.ioc_count} индикаторов, сгруппированных по типу</p></div><button class="close-intel" aria-label="Закрыть">×</button></div><div class="ioc-groups">${data.ioc_groups.map(g => `<section class="ioc-group"><h4>${esc(g.type)} <span>${g.items.length}</span></h4><div class="ioc-list">${g.items.map(i => `<code title="${esc(i.value)}">${esc(i.value)}</code>`).join('')}</div></section>`).join('')}</div><details class="materials"><summary><span>Материалы сценария</span><small>${data.materials.length} файлов</small></summary><div class="material-list">${data.materials.map(f => `<a href="/api/download?path=${encodeURIComponent(f.path)}" class="material" download><span class="file-kind">${esc(f.kind)}</span><span class="file-name" title="${esc(f.path)}">${esc(f.path)}</span><small>${fileSize(f.size)}</small><b>↓</b></a>`).join('')}</div></details>${data.readmes[0] ? `<button class="open-doc" data-readme="${encodeURIComponent(data.readmes[0])}">Открыть документацию атаки →</button>` : ''}`;
  panel.scrollIntoView({behavior: 'smooth', block: 'nearest'});
}

async function loadDocument(path) {
  const doc = $('#document'); doc.innerHTML = '<div class="loader">Загрузка документа…</div>';
  try { const data = await api('/api/readme?path=' + encodeURIComponent(path)); doc.innerHTML = `<div class="doc-path">${esc(data.path)}</div>${data.html}`; history.replaceState(null, '', '#knowledge'); doc.scrollIntoView({behavior:'smooth', block:'start'}); }
  catch { doc.innerHTML = '<div class="document-empty"><h3>Документ не найден</h3></div>'; }
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
  const docs = await api('/api/readmes');
  $('#readme-nav').innerHTML = `<p>ДОКУМЕНТЫ <span>${docs.length}</span></p>` + docs.map(d => `<button data-readme="${encodeURIComponent(d.path)}"><small>${esc(d.title)}</small><span>${esc(d.path.split('/').slice(1,-1).join(' / ') || 'Общее')}</span></button>`).join('');
}
document.addEventListener('click', e => {
  const readme = e.target.closest('[data-readme]'); if (readme?.dataset.readme) return loadDocument(decodeURIComponent(readme.dataset.readme));
  const attack = e.target.closest('[data-attack]'); if (attack?.dataset.attack) return showAttack(decodeURIComponent(attack.dataset.attack));
  if (e.target.closest('.close-intel')) $('#attack-detail').hidden = true;
});
$('#ioc-search').addEventListener('input', e => { clearTimeout(timer); timer = setTimeout(() => search(e.target.value), 220); });
document.addEventListener('keydown', e => { if (e.key === 'Escape') { $('#ioc-search').value = ''; $('#ioc-search').blur(); search(''); } });
$('#reindex').addEventListener('click', async () => { $('#reindex').classList.add('spin'); await api('/api/reindex', {method:'POST'}); $('#reindex').classList.remove('spin'); init(); });
init();
