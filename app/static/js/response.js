import { initTheme } from "./theme.js";

const $ = (s) => document.querySelector(s);
const profiles = [
  { match: /EternalBlue|2017-0143/i, title: "EternalBlue · CVE-2017-0143", signal: "Сверьте Suricata/SMB сигнатуру с PCAP: источник, цель, последовательность SMBv1/Trans2 и итоговый статус. В README успешная и неуспешная попытки представлены раздельными дампами.", investigate: "Сопоставьте PCAP и EVE/fast.log с Security 4624 и Sysmon. README отмечает анонимный вход 4624 как вспомогательный и некритичный IOC: сам по себе он не подтверждает эксплуатацию. Ищите последующую активную сессию между целью и управляющим узлом, создание процессов/служб и распространение на соседние узлы.", contain: "При подтверждении эксплуатации ограничьте SMB между сегментами и изолируйте уязвимый узел по IR-процедуре. Сохраните PCAP, EVE, журналы и артефакты до очистки.", remediate: "Установите поддерживаемые обновления MS17-010, отключите SMBv1 по утверждённому плану, проверьте соседние узлы и учётные записи; восстановите систему из доверенного источника после проверки." },
  { match: /PetitPotam|36942/i, title: "PetitPotam · CVE-2021-36942", signal: "Соберите цепочку из README: входящее SMB к DC → RPC bind к MS-EFSRPC → EfsRpcOpenFileRaw с UNC-путём → исходящее SMB/NTLM от DC к инициатору или relay-хосту. Сверьте Sysmon 3/18 и SMBClient 30805/30816.", investigate: "На DC проверьте Security 4624 (Logon Type 3, ANONYMOUS LOGON или учётная запись компьютера), направления и время Sysmon-соединений, SMB статусы и PCAP. Отдельно установите, завершилась ли цепочка NTLM relay и были ли изменения AD или доступ к ресурсам.", contain: "Считайте исходящее SMB от DC к неизвестному узлу при такой RPC-цепочке критичным признаком. Эскалируйте владельцу AD, ограничьте исходящие SMB/NTLM по утверждённой процедуре и изолируйте инициатор; при признаках relay действуйте как при компрометации домена.", remediate: "Установите обновления и меры Microsoft против NTLM relay/coercion, ограничьте NTLM и доступ к RPC/SMB согласно архитектуре. Проверьте DC и целевой хост на последствия и повторную активность." },
  { match: /Zerologon|2020-1472/i, title: "Zerologon · CVE-2020-1472", signal: "Проверьте Suricata/Netlogon RPC аномалии и повторные попытки от одного источника. Сверьте Security 4742 по машинной учётной записи DC и NETLOGON 5823.", investigate: "README указывает, что для штатной смены пароля характерен порядок NETLOGON 5823 → Security 4742. Подозрительно изменение PasswordLastSet/пароля DC до 5823 либо с субъектом ANONYMOUS LOGON; проверьте 5805/4742, 4624 и последующую DRSUAPI-активность. Ответ STATUS_SUCCESS на отдельный RPC-вызов ещё не подтверждает компрометацию.", contain: "Немедленно эскалируйте L2 и владельцу AD. Ограничьте доступ подозрительного источника к DC; не сбрасывайте пароль DC вручную и не меняйте машинную учётную запись без плана восстановления домена.", remediate: "Сверьте состояние патчей и enforcement Netlogon с бюллетенем Microsoft. Если пароль DC был изменён несанкционированно — восстановление доверия выполняет команда AD по проверенной процедуре; затем проверьте репликацию и все DC." },
  { match: /DCSync/i, title: "DCSync · репликация каталога", signal: "Алерт на DRSUAPI / DRSGetNCChanges или Security 4662 с правами репликации. Определите субъект, DC-цель, источник и объём операций.", investigate: "Проверьте 4662 (репликационные GUID/права), 4624 и сетевые RPC-соединения. Сравните субъект с утверждёнными DC и сервисными аккаунтами; ищите новые делегирования, членство в привилегированных группах и следы доступа к NTDS.", contain: "Если субъект не авторизован — срочно привлеките владельца AD, ограничьте учётную запись и источник по IR-процедуре. Сохраните журналы DC и данные репликации.", remediate: "Удалите несанкционированные права репликации, смените затронутые секреты в согласованном порядке, проверьте DC и восстановите доверие домена." },
  { match: /2025-33073/i, title: "CVE-2025-33073 · SMB Client", signal: "В этой папке нет README и detection_rule: используйте приложенные PCAP (успешный, неуспешный и DFS coercion) как лабораторные примеры. Проверьте цепочку SMB/Kerberos, DNS-имя и алерт Defender for Identity, связанный с malicious Kerberos activity.", investigate: "Microsoft описывает сценарий как принуждение устройства к аутентификации через специально сформированное имя/запись DNS (маркер 1UWhR): проверьте создание/разрешение имени, SMB-клиент, Kerberos TGS/CIFS или NTLM-аутентификацию и дальнейшую активность на узле-цели. Сравните успешный и неуспешные PCAP из каталога; сам факт SMB-соединения недостаточен.", contain: "При подтверждении изолируйте затронутый endpoint, ограничьте вредоносное разрешение DNS/SMB-направление по процедуре и сохраните DNS, Kerberos, endpoint и PCAP артефакты. Оцените, использовались ли полученные билеты/учётные данные.", remediate: "Установите обновление Microsoft для CVE-2025-33073 и проверьте статус по инвентарю. Устраните несанкционированную DNS-запись/механизм coercion, отзовите или смените затронутые credentials по решению AD, проверьте SAM/учётные данные и повторите поиск по домену." },
  { match: /Nginx UI|27944/i, title: "Nginx UI · CVE-2026-27944", signal: "Проверьте обращения к `/api/backup`: метод, исходный адрес, код ответа и заголовок `X-Backup-Security`. По README уязвимость до версии 2.3.3 позволяла без аутентификации скачать backup и получить ключ расшифрования из заголовка.", investigate: "Сохраните PCAP, access/error-логи и reverse-proxy журналы. Установите, отдавался ли backup и заголовок с ключом; считайте возможными раскрытые учётные данные, токены сессий, SSL-ключи и конфигурацию. Проверьте дальнейшие входы, изменения Nginx и повторное использование секретов.", contain: "Ограничьте внешний доступ к панели/endpoint через владельца сервиса, сохраните копию журналов и отзовите сессии. Не пересылайте backup или ключ открытым текстом.", remediate: "Обновите Nginx UI как минимум до версии с исправлением (README указывает 2.3.3), подтвердите версию у поставщика, смените потенциально раскрытые credentials, токены и ключи, проверьте конфигурацию и повторно найдите обращения к endpoint." },
  { match: /Copy fail|31431/i, title: "Copy Fail · CVE-2026-31431", signal: "Это локальная эскалация до root: для эксплуатации нужен доступ обычного пользователя к Linux-хосту. По README проверьте Auditd-события успешных `socket`/`bind`/`setsockopt` для AF_ALG и последующую корреляцию с запуском оболочки.", investigate: "Сопоставьте auditd, Sigma/MaxPatrol XP корреляцию и трассировки из triage: пользователь, процесс, родительский процесс, время и переход привилегий. Сверьте с примером легитимной активности AF_ALG из репозитория: сами криптографические вызовы не доказывают эксплуатацию, важна связанная последовательность и результат. Уточните версию ядра и vendor-пакет.", contain: "При подтверждённом переходе к root изолируйте хост, сохраните volatile-данные и audit-логи, ограничьте скомпрометированную учётную запись и привлеките администратора Linux.", remediate: "Установите исправленное ядро из репозитория поставщика и перезагрузите по change-процедуре. Если обновление пока невозможно, применяйте только одобренные поставщиком меры снижения риска. Проверьте целостность, persistence, секреты и повторные попытки." },
];
const getProfile = (attack) => profiles.find((p) => p.match.test(`${attack.id} ${attack.title}`)) || {
  title: attack.title, signal: "Проверьте исходное событие в SIEM/EDR и откройте карточку сценария в каталоге: сверьте точные поля детектора, источник данных, актив и временное окно.",
  investigate: "Сопоставьте сетевую и endpoint-телеметрию, журналы аутентификации и изменения конфигурации. Зафиксируйте временную линию и оцените охват по IOC сценария.",
  contain: "При подтверждении воздействия ограничьте затронутый узел/учётную запись согласованным способом и сохраните доказательства. При неопределённости передайте L2 и запросите недостающие данные.",
  remediate: "Владелец системы устраняет первопричину по change/IR-процедуре; SOC проверяет повторную активность, соседние активы и завершает отчёт." };

function buildSteps(attack) {
  const p = getProfile(attack);
  const data = [
    ["l1", "Алерт получен", "L1 · первичная обработка", `Откройте событие и исходный алерт. Сценарий: ${p.title}. Сохраните ID алерта, время, источник, цель и ссылку на событие.`, "start"],
    ["scope", "Зафиксировать контекст", "L1 · первичная обработка", "Уточните критичность актива, владельца, учётную запись, сегмент, успешность действия и связанные алерты ±30 минут. Все времена укажите с часовым поясом.", "normal"],
    ["legit", "Проверить легитимность", "L1 · проверка контекста", "Сверьте с заявкой на работы, тестом на проникновение и владельцем системы. Попросите подтверждение через известный канал; совпадение IP или имени само по себе не доказывает легитимность.", "decision"],
    ["false", "Подтверждена работа", "Ветка · закрытие", "Приложите подтверждение, исполнителя, окно работ и совпавшие артефакты. Закройте по регламенту с корректным основанием и отметьте возможные улучшения правила.", "success"],
    ["escalate", "Нет подтверждения / есть риск", "Передача L2", "Не закрывайте событие. Передайте L2 факты, гипотезу отдельно, активы, учётные записи, временную линию, сырой запрос и недостающие источники.", "warning"],
    ["evidence", "Собрать телеметрию", "L2 · расследование", p.signal, "normal"],
    ["correlate", "Построить временную линию", "L2 · расследование", p.investigate, "normal"],
    ["confirmed", "Воздействие подтверждено?", "L2 · решение", "Оцените достоверность по нескольким независимым признакам, наличие успешного воздействия и охват. При нехватке данных запросите их и держите кейс открытым.", "decision"],
    ["scope2", "Оценить охват", "L2 · подтверждённый инцидент", "Ищите тот же источник, учётную запись, индикаторы и цепочку действий на соседних хостах. Определите критичность, persistence, lateral movement и затронутые данные.", "danger"],
    ["contain", "Локализовать", "IT / IR · сдерживание", p.contain, "danger"],
    ["fix", "Устранить и восстановить", "IT / IR · восстановление", p.remediate, "normal"],
    ["close", "Постинцидентный контроль", "L2 · закрытие", "Зафиксируйте подтверждённую причину, охват, действия и согласования, доказательства, владельцев и сроки. Выполните контрольный поиск после устранения и обновите детектирование при необходимости.", "success"],
  ].map(([id, title, lane, detail, kind]) => ({ id, title, lane, detail, kind }));
  return { steps: data, edges: [[0,1,""],[1,2,""],[2,3,"Да"],[2,4,"Нет / неясно"],[4,5,""],[5,6,""],[6,7,""],[7,8,"Да"],[7,5,"Недостаточно данных"],[8,9,""],[9,10,""],[10,11,""],[3,11,""],[7,11,"Нет"]] };
}

const viewport = $("#flow-viewport"), world = $("#flow-world"), nodesHost = $("#flow-nodes"), links = $("#flow-links");
const minimap = $("#flow-minimap"), minimapSvg = $("#flow-minimap-svg"), minimapNodes = $("#minimap-nodes"), minimapWindow = $("#minimap-window");
let scale = 1, x = 0, y = 0, dragging = null, mapDragging = false, attackList = [], activeId = "", flowSteps = [], currentStepIndex = 0;
const layout = { width: 3970, height: 1000, positions: [[60,420],[410,420],[760,420],[1110,125],[1110,700],[1460,700],[1810,700],[2160,700],[2510,400],[2860,400],[3210,400],[3560,400]] };
function placeWorld() { world.style.transform = `translate(${x}px, ${y}px) scale(${scale})`; $("#zoom-value").textContent = `${Math.round(scale*100)}%`; updateMinimap(); }
function centerWorldPoint(cx,cy) { x=viewport.clientWidth/2-cx*scale; y=viewport.clientHeight/2-cy*scale; placeWorld(); }
function centerStep(index=currentStepIndex) { const [left,top]=layout.positions[index]; centerWorldPoint(left+145,top+51); }
function updateMinimap() {
  if (!minimapWindow || !viewport.clientWidth || !scale) return;
  const left=Math.max(0,-x/scale), top=Math.max(0,-y/scale);
  minimapWindow.setAttribute("x",String(Math.min(layout.width,left)));
  minimapWindow.setAttribute("y",String(Math.min(layout.height,top)));
  minimapWindow.setAttribute("width",String(Math.min(layout.width,viewport.clientWidth/scale)));
  minimapWindow.setAttribute("height",String(Math.min(layout.height,viewport.clientHeight/scale)));
}
function moveFromMinimap(event) {
  const rect=minimapSvg.getBoundingClientRect();
  const px=(event.clientX-rect.left)/rect.width*layout.width;
  const py=(event.clientY-rect.top)/rect.height*layout.height;
  centerWorldPoint(px,py);
}
function renderSummary(attack) {
  const p=getProfile(attack), key=`${attack.id} ${attack.title}`;
  const sources = /EternalBlue|2017-0143/i.test(key) ? "Suricata EVE/PCAP · Windows Security · Sysmon" :
    /PetitPotam|36942/i.test(key) ? "Sysmon 3/18 · Security 4624 · SMBClient/Server · PCAP" :
    /Zerologon|2020-1472/i.test(key) ? "Netlogon · Security 4742/4624 · Suricata RPC" :
    /DCSync/i.test(key) ? "Security 4662/4624 · Directory Service · RPC/DRSUAPI" :
    /2025-33073/i.test(key) ? "DNS · SMB Client · Kerberos · Defender for Identity · PCAP" :
    /Nginx UI|27944/i.test(key) ? "HTTP access/error · WAF/reverse proxy · audit trail · PCAP" :
    /Copy fail|31431/i.test(key) ? "Linux Audit · kernel logs · EDR · inventory ядра" : "SIEM/EDR · сетевые и endpoint журналы · инвентарь актива";
  const escalation = /EternalBlue|2017-0143/i.test(key) ? "Подозрительная SMB-сигнатура вместе с последующей активной сессией или действиями на узле." :
    /PetitPotam|36942/i.test(key) ? "После EFS RPC DC инициирует SMB/NTLM к неизвестному узлу либо подтверждён relay." :
    /Zerologon|2020-1472/i.test(key) ? "Изменение учётной записи DC без ожидаемого события Netlogon 5823 или от анонимного субъекта." :
    /DCSync/i.test(key) ? "4662/DRSUAPI у неавторизованного субъекта или источника вне списка контроллеров домена." :
    /2025-33073/i.test(key) ? "Устройство разрешило подозрительное имя и отправило Kerberos/SMB-аутентификацию на неутверждённый узел." :
    /Nginx UI|27944/i.test(key) ? "Неавторизованный успешный ответ `/api/backup` или утечка ключа/резервной копии." :
    /Copy fail|31431/i.test(key) ? "Коррелированная AF_ALG последовательность с запуском оболочки или подтверждённым повышением привилегий." : "Подтверждённое воздействие, несанкционированное изменение или неполнота критичной телеметрии.";
  $("#summary-title").textContent=p.title;
  const severity=$("#summary-severity"); severity.textContent=[attack.severity,attack.cvss?`CVSS ${attack.cvss}`:""].filter(Boolean).join(" · ") || "Уровень по сценарию";
  severity.dataset.level=String(attack.severity||"").toLocaleLowerCase("ru");
  $("#summary-signals").textContent=p.signal;
  $("#summary-sources").textContent=sources;
  $("#summary-escalation").textContent=escalation;
}
function draw(attack) {
  const { steps, edges } = buildSteps(attack); flowSteps=steps; currentStepIndex=0; nodesHost.innerHTML = "";
  const maxY = layout.height; world.style.width = `${layout.width}px`; world.style.height = `${maxY}px`; links.setAttribute("viewBox", `0 0 ${layout.width} ${maxY}`); links.setAttribute("width", layout.width); links.setAttribute("height", maxY);
  const rects = steps.map((step,i) => { const [left,top] = layout.positions[i]; const node = document.createElement("button"); node.type="button"; node.className=`flow-node flow-node--${step.kind}`; node.style.left=`${left}px`; node.style.top=`${top}px`; node.innerHTML=`<span class="flow-node__lane">${step.lane}</span><strong>${step.title}</strong><span class="flow-node__open">Открыть справку ↗</span>`; node.addEventListener("click",()=>showDetail(step,true)); nodesHost.append(node); return {left,top,width:290,height:102}; });
  links.innerHTML = edges.map(([from,to,label]) => { const a=rects[from], b=rects[to]; let sx=a.left+a.width/2, sy=a.top+a.height, ex=b.left+b.width/2, ey=b.top; if (Math.abs(ex-sx)>100 || ey<sy) { sx=a.left+a.width; sy=a.top+a.height/2; ex=b.left; ey=b.top+b.height/2; }
    const mid=(sy+ey)/2, d=`M ${sx} ${sy} C ${sx} ${mid}, ${ex} ${mid}, ${ex} ${ey}`; const lx=(sx+ex)/2, ly=(sy+ey)/2;
    return `<path d="${d}" marker-end="url(#arrow)"/><text x="${lx}" y="${ly-6}">${label}</text>`; }).join("");
  links.innerHTML=`<defs><marker id="arrow" markerWidth="8" markerHeight="8" refX="6" refY="3" orient="auto"><path d="M0,0 L0,6 L6,3 z"/></marker></defs>${links.innerHTML}`;
  minimapNodes.innerHTML=rects.map((node,i)=>`<rect class="minimap-node minimap-node--${steps[i].kind}" data-minimap-step="${i}" x="${node.left}" y="${node.top}" width="${node.width}" height="${node.height}" rx="20"/>`).join("");
  minimapNodes.querySelectorAll("[data-minimap-step]").forEach(node=>node.addEventListener("click",event=>{event.stopPropagation();showDetail(steps[Number(node.dataset.minimapStep)],true);}));
  renderSummary(attack); showDetail(steps[0]); renderGuide(attack); scale=Math.min(.72, Math.max(.62,(viewport.clientWidth-40)/1100)); centerStep(0);
}
let guideRoles = [], guideRoleIndex = 0;
function renderGuide(attack) {
  const p=getProfile(attack), source=(attack.readmes||[]).find(path=>/README\.md$/i.test(path));
  $("#guide-scenario").textContent=p.title;
  guideRoles=[
    {name:"SOC L1",steps:[
      ["Принять алерт",`Зарегистрируйте событие и сохраните ID правила, время, источник, цель, учётную запись и критичность актива. Откройте исходную запись в SIEM/EDR, не ограничивайтесь текстом уведомления.`],
      ["Проверить контекст",`Сверьте активность с окном работ, заявкой и известными тестами; подтвердите у владельца по доверенному каналу. ${p.signal}`],
      ["Передать или закрыть",`Подтверждённую легитимную активность закройте по регламенту с приложенным обоснованием. При отсутствии подтверждения, признаках успеха или нехватке данных передайте L2 и оставьте кейс открытым.`]
    ]},
    {name:"SOC L2",steps:[
      ["Подтвердить признаки",`${p.investigate}`],
      ["Собрать временную линию",`Сопоставьте исходные события и PCAP/EDR/сетевую телеметрию в одном часовом поясе. Проверьте активность до и после алерта, соседние узлы и связанные учётные записи; сохраните запросы и найденные артефакты.`],
      ["Оценить масштаб и уверенность",`Отделите факты от гипотез. Сетевой контакт или один индикатор сами по себе не доказывают компрометацию. Определите, есть ли успешное воздействие, persistence, повышение привилегий, lateral movement или доступ к данным.`],
      ["Принять решение",`Если данных недостаточно — запросите телеметрию у владельца, продолжайте расследование и не закрывайте кейс как ложное срабатывание. При подтверждении определите охват и координируйте локализацию с IT/IR.`]
    ]},
    {name:"IT / IR",steps:[
      ["Локализовать",`${p.contain} Перед изменением состояния хоста сохраните необходимые доказательства и volatile-данные по IR-процедуре.`],
      ["Устранить причину",`${p.remediate}`],
      ["Проверить восстановление",`Проверьте целостность и доступность сервиса с владельцем, состояние соседних активов и отсутствие повторных индикаторов. Сброс секретов и восстановление выполняйте согласованно, чтобы не нарушить работу домена или сервиса.`]
    ]},
    {name:"Закрытие",steps:[
      ["Оформить результат",`В кейсе сохраните таймлайн, охват, основание решения, выполненные меры, согласования и ссылки на журналы/артефакты. Укажите остаточные риски и владельцев задач.`],
      ["Контроль и улучшения",`После устранения повторите поиск по индикаторам сценария и подтвердите восстановление с владельцем. Если для вывода не хватало данных или этап не детектировался, заведите задачу на покрытие телеметрией или улучшение правила.`]
    ]}
  ];
  guideRoleIndex=0;drawGuideStep();
  const outside= /2025-33073/i.test(attack.id) ? ` <a href="https://learn.microsoft.com/defender-for-identity/alerts-xdr" target="_blank" rel="noreferrer">Источник Microsoft ↗</a>` : /31431/i.test(attack.id) ? ` <a href="https://access.redhat.com/security/cve/cve-2026-31431" target="_blank" rel="noreferrer">Источник Red Hat ↗</a>` : "";
  $("#guide-source").innerHTML=`Материалы сценария: <code>${source||attack.id+" (README отсутствует)"}</code> · правила обнаружения и triage${outside}`;
}
function drawGuideStep() {
  const role=guideRoles[guideRoleIndex];
  const host=$("#guide-content");
  host.innerHTML=`<div class="guide-tabs" role="tablist" aria-label="Этап реагирования">${guideRoles.map((r,i)=>`<button class="guide-tab ${i===guideRoleIndex?"is-active":""}" type="button" role="tab" aria-selected="${i===guideRoleIndex}" data-role="${i}">${r.name}</button>`).join("")}</div><div class="guide-steps-list">${role.steps.map(([title,text],i)=>`<article class="guide-current"><span class="guide-current__index">${String(i+1).padStart(2,"0")}</span><div><h3>${title}</h3><p>${text}</p></div></article>`).join("")}</div>`;
  host.querySelectorAll("[data-role]").forEach(button=>button.addEventListener("click",()=>{guideRoleIndex=Number(button.dataset.role);drawGuideStep();}));
}
function showDetail(step, center=false) {
  currentStepIndex=flowSteps.indexOf(step);
  $("#step-detail").innerHTML='<p class="eyebrow">'+step.lane+'</p><h2>'+step.title+'</h2><p>'+step.detail+'</p><p class="detail-tip"><b>Фиксация:</b> сохраните ссылку на источник и артефакты в карточке кейса. Указывайте, что подтверждено и какие данные ещё нужны.</p>';
  $("#flow-step-count").textContent='Этап '+(currentStepIndex+1)+' из '+flowSteps.length;
  $("#flow-prev").disabled=currentStepIndex<=0; $("#flow-next").disabled=currentStepIndex>=flowSteps.length-1;
  document.querySelectorAll(".flow-node").forEach((node,i)=>node.classList.toggle("is-active",i===currentStepIndex));
  minimapNodes.querySelectorAll(".minimap-node").forEach((node,i)=>node.classList.toggle("is-active",i===currentStepIndex));
  if(center)centerStep(currentStepIndex);
}
async function init() {
  initTheme();
  const navToggle=$("#nav-toggle"), nav=$("#nav");
  navToggle?.addEventListener("click",()=>{const open=nav?.dataset.open!=="true";if(nav)nav.dataset.open=String(open);navToggle.setAttribute("aria-expanded",String(open));});
  document.addEventListener("click", (event) => {
    document.querySelectorAll(".nav-more[open]").forEach((menu) => {
      if (!menu.contains(event.target)) menu.removeAttribute("open");
    });
  });

  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape") document.querySelectorAll(".nav-more[open]").forEach((menu) => menu.removeAttribute("open"));
  });
  nav?.addEventListener("click",e=>{if(e.target.closest("a")&&matchMedia("(max-width: 860px)").matches){nav.dataset.open="false";navToggle?.setAttribute("aria-expanded","false");}});
  try { const res=await fetch("/api/attacks"); if(!res.ok) throw Error(); attackList=await res.json(); const select=$("#attack-select");
    attackList.forEach(a=>{const option=document.createElement("option");option.value=a.id;option.textContent=a.title || a.id;select.append(option);});
    $("#flow-empty").hidden=true;
    if(!attackList.length) throw Error();
    select.addEventListener("change",()=>{activeId=select.value;const a=attackList.find(v=>v.id===activeId);draw(a);}); activeId=attackList[0].id;draw(attackList[0]);
  } catch { $("#flow-empty").hidden=false; $("#flow-empty").textContent="Не удалось загрузить сценарии. Проверьте доступность каталога SOC Atlas."; }
}
$("#zoom-in").addEventListener("click",()=>{scale=Math.min(2.2,scale*1.15);placeWorld();});
$("#zoom-out").addEventListener("click",()=>{scale=Math.max(.45,scale/1.15);placeWorld();});
$("#zoom-fit").addEventListener("click",()=>{scale=Math.min(1,(viewport.clientWidth-40)/layout.width);x=20;y=12;placeWorld();});
$("#flow-center").addEventListener("click",()=>centerStep());
$("#flow-prev").addEventListener("click",()=>{if(currentStepIndex>0)showDetail(flowSteps[currentStepIndex-1],true);});
$("#flow-next").addEventListener("click",()=>{if(currentStepIndex<flowSteps.length-1)showDetail(flowSteps[currentStepIndex+1],true);});
viewport.addEventListener("wheel",e=>{e.preventDefault(); const before=scale, bounds=viewport.getBoundingClientRect(), cx=e.clientX-bounds.left, cy=e.clientY-bounds.top; scale=Math.max(.45,Math.min(2.2,scale*(e.deltaY<0?1.1:.9))); x=cx-(cx-x)*(scale/before);y=cy-(cy-y)*(scale/before);placeWorld();},{passive:false});
viewport.addEventListener("pointerdown",e=>{if(e.target.closest("button"))return;dragging={x:e.clientX-x,y:e.clientY-y};viewport.classList.add("is-dragging");viewport.setPointerCapture(e.pointerId);});
viewport.addEventListener("pointermove",e=>{if(!dragging)return;x=e.clientX-dragging.x;y=e.clientY-dragging.y;placeWorld();});
viewport.addEventListener("pointerup",()=>{dragging=null;viewport.classList.remove("is-dragging");});
viewport.addEventListener("keydown",e=>{if(e.key==="ArrowRight"&&currentStepIndex<flowSteps.length-1){e.preventDefault();showDetail(flowSteps[currentStepIndex+1],true);}else if(e.key==="ArrowLeft"&&currentStepIndex>0){e.preventDefault();showDetail(flowSteps[currentStepIndex-1],true);}});
minimap.addEventListener("pointerdown",e=>{e.stopPropagation();mapDragging=true;minimap.setPointerCapture(e.pointerId);moveFromMinimap(e);});
minimap.addEventListener("pointermove",e=>{if(mapDragging)moveFromMinimap(e);});
minimap.addEventListener("pointerup",()=>{mapDragging=false;});
minimap.addEventListener("pointercancel",()=>{mapDragging=false;});
window.addEventListener("resize",()=>{if(attackList.length){scale=Math.min(.72,Math.max(.62,(viewport.clientWidth-40)/1100));centerStep();}else updateMinimap();});
init();
