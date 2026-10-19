/* Единая база инструментов и материалов для blue team.
   Каждый пункт описан по своему README: что это и зачем в SOC.
   Источник данных для страницы /tools — правится только здесь.

   Поля: id, name, url, group (задача), format, platforms, summary, why, tags, note, source, kind.

   Формулировки: summary — назначение инструмента, нейтрально и без оценки;
   why — место в процессе SOC и практическая функция. Без оценочных суждений,
   разговорных оборотов и риторических вопросов. */

export const SOURCES = {
  blue: { id: "blue", title: "BlueTeam-Tools", url: "https://github.com/A-poc/BlueTeam-Tools" },
  zimmerman: { id: "zimmerman", title: "Eric Zimmerman's Tools", url: "https://ericzimmerman.github.io/" },
  memory: { id: "memory", title: "Awesome Memory Forensics", url: "https://github.com/digitalisx/awesome-memory-forensics" },
  dfirtk: { id: "dfirtk", title: "DFIR Toolkit", url: "https://codeberg.org/dfir-dd/dfir-toolkit" },
  linuxir: { id: "linuxir", title: "Linux Incident Response", url: "https://github.com/vm32/Linux-Incident-Response" },
  huntlib: { id: "huntlib", title: "Threat Hunting Project", url: "https://github.com/ThreatHuntingProject" },
  sans: { id: "sans", title: "SANS", url: "https://www.sans.org/white-papers/" },
  vendor: { id: "vendor", title: "Вендорские материалы", url: "#" },
  mine: { id: "mine", title: "SOC Detection Rules", url: "https://github.com/bangsv/soc-detection-rules" },
};

/* Объединённая таксономия: 10 разделов вместо 16.
   Смежные темы стоят рядом, чтобы не приходилось выбирать между ветками. */
export const GROUPS = [
  {
    id: "threat-hunting",
    title: "Threat Hunting",
    note: "Поиск атакующего: методики, уровни зрелости, конкретные hunts и инфраструктурные сервисы.",
    aliases: ["hunting"],
  },
  {
    id: "network",
    title: "Сеть и сканирование",
    note: "Карта сети, поверхность атаки, сетевые утилиты и разбор трафика.",
    aliases: ["network"],
  },
  {
    id: "vuln",
    title: "Уязвимости и соответствие",
    note: "Сканеры уязвимостей, аудит конфигураций и бенчмарки.",
    aliases: ["vuln"],
  },
  {
    id: "monitoring",
    title: "Мониторинг и телеметрия",
    note: "Сбор и разбор событий: Sysmon, агенты, визуализация логов, Event ID.",
    aliases: ["monitoring"],
  },
  {
    id: "ttp",
    title: "Техники атакующих",
    note: "Справочники TTP, YARA, поведенческий анализ, закрепление в системе.",
    aliases: ["ttp"],
  },
  {
    id: "intel",
    title: "Threat Intelligence",
    note: "Агрегаторы, платформы обмена индикаторами, фиды правил.",
    aliases: ["intel"],
  },
  {
    id: "ir",
    title: "Incident Response",
    note: "Планы реагирования, чек-листы и сборники по IR.",
    aliases: ["ir", "tips"],
  },
  {
    id: "malware",
    title: "Малварь, реверс и фишинг",
    note: "Анализ образцов, дизассемблирование, песочницы, разбор писем.",
    aliases: ["malware"],
  },
  {
    id: "forensics",
    title: "Форензика",
    note: "Общие инструменты, память, Windows и Linux — всё для разбора хоста.",
    aliases: ["dfir", "memory", "windows", "linux", "recovery"],
  },
  {
    id: "training",
    title: "Обучение и сообщество",
    note: "Практические лаборатории, тренировки и где читать об угрозах.",
    aliases: ["training", "community"],
  },
];

/* Старые id разделов → новые, чтобы уже открытые ссылки с фильтрами продолжали работать. */
export const GROUP_ALIASES = Object.fromEntries(
  GROUPS.flatMap((group) => (group.aliases || []).map((alias) => [alias, group.id])),
);

export const FORMATS = [
  { id: "program", title: "Программа", note: "устанавливается и запускается" },
  { id: "online", title: "Онлайн-сервис", note: "работает в браузере" },
  { id: "dataset", title: "Набор данных", note: "файлы и образцы" },
  { id: "rules", title: "Правила и конфиги", note: "то, что внедряется в систему" },
  { id: "reference", title: "Справочник", note: "тексты и каталоги" },
];

export const PLATFORMS = ["Windows", "Linux", "macOS", "Docker", "Web"];

const T = (name, url, group, format, platforms, summary, extra = {}) => {
  const { idx, ...rest } = extra;
  const slug =
    idx ||
    name
      .toLowerCase()
      .replace(/ё/g, "e")
      .replace(/[^a-z0-9]+/g, "-")
      .replace(/^-|-$/g, "");
  return { id: slug, name, url, group, format, platforms, summary, ...rest };
};

/* Разделы из старых данных, которые теперь объединены в «Форензику». */
const FORENSICS_PARTS = new Set(["dfir", "memory", "windows", "linux", "recovery"]);

/* Материалы из присланного списка, которых ещё не было в базе. */
const EXTRA = [
  /* ------------------------------------------------------------ threat hunting */
  T("TaHiTI — Threat Hunting Methodology", "https://www.betaalvereniging.nl/wp-content/uploads/DEF-TaHiTI-Threat-Hunting-Methodology.pdf", "threat-hunting", "reference", ["Web"],
    "Методика targeted threat hunting от голландской Betaalvereniging.",
    {
      why: "Даёт порядок охоты: гипотезы, выбор источников, критерии успеха и как охоту встроить в процессы SOC, а не делать разово.",
      source: "huntlib", kind: "Reference",
    }),
  T("TaHiTI Framework", "https://www.betaalvereniging.nl/samenwerking/publiek-private-samenwerking/magma/", "threat-hunting", "reference", ["Web"],
    "Страница проекта с рамкой targeted threat hunting.",
    {
      why: "Контекст вокруг методики: как строится hunting во внутренних и внешних схемах сотрудничества, что считается результатом.",
      source: "huntlib", kind: "Reference",
    }),
  T("Cyber Hunting Maturity Model", "https://medium.com/@sqrrldata/the-cyber-hunting-maturity-model-6d506faa8ad5", "threat-hunting", "reference", ["Web"],
    "Модель зрелости охоты на угрозы (HMM): H0–H5.",
    {
      why: "Быстро понять, на каком этапе находится практика: если всё сводится к алертам, это H1, а не реальная охота.",
      source: "huntlib", kind: "Reference",
    }),
  T("Framework for Threat Hunting", "https://www.threathunting.net/files/framework-for-threat-hunting-whitepaper.pdf", "threat-hunting", "reference", ["Web"],
    "Белая книга с рамкой охоты на угрозы.",
    {
      why: "Описание модели «как вести охоту» с гипотезами из данных: удобно как опору для внутреннего регламента.",
      source: "huntlib", kind: "Reference",
    }),
  T("Hunt: Lateral Movement via Explicit Credentials", "https://github.com/ThreatHuntingProject/ThreatHunting/blob/master/hunts/lateral-movement-via-explicit-credentials.md", "threat-hunting", "reference", ["Windows"],
    "Готовый hunt по горизонтальному продвижению с явными учётными данными.",
    {
      why: "Готовые запросы и логика проверки: запуск процессов от другого пользователя, RunAs и кэшированные креды.",
      source: "huntlib", kind: "Reference",
    }),
  T("Hunt: Lateral Movement via Windows Authentication Logs", "https://github.com/ThreatHuntingProject/ThreatHunting/blob/master/hunts/lateral-movement-windows-authentication-logs.md", "threat-hunting", "reference", ["Windows"],
    "Hunt по журналам аутентификации Windows.",
    {
      why: "Связка 4624 по типу входа, 4625 и 4776: как отличить штатное администрирование от перебора и следования по сети.",
      source: "huntlib", kind: "Reference",
    }),
  T("Hunt: Lateral Movement via Process Monitoring", "https://github.com/ThreatHuntingProject/ThreatHunting/blob/master/hunts/lateral_movement_detection_via_process_monitoring.md", "threat-hunting", "reference", ["Windows"],
    "Hunt по событиям создания процессов.",
    {
      why: "Показывает, какие процессы и их родители характерны для удалённого запуска — от `psexec` до SMB-выполнения.",
      source: "huntlib", kind: "Reference",
    }),
  T("Threat Hunting in Large Datasets", "https://blog.talosintelligence.com/threat-hunting-in-large-datasets-by/", "threat-hunting", "reference", ["Web"],
    "Разбор Cisco Talos: охота по большим массивам данных.",
    {
      why: "Практика на серьёзных объёмах: как формулировать гипотезу, подбирать поля и не утонуть в событиях.",
      source: "vendor", kind: "Reference",
    }),
  T("Proactive Threat Hunting: Tools and Techniques", "https://www.stickmancyber.com/cybersecurity-blog/proactive-threat-hunting-tools-techniques", "threat-hunting", "reference", ["Web"],
    "Подборка приёмов и инструментов для проактивной охоты.",
    {
      why: "Быстрый обзор: чем искать, как технически провести охоту от индикатора к системе.",
      source: "vendor", kind: "Reference",
    }),
  T("Threat Hunting Tips and Tools", "https://www.guidepointsecurity.com/education-center/threat-hunting-tips-and-tools-2/", "threat-hunting", "reference", ["Web"],
    "Советы GuidePoint по проведению охоты и набору инструментов.",
    {
      why: "Практические рекомендации по планированию и инструментам — полезно при запуске регулярной охоты.",
      source: "vendor", kind: "Reference",
    }),
  T("Threat Hunting Techniques Checklist", "https://proinf.com/threat-hunting-techniques-checklist-examples-process-exection-metrics", "threat-hunting", "reference", ["Web"],
    "Чек-лист техник охоты с примерами и метриками процесса.",
    {
      why: "Готовый список техник и метрик: можно взять как шаблон отчёта об охоте для руководства.",
      source: "vendor", kind: "Reference",
    }),
  T("Effective Threat Hunting", "https://www.bluevoyant.com/knowledge-center/threat-hunting-how-it-works-and-4-tips-for-success", "threat-hunting", "reference", ["Web"],
    "Как устроена охота на угрозы и tips for success.",
    {
      why: "Введение для тех, кому предстоит объяснять пользу охоты: что такое hunting и чем он отличается от мониторинга.",
      source: "vendor", kind: "Reference",
    }),
  T("Who, What, Where, When, Why and How of Effective Threat Hunting", "https://www.sans.org/white-papers/who-what-where-when-why-how-effective-threat-hunting/", "threat-hunting", "reference", ["Web"],
    "SANS: шесть вопросов об эффективной охоте.",
    {
      why: "Даёт структуру: кто в команде, по каким данным, в каких временных рамках и с какой целью охотится.",
      source: "sans", kind: "Reference",
    }),

  /* ------------------------------------------------------------ network и vuln */
  T("TCPView", "https://learn.microsoft.com/en-us/sysinternals/downloads/tcpview", "network", "program", ["Windows"],
    "Сетевые соединения Windows с процессом-владельцем.",
    {
      why: "Показать, какой процесс держит соединение и куда оно идёт, — первый шаг при разборе подозрительного хоста.",
      source: "mine", kind: "Program",
    }),
  T("MITRE CAR — покрытие ATT&CK", "https://car.mitre.org/coverage/", "vuln", "reference", ["Web"],
    "Проект MITRE по маппингу аналитик на матрицу ATT&CK.",
    {
      why: "Показывает, какие аналитики покрывают какие техники — и где у вас в правилах зияют дыры.",
      source: "mine", kind: "Reference",
    }),
  T("Список «плохих» User Agent", "https://github.com/mitchellkrogza/nginx-ultimate-bad-bot-blocker/blob/master/_generator_lists/bad-useragents.list", "monitoring", "dataset", ["Web"],
    "Список User Agent подозрительных сканеров и ботов для nginx/traefik.",
    {
      why: "Фильтр на шлюзе и детект на NDR: находить сканеры и вредоносные UA в веб-логах и отличать их от нормального трафика.",
      note: "Подключается как список блокировки; регулярно обновляется автором.",
      source: "blue", kind: "Dataset",
    }),
  T("Density Scout", "https://cert.at/en/downloads/software/software-densityscout", "monitoring", "program", ["Windows", "Linux", "macOS"],
    "Оценка плотности файлов и по маске вычисляет, сколько копий фрагмента содержимого встречается в каталоге.",
    {
      why: "Утилита CERT.at для поиска уникальных бинарников и глубокого разбора каталогов: помогает находить аномально распространённые или крайне редкие коды.",
      source: "mine", kind: "Program",
    }),
  T("Полный набор Sysinternals", "https://learn.microsoft.com/en-us/sysinternals/", "monitoring", "program", ["Windows"],
    "Все утилиты Sysinternals в одном пакете.",
    {
      why: "TCPView, Sigcheck, Autoruns, Process Explorer — базовый набор для живого разбора Windows-хоста из одного места.",
      source: "mine", kind: "Program",
    }),
  T("Captian: детект инжектов и безфайловых атак", "https://github.com/y3n11/Captain", "monitoring", "program", ["Windows"],
    "Утилита для поиска инжекта в память и признаков fileless-атак.",
    {
      why: "Закрывает разрыв между ИБ-событиями и памятью: ищет подозрительные регионы, скомпрометированные потоки и несоответствия на хосте.",
      source: "mine", kind: "Program",
    }),

  /* --------------------------------------------------------------- monitoring */
  T("Notable Event IDs (TonyPhipps)", "https://github.com/TonyPhipps/SIEM/blob/master/Notable-Event-IDs.md", "monitoring", "reference", ["Windows"],
    "Справочник значимых Event ID Windows и Sysmon.",
    {
      why: "Быстро понять, что означает Event ID из лога, и что искать рядом с ним — полезно при написании правил и разборе.",
      source: "mine", kind: "Reference",
    }),
  T("Карта Event ID для охоты", "https://www.socinvestigation.com/most-common-windows-event-ids-to-hunt-mind-map/", "monitoring", "reference", ["Windows"],
    "Mind map самых частых Event ID Windows для hunting и расследования.",
    {
      why: "Визуальная карта событий по техникам: с чего начать разбор инцидента и какие события смотреть вместе.",
      source: "mine", kind: "Reference",
    }),
  T("Emerging Threats — набор правил Suricata", "https://rules.emergingthreats.net/open/suricata-5.0/emerging-all.rules", "monitoring", "rules", ["Linux"],
    "Открытый набор правил от Proofpoint Emerging Threats.",
    {
      why: "Базовые правила для Suricata: приёмник с которого разумно начинать. Многие ложные срабатывания при этом идут именно отсюда — правила нужно вычитывать под свою сеть.",
      source: "vendor", kind: "Rules",
    }),
  T("Security Compliance Toolkit", "https://www.microsoft.com/en-us/download/details.aspx?id=55319", "vuln", "rules", ["Windows"],
    "Базовые политики Microsoft Security Compliance Toolkit.",
    {
      why: "Эталонные настройки Windows Server и домена: с ними проверяют, что GPO не ослабили защиту — и как должна выглядеть норма.",
      source: "mine", kind: "Rules",
    }),
  T("CIS Benchmarks", "https://www.cisecurity.org/cis-benchmarks", "vuln", "dataset", ["Windows", "Linux", "macOS"],
    "Базовая эталонная конфигурация CIS для ОС и сервисов.",
    {
      why: "Проверять и приводить системы к эталону: отключение устаревших протоколов, разграничение прав, настройки аудита.",
      note: "Полный текст набора бесплатен только для некоммерческого использования после регистрации.",
      source: "mine", kind: "Dataset",
    }),
  T("Sigcheck", "https://learn.microsoft.com/en-us/sysinternals/downloads/sigcheck", "monitoring", "program", ["Windows"],
    "Проверка цифровых подписей файлов.",
    {
      why: "Быстро показать, что бинарник не подписан или подписан не тем — типичный признак подложенного файла рядом с легитимным.",
      source: "mine", kind: "Program",
    }),

  /* ---------------------------------------------------------------------- ttp */
  T("Как писать YARA-правила, часть 1", "https://www.nextron-systems.com/2015/02/16/write-simple-sound-yara-rules/", "ttp", "reference", ["Web"],
    "Nextron Systems: простые и надёжные YARA-правила.",
    {
      why: "Основы: какие строки выбирать, как избегать коротких и общих последовательностей, почему правило должно быть узким и проверяемым.",
      source: "vendor", kind: "Reference",
    }),
  T("Как писать YARA-правила, часть 2", "https://www.nextron-systems.com/2015/10/17/how-to-write-simple-but-sound-yara-rules-part-2/", "ttp", "reference", ["Web"],
    "Продолжение: условия, wildcard и работа с ложными срабатываниями.",
    {
      why: "Показывает, как формализовать логику в условии: точный подсчёт совпадений, ограничения по смещениям, уточнение через PE-модуль.",
      source: "vendor", kind: "Reference",
    }),
  T("Как писать YARA-правила, часть 3", "https://www.nextron-systems.com/2016/04/15/how-to-write-simple-but-sound-yara-rules-part-3/", "ttp", "reference", ["Web"],
    "Финальная часть: имена, метаданные и поддержка набора правил.",
    {
      why: "Правило живёт годами: теги, `meta`, версии, ложные срабатывания — та часть, из-за которой набор не превращается в кашу.",
      source: "vendor", kind: "Reference",
    }),
  T("Tool Analysis Result Sheet (JPCERT)", "https://jpcertcc.github.io/ToolAnalysisResultSheet/", "ttp", "reference", ["Windows"],
    "Поведенческий анализ утилит атакующих: какие события и артефакты они оставляют.",
    {
      why: "По каждой утилите — журналы, реестр и другие следы. Удобно проверять детект: «запустили mimikatz — а что мы должны были увидеть».",
      source: "vendor", kind: "Reference",
    }),

  /* -------------------------------------------------------------------- intel */
  T("Pulsedive", "https://pulsedive.com/", "intel", "online", ["Web"],
    "Бесплатная TI-платформа: обогащение и репутация индикаторов.",
    {
      why: "Быстро посмотреть репутацию домена, IP или хеша из инцидента и связанные индикаторы — без корпоративного контракта.",
      source: "mine", kind: "Online",
    }),
  T("Feedly", "https://feedly.com/", "intel", "online", ["Web"],
    "Агрегатор RSS-подписок по безопасности.",
    {
      why: "Один поток вместо браузера в шестнадцати вкладках: отчёты вендоров, разборы инцидентов, свежие IOC.",
      source: "mine", kind: "Online",
    }),
  T("cti_news.opml — список подписок", "https://github.com/QwertyBubble/cti_news/blob/main/cti_news.opml", "intel", "dataset", ["Web"],
    "Готовый файл подписок по ИБ для импорта в RSS-агрегатор.",
    {
      why: "Импортировать один файл вместо ручного поиска источников — и получить рабочий поток TI с нуля.",
      source: "mine", kind: "Dataset",
    }),
  T("abuse.ch MalwareBazaar", "https://bazaar.abuse.ch/", "intel", "dataset", ["Web"],
    "Хранилище образцов ВПО с метаданными.",
    {
      why: "Образцы и хеши для проверки YARA-правил и разбора семейств; в метаданных — то, чего нет в песочнице.",
      source: "mine", kind: "Dataset",
    }),
  T("Список выходных узлов TOR", "https://www.dan.me.uk/torlist/?exit", "intel", "dataset", ["Web"],
    "Обновляемый список выходных нод сети TOR.",
    {
      why: "Подсветить в логах подключения через TOR, которые не должны встречаться в рабочей сети.",
      note: "Список сгенерирован автоматически; вендор отмечает, что не гарантирует полноту.",
      source: "mine", kind: "Dataset",
    }),
  T("UUID Generator v4", "https://www.uuidgenerator.net/version4", "intel", "online", ["Web"],
    "Генератор UUID версии 4.",
    {
      why: "Ручная мелочь, которая всплывает при пересборке правил: сгенерировать GUID для описания объектов, интерфейсов и полей.",
      source: "mine", kind: "Online",
    }),

  /* ----------------------------------------------------------------------- ir */
  T("Чек-лист по шифровальщикам", "https://www.knowbe4.com/hubfs/RansomwareChecklist.pdf?hsLang=en", "ir", "reference", ["Web"],
    "Чек-лист подготовки и реагирования на ransomware от KnowBe4.",
    {
      why: "Пошаговый список действий до и во время шифрования: проверка резервных копий, изоляция, порядок восстановления.",
      idx: "ransomware-checklist", source: "vendor", kind: "Reference",
    }),
  T("NoMoreRansom — инструменты расшифровки", "https://www.nomoreransom.org/en/decryption-tools.html", "ir", "online", ["Web"],
    "Каталог бесплатных расшифровщиков от полиции и ИБ-вендоров.",
    {
      why: "Если шифрование уже произошло, это первое место, где стоит искать расшифровщик и антивирусную сигнатуру по семейству.",
      source: "mine", kind: "Online",
    }),
  T("SANS — Threat Hunting планы", "https://www.sans.org/white-papers/37172/", "ir", "reference", ["Web"],
    "SANS: как строить hunting-планы и связывать их с расследованием.",
    {
      why: "Связывает охоту с разбором: как продумать последовательность проверки, чтобы результаты ложились в отчёт.",
      source: "sans", kind: "Reference",
    }),
  T("SANS — Ценность аналитика для SOC", "https://www.sans.org/white-papers/39610/", "ir", "reference", ["Web"],
    "Вторая SANS-книга: роль аналитика и обоснование мер.",
    {
      why: "Озвучивает недостающую для L1–L2 часы: как описывать свою работу и результат аналитика в общедоступных терминах, без цифр и формата.",
      source: "sans", kind: "Reference",
    }),
  T("SANS — построение программы hunting", "https://www.sans.org/media/analyst-program/building-maturing-threat-hunting-program-39025.pdf", "ir", "reference", ["Web"],
    "SANS: как построить и развить программу threat hunting.",
    {
      why: "Честная опция для тех, кому нужно назвать делом не только логотипы продуктов: зрелость, метрики и модели.",
      source: "sans", kind: "Reference",
    }),

  /* ----------------------------------------------------------------- training */
  T("TryHackMe — Volatility Room", "https://tryhackme.com/room/bpvolatility", "training", "online", ["Web"],
    "Практическая комната по анализу памяти с Volatility.",
    {
      why: "От теории к дампу: реальные задачи на процессы, соединения и инжекты — быстрее, чем видео и повторение документации.",
      source: "mine", kind: "Online",
    }),
  T("TryHackMe — Forensics Room", "https://tryhackme.com/room/forensics", "training", "online", ["Web"],
    "Комната по основам форензики.",
    {
      why: "Основа, на которой потом держатся все остальные камеры — интерпретация журналов и порядок разбора.",
      source: "mine", kind: "Online",
    }),
  T("Root-Me — Forensic Challenges", "https://www.root-me.org/en/Challenges/Forensic/", "training", "online", ["Web"],
    "Задачи по форензике и восстановлению данных.",
    {
      why: "Бесплатные Challenge-задачи: интерпретировать журналы, извлечь данные, доказать вывод. Без спроса и сертификатов.",
      source: "mine", kind: "Online",
    }),
  T("CIRCL — обучающие материалы по форензике", "https://www.circl.lu/services/forensic-training-materials/", "training", "dataset", ["Web"],
    "Материалы и образы от CERT Luxembourg.",
    {
      why: "Готовые наборы для практики разбора: образы диска, памяти и трафика под упражнения.",
      source: "mine", kind: "Dataset",
    }),

  /* --------------------------------------------------------------------- tips */
  T("SpeedGuide — порты и сервисы", "https://www.speedguide.net/port.php?port=1000", "network", "reference", ["Web"],
    "Справочник по портам и использующим их сервисам.",
    {
      why: "Быстро ответить на вопрос «а что у нас на 1000 сидит» и какие ещё порты у этого сервиса, — при разборе соединений.",
      source: "mine", kind: "Reference",
    }),
  T("SANS — AppCompatCacheParser", "https://www.sans.org/tools/appcompatcacheparser/", "forensics", "program", ["Windows"],
    "Разбор ShimCache (AppCompatCache) — следы исполнения программ.",
    {
      why: "Дополняет Prefetch: показывает путь и время файла, который запускали или хотя бы трогали, даже если он уже удалён.",
      source: "sans", kind: "Program",
    }),
];


export const TOOLS = [
  /* ---------------------------------------------------------- threat hunting */  T("threathunt.app", "https://threathunt.app", "hunting", "online", ["Web"],
    "Набор инструментов для внутреннего и внешнего threat hunting.",
    {
      why: "Документировать охоту на угрозу: схемы узлов, одностраничные отчёты, граф OSINT-исследования и самооценка по модели зрелости HMM.",
      note: "Часть инструментов платная, есть 14-дневный триал без карты.",
      source: "blue", kind: "Online",
    }),
  T("hunt.io", "https://hunt.io", "hunting", "online", ["Web"],
    "Платформа для поиска C2-серверов и проактивной охоты по инфраструктуре.",
    {
      why: "Найти инфраструктуру атакующего по IOC из инцидента: домены, серверы, TLS, история DNS. Помогает связать одиночный индикатор с семейством активности.",
      note: "Платная, 14-дневный триал без данных карты.",
      source: "blue", kind: "Online",
    }),
  T("Validin", "https://www.validin.com/", "hunting", "online", ["Web"],
    "Агрегатор исторических DNS-данных, сертификатов и ответов хостов.",
    {
      why: "Пассивный DNS и pivot по сертификатам — классический способ раскрыть сеть атакующего, когда домены меняются, а инфраструктура остаётся.",
      note: "Бесплатно, но нужна корпоративная почта для верификации.",
      source: "blue", kind: "Online",
    }),

  /* --------------------------------------------------------- network scanning */
  T("Nmap", "https://nmap.org", "network", "program", ["Windows", "Linux", "macOS"],
    "Классический сканер сети: хосты, порты, сервисы и их версии.",
    {
      why: "Проверить, что из периметра реально видно снаружи, и сопоставить с тем, что должно быть. `-A` и NSE-скрипты дают контекст для проверки детектов на SMB и RPC.",
      source: "blue", kind: "Program",
    }),
  T("Nuclei", "https://nuclei.projectdiscovery.io/nuclei/get-started/", "network", "program", ["Linux", "Windows", "macOS"],
    "Сканер уязвимостей на шаблонах: быстрый прогон известных CVE и мисконфигураций.",
    {
      why: "Собрать список сервисов, уязвимых к известным CVE, и приоритизировать патчинг. Шаблоны можно писать под свои проверки.",
      source: "blue", kind: "Program",
    }),
  T("Masscan", "https://github.com/robertdavidgraham/masscan", "network", "program", ["Linux", "macOS"],
    "Максимально быстрый сканер портов на больших подсетях.",
    {
      why: "Когда нужно быстро понять картину по /16 — например, найти все открытые 445 и 3389 в сегменте.",
      note: "Резко нагружает сеть: согласуйте прогон и ставьте лимит скорости.",
      source: "blue", kind: "Program",
    }),
  T("Angry IP Scanner", "https://angryip.org/", "network", "program", ["Windows", "Linux", "macOS"],
    "Простой GUI-сканер диапазонов IP и портов.",
    {
      why: "Быстрый ping-sweep и инвентаризация хостов в лаборатории без изучения синтаксиса CLI.",
      source: "blue", kind: "Program",
    }),
  T("ZMap", "https://github.com/zmap/zmap", "network", "program", ["Linux"],
    "Сканер для анализа больших объёмов адресного пространства IPv4.",
    {
      why: "Исследование поверхности атаки на уровне интернета: сколько устройств с таким сервисом вообще существует.",
      source: "blue", kind: "Program",
    }),
  T("Shodan", "https://www.shodan.io/dashboard", "network", "online", ["Web"],
    "Поисковик устройств, подключённых к интернету.",
    {
      why: "Найти свои сервисы, случайно выставленные наружу, и изучить инфраструктуру по портам, баннерам и версиям ПО.",
      source: "blue", kind: "Online",
    }),

  /* ------------------------------------------------------------- vulnerabilities */
  T("OpenVAS", "https://openvas.org/", "vuln", "program", ["Linux", "Docker"],
    "Open-source сканер уязвимостей от Greenbone.",
    {
      why: "Бесплатная альтернатива коммерческим сканерам: регулярный прогон по сети даёт список уязвимостей для приоритизации.",
      source: "blue", kind: "Program",
    }),
  T("Nessus Essentials", "https://www.tenable.com/products/nessus/nessus-essentials", "vuln", "program", ["Windows", "Linux", "macOS"],
    "Сканер уязвимостей Tenable, бесплатная версия для личного использования.",
    {
      why: "Отчёт с приоритетами по CVSS и готовыми рекомендациями — удобно как второй независимый взгляд рядом с OpenVAS.",
      note: "Бесплатная версия предназначена только для личного использования.",
      source: "blue", kind: "Program",
    }),
  T("Nexpose", "https://www.rapid7.com/products/nexpose/", "vuln", "program", ["Windows", "Linux"],
    "Коммерческий vulnerability management от Rapid7 (сейчас InsightVM).",
    {
      why: "Непрерывное сканирование, обнаружение активов и приоритизация риска — когда нужен процесс, а не разовый скан.",
      note: "Требует коммерческой лицензии.",
      source: "blue", kind: "Program",
    }),
  T("HackerOne", "https://www.hackerone.com/", "vuln", "online", ["Web"],
    "Платформа управления программами bug bounty.",
    {
      why: "Внешняя оценка защищённости силами исследователей: задаёте scope и правила, получаете триаж отчётов.",
      source: "blue", kind: "Online",
    }),
  T("Lynis", "https://github.com/cisofy/lynis", "vuln", "program", ["Linux", "macOS"],
    "Аудит защищённости и hardening для Linux и UNIX.",
    {
      why: "Локальная проверка хоста: конфигурация, устаревшие пакеты, слабые настройки. Полезно перед тем, как считать сервер эталонным стендом.",
      source: "blue", kind: "Program",
    }),

  /* ---------------------------------------------------------------- monitoring */
  T("Sysmon", "https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon", "monitoring", "program", ["Windows"],
    "Системный монитор Windows: процессы, сеть, файлы, реестр — в журнал событий.",
    {
      why: "Базовый источник телеметрии для правил на хосте. Большая часть детектов Windows строится именно на Event ID Sysmon.",
      source: "blue", kind: "Program",
    }),
  T("Kibana", "https://www.elastic.co/kibana/", "monitoring", "program", ["Linux", "Docker", "Windows"],
    "Визуализация и поиск по логам Elasticsearch.",
    {
      why: "Проверять правила запросами, а не на глаз: собирать дашборды по событиям 4624/4662, смотреть аномалии и настраивать алерты.",
      source: "blue", kind: "Program",
    }),
  T("Logstash", "https://www.elastic.co/logstash/", "monitoring", "program", ["Linux", "Docker"],
    "Конвейер сбора и нормализации логов.",
    {
      why: "Привести разнородные логи к единой схеме до записи в хранилище: парсинг EVTX, auditd, Suricata — иначе корреляция не работает.",
      source: "blue", kind: "Program",
    }),
  T("parsedmarc", "https://github.com/domainaware/parsedmarc", "monitoring", "program", ["Linux"],
    "Разбор DMARC-отчётов в JSON/CSV и отправка в Elastic или Splunk.",
    {
      why: "Контроль подделок домена: видно, кто отправляет письма от вашего имени и проходят ли они DMARC.",
      source: "blue", kind: "Program",
    }),
  T("Phishing Catcher", "https://github.com/x0rz/phishing_catcher", "monitoring", "program", ["Linux", "macOS"],
    "Поиск фишинговых доменов по логам Certificate Transparency.",
    {
      why: "Находить фишинг раньше жертвы: подозрительные сертификаты на похожие домены появляются за дни до рассылки.",
      source: "blue", kind: "Program",
    }),
  T("maltrail", "https://github.com/stamparm/maltrail", "monitoring", "program", ["Linux"],
    "Детектор вредоносного трафика по публичным и своим спискам.",
    {
      why: "Ловит обращения к известным плохим доменам, IP, URL и User-Agent — быстрый способ увидеть исходящую активность заражённого хоста.",
      source: "blue", kind: "Program",
    }),
  T("AutorunsToWinEventLog", "https://github.com/palantir/windows-event-forwarding/tree/master/AutorunsToWinEventLog", "monitoring", "rules", ["Windows"],
    "Перенос данных Autoruns в журнал событий Windows.",
    {
      why: "Автозапуски — любимое место закрепления атакующего. Скрипт превращает список Autoruns в события, которые уже текут в SIEM через WEF.",
      source: "blue", kind: "Program",
    }),
  T("procfilter", "https://github.com/godaddy/procfilter", "monitoring", "program", ["Windows"],
    "Фильтрация процессов Windows с интеграцией YARA.",
    {
      why: "Точечные YARA-правила на конкретную угрозу с реакцией на совпадение. Не замена антивирусу, а профилактика в контролируемой среде.",
      source: "blue", kind: "Program",
    }),
  T("Velociraptor", "https://github.com/Velocidex/velociraptor", "monitoring", "program", ["Windows", "Linux", "macOS"],
    "Агент мониторинга и сбора данных с парка машин.",
    {
      why: "Один агент даёт охоту по артефактам и сбор по запросу: можно снять с подозрительного хоста процессы, автозапуски и сеть, не трогая его руками.",
      source: "blue", kind: "Program",
    }),
  T("SysmonSearch", "https://github.com/JPCERTCC/SysmonSearch", "monitoring", "program", ["Linux", "Docker"],
    "Плагин Kibana для анализа логов Sysmon.",
    {
      why: "Готовый разбор Sysmon: визуализация связей процессов и сети, статистика по Event ID и мониторинг по правилам — без ручной сборки дашбордов.",
      source: "blue", kind: "Program",
    }),
  T("Canary Tokens", "https://canarytokens.org/nest/", "monitoring", "online", ["Web"],
    "Ловушки-приманки в файлах, папках и сетевых устройствах.",
    {
      why: "Датчики движения в инфраструктуре: если кто-то открыл приманку в папке, куда не должен был заходить, — приходит уведомление.",
      source: "blue", kind: "Online",
    }),

  /* --------------------------------------------------------------------- тtp */
  T("LOLBAS", "https://lolbas-project.github.io/", "ttp", "reference", ["Windows", "Web"],
    "Каталог штатных бинарников Windows, которые используют атакующие.",
    {
      why: "Обратный поиск: если в логах встретился `certutil` с параметрами загрузки, здесь видно, как ещё он используется и на что смотреть.",
      source: "blue", kind: "Reference",
    }),
  T("GTFOBins", "https://gtfobins.github.io/", "ttp", "reference", ["Linux", "Web"],
    "Каталог Unix-бинарников для эскалации и обхода ограничений.",
    {
      why: "Linux-аналог LOLBAS: по имени бинарника видно, какие его опции дают shell, чтение файла или обход, и что искать в auditd.",
      source: "blue", kind: "Reference",
    }),
  T("filesec.io", "https://filesec.io/", "ttp", "reference", ["Web"],
    "Справочник расширений файлов, применяемых атакующими.",
    {
      why: "Разбор почты и вложений: что делает `.iso`, `.one`, `.ppam` и как ограничить их запуск на почтовом шлюзе и хостах.",
      source: "blue", kind: "Reference",
    }),
  T("KQL Search", "https://www.kqlsearch.com/", "ttp", "online", ["Web"],
    "Агрегатор KQL-запросов из GitHub.",
    {
      why: "Быстрый поиск готовых запросов для Azure Monitor, Microsoft Defender и Sentinel — вместо написания запроса с нуля.",
      source: "blue", kind: "Online",
    }),
  T("Unprotect Project", "https://unprotect.it/about/", "ttp", "reference", ["Web"],
    "База техник обхода средств защиты.",
    {
      why: "Понимание, как малварь обходит детект, — основа для правок правила: база подсказывает, какие техники стоит проверить у себя.",
      source: "blue", kind: "Reference",
    }),
  T("chainsaw", "https://github.com/WithSecureLabs/chainsaw", "ttp", "program", ["Windows", "Linux", "macOS"],
    "Быстрый поиск угроз по журналам Windows с поддержкой Sigma.",
    {
      why: "First response на выгрузке EVTX: прогнать Sigma-правила по журналам и получить найденные события, не поднимая SIEM.",
      source: "blue", kind: "Program",
    }),
  T("freq", "https://github.com/MarkBaggett/freq", "ttp", "program", ["Linux"],
    "Оценка случайности строк для поиска сгенерированных имён.",
    {
      why: "Атакующие рандомизируют имена доменов, служб и сертификатов. `freq` считает эту случайность и отдаёт результат в SIEM.",
      source: "blue", kind: "Program",
    }),
  T("yarGen", "https://github.com/Neo23x0/yarGen", "ttp", "program", ["Windows", "Linux"],
    "Генератор YARA-правил по содержимому образцов.",
    {
      why: "Создать правило по семейству образцов, автоматически отбросив строки, которые встречаются в чистых файлах.",
      source: "blue", kind: "Program",
    }),
  T("EmailAnalyzer", "https://github.com/keraattin/EmailAnalyzer", "ttp", "program", ["Linux", "Windows"],
    "Разбор подозрительных писем `.eml`: заголовки, ссылки, вложения, хеши.",
    {
      why: "Фишинг-инцидент начинается с письма: нужно быстро достать заголовки доставки, ссылки и хеши вложений для проверки.",
      source: "blue", kind: "Program",
    }),
  T("VCG", "https://github.com/nccgroup/VCG", "ttp", "program", ["Windows"],
    "Автоматический обзор безопасности кода (C/C++, Java, C#, VB, PL/SQL).",
    {
      why: "Проверить код собственных правил и парсеров на опасные функции, проверить целевую систему перед вводом в эксплуатацию.",
      source: "blue", kind: "Program",
    }),
  T("CyberChef", "https://gchq.github.io/CyberChef/", "ttp", "online", ["Web"],
    "Онлайн-инструмент преобразования данных от GCHQ.",
    {
      why: "Раскодировать base64 на два слоя, вытащить строки из бинарника, снять null-байты после декодирования — всё в браузере и с сохранёнными рецептами.",
      source: "blue", kind: "Online",
    }),
  T("PersistenceSniper", "https://github.com/last-byte/PersistenceSniper", "ttp", "program", ["Windows"],
    "PowerShell-модуль поиска точек закрепления на Windows.",
    {
      why: "При разборе инцидента быстро ответить на вопрос «как они закрепятся снова»: проверяются десятки методов persistence.",
      source: "blue", kind: "Program",
    }),

  /* ------------------------------------------------------------------- intel */
  T("Maltego", "https://www.maltego.com/solutions/cyber-threat-intelligence/", "intel", "program", ["Windows", "Linux", "macOS"],
    "Платформа визуального анализа связей в threat intelligence.",
    {
      why: "Разложить инфраструктуру атаки графом: домены, IP, сертификаты, лица и связи между ними, которые не видны в таблице.",
      note: "Коммерческий продукт с бесплатным режимом ограниченной функциональности.",
      source: "blue", kind: "Program",
    }),
  T("MISP", "https://www.misp-project.org/", "intel", "program", ["Linux", "Docker"],
    "Open-source платформа обмена индикаторами компрометации.",
    {
      why: "Своё хранилище IOC с корреляцией и таксономией: индикаторы из инцидентов не теряются и подключаются к SIEM по API.",
      source: "blue", kind: "Program",
    }),
  T("ThreatConnect", "https://threatconnect.com/threat-intelligence-platform/", "intel", "online", ["Web"],
    "Коммерческая платформа агрегации и анализа threat intelligence.",
    {
      why: "Единое окно по всем источникам TI с отчётами и приоритизацией — когда источников много и их нужно сводить вручную.",
      note: "Платная.",
      source: "blue", kind: "Online",
    }),
  T("Adversary Emulation Library", "https://github.com/center-for-threat-informed-defense/adversary_emulation_library", "intel", "dataset", ["Windows", "Linux"],
    "Библиотека планов эмуляции реальных атакующих групп.",
    {
      why: "Проверка защит не на абстрактных техниках, а на конкретной группе: план повторяет её TTP, а вы смотрите, что из этого поймали.",
      source: "blue", kind: "Dataset",
    }),

  /* ---------------------------------------------------------------------- ir */
  T("NIST CSF", "https://www.nist.gov/cyberframework", "ir", "reference", ["Web"],
    "NIST Cybersecurity Framework: Identify, Protect, Detect, Respond, Recover.",
    {
      why: "Общая рамка, по которой удобно объяснять зрелость SOC и место своих детектов в общей картине.",
      source: "blue", kind: "Reference",
    }),
  T("Incident Response Plan", "https://www.ncsc.gov.uk/collection/incident-management/incident-response", "ir", "reference", ["Web"],
    "Материалы для составления плана реагирования на инциденты.",
    {
      why: "Шаблоны и рамочные документы: NCSC, SANS, CISA — из них собирается свой регламент, если его ещё нет.",
      source: "blue", kind: "Reference",
    }),
  T("Ransomware Response Plan", "https://www.cisa.gov/stopransomware/ransomware-guide", "ir", "reference", ["Web"],
    "Материалы по подготовке и реагированию на шифровальщики.",
    {
      why: "Отдельный класс инцидентов со своими сроками и правилами: гасить шифрование, изолировать, восстанавливать из бэкапа.",
      source: "blue", kind: "Reference",
    }),
  T("Incident Response Reference Guide", "https://info.microsoft.com/rs/157-GQE-382/images/EN-US-CNTNT-emergency-doc-digital.pdf", "ir", "reference", ["Web"],
    "«Первая помощь» Microsoft по крупному инциденту.",
    {
      why: "Технические, операционные, юридические и коммуникационные аспекты в одном документе. Главное: подготовка окупается, координация критична, не переусердствовать с реакцией.",
      source: "blue", kind: "Reference",
    }),
  T("Awesome Incident Response", "https://github.com/meirwah/awesome-incident-response", "ir", "reference", ["Web"],
    "Подборка инструментов и материалов для IR и DFIR.",
    {
      why: "Оглавление по всем направлениям реагирования: эмуляция, сбор образов, all-in-one наборы, книги и сообщества.",
      source: "blue", kind: "Reference",
    }),
  T("Linux Incident Response", "https://github.com/vm32/Linux-Incident-Response", "ir", "program", ["Linux"],
    "Шпаргалка по реагированию на Linux: команды для сбора живых данных и готовый скрипт.",
    {
      why: "Первый ответ на Linux-хосте: за одну серию команд собрать учётные записи, журналы, процессы, службы, файлы и сеть. Скрипт делает это автоматически и складывает отчёт.",
      note: "`chmod +x IRLinux_Script.sh && sudo ./IRLinux_Script.sh` — результат в `/tmp/IRLinux.txt`.",
      idx: "linux-ir-first-response", source: "linuxir", kind: "Program",
    }),

  /* ------------------------------------------------------------------ malware */
  T("VirusTotal", "https://www.virustotal.com/gui/home/search", "malware", "online", ["Web"],
    "Многоантивирусная проверка файлов, URL и хешей.",
    {
      why: "Проверка IOC из инцидента и поиск по смежным образцам. Продвинутые запросы находят свежие макросные документы ещё до рассылки.",
      source: "blue", kind: "Online",
    }),
  T("IDA", "https://hex-rays.com/ida-free/", "malware", "program", ["Windows", "Linux", "macOS"],
    "Дизассемблер и отладчик для анализа бинарников.",
    {
      why: "Когда нужно понять логику образца: IDA Free покрывает базовый статический разбор, IDAPython позволяет автоматизировать рутину.",
      note: "Полная версия платная, бесплатная — с ограничениями.",
      source: "blue", kind: "Program",
    }),
  T("Ghidra", "https://ghidra-sre.org/", "malware", "program", ["Windows", "Linux", "macOS"],
    "Бесплатный реверс-инжиниринговый инструмент с декомпилятором.",
    {
      why: "Открытый аналог IDA от NSA: декомпиляция в C-подобный код, графы и отладка. Полностью бесплатен.",
      source: "blue", kind: "Program",
    }),
  T("decode-vbe", "https://github.com/DidierStevens/DidierStevensSuite/blob/master/decode-vbe.py", "malware", "program", ["Windows", "Linux", "macOS"],
    "Декодер VBE-скриптов, скрытых Microsoft Script Encoding.",
    {
      why: "Атакующие кодируют VBScript, чтобы спрятать код и строки. Скрипт возвращает читаемый текст за один запуск.",
      source: "blue", kind: "Program",
    }),
  T("pafish", "https://github.com/a0rtega/pafish", "malware", "program", ["Windows"],
    "Проверка, как малварь распознаёт виртуальную машину и песочницу.",
    {
      why: "Оценить качество анализа стенда: если pafish видит виртуалку, малварь тоже её увидит и не раскроет поведение.",
      source: "blue", kind: "Program",
    }),
  T("Lookyloo", "https://github.com/Lookyloo/lookyloo", "malware", "program", ["Linux", "Docker"],
    "Захват веб-страницы и дерево доменов, к которым она обращается.",
    {
      why: "Фишинг-URL ведёт на цепочку редиректов и сторонние домены. Lookyloo строит карту этого пути для блокировки.",
      source: "blue", kind: "Program",
    }),
  T("YARA", "https://github.com/virustotal/yara", "malware", "program", ["Windows", "Linux", "macOS"],
    "Поиск малвари по текстовым и бинарным шаблонам.",
    {
      why: "Универсальный язык описания образцов: правило YARA работает и в сканере файлов, и в Velociraptor, и в procfilter.",
      source: "blue", kind: "Program",
    }),
  T("Cuckoo Sandbox", "https://cuckoosandbox.org/", "malware", "program", ["Linux", "macOS"],
    "Автоматическая песочница анализа малвари.",
    {
      why: "Запустить образец в изоляции и получить вызовы API, созданные файлы, дамп памяти, PCAP и скриншоты — готовый материал для правил.",
      note: "Проект давно не развивается: для новых задач смотрите CAPE.",
      source: "blue", kind: "Program",
    }),
  T("radare2", "https://github.com/radareorg/radare2", "malware", "program", ["Windows", "Linux", "macOS"],
    "Фреймворк реверса с CLI, скриптами и широкой поддержкой архитектур.",
    {
      why: "Быстрый разбор по строкам и функциям прямо в терминале: `afl`, `pdf`, графы — без графического интерфейса.",
      source: "blue", kind: "Program",
    }),
  T("dnSpy", "https://github.com/dnSpy/dnSpy", "malware", "program", ["Windows"],
    "Отладчик и редактор .NET-сборок.",
    {
      why: ".NET-малварь частая, и .NET легко читается: dnSpy показывает код сборки и позволяет отладить её.",
      note: "Проект заморожен: активно развивается dnSpyEx.",
      source: "blue", kind: "Program",
    }),
  T("malware-traffic-analysis.net", "https://www.malware-traffic-analysis.net/", "malware", "dataset", ["Web"],
    "Блог с разборами вредоносного трафика и образцами PCAP.",
    {
      why: "Упражнения на реальном трафике: почти в каждом посте есть pcap — идеально для проверки Suricata-правил и практики разбора.",
      source: "blue", kind: "Dataset",
    }),

  /* ---------------------------------------------------------------------- dfir */
  T("DFIR Toolkit", "https://codeberg.org/dfir-dd/dfir-toolkit", "dfir", "program", ["Windows", "Linux", "macOS"],
    "Набор утилит командной строки на Rust для построения таймлайнов.",
    {
      why: "Сводит журналы, реестр, Prefetch, ярлыки и архивы в единый формат bodyfile: `evtx2bodyfile`, `pf2bodyfile`, `lnk2bodyfile`, `zip2bodyfile` — и один общий таймлайн через `mactime2`. Для разбора «что происходило в эти минуты» это самый быстрый путь.",
      note: "Установка: `cargo install dfir-toolkit`. Репозиторий переехал с GitHub на Codeberg.",
      source: "dfirtk", kind: "Program",
    }),
  T("mactime2", "https://codeberg.org/dfir-dd/dfir-toolkit", "dfir", "program", ["Windows", "Linux", "macOS"],
    "Сборка таймлайна из bodyfile с настраиваемым форматом времени.",
    {
      why: "Финальный шаг разбора: собрать все извлечённые артефакты в один CSV, отсортированный по времени, и найти пересечения активности.",
      note: "Формат: `mactime2 -b sample.bodyfile -d`; формат даты задаётся переменной `DFIR_DATE`.",
      source: "dfirtk", kind: "Program",
    }),
  T("evtx2bodyfile", "https://codeberg.org/dfir-dd/dfir-toolkit", "dfir", "program", ["Windows", "Linux", "macOS"],
    "Преобразование EVTX-журналов в bodyfile для таймлайна.",
    {
      why: "Журналы Windows встают в общий таймлайн рядом с файлами и реестром — видно порядок событий, а не отдельные журналы.",
      source: "dfirtk", kind: "Program",
    }),
  T("pf2bodyfile", "https://codeberg.org/dfir-dd/dfir-toolkit", "dfir", "program", ["Windows", "Linux", "macOS"],
    "Преобразование Prefetch в bodyfile.",
    {
      why: "Запуски программ попадают в общий таймлайн с журналами и файлами — без ручного сведения таблиц.",
      source: "dfirtk", kind: "Program",
    }),
  T("lnk2bodyfile", "https://codeberg.org/dfir-dd/dfir-toolkit", "dfir", "program", ["Windows", "Linux", "macOS"],
    "Преобразование ярлыков `.lnk` в bodyfile.",
    {
      why: "Открытые пользователем файлы и сетевые ресурсы становятся частью единой хронологии.",
      source: "dfirtk", kind: "Program",
    }),
  T("zip2bodyfile", "https://codeberg.org/dfir-dd/dfir-toolkit", "dfir", "program", ["Windows", "Linux", "macOS"],
    "Преобразование содержимого ZIP в bodyfile.",
    {
      why: "Архивы и их содержимое встают в таймлайн: видно, что было упаковано и когда.",
      source: "dfirtk", kind: "Program",
    }),
  T("evtxanalyze", "https://codeberg.org/dfir-dd/dfir-toolkit", "dfir", "program", ["Windows", "Linux", "macOS"],
    "Поиск аномалий в журналах EVTX.",
    {
      why: "Быстро найти необычные Event ID и редкие сочетания полей, не проходя журнал вручную.",
      source: "dfirtk", kind: "Program",
    }),
  T("evtxscan", "https://codeberg.org/dfir-dd/dfir-toolkit", "dfir", "program", ["Windows", "Linux", "macOS"],
    "Сканирование EVTX-файлов с подсчётом событий.",
    {
      why: "Понять состав журнала до разбора: какие события есть, каких много, что встречается редко.",
      source: "dfirtk", kind: "Program",
    }),
  T("evtxcat", "https://codeberg.org/dfir-dd/dfir-toolkit", "dfir", "program", ["Windows", "Linux", "macOS"],
    "Вывод событий EVTX в текстовом или JSON виде.",
    {
      why: "Прокрутить журнал в консоли или отдать в другой инструмент, не поднимая просмотрщик.",
      source: "dfirtk", kind: "Program",
    }),
  T("evtxls", "https://codeberg.org/dfir-dd/dfir-toolkit", "dfir", "program", ["Windows", "Linux", "macOS"],
    "Список журналов и каналов внутри EVTX.",
    {
      why: "Понять, какие каналы лежат в выгрузке, прежде чем выбирать, что разбирать.",
      source: "dfirtk", kind: "Program",
    }),
  T("regdump", "https://codeberg.org/dfir-dd/dfir-toolkit", "dfir", "program", ["Windows", "Linux", "macOS"],
    "Дамп содержимого кустов реестра в читаемом виде.",
    {
      why: "Реестр в текстовом виде удобно грепать и сравнивать между снимками системы.",
      source: "dfirtk", kind: "Program",
    }),
  T("hivescan", "https://codeberg.org/dfir-dd/dfir-toolkit", "dfir", "program", ["Windows", "Linux", "macOS"],
    "Поиск кустов реестра в образе или памяти.",
    {
      why: "Найти hive без заранее известного пути — например, в дампе или неразмеченной области.",
      source: "dfirtk", kind: "Program",
    }),
  T("pol_export", "https://codeberg.org/dfir-dd/dfir-toolkit", "dfir", "program", ["Windows", "Linux", "macOS"],
    "Экспорт групповых политик (POL) в читаемый формат.",
    {
      why: "Понять, какие политики включены на хосте и не ослабили ли они защиту — например, отключили UAC или аудит.",
      source: "dfirtk", kind: "Program",
    }),
  T("es4forensics", "https://codeberg.org/dfir-dd/dfir-toolkit", "dfir", "program", ["Windows", "Linux", "macOS"],
    "Загрузка артефактов в Elasticsearch для поиска.",
    {
      why: "Собранные артефакты инцидента заводятся в Elastic и исследуются через Kibana, а не в текстовом редакторе.",
      source: "dfirtk", kind: "Program",
    }),
  T("ipgrep", "https://codeberg.org/dfir-dd/dfir-toolkit", "dfir", "program", ["Windows", "Linux", "macOS"],
    "Поиск IP-адресов по файлам и артефактам.",
    {
      why: "Быстро найти, к каким адресам обращался хост, по логам, конфигам и дампам.",
      source: "dfirtk", kind: "Program",
    }),
  T("ts2date", "https://codeberg.org/dfir-dd/dfir-toolkit", "dfir", "program", ["Windows", "Linux", "macOS"],
    "Преобразование сырых временных меток в дату и время.",
    {
      why: "Win32 FILETIME, Unix time и другие форматы — в нормальную дату, чтобы время в разных артефактах можно было сравнивать.",
      source: "dfirtk", kind: "Program",
    }),
  T("cleanhive", "https://codeberg.org/dfir-dd/dfir-toolkit", "dfir", "program", ["Windows", "Linux", "macOS"],
    "Чистка куста реестра перед анализом.",
    {
      why: "Привести hive в состояние, с которым работают остальные утилиты: убрать служебный мусор и сделать файл предсказуемым.",
      source: "dfirtk", kind: "Program",
    }),

  /* ------------------------------------------------------------ форензика памяти */
  T("Volatility 3", "https://github.com/volatilityfoundation/volatility3", "memory", "program", ["Windows", "Linux", "macOS"],
    "Современная ветка Volatility для анализа дампов памяти.",
    {
      why: "Основной инструмент разбора RAM: процессы, соединения, внедрённый код, модули, история. Для Windows 10/11 и современных Linux профили собираются автоматически.",
      note: "Для старых образцов остаётся Volatility 2, но ветка 2.x заархивирована.",
      source: "memory", kind: "Program",
    }),
  T("Volatility 2", "https://github.com/volatilityfoundation/volatility", "memory", "program", ["Windows", "Linux", "macOS"],
    "Классическая ветка Volatility с профилями под старые ОС.",
    {
      why: "Нужна, когда дамп снят со старой системы: Windows XP–2008 R2, Linux до 5.5, macOS до Catalina. Плагины `malfind`, `netscan`, `handles` до сих пор полезны.",
      note: "Проект заморожен, для новых задач — Volatility 3.",
      source: "blue", kind: "Program",
    }),
  T("MemProcFS", "https://github.com/ufrisk/MemProcFS", "memory", "program", ["Windows", "Linux"],
    "Дамп памяти, смонтированный как файловая система.",
    {
      why: "К дампу можно обращаться обычными командами: `cat`, `grep`, `ls` по процессам, драйверам и сетевым соединениям — без изучения плагинов.",
      source: "memory", kind: "Program",
    }),
  T("WinDbg", "https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/debugger-download-tools", "memory", "program", ["Windows"],
    "Отладчик Microsoft для ядра и пользовательских процессов.",
    {
      why: "Разбор дампов ядра и подозрительных драйверов, проверка структур памяти, `!analyse -v` по краш-дампу.",
      source: "memory", kind: "Program",
    }),
  T("Volcano", "https://www.volexity.com/products-overview/volcano", "memory", "program", ["Windows"],
    "Коммерческий анализатор памяти от Volexity.",
    {
      why: "Автоматическая корреляция артефактов памяти: инжекты, скрытые процессы, подозрительные драйверы — с интерфейсом вместо консоли.",
      note: "Платная, есть бесплатная версия Volcano.",
      source: "memory", kind: "Program",
    }),
  T("Surge", "https://www.volexity.com/products-overview/surge/", "memory", "program", ["Windows"],
    "Сборщик памяти от Volexity.",
    {
      why: "Снять память, не уронив систему: ориентирован на устойчивый сбор и понятность для дежурного, а не только для эксперта.",
      note: "Коммерческий.",
      source: "memory", kind: "Program",
    }),
  T("MAGNET RAM Capture", "https://www.magnetforensics.com/resources/magnet-ram-capture/", "memory", "program", ["Windows"],
    "Бесплатный сборщик физической памяти.",
    {
      why: "Быстрый дамп RAM с подозрительной машины без установки тяжёлого ПО.",
      source: "memory", kind: "Program",
    }),
  T("FTK Imager", "https://www.exterro.com/digital-forensics-software/ftk-imager", "memory", "program", ["Windows"],
    "Предварительный просмотр и снятие образов.",
    {
      why: "Кроме образов диска снимает память и умеет открывать дампы для быстрой проверки: подходит как универсальный первый инструмент.",
      source: "memory", kind: "Program",
    }),
  T("Ram Capturer", "https://belkasoft.com/ram-capturer", "memory", "program", ["Windows"],
    "Небольшой бесплатный сборщик RAM от Belkasoft.",
    {
      why: "Простейший дамп всей памяти, в том числе при активной анти-отладке и анти-дампе.",
      source: "memory", kind: "Program",
    }),
  T("FEX Memory Imager", "https://getdataforensics.com/product/fex-memory-imager/", "memory", "program", ["Windows"],
    "Бесплатный сборщик физической памяти.",
    {
      why: "Альтернатива WinPmem и Ram Capturer, когда нужен ещё один способ снять память на проблемной машине.",
      source: "memory", kind: "Program",
    }),
  T("LiME", "https://github.com/504ensicsLabs/LiME", "memory", "program", ["Linux"],
    "Ядровый модуль для снятия памяти на Linux и Android.",
    {
      why: "Основной способ снять RAM с Linux-хоста: дамп в файл или по сети.",
      note: "Давно не развивается: для новых задач — AVML.",
      source: "memory", kind: "Program",
    }),
  T("AVML", "https://github.com/microsoft/avml", "memory", "program", ["Linux"],
    "Сборщик памяти на Rust — статический бинарник для Linux.",
    {
      why: "Один файл на любой Linux-машине: не нужен модуль ядра и компилятор, удобно для контейнеров и облака.",
      source: "memory", kind: "Program",
    }),
  T("fmem", "https://github.com/NateBrune/fmem", "memory", "program", ["Linux"],
    "Создаёт устройство `/dev/fmem` для чтения памяти без лимитов `/dev/mem`.",
    {
      why: "Когда `/dev/mem` не даёт прочитать нужные области — klassический приём для снятия полной памяти.",
      source: "memory", kind: "Program",
    }),
  T("Digital Collector", "https://cellebrite.com/en/digital-collector/", "memory", "program", ["Windows", "macOS"],
    "Коммерческий сбор данных и образов.",
    {
      why: "Триаж и целевой сбор данных на Windows и macOS с минимальным вмешательством в систему.",
      note: "Платная.",
      source: "memory", kind: "Program",
    }),
  T("varc", "https://github.com/cado-security/varc", "memory", "program", ["Windows", "Linux", "macOS"],
    "Volatile Artifact Collector: снимок летучих артефактов.",
    {
      why: "Одним запуском собрать то, что исчезнет при перезагрузке: процессы, соединения, модули.",
      source: "memory", kind: "Program",
    }),
  T("PCILeech", "https://github.com/ufrisk/pcileech", "memory", "program", ["Windows", "Linux"],
    "Чтение и запись памяти через DMA по PCIe.",
    {
      why: "Когда нельзя ставить драйверы на исследуемую систему: чтение памяти напрямую через hardware-устройство.",
      note: "Требует аппаратного модуля.",
      source: "memory", kind: "Program",
    }),
  T("EVTXtract", "https://github.com/williballenthin/EVTXtract", "memory", "program", ["Windows", "Linux", "macOS"],
    "Восстановление фрагментов EVTX из сырых данных.",
    {
      why: "Если журналы повреждены или удалены, их куски всё ещё могут лежать в неразмеченной области или в памяти.",
      source: "memory", kind: "Program",
    }),
  T("Volatility3 Inodes Plugin", "https://github.com/forensicxlab/volatility3_plugins/blob/main/inodes.py", "memory", "program", ["Linux"],
    "Плагин Volatility 3: метаданные inode по процессу.",
    {
      why: "Для Linux: `lsof` не всегда доступен, а плагин показывает, какие файлы (по inode) держит каждый процесс. Часто расширяется для поиска выгруженных журналов.",
      source: "memory", kind: "Program",
    }),
  T("Volatility3 Prefetch Plugin", "https://github.com/forensicxlab/volatility3_plugins/blob/main/prefetch.py", "memory", "program", ["Windows"],
    "Плагин Volatility 3: извлечение Prefetch из памяти.",
    {
      why: "Вытащить Prefetch, не имея образа диска: доказательства запуска программ остаются в памяти.",
      source: "memory", kind: "Program",
    }),
  T("WinPmem", "https://github.com/Velocidex/WinPmem", "memory", "program", ["Windows"],
    "Сборщик дампа физической памяти Windows.",
    {
      why: "Три независимых метода чтения — шанс снять память даже при kernel-руткитах.",
      note: "Для Linux есть Linpmem. Подписанные драйверы не поддерживают запись в память.",
      source: "mine", kind: "Program",
    }),

  /* ------------------------------------------------------------ форензика Linux */
  T("Linux Incident Response", "https://github.com/vm32/Linux-Incident-Response", "linux", "program", ["Linux"],
    "Чек-лист и скрипт для сбора живых данных на Linux.",
    {
      why: "Готовый порядок действий на подозрительном сервере: учётные записи, журналы, ресурсы, процессы, службы, файлы, сеть — в одном отчёте `/tmp/IRLinux.txt`.",
      idx: "linux-ir-gatherer", source: "linuxir", kind: "Program",
    }),
  T("AVML", "https://github.com/microsoft/avml", "linux", "program", ["Linux"],
    "Статический сборщик памяти для Linux.",
    {
      why: "Снять RAM с минимальными требованиями: не нужен модуль ядра и компилятор на хосте.",
      idx: "avml-linux", source: "memory", kind: "Program",
    }),
  T("LiME", "https://github.com/504ensicsLabs/LiME", "linux", "program", ["Linux"],
    "Модуль ядра для снятия памяти на Linux.",
    {
      why: "Классический способ снять полный дамп RAM на Linux-хосте, когда можно загрузить модуль.",
      idx: "lime-linux", source: "memory", kind: "Program",
    }),
  T("Volatility 3 (Linux)", "https://github.com/volatilityfoundation/volatility3", "linux", "program", ["Linux"],
    "Разбор дампа памяти Linux.",
    {
      why: "Плагины `linux_pslist`, `linux_bash`, `linux_malfind`, `linux_check_*` показывают скрытые процессы, модифицированные syscall-таблицы и утечки.",
      idx: "volatility3-linux", source: "memory", kind: "Program",
    }),
  T("dwarf2json", "https://github.com/volatilityfoundation/dwarf2json", "linux", "program", ["Linux"],
    "Генерация символов Volatility 3 из DWARF.",
    {
      why: "Для сборки символов под конкретное ядро Linux, если готового профиля нет.",
      source: "memory", kind: "Program",
    }),
  T("MemProcFS (Linux)", "https://github.com/ufrisk/MemProcFS", "linux", "program", ["Windows", "Linux"],
    "Дамп памяти как файловая система — работает и с Linux-дампами.",
    {
      why: "Просмотр памяти обычными командами без плагинов: удобно при беглом разборе и для скриптов.",
      idx: "memprocfs-linux", source: "memory", kind: "Program",
    }),
  T("Volatility3 Inodes Plugin", "https://github.com/forensicxlab/volatility3_plugins/blob/main/inodes.py", "linux", "program", ["Linux"],
    "Плагин Volatility 3: inode-метаданные по процессам.",
    {
      why: "Показать, какие файлы держат процессы, даже если `/proc` уже потерян.",
      idx: "inodes-linux", source: "memory", kind: "Program",
    }),
  T("Neo23x0 auditd", "https://github.com/Neo23x0/auditd", "linux", "rules", ["Linux"],
    "Best-practice конфигурация auditd для Linux.",
    {
      why: "Основа Linux-детекции: ядро и модули, PAM и sudo, cron, сеть, `ptrace`, `bpf`, `memfd_create`. Есть блок `af_alg` под Copy Fail.",
      source: "mine", kind: "Rules",
    }),

  /* ---------------------------------------------------------- форензика Windows */
  T("EvtxECmd", "https://download.ericzimmermanstools.com/net9/EvtxECmd.zip", "windows", "program", ["Windows"],
    "Разбор журналов EVTX в CSV, XML и JSON.",
    {
      why: "Главный конвертер для DFIR: быстро превращает набор EVTX в таблицу, где ищут по времени, Event ID и полям. Поддерживает карты (maps) и работает с занятыми файлами.",
      source: "zimmerman", kind: "Program",
    }),
  T("MFTECmd", "https://download.ericzimmermanstools.com/net9/MFTECmd.zip", "windows", "program", ["Windows"],
    "Разбор $MFT, $Boot, $J, $SDS, $I30 и $LogFile.",
    {
      why: "Показать, какие файлы появлялись, удалялись и переименовывались на диске — то, что журналы событий уже не помнят.",
      source: "zimmerman", kind: "Program",
    }),
  T("PECmd", "https://download.ericzimmermanstools.com/net9/PECmd.zip", "windows", "program", ["Windows"],
    "Разбор Prefetch: какие программы запускались и когда.",
    {
      why: "Доказательство запуска инструментов атакующего на хосте с точностью до секунды и с путём к исполняемому файлу.",
      source: "zimmerman", kind: "Program",
    }),
  T("AmcacheParser", "https://download.ericzimmermanstools.com/net9/AmcacheParser.zip", "windows", "program", ["Windows"],
    "Разбор Amcache.hve.",
    {
      why: "Следы исполняемых файлов, которых уже нет на диске: хеши, версии, время первого появления.",
      source: "zimmerman", kind: "Program",
    }),
  T("AppCompatCacheParser", "https://download.ericzimmermanstools.com/net9/AppCompatCacheParser.zip", "windows", "program", ["Windows"],
    "Разбор ShimCache — следы исполнения программ.",
    {
      why: "Дополняет Prefetch для программ, запущенных необычным путём: ShimCache помнит путь и время последнего изменения файла.",
      source: "zimmerman", kind: "Program",
    }),
  T("RECmd", "https://download.ericzimmermanstools.com/net9/RECmd.zip", "windows", "program", ["Windows"],
    "Командный разбор реестра с плугинами и batch-файлами.",
    {
      why: "Вытащить из реестра конкретные следы: USB, автозапуски, UserAssist, RDP — по готовым batch-профилям, а не вручную.",
      source: "zimmerman", kind: "Program",
    }),
  T("Registry Explorer", "https://download.ericzimmermanstools.com/net9/RegistryExplorer.zip", "windows", "program", ["Windows"],
    "Графический просмотрщик реестра с поиском и плугинами.",
    {
      why: "Читать hive так, как его видит система: с живыми ключами, поиском и обработкой занятых файлов при разборе инцидента.",
      source: "zimmerman", kind: "Program",
    }),
  T("RLA", "https://download.ericzimmermanstools.com/net9/rla.zip", "windows", "program", ["Windows"],
    "Воспроизведение журналов транзакций реестра.",
    {
      why: "Снять «грязный» hive после аварийного завершения: без этого часть последних изменений останется вне разбора.",
      source: "zimmerman", kind: "Program",
    }),
  T("SBECmd", "https://download.ericzimmermanstools.com/net9/SBECmd.zip", "windows", "program", ["Windows"],
    "Извлечение данных ShellBags (командная версия).",
    {
      why: "Показать, какие папки и сетевые ресурсы открывал пользователь, даже если они уже удалены.",
      source: "zimmerman", kind: "Program",
    }),
  T("ShellBags Explorer", "https://download.ericzimmermanstools.com/net9/ShellBagsExplorer.zip", "windows", "program", ["Windows"],
    "GUI для просмотра ShellBags.",
    {
      why: "Разбирать папки, которые открывали на машине: удобнее деревом в интерфейсе, чем таблицей.",
      source: "zimmerman", kind: "Program",
    }),
  T("LECmd", "https://download.ericzimmermanstools.com/net9/LECmd.zip", "windows", "program", ["Windows"],
    "Разбор ярлыков `.lnk`.",
    {
      why: "Ярлыки хранят пути, тома и MAC-адреса — доказательство того, что файл открывали и откуда он пришёл.",
      source: "zimmerman", kind: "Program",
    }),
  T("JLECmd", "https://download.ericzimmermanstools.com/net9/JLECmd.zip", "windows", "program", ["Windows"],
    "Разбор jump list.",
    {
      why: "История недавних документов и папок по приложениям: помогает понять, что именно искал и открывал пользователь.",
      source: "zimmerman", kind: "Program",
    }),
  T("JumpList Explorer", "https://download.ericzimmermanstools.com/net9/JumpListExplorer.zip", "windows", "program", ["Windows"],
    "GUI для просмотра jump list.",
    {
      why: "Визуальный разбор недавней активности приложений с сохранением в CSV.",
      source: "zimmerman", kind: "Program",
    }),
  T("RBCmd", "https://download.ericzimmermanstools.com/net9/RBCmd.zip", "windows", "program", ["Windows"],
    "Разбор корзины (INFO2 / $I).",
    {
      why: "Что удалили и когда: удаление файлов — типичный шаг заметания следов.",
      source: "zimmerman", kind: "Program",
    }),
  T("RecentFileCacheParser", "https://download.ericzimmermanstools.com/net9/RecentFileCacheParser.zip", "windows", "program", ["Windows"],
    "Разбор RecentFileCache.",
    {
      why: "Старый артефакт Windows 7, но в смешанных средах всё ещё встречается и добавляет следы запуска программ.",
      source: "zimmerman", kind: "Program",
    }),
  T("SrumECmd", "https://download.ericzimmermanstools.com/net9/SrumECmd.zip", "windows", "program", ["Windows"],
    "Разбор SRUM: сеть, процессы и энергопотребление.",
    {
      why: "Привязка сетевой активности к процессам и пользователям — то, чего нет в обычных журналах.",
      source: "zimmerman", kind: "Program",
    }),
  T("SumECmd", "https://download.ericzimmermanstools.com/net9/SumECmd.zip", "windows", "program", ["Windows"],
    "Разбор журналов User Access (SUM).",
    {
      why: "Следы доступа к сетевым ресурсам и RDP на серверах — полезно при разборе lateral movement.",
      source: "zimmerman", kind: "Program",
    }),
  T("WxTCmd", "https://download.ericzimmermanstools.com/net9/WxTCmd.zip", "windows", "program", ["Windows"],
    "Разбор базы Windows Timeline.",
    {
      why: "Хронология действий пользователя по приложениям и документам — готовая лента для отчёта.",
      source: "zimmerman", kind: "Program",
    }),
  T("SQLECmd", "https://download.ericzimmermanstools.com/net9/SQLECmd.zip", "windows", "program", ["Windows"],
    "Разбор SQLite-файлов по картам.",
    {
      why: "Браузеры, Teams и другие приложения хранят историю в SQLite: карты (maps) позволяют разбирать их без ручных запросов.",
      source: "zimmerman", kind: "Program",
    }),
  T("bstrings", "https://download.ericzimmermanstools.com/net9/bstrings.zip", "windows", "program", ["Windows"],
    "Поиск строк по файлам с готовыми регулярными выражениями.",
    {
      why: "Быстро найти GUID, пути и артефакты в бинарниках и базах, когда полноценный реверс избыточен.",
      source: "zimmerman", kind: "Program",
    }),
  T("Hasher", "https://download.ericzimmermanstools.com/hasher.zip", "windows", "program", ["Windows"],
    "Хеширование файлов и каталогов.",
    {
      why: "Зафиксировать целостность доказательств и сверить файлы с базами хешей.",
      source: "zimmerman", kind: "Program",
    }),
  T("SDB Explorer", "https://download.ericzimmermanstools.com/net9/SDBExplorer.zip", "windows", "program", ["Windows"],
    "Просмотр базы шимов (Shim Database).",
    {
      why: "Шимы — известный канал обхода UAC и закрепления. SDB Explorer показывает, что реально применяется к процессам.",
      source: "zimmerman", kind: "Program",
    }),
  T("MFTExplorer", "https://download.ericzimmermanstools.com/net9/MFTExplorer.zip", "windows", "program", ["Windows"],
    "Графический просмотрщик $MFT.",
    {
      why: "Изучать структуру каталогов и метаданные файлов без выгрузки в CSV.",
      source: "zimmerman", kind: "Program",
    }),
  T("Timeline Explorer", "https://download.ericzimmermanstools.com/net9/TimelineExplorer.zip", "windows", "program", ["Windows"],
    "Просмотр CSV и Excel с фильтрацией и группировкой.",
    {
      why: "Финальная сборка таймлайна: свести вывод всех утилит в один файл и отсортировать по времени инцидента.",
      source: "zimmerman", kind: "Program",
    }),
  T("VSCMount", "https://download.ericzimmermanstools.com/net9/VSCMount.zip", "windows", "program", ["Windows"],
    "Монтирование теневых копий (VSS).",
    {
      why: "Заглянуть в состояние диска до действий атакующего — иногда единственный способ увидеть исходные файлы.",
      source: "zimmerman", kind: "Program",
    }),
  T("EZViewer", "https://download.ericzimmermanstools.com/net9/EZViewer.zip", "windows", "program", ["Windows"],
    "Автономный просмотрщик документов и логов.",
    {
      why: "Открыть отчёт, лог или документ прямо на аналитической машине, не запуская офисный пакет, который может быть вектором атаки.",
      source: "zimmerman", kind: "Program",
    }),
  T("iisGeoLocate", "https://download.ericzimmermanstools.com/net9/iisGeolocate.zip", "windows", "program", ["Windows"],
    "Геолокация IP из журналов IIS.",
    {
      why: "Быстро понять, откуда шли запросы к веб-серверу, и отсечь шум ботов от целевой активности.",
      source: "zimmerman", kind: "Program",
    }),
  T("KAPE", "https://kape.zip", "windows", "program", ["Windows"],
    "Kroll Artifact Parser/Extractor: сбор и обработка артефактов.",
    {
      why: "Типовой первый шаг IR: по целям (targets) собрать артефакты с хоста и сразу прогнать их нужными утилитами.",
      source: "zimmerman", kind: "Program",
    }),
  T("Get-ZimmermanTools", "https://download.ericzimmermanstools.com/Get-ZimmermanTools.zip", "windows", "program", ["Windows"],
    "Скрипт, который скачивает и обновляет весь набор утилит.",
    {
      why: "Поддерживать набор в актуальном состоянии одной командой вместо ручного скачивания двадцати архивов.",
      source: "zimmerman", kind: "Program",
    }),

  /* --------------------------------------------------------------- recovery */
  T("Recuva", "https://www.ccleaner.com/recuva", "recovery", "program", ["Windows", "macOS"],
    "Восстановление удалённых файлов.",
    {
      why: "Иногда удалённые логи или документы — это как раз то, что нужно для разбора.",
      source: "blue", kind: "Program",
    }),
  T("Extundelete", "https://extundelete.sourceforge.net/", "recovery", "program", ["Linux"],
    "Восстановление файлов на ext3/ext4.",
    {
      why: "Linux-сторона: вернуть удалённые журналы и конфиги на томе, где работал злоумышленник.",
      note: "Работайте с образом, а не с живым разделом: любая запись уменьшает шансы.",
      source: "blue", kind: "Program",
    }),
  T("TestDisk", "https://www.cgsecurity.org/wiki/TestDisk_Download", "recovery", "program", ["Windows", "Linux", "macOS"],
    "Восстановление разделов и загрузочных записей.",
    {
      why: "Если повреждена таблица разделов, TestDisk может вернуть доступ к данным до начала форензики.",
      source: "blue", kind: "Program",
    }),

  /* -------------------------------------------------------------- обучение */
  T("TryHackMe", "https://tryhackme.com/", "training", "online", ["Web"],
    "Платформа практических лабораторий по кибербезопасности.",
    {
      why: "Прокачка навыков с нуля: комнаты по сетевым атакам, логам и защите — с проверкой в интерактивной среде.",
      source: "blue", kind: "Online",
    }),
  T("HackTheBox", "https://www.hackthebox.com/", "training", "online", ["Web"],
    "Платформа соревновательных задач по взлому.",
    {
      why: "Понять, как действует атакующий, проще, пройдя его путь руками: это делает сильнее восприятие логов.",
      source: "blue", kind: "Online",
    }),
  T("CyberDefenders", "https://cyberdefenders.org/", "training", "online", ["Web"],
    "Платформа blue-team лабораторий с реальными сценариями.",
    {
      why: "Тренировка на задачах, близких к работе SOC: инцидент, форензика, охота — с отчётом, как в реальной очереди.",
      source: "blue", kind: "Online",
    }),
  T("PhishMe (Cofense)", "https://cofense.com/product-services/phishme/", "training", "online", ["Web"],
    "Тренинги по распознаванию фишинга для сотрудников.",
    {
      why: "Самое слабое звено — человек. Программы имитации фишинга и обучения снижают число инцидентов на входе.",
      note: "Коммерческая платформа.",
      source: "blue", kind: "Online",
    }),
  T("kc7cyber", "https://kc7cyber.com/", "training", "online", ["Web"],
    "Геймифицированная платформа с расследованием симулированных атак.",
    {
      why: "Для новичков: охота на атакующего по логам без предварительного опыта — хороший способ привить мышление аналитика.",
      source: "blue", kind: "Online",
    }),

  /* ------------------------------------------------------------------- советы */
  T("Извлечение payload через Process Hacker", "https://twitter.com/embee_research/status/1614871485931458560", "tips", "reference", ["Windows"],
    "Приём анализа: найти .NET-нагрузку в новом процессе.",
    {
      why: "В новых процессах ищут подозрительные .NET-сборки. Вместе с dnSpy можно вытащить нагрузку без ручной деобфускации.",
      note: "Источник: BlueTeam-Tools, автор @embee_research.",
      idx: "process-hacker-payload", source: "blue", kind: "Reference",
    }),
  T("Запрет запуска скриптов двойным щелчком", "https://bluesoul.me/2016/05/12/use-gpo-to-change-the-default-behavior-of-potentially-malicious-file-extensions/", "tips", "rules", ["Windows"],
    "Приём защиты: смена приложения по умолчанию для HTA/JS/VBA/VBS на notepad.",
    {
      why: "Атакующие маскируют скрипты под офисные файлы. Если двойным щелчком они открываются в блокноте, выполнения не происходит.",
      idx: "block-script-execution", source: "blue", kind: "Reference",
    }),
  T("Криптоджекеры по логам прокси", "https://www.howtogeek.com/devops/how-to-detect-and-defeat-cryptominers-in-your-network/", "tips", "reference", ["Web"],
    "Приём: поиск подключений к майнинг-пулам в прокси и DNS-логах.",
    {
      why: "Майнер может прятаться через DLL sideloading, но подключение к пулу остаётся: `*xmr.*`, `*pool.com`, `pool.*`.",
      idx: "cryptojacking-proxy-logs", source: "blue", kind: "Reference",
    }),
  T("Удаление null-байтов в CyberChef", "https://twitter.com/securityinbits/status/1628364983661694976", "tips", "reference", ["Web"],
    "Приём: чистка декодированной строки от null-байтов.",
    {
      why: "После base64-декодирования Unicode остаются null-байты, и код невозможно читать. Операция «Remove null bytes» решает это одним шагом.",
      idx: "cyberchef-null-bytes", source: "blue", kind: "Reference",
    }),
  T("Восстановление метаданных PDF", "https://twitter.com/securityinbits/status/1628364983661694976", "tips", "reference", ["Windows", "Linux", "macOS"],
    "Приём: вернуть «вычищенные» метаданные PDF.",
    {
      why: "Правки PDF инкрементальны, и история остаётся в файле. Команда `exiftool -PDF-update:all= file.pdf` убирает обновления и возвращает исходные метаданные.",
      idx: "pdf-metadata-recovery", source: "blue", kind: "Reference",
    }),

  /* ---------------------------------------------------------------- сообщество */
  T("X / Twitter — аккаунты", "https://twitter.com/", "community", "online", ["Web"],
    "Подборка аккаунтов по безопасности от авторов BlueTeam-Tools.",
    {
      why: "Свежие разборы техник и образцов появляются здесь раньше, чем в отчётах: @vxunderground, @GossiTheDog, @TheHackersNews и другие из списка.",
      idx: "twitter-security-accounts", source: "blue", kind: "Online",
    }),
  T("Facebook ThreatExchange", "https://developers.facebook.com/docs/threat-exchange/getting-started", "community", "online", ["Web"],
    "Платформа обмена индикаторами между организациями.",
    {
      why: "Закрытый обмен IOC с другими компаниями и отраслевыми группами — больше контекста, чем публичные фиды.",
      source: "blue", kind: "Online",
    }),

  /* --------------------------------- материалы из присланного списка */
  ...EXTRA,
];

/* Профессиональные формулировки описаний.
   summary — назначение инструмента; why — место в процессе SOC и практическая функция.
   Стиль: без оценок, разговорных оборотов и риторики. Ключ — id записи. */
export const DESCRIPTIONS = {
  /* -------------------------------------------------------- threat hunting */
  "threathunt-app": [
    "Набор сервисов для планирования и документирования операций threat hunting.",
    "Поддерживает полный цикл охоты: постановку гипотезы, схемы узлов и граф OSINT-исследования, одностраничный отчёт и самооценку по модели зрелости HMM. Применяется, когда результаты охоты требуется представить в едином формате.",
  ],
  "hunt-io": [
    "Платформа для поиска и мониторинга вредоносной интернет-инфраструктуры.",
    "Сопоставляет индикатор из инцидента с набором связанных доменов, серверов и сертификатов. Используется для перехода от единичного IOC к инфраструктуре кампании и для проактивного поиска C2-узлов.",
  ],
  "validin": [
    "Агрегатор исторических DNS-записей, сертификатов и ответов хостов.",
    "Пассивный DNS и pivot по сертификатам позволяют выявить устойчивые элементы инфраструктуры атакующего при смене доменных имён. Применяется при атрибуции и уточнении области воздействия.",
  ],

  /* --------------------------------------------------- сеть и сканирование */
  "nmap": [
    "Сканер сети: обнаружение хостов, портов и версий сервисов.",
    "Позволяет сопоставить фактически доступные сервисы с утверждённым перечнем и оценить поверхность атаки. Режим определения версий и NSE-скрипты используются для получения контекста при проверке правил на SMB и RPC.",
  ],
  "nuclei": [
    "Сканер уязвимостей на основе шаблонов.",
    "Выполняет проверку сервисов по базам известных уязвимостей и мисконфигураций. Результат применяется для приоритизации устранения и для оценки актуальности правил детектирования.",
  ],
  "masscan": [
    "Высокоскоростной сканер портов для больших адресных пространств.",
    "Используется для быстрой инвентаризации открытых портов в крупных сегментах. Требует согласования и ограничения интенсивности: создаёт существенную нагрузку на сеть.",
  ],
  "angry-ip-scanner": [
    "Графический сканер диапазонов IP-адресов и портов.",
    "Применяется для быстрой инвентаризации лабораторного сегмента и проверки доступности хостов без изучения синтаксиса командной строки.",
  ],
  "zmap": [
    "Сканер для исследования больших объёмов адресного пространства IPv4.",
    "Позволяет оценить распространённость сервиса в масштабе сети или интернета. Используется преимущественно в исследовательских задачах.",
  ],
  "shodan": [
    "Поисковая система по устройствам, доступным из интернета.",
    "Применяется для выявления собственных сервисов, опубликованных наружу без согласования, и для изучения инфраструктуры по баннерам, портам и версиям ПО.",
  ],
  "tcpview": [
    "Просмотр сетевых соединений Windows с указанием процесса-владельца.",
    "Позволяет установить, какой процесс инициировал соединение, и сопоставить направление трафика с задачами хоста. Применяется на этапе первичного анализа подозрительной системы.",
  ],
  "speedguide-port": [
    "Справочник соответствия портов и использующих их сервисов.",
    "Используется при анализе сетевых соединений: позволяет определить типовое назначение порта и связанные с ним сервисы.",
  ],

  /* ------------------------------------------------ уязвимости и соответствие */
  "openvas": [
    "Сканер уязвимостей с открытым исходным кодом (Greenbone).",
    "Обеспечивает регулярное сканирование инфраструктуры и формирование перечня уязвимостей для приоритизации. Применяется в качестве базового средства контроля.",
  ],
  "nessus-essentials": [
    "Сканер уязвимостей Tenable, бесплатная редакция для личного использования.",
    "Формирует отчёт с оценкой по CVSS и рекомендациями по устранению. Используется как независимая вторая проверка результатов сканирования.",
  ],
  "nexpose": [
    "Платформа управления уязвимостями Rapid7 (InsightVM).",
    "Обеспечивает непрерывное сканирование, инвентаризацию активов и приоритизацию рисков. Предназначена для организаций с формализованным процессом управления уязвимостями.",
  ],
  "hackerone": [
    "Платформа управления программами bug bounty.",
    "Позволяет привлекать внешних исследователей к оценке защищённости с заданной областью и правилами. Обеспечивает приём и триаж сообщений об уязвимостях.",
  ],
  "lynis": [
    "Средство аудита защищённости и hardening для Linux и UNIX.",
    "Выполняет локальную проверку конфигурации, версий пакетов и параметров безопасности. Применяется при подготовке эталонных образов и при периодическом контроле соответствия.",
  ],
  "security-compliance-toolkit": [
    "Набор базовых политик безопасности Microsoft.",
    "Содержит эталонные настройки Windows Server и домена. Используется для проверки, что групповые политики не ослабили механизмы защиты, и для формирования эталонного профиля аудита.",
  ],
  "cis-benchmarks": [
    "Бенчмарки CIS — эталонные конфигурации операционных систем и сервисов.",
    "Определяют рекомендуемые значения параметров безопасности: протоколы, разграничение прав, настройки аудита. Применяются для оценки соответствия и планирования hardening.",
  ],
  "mitre-car-coverage": [
    "Проект MITRE по сопоставлению аналитических методов с матрицей ATT&CK.",
    "Позволяет определить, какие методы анализа покрывают конкретные техники и где в наборе правил остаются пробелы. Используется при планировании развития детектирования.",
  ],

  /* ------------------------------------------- мониторинг и телеметрия */
  "sysmon": [
    "Системный монитор Windows с записью событий в журнал.",
    "Обеспечивает телеметрию процессов, сетевых соединений, файловых и реестровых операций. Является основным источником для правил на хосте: значительная часть детектов Windows строится на Event ID Sysmon.",
  ],
  "kibana": [
    "Средство визуализации и поиска по данным Elasticsearch.",
    "Применяется для проверки правил запросами и для наблюдения за отработкой детектов на временных рядах. Позволяет настраивать дашборды и оповещения.",
  ],
  "logstash": [
    "Конвейер сбора и нормализации событий.",
    "Приводит разнородные источники (EVTX, auditd, Suricata) к единой схеме до записи в хранилище. Без нормализации корреляция событий между системами не выполняется.",
  ],
  "parsedmarc": [
    "Разбор отчётов DMARC с выгрузкой в JSON, CSV, Elasticsearch или Splunk.",
    "Обеспечивает контроль подделки домена: показывает источники отправки от имени организации и результат проверки DMARC.",
  ],
  "phishing-catcher": [
    "Обнаружение фишинговых доменов по журналам Certificate Transparency.",
    "Выявляет регистрацию сертификатов на домены, сходные с целевыми, за несколько суток до рассылки. Даёт запас времени на блокировку.",
  ],
  "maltrail": [
    "Система обнаружения вредоносного трафика по публичным и собственным спискам.",
    "Фиксирует обращения к известным вредоносным доменам, адресам, URL и значениям User-Agent. Применяется для выявления исходящей активности скомпрометированного узла.",
  ],
  "autorunstowineventlog": [
    "Перенос результатов Autoruns в журнал событий Windows.",
    "Автозапуск является распространённым механизмом закрепления. Скрипт преобразует перечень Autoruns в события, которые передаются в SIEM существующими средствами WEF.",
  ],
  "procfilter": [
    "Фильтрация процессов Windows с поддержкой правил YARA.",
    "Позволяет применять точечные правила на конкретное семейство ВПО с заданной реакцией при совпадении. Не заменяет антивирусную защиту; применяется в контролируемых средах.",
  ],
  "velociraptor": [
    "Агент мониторинга и сбора данных с парка конечных устройств.",
    "Обеспечивает поиск артефактов по запросу и непрерывное наблюдение. Позволяет получить с подозрительного хоста процессы, автозапуск и сетевые соединения без непосредственного доступа.",
  ],
  "sysmonsearch": [
    "Расширение Kibana для анализа журналов Sysmon.",
    "Предоставляет готовые представления: связи процессов и сетевых соединений, статистику по Event ID и оповещения по заданным условиям. Сокращает затраты на подготовку дашбордов.",
  ],
  "canary-tokens": [
    "Средства создания приманок в файлах, каталогах и сетевых устройствах.",
    "Размещаются в местах, недоступных для легитимных пользователей. Обращение к приманке формирует уведомление и указывает на несанкционированное исследование инфраструктуры.",
  ],
  "bad-useragents-list": [
    "Перечень значений User-Agent, характерных для сканеров и автоматизированных инструментов.",
    "Применяется для фильтрации на уровне обратного прокси и для анализа веб-логов. Позволяет отделить автоматизированное исследование периметра от пользовательского трафика.",
  ],
  "density-scout": [
    "Средство оценки плотности файлов и содержимого каталогов.",
    "Определяет, сколько копий фрагмента содержимого встречается в исследуемом наборе. Применяется для поиска уникальных или аномально распространённых файлов, в том числе при подготовке YARA-правил.",
  ],
  "sysinternals": [
    "Комплект системных утилит Microsoft Sysinternals.",
    "Объединяет средства оперативного анализа Windows: TCPView, Sigcheck, Autoruns, Process Explorer. Применяется для первичного разбора хоста.",
  ],
  "captain": [
    "Средство выявления инжектов в память и признаков бесфайловых атак.",
    "Исследует память процессов и обнаруживает несоответствия, характерные для внедрённого кода. Дополняет журналы событий данными, которые в них не фиксируются.",
  ],
  "notable-event-ids": [
    "Справочник значимых Event ID Windows и Sysmon.",
    "Содержит назначение событий и связанные с ними признаки. Применяется при разработке правил и при разборе инцидентов.",
  ],
  "event-id-map": [
    "Карта Event ID Windows, применяемых при охоте и расследовании.",
    "Представляет события в структурированном виде и показывает сочетания, которые проверяются совместно. Используется как отправная точка анализа инцидента.",
  ],
  "emerging-threats": [
    "Открытый набор правил Suricata от Proofpoint Emerging Threats.",
    "Служит базой для развёртывания сетевого детектирования. Требует ревизии под конкретную сеть: часть правил даёт ложные срабатывания в типовой корпоративной среде.",
  ],
  "sigcheck": [
    "Проверка цифровых подписей исполняемых файлов.",
    "Позволяет установить отсутствие подписи или её принадлежность стороннему издателю. Применяется при проверке файлов, размещённых рядом с легитимными бинарниками.",
  ],

  /* ---------------------------------------------------- техники атакующих */
  "lolbas": [
    "Каталог штатных исполняемых файлов Windows, применяемых атакующими.",
    "Обеспечивает обратный поиск: по обнаруженному в журналах бинарнику позволяет определить известные способы его применения и признаки, подлежащие проверке.",
  ],
  "gtfobins": [
    "Каталог Unix-утилит, применяемых для повышения привилегий и обхода ограничений.",
    "Содержит перечень функций и параметров, характерных для злоупотребления. Применяется при разработке правил контроля выполнения команд в Linux.",
  ],
  "filesec-io": [
    "Справочник расширений файлов, используемых в атаках.",
    "Описывает назначение и механизм обработки расширений, а также меры ограничения. Применяется при разборе вложений и при настройке политик почтовых шлюзов.",
  ],
  "kql-search": [
    "Агрегатор запросов на языке KQL из открытых репозиториев.",
    "Сокращает время подготовки запросов к Azure Monitor, Microsoft Defender и Sentinel за счёт повторного использования готовых формулировок.",
  ],
  "unprotect-project": [
    "База методов обхода средств защиты.",
    "Систематизирует приёмы, применяемые ВПО для уклонения от обнаружения. Используется при оценке полноты набора правил и при корректировке логики детектирования.",
  ],
  "chainsaw": [
    "Средство поиска угроз в журналах Windows с поддержкой Sigma.",
    "Обеспечивает первичный анализ выгрузки EVTX без развёртывания SIEM. Позволяет применить существующий набор правил Sigma к журналам и получить перечень совпадений.",
  ],
  "freq": [
    "Средство оценки случайности строк для выявления сгенерированных имён.",
    "Вычисляет вероятность последовательности символов по таблицам частот. Применяется для обнаружения доменов и сервисов, созданных алгоритмически, с передачей результата в SIEM.",
  ],
  "yargen": [
    "Генератор правил YARA по выборке образцов.",
    "Формирует правило с исключением строк, встречающихся в легитимных файлах. Снижает трудозатраты при подготовке правил для семейства ВПО.",
  ],
  "emailanalyzer": [
    "Средство разбора вложений электронной почты формата EML.",
    "Извлекает заголовки доставки, ссылки, вложения и хеши. Применяется на начальном этапе обработки сообщения о фишинге.",
  ],
  "vcg": [
    "Средство автоматизированного обзора безопасности исходного кода.",
    "Выполняет поиск опасных конструкций для C/C++, Java, C#, VB и PL/SQL. Применяется при проверке кода собственных правил и вспомогательных средств.",
  ],
  "cyberchef": [
    "Средство преобразования данных, работающее в браузере.",
    "Позволяет выполнять декодирование base64 и шестнадцатеричного представления, извлечение строк и очистку данных. Последовательность операций сохраняется и воспроизводится.",
  ],
  "persistencesniper": [
    "Модуль PowerShell для поиска механизмов закрепления в Windows.",
    "Проверяет десятки методов автозапуска и закрепления. Применяется при оценке возможности повторной компрометации хоста.",
  ],
  "yara-1": [
    "Первая часть руководства Nextron Systems по разработке правил YARA.",
    "Рассматривает выбор строк, исключение коротких и распространённых последовательностей, требования к точности правила.",
  ],
  "yara-2": [
    "Вторая часть руководства по разработке правил YARA.",
    "Описывает построение условий: подсчёт совпадений, ограничения по смещениям, уточнение через модуль PE.",
  ],
  "yara-3": [
    "Третья часть руководства по разработке правил YARA.",
    "Посвящена сопровождению набора правил: именование, метаданные, версии и обработка ложных срабатываний.",
  ],
  "tool-analysis-result-sheet": [
    "Результаты поведенческого анализа утилит, применяемых в атаках.",
    "Содержит перечень событий и артефактов для каждой утилиты. Используется для проверки полноты детектирования конкретного инструмента.",
  ],

  /* ------------------------------------------------------------- intel */
  "pulsedive": [
    "Платформа threat intelligence с открытым доступом.",
    "Обеспечивает проверку репутации и обогащение индикаторов. Применяется на этапе первичной оценки IOC.",
  ],
  "feedly": [
    "Агрегатор RSS-подписок.",
    "Позволяет централизованно получать отчёты вендоров и разборы инцидентов. Используется как единый источник отраслевых публикаций.",
  ],
  "cti-news": [
    "Файл подписок по информационной безопасности.",
    "Импортируется в RSS-агрегатор и формирует перечень источников без ручного отбора.",
  ],
  "malwarebazaar": [
    "Хранилище образцов ВПО с метаданными.",
    "Обеспечивает доступ к образцам и хешам для проверки правил и анализа семейств. Метаданные дополняют результаты песочницы.",
  ],
  "tor-exit-list": [
    "Список выходных узлов сети TOR.",
    "Применяется для выявления подключений через TOR, не характерных для рабочей сети. Список формируется автоматически и требует периодического обновления.",
  ],
  "uuid-generator": [
    "Генератор идентификаторов UUID версии 4.",
    "Применяется при описании объектов интерфейсов и полей в правилах и документации.",
  ],
  "maltego": [
    "Платформа визуального анализа связей в threat intelligence.",
    "Представляет инфраструктуру в виде графа доменов, адресов и сертификатов. Позволяет выявлять связи, неочевидные в табличном представлении.",
  ],
  "misp": [
    "Платформа обмена индикаторами компрометации с открытым исходным кодом.",
    "Обеспечивает хранение, корреляцию и распространение IOC между системами по API. Применяется для централизации индикаторов из разборов инцидентов.",
  ],
  "threatconnect": [
    "Платформа агрегации и анализа threat intelligence.",
    "Объединяет данные нескольких источников и формирует отчёты. Применяется при значительном числе источников и необходимости их сопоставления.",
  ],
  "adversary-emulation-library": [
    "Библиотека планов эмуляции действий атакующих групп.",
    "Планы воспроизводят последовательность действий конкретной группы. Позволяют оценить полноту детектирования на реальных цепочках, а не на отдельных техниках.",
  ],

  /* ----------------------------------------------------------- threat hunting */
  "tahiti-methodology": [
    "Методика целевой охоты на угрозы (TaHiTI).",
    "Определяет последовательность охоты: формулирование гипотезы, выбор источников данных, критерии оценки результата. Применяется для регламентации деятельности SOC.",
  ],
  "tahiti-framework": [
    "Описание рамки целевой охоты проекта MAGMA.",
    "Раскрывает организационные условия проведения охоты и формы представления результата.",
  ],
  "hunting-maturity-model": [
    "Модель зрелости охоты на угрозы (HMM), уровни H0–H5.",
    "Позволяет определить текущий уровень практики и направление развития: от реакции на оповещения к охоте на основе гипотез.",
  ],
  "hunting-framework": [
    "Белая книга с рамкой охоты на угрозы.",
    "Описывает методологию проведения охоты на основе гипотез. Применяется как основа внутреннего регламента.",
  ],
  "hunt-lateral-explicit-credentials": [
    "Методика охоты: горизонтальное перемещение с явными учётными данными.",
    "Определяет запросы и логику проверки запуска процессов от имени другого пользователя, включая RunAs и использование кэшированных учётных данных.",
  ],
  "hunt-lateral-auth-logs": [
    "Методика охоты по журналам аутентификации Windows.",
    "Описывает сопоставление событий 4624, 4625 и 4776 для отделения администрирования от перебора и перемещения по сети.",
  ],
  "hunt-lateral-process": [
    "Методика охоты по событиям создания процессов.",
    "Определяет признаки удалённого запуска: характер процессов, их родительские процессы и параметры командной строки.",
  ],
  "talos-hunting": [
    "Материал Cisco Talos по охоте в больших наборах данных.",
    "Рассматривает формулирование гипотезы и отбор полей при значительных объёмах событий.",
  ],
  "stickman-hunting": [
    "Обзор методов и инструментов проактивной охоты.",
    "Описывает последовательность действий от индикатора к системе и перечень применяемых средств.",
  ],
  "guidepoint-hunting": [
    "Рекомендации GuidePoint по организации охоты.",
    "Содержит практические указания по планированию охоты и выбору инструментов.",
  ],
  "proinf-hunting": [
    "Чек-лист методов охоты с метриками процесса.",
    "Содержит перечень методов и метрик, пригодный для отчётности о результатах охоты.",
  ],
  "bluevoyant-hunting": [
    "Материал об организации охоты на угрозы.",
    "Разъясняет отличие охоты от мониторинга и условия её применения в SOC.",
  ],
  "sans-who-what": [
    "Материал SANS о планировании охоты на угрозы.",
    "Определяет состав участников, источники данных, временные рамки и цели охоты.",
  ],

  /* ---------------------------------------------------------------- ir */
  "nist-csf": [
    "NIST Cybersecurity Framework.",
    "Определяет функции Identify, Protect, Detect, Respond, Recover. Применяется для оценки зрелости SOC и определения места детектирования в общей модели управления.",
  ],
  "incident-response-plan": [
    "Материалы для разработки плана реагирования на инциденты.",
    "Содержит шаблоны и рамочные документы NCSC, SANS и CISA. Используется при формировании внутреннего регламента.",
  ],
  "ransomware-response": [
    "Материалы по подготовке и реагированию на программы-шифровальщики.",
    "Определяют порядок действий: локализация, оценка области шифрования, восстановление из резервных копий.",
  ],
  "ir-reference-guide": [
    "Практическое руководство Microsoft по реагированию на крупные инциденты.",
    "Рассматривает технические, организационные, правовые и коммуникационные аспекты. Основные положения: подготовка снижает ущерб, координация обязательна, избыточная реакция столь же вредна, как и недостаточная.",
  ],
  "awesome-incident-response": [
    "Подборка средств и материалов по реагированию на инциденты.",
    "Систематизирует источники по направлениям: эмуляция, создание образов, комплексные средства, документация и сообщества.",
  ],
  "linux-incident-response": [
    "Комплект для сбора данных с Linux-хоста при реагировании на инцидент.",
    "Содержит перечень команд и скрипт, формирующий отчёт по учётным записям, журналам, процессам, службам, файлам и сетевым соединениям.",
    "Скрипт запускается с правами root; отчёт формируется в /tmp/IRLinux.txt.",
  ],
  "ransomware-checklist": [
    "Чек-лист подготовки и реагирования на программы-шифровальщики.",
    "Определяет последовательность действий до и в ходе шифрования: проверка резервных копий, изоляция, порядок восстановления.",
  ],
  "nomoreransom": [
    "Каталог средств расшифровки данных.",
    "Содержит расшифровщики и сведения о семействах, предоставленные правоохранительными органами и вендорами. Применяется при наличии зашифрованных данных.",
  ],
  "sans-hunting-plans": [
    "Материал SANS о построении планов охоты.",
    "Связывает охоту с расследованием: определяет последовательность проверок и форму представления результата.",
  ],
  "sans-analyst-value": [
    "Материал SANS о роли аналитика в SOC.",
    "Описывает представление результатов работы аналитика в форматах, применимых для управления SOC.",
  ],
  "sans-hunting-program": [
    "Материал SANS о построении программы охоты на угрозы.",
    "Рассматривает уровни зрелости, метрики и порядок развития программы.",
  ],
  "process-hacker-payload": [
    "Приём анализа: поиск .NET-нагрузки в новых процессах.",
    "Подозрительные .NET-сборки в только что запущенных процессах исследуются в Process Hacker и загружаются в dnSpy. Позволяет извлечь нагрузку без ручной деобфускации.",
  ],
  "block-script-execution": [
    "Приём защиты: ограничение запуска скриптов двойным щелчком.",
    "Назначение приложения по умолчанию для расширений HTA, JS, VBA, VBS в notepad.exe через групповые политики исключает выполнение при открытии файла.",
  ],
  "cryptojacking-proxy-logs": [
    "Приём выявления майнеров по журналам прокси и DNS.",
    "Майнер может скрывать процессы, но подключения к пулам сохраняются. Поиск выполняется по шаблонам *xmr.*, *pool.com, *pool.org, pool.*.",
  ],
  "cyberchef-null-bytes": [
    "Приём очистки декодированных строк от null-байтов.",
    "После декодирования base64 для Unicode остаются null-байты, затрудняющие чтение. Операция Remove null bytes удаляет их из результата.",
  ],
  "pdf-metadata-recovery": [
    "Приём восстановления изменённых метаданных PDF.",
    "Правки PDF вносятся инкрементально, поэтому история сохраняется в файле. Команда exiftool -PDF-update:all= убирает обновления и возвращает исходные метаданные.",
  ],

  /* ------------------------------------------------------------ malware */
  "virustotal": [
    "Платформа проверки файлов, ссылок и хешей по базам средств защиты.",
    "Применяется для оценки индикаторов из инцидента и поиска связанных образцов. Расширенные запросы позволяют выявлять документы с макросами на раннем этапе.",
  ],
  "ida": [
    "Дизассемблер и отладчик для анализа исполняемых файлов.",
    "Применяется для статического анализа логики образца. Бесплатная редакция обеспечивает базовый набор функций, IDAPython позволяет автоматизировать рутинные операции.",
  ],
  "ghidra": [
    "Среда обратной разработки с декомпилятором.",
    "Обеспечивает декомпиляцию в представление, близкое к исходному коду, построение графов и отладку. Распространяется без ограничений.",
  ],
  "decode-vbe": [
    "Средство декодирования скриптов, закодированных Microsoft Script Encoding.",
    "Возвращает читаемое представление VBScript, скрытого в формате VBE. Применяется при анализе скриптовых атак.",
  ],
  "pafish": [
    "Средство проверки признаков виртуализации и песочницы.",
    "Позволяет оценить среду анализа: ВПО использует аналогичные механизмы обнаружения и при их срабатывании не проявляет функциональность.",
  ],
  "lookyloo": [
    "Средство фиксации веб-страницы и построения дерева обращений.",
    "Отображает цепочку перенаправлений и сторонние домены, к которым обращается страница. Применяется при анализе фишинговых ресурсов.",
  ],
  "yara": [
    "Язык описания шаблонов для поиска и классификации ВПО.",
    "Правило описывает набор строк и условие их совпадения. Применяется в системах сканирования, в Velociraptor и в procfilter.",
  ],
  "cuckoo": [
    "Автоматизированная песочница анализа ВПО.",
    "Выполняет образец в изолированной среде и фиксирует вызовы API, созданные файлы, сетевой трафик, дампы памяти и снимки экрана.",
    "Проект не развивается; для текущих задач применяются актуальные решения (CAPE).",
  ],
  "radare2": [
    "Среда обратной разработки с поддержкой широкого набора архитектур.",
    "Работает из командной строки и допускает автоматизацию скриптами. Применяется для быстрого статического анализа бинарных файлов.",
  ],
  "dnspy": [
    "Отладчик и редактор сборок .NET.",
    "Обеспечивает просмотр и отладку сборок .NET, в том числе скомпилированных из Unity.",
    "Разработка проекта приостановлена; актуальная поддержка — в dnSpyEx.",
  ],
  "malware-traffic-analysis": [
    "Блог с разборами вредоносного трафика и образцами записей.",
    "Содержит упражнения с записями сетевого трафика и пояснениями к применяемым методам. Используется для проверки правил Suricata и практики анализа.",
  ],

  /* ------------------------------------------------------------ forensics */
  "dfir-toolkit": [
    "Комплект утилит командной строки для построения таймлайнов.",
    "Приводит журналы, реестр, Prefetch, ярлыки и архивы к единому формату bodyfile. Позволяет построить общий таймлайн событий через mactime2 и сопоставить активность из разных источников.",
    "Устанавливается через cargo install dfir-toolkit. Репозиторий размещён на Codeberg.",
  ],
  "mactime2": [
    "Построение таймлайна из данных формата bodyfile.",
    "Формирует упорядоченный по времени перечень событий из результатов предыдущих шагов разбора. Формат даты задаётся переменной окружения DFIR_DATE.",
  ],
  "evtx2bodyfile": [
    "Преобразование журналов EVTX в формат bodyfile.",
    "Включает события Windows в общий таймлайн, сопоставляя их с файловыми и реестровыми артефактами.",
  ],
  "pf2bodyfile": [
    "Преобразование данных Prefetch в формат bodyfile.",
    "Включает сведения о запуске программ в общий таймлайн без ручного сведения таблиц.",
  ],
  "lnk2bodyfile": [
    "Преобразование ярлыков LNK в формат bodyfile.",
    "Добавляет сведения об открытых файлах и сетевых ресурсах в общую хронологию.",
  ],
  "zip2bodyfile": [
    "Преобразование содержимого ZIP-архивов в формат bodyfile.",
    "Позволяет включить архивы и их содержимое в таймлайн с отметками времени.",
  ],
  "evtxanalyze": [
    "Поиск отклонений в журналах EVTX.",
    "Выявляет редкие сочетания кодов событий и значений полей без последовательного просмотра журнала.",
  ],
  "evtxscan": [
    "Сканирование файлов EVTX с подсчётом событий.",
    "Формирует распределение событий по кодам. Применяется для предварительной оценки состава журнала.",
  ],
  "evtxcat": [
    "Вывод событий EVTX в текстовом или JSON-представлении.",
    "Позволяет просмотреть журнал в терминале или передать события в другую систему обработки.",
  ],
  "evtxls": [
    "Перечень журналов и каналов в файле EVTX.",
    "Определяет состав каналов в выгрузке до начала разбора.",
  ],
  "regdump": [
    "Выгрузка содержимого ветвей реестра в текстовом виде.",
    "Обеспечивает поиск и сравнение значений между снимками системы.",
  ],
  "hivescan": [
    "Поиск ветвей реестра в образе или дампе.",
    "Позволяет обнаружить hive без заранее известного расположения.",
  ],
  "pol-export": [
    "Экспорт групповых политик (POL) в читаемый формат.",
    "Показывает применённые политики и позволяет проверить, не ослаблены ли механизмы защиты и параметры аудита.",
  ],
  "es4forensics": [
    "Загрузка артефактов в Elasticsearch.",
    "Переносит собранные данные инцидента в Elastic для поиска и анализа средствами Kibana.",
  ],
  "ipgrep": [
    "Поиск IP-адресов в файлах и артефактах.",
    "Определяет адреса, с которыми взаимодействовал хост, по журналам, конфигурациям и дампам.",
  ],
  "ts2date": [
    "Преобразование временных меток в дату и время.",
    "Приводит форматы Win32 FILETIME, Unix time и другие к единому представлению для сопоставления событий.",
  ],
  "cleanhive": [
    "Подготовка ветви реестра к анализу.",
    "Приводит файл реестра к виду, совместимому с остальными средствами разбора.",
  ],
  "volatility3": [
    "Средство анализа дампов оперативной памяти, версия 3.",
    "Обеспечивает разбор процессов, сетевых соединений, внедрённого кода и загруженных модулей. Профили для актуальных версий Windows и Linux формируются автоматически.",
  ],
  "volatility2": [
    "Средство анализа дампов оперативной памяти, версия 2.",
    "Применяется для образов более ранних версий систем: Windows XP–2008 R2, Linux до 5.5, macOS до Catalina.",
    "Разработка ветки прекращена; для новых задач применяется версия 3.",
  ],
  "memprocfs": [
    "Доступ к дампу памяти через файловую систему.",
    "Позволяет исследовать процессы, драйверы и сетевые соединения стандартными командами файловой системы без изучения плагинов.",
  ],
  "windbg": [
    "Отладчик Microsoft для режима ядра и пользовательского режима.",
    "Применяется для анализа дампов ядра, проверки структур памяти и исследования драйверов.",
  ],
  "volcano": [
    "Средство анализа памяти Volexity.",
    "Выполняет автоматическую корреляцию артефактов: инъецированный код, скрытые процессы, подозрительные драйверы.",
  ],
  "surge": [
    "Средство снятия дампа памяти Volexity.",
    "Ориентировано на устойчивый сбор данных без прерывания работы исследуемой системы.",
  ],
  "magnet-ram": [
    "Средство снятия дампа оперативной памяти.",
    "Применяется для получения образа памяти без установки дополнительного программного обеспечения.",
  ],
  "ftk-imager": [
    "Средство предварительного просмотра и создания образов.",
    "Обеспечивает снятие образа диска и памяти, а также просмотр дампов. Применяется как универсальное средство первичного сбора.",
  ],
  "ram-capturer": [
    "Средство снятия дампа оперативной памяти Belkasoft.",
    "Формирует образ памяти, в том числе при активных механизмах защиты от дампинга.",
  ],
  "fex-memory": [
    "Средство снятия дампа оперативной памяти.",
    "Применяется как альтернативный способ получения образа на системах, где штатные средства недоступны.",
  ],
  "lime": [
    "Модуль ядра для снятия дампа памяти Linux и Android.",
    "Позволяет получить образ памяти Linux-хоста в файл или по сети.",
    "Разработка прекращена; для актуальных систем применяется AVML.",
  ],
  "avml": [
    "Средство снятия дампа памяти Linux, статический исполняемый файл.",
    "Не требует загрузки модуля ядра и наличия компилятора на исследуемой системе.",
  ],
  "fmem": [
    "Модуль, создающий устройство /dev/fmem для чтения памяти.",
    "Устраняет ограничения /dev/mem и позволяет получить полный образ оперативной памяти.",
  ],
  "digital-collector": [
    "Средство сбора данных Cellebrite.",
    "Обеспечивает триаж и целевой сбор на системах Windows и macOS при минимальном вмешательстве.",
  ],
  "varc": [
    "Средство сбора летучих артефактов.",
    "Формирует снимок данных, утрачиваемых при перезагрузке: процессы, сетевые соединения, загруженные модули.",
  ],
  "pcileech": [
    "Чтение и запись памяти через шину PCIe (DMA).",
    "Применяется при невозможности установки драйвера на исследуемую систему. Требует аппаратного модуля.",
  ],
  "evtxtract": [
    "Восстановление фрагментов журналов EVTX из необработанных данных.",
    "Позволяет извлечь содержимое повреждённых или удалённых журналов из неразмеченных областей и образов памяти.",
  ],
  "inodes-plugin": [
    "Плагин Volatility 3 для получения метаданных inode по процессам.",
    "Показывает файлы, удерживаемые процессом, при недоступности сведений /proc.",
  ],
  "prefetch-plugin": [
    "Плагин Volatility 3 для извлечения данных Prefetch из памяти.",
    "Позволяет получить сведения о запуске программ без образа диска.",
  ],
  "winpmem": [
    "Средство снятия дампа физической памяти Windows.",
    "Реализует три независимых метода чтения, что повышает вероятность получения образа при наличии механизмов сокрытия на уровне ядра.",
    "Для Linux предусмотрен отдельный проект Linpmem. Подписанные драйверы не поддерживают запись в память.",
  ],
  "sans-appcompat": [
    "Средство разбора ShimCache (AppCompatCache).",
    "Дополняет Prefetch сведениями о пути и времени изменения файла, в том числе удалённого.",
  ],
  "evtxecmd": [
    "Средство разбора журналов EVTX с выгрузкой в CSV, XML и JSON.",
    "Основное средство преобразования журналов для последующего анализа: поддерживает карты полей и обработку занятых файлов.",
  ],
  "mftecmd": [
    "Средство разбора структур $MFT, $Boot, $J, $SDS, $I30 и $LogFile.",
    "Восстанавливает сведения о создании, удалении и переименовании файлов, отсутствующие в журналах событий.",
  ],
  "pecmd": [
    "Средство разбора данных Prefetch.",
    "Определяет время запуска программ и путь к исполняемым файлам с точностью до секунды.",
  ],
  "amcacheparser": [
    "Средство разбора Amcache.hve.",
    "Содержит сведения об исполняемых файлах, отсутствующих на диске: хеши, версии, время первого появления.",
  ],
  "appcompatcacheparser": [
    "Средство разбора ShimCache.",
    "Фиксирует путь и время последнего изменения файла для программ, запущенных нестандартным способом.",
  ],
  "recmd": [
    "Средство разбора реестра с поддержкой плагинов и пакетных заданий.",
    "Извлекает заданные артефакты: сведения о USB-устройствах, автозапуске, UserAssist, подключениях RDP.",
  ],
  "registry-explorer": [
    "Графическое средство просмотра реестра.",
    "Обеспечивает поиск и просмотр ветвей реестра, включая занятые файлы, при разборе инцидента.",
  ],
  "rla": [
    "Воспроизведение журналов транзакций реестра.",
    "Приводит файл реестра в актуальное состояние после некорректного завершения работы системы.",
  ],
  "sbecmd": [
    "Извлечение данных ShellBags (командная версия).",
    "Определяет каталоги и сетевые ресурсы, открытые пользователем, в том числе удалённые.",
  ],
  "shellbags-explorer": [
    "Графическое средство просмотра ShellBags.",
    "Представляет историю работы с каталогами в виде дерева с возможностью выгрузки.",
  ],
  "lecmd": [
    "Средство разбора ярлыков LNK.",
    "Содержит сведения о путях, томах и параметрах узла, подтверждающие открытие файла и источник его появления.",
  ],
  "jlecmd": [
    "Средство разбора списков переходов (jump list).",
    "Показывает недавние документы и каталоги в разрезе приложений.",
  ],
  "jumplist-explorer": [
    "Графическое средство просмотра списков переходов.",
    "Обеспечивает визуальный разбор недавней активности приложений с выгрузкой в CSV.",
  ],
  "rbcmd": [
    "Средство разбора корзины (INFO2, $I).",
    "Определяет перечень и время удаления файлов.",
  ],
  "recentfilecacheparser": [
    "Средство разбора RecentFileCache.",
    "Артефакт ранних версий Windows, сохраняющий сведения о запуске программ в смешанных средах.",
  ],
  "srumecmd": [
    "Средство разбора SRUM.",
    "Сопоставляет сетевую активность с процессами и пользователями.",
  ],
  "sumecmd": [
    "Средство разбора журналов User Access (SUM).",
    "Фиксирует обращения к сетевым ресурсам и подключения RDP на серверах.",
  ],
  "wxtcmd": [
    "Средство разбора базы Windows Timeline.",
    "Формирует хронологию действий пользователя по приложениям и документам.",
  ],
  "sqlecmd": [
    "Средство разбора файлов SQLite по картам.",
    "Позволяет извлекать данные приложений (браузеры, клиенты) без ручного составления запросов.",
  ],
  "bstrings": [
    "Поиск строк в файлах с набором предопределённых шаблонов.",
    "Применяется для извлечения идентификаторов, путей и артефактов из исполняемых файлов и баз данных.",
  ],
  "hasher": [
    "Вычисление хешей файлов и каталогов.",
    "Обеспечивает фиксацию целостности доказательств и сверку с известными наборами хешей.",
  ],
  "sdb-explorer": [
    "Средство просмотра базы шимов (Shim Database).",
    "Показывает шимы, применяемые к процессам. Применяется при разборе техник обхода UAC и закрепления.",
  ],
  "mft-explorer": [
    "Графическое средство просмотра $MFT.",
    "Обеспечивает просмотр структуры каталогов и метаданных файлов без выгрузки.",
  ],
  "timeline-explorer": [
    "Средство просмотра CSV и Excel с фильтрацией и группировкой.",
    "Применяется для сведения результатов разбора в единый упорядоченный перечень.",
  ],
  "vscmount": [
    "Монтирование теневых копий тома (VSS).",
    "Позволяет получить состояние диска на момент, предшествующий действиям в системе.",
  ],
  "ezviewer": [
    "Средство просмотра документов и журналов без внешних зависимостей.",
    "Применяется для просмотра файлов на аналитической системе без запуска офисных приложений.",
  ],
  "iisgeolocate": [
    "Геолокация адресов из журналов IIS.",
    "Определяет источники запросов к веб-серверу и позволяет отделить автоматизированную активность от обращений пользователей.",
  ],
  "kape": [
    "Средство сбора и обработки артефактов Kroll.",
    "Обеспечивает сбор заданных артефактов с хоста и их последующую обработку стандартными средствами.",
  ],
  "get-zimmermantools": [
    "Скрипт загрузки и обновления комплекта утилит.",
    "Поддерживает актуальность набора без ручной загрузки отдельных архивов.",
  ],
  "linux-ir-gatherer": [
    "Скрипт сбора данных с Linux-хоста при реагировании на инцидент.",
    "Формирует единый отчёт по учётным записям, журналам, ресурсам, процессам, службам, файлам и сети.",
  ],
  "avml-linux": [
    "Средство снятия дампа памяти Linux.",
    "Не требует модуля ядра и компилятора на исследуемой системе.",
  ],
  "lime-linux": [
    "Модуль ядра для снятия дампа памяти Linux.",
    "Применяется при наличии возможности загрузки модуля на исследуемой системе.",
  ],
  "volatility3-linux": [
    "Разбор дампа памяти Linux средствами Volatility 3.",
    "Плагины linux_pslist, linux_bash, linux_malfind, linux_check_* выявляют скрытые процессы, изменения таблиц системных вызовов и внедрённый код.",
  ],
  "dwarf2json": [
    "Формирование профилей Volatility 3 из отладочной информации DWARF.",
    "Применяется при отсутствии готового профиля для используемой версии ядра.",
  ],
  "memprocfs-linux": [
    "Доступ к дампу памяти Linux через файловую систему.",
    "Позволяет исследовать образ стандартными командами без изучения плагинов.",
  ],
  "inodes-linux": [
    "Плагин Volatility 3 для получения метаданных inode.",
    "Показывает файлы, удерживаемые процессами, при недоступности сведений /proc.",
  ],
  "neo23x0-auditd": [
    "Базовая конфигурация auditd для Linux.",
    "Обеспечивает сбор событий по ядру и модулям, PAM и sudo, планировщику, сети, а также вызовам ptrace, bpf и memfd_create. Содержит блок правил af_alg для выявления эксплуатации CVE-2026-31431.",
  ],
  "recuva": [
    "Средство восстановления удалённых файлов.",
    "Применяется для получения удалённых журналов и документов, значимых для разбора.",
  ],
  "extundelete": [
    "Средство восстановления файлов на файловых системах ext3 и ext4.",
    "Применяется для получения удалённых журналов и конфигураций.",
    "Работы выполняются на образе тома: запись на исходный раздел снижает вероятность восстановления.",
  ],
  "testdisk": [
    "Средство восстановления разделов и загрузочных записей.",
    "Применяется при повреждении таблицы разделов для получения доступа к данным до начала разбора.",
  ],

  /* ------------------------------------------------------------- training */
  "tryhackme": [
    "Платформа практических лабораторий по информационной безопасности.",
    "Содержит интерактивные задания по сетевым атакам, анализу журналов и защите систем с проверкой результата.",
  ],
  "hackthebox": [
    "Платформа практических заданий по тестированию на проникновение.",
    "Позволяет пройти последовательность действий атакующего и оценить, какие из них фиксируются средствами защиты.",
  ],
  "cyberdefenders": [
    "Платформа лабораторий для специалистов blue team.",
    "Содержит сценарии, приближенные к задачам SOC: расследование инцидентов, форензика, охота на угрозы, с оформлением отчёта.",
  ],
  "phishme": [
    "Программа обучения сотрудников распознаванию фишинга.",
    "Включает имитацию фишинговых рассылок и обучающие материалы. Применяется для снижения числа инцидентов на этапе начального доступа.",
  ],
  "kc7cyber": [
    "Платформа с игровыми сценариями расследования инцидентов.",
    "Позволяет отработать поиск признаков атаки по журналам без предварительного опыта.",
  ],
  "thm-volatility": [
    "Практическое задание по анализу памяти средствами Volatility.",
    "Содержит задачи на разбор процессов, сетевых соединений и внедрённого кода в дампе памяти.",
  ],
  "thm-forensics": [
    "Практическое задание по основам форензики.",
    "Формирует базовые навыки интерпретации журналов и последовательности разбора системы.",
  ],
  "root-me": [
    "Набор задач по форензике и восстановлению данных.",
    "Позволяет отработать интерпретацию журналов и извлечение данных с обоснованием вывода.",
  ],
  "circl-training": [
    "Учебные материалы и образы от CERT Luxembourg.",
    "Содержит наборы образов диска, памяти и сетевых записей для практических упражнений.",
  ],
  "twitter-accounts": [
    "Перечень профилей по информационной безопасности.",
    "Используется для получения сведений о новых методах и образцах до выхода отчётов вендоров.",
  ],
  "threatexchange": [
    "Платформа обмена индикаторами между организациями.",
    "Обеспечивает закрытый обмен IOC с отраслевыми группами и партнёрами.",
  ],

  "tahiti-threat-hunting-methodology": [
    "Методика целевой охоты на угрозы (TaHiTI).",
    "Определяет последовательность охоты: формулирование гипотезы, выбор источников данных, критерии оценки результата. Применяется для регламентации деятельности SOC.",
  ],
  "cyber-hunting-maturity-model": [
    "Модель зрелости охоты на угрозы (HMM), уровни H0–H5.",
    "Позволяет определить текущий уровень практики и направление развития: от реакции на оповещения к охоте на основе гипотез.",
  ],
  "framework-for-threat-hunting": [
    "Белая книга с рамкой охоты на угрозы.",
    "Описывает методологию проведения охоты на основе гипотез. Применяется как основа внутреннего регламента.",
  ],
  "hunt-lateral-movement-via-explicit-credentials": [
    "Методика охоты: горизонтальное перемещение с явными учётными данными.",
    "Определяет запросы и логику проверки запуска процессов от имени другого пользователя, включая RunAs и использование кэшированных учётных данных.",
  ],
  "hunt-lateral-movement-via-windows-authentication-logs": [
    "Методика охоты по журналам аутентификации Windows.",
    "Описывает сопоставление событий 4624, 4625 и 4776 для отделения администрирования от перебора и перемещения по сети.",
  ],
  "hunt-lateral-movement-via-process-monitoring": [
    "Методика охоты по событиям создания процессов.",
    "Определяет признаки удалённого запуска: характер процессов, их родительские процессы и параметры командной строки.",
  ],
  "threat-hunting-in-large-datasets": [
    "Материал Cisco Talos по охоте в больших наборах данных.",
    "Рассматривает формулирование гипотезы и отбор полей при значительных объёмах событий.",
  ],
  "proactive-threat-hunting-tools-and-techniques": [
    "Обзор методов и инструментов проактивной охоты.",
    "Описывает последовательность действий от индикатора к системе и перечень применяемых средств.",
  ],
  "threat-hunting-tips-and-tools": [
    "Рекомендации GuidePoint по организации охоты.",
    "Содержит практические указания по планированию охоты и выбору инструментов.",
  ],
  "threat-hunting-techniques-checklist": [
    "Чек-лист методов охоты с метриками процесса.",
    "Содержит перечень методов и метрик, пригодный для отчётности о результатах охоты.",
  ],
  "effective-threat-hunting": [
    "Материал об организации охоты на угрозы.",
    "Разъясняет отличие охоты от мониторинга и условия её применения в SOC.",
  ],
  "who-what-where-when-why-and-how-of-effective-threat-hunting": [
    "Материал SANS о планировании охоты на угрозы.",
    "Определяет состав участников, источники данных, временные рамки и цели охоты.",
  ],
  "mitre-car-att-ck": [
    "Проект MITRE по сопоставлению аналитических методов с матрицей ATT&CK.",
    "Позволяет определить, какие методы анализа покрывают конкретные техники и где в наборе правил остаются пробелы.",
  ],
  "user-agent": [
    "Перечень значений User-Agent, характерных для сканеров и автоматизированных инструментов.",
    "Применяется для фильтрации на уровне обратного прокси и для анализа веб-логов. Позволяет отделить автоматизированное исследование периметра от пользовательского трафика.",
  ],
  "captian": [
    "Средство выявления инжектов в память и признаков бесфайловых атак.",
    "Исследует память процессов и обнаруживает несоответствия, характерные для внедрённого кода. Дополняет журналы событий данными, которые в них не фиксируются.",
  ],
  "notable-event-ids-tonyphipps": [
    "Справочник значимых Event ID Windows и Sysmon.",
    "Содержит назначение событий и связанные с ними признаки. Применяется при разработке правил и при разборе инцидентов.",
  ],
  "event-id": [
    "Карта Event ID Windows, применяемых при охоте и расследовании.",
    "Представляет события в структурированном виде и показывает сочетания, которые проверяются совместно.",
  ],
  "emerging-threats-suricata": [
    "Открытый набор правил Suricata от Proofpoint Emerging Threats.",
    "Служит базой для развёртывания сетевого детектирования. Требует ревизии под конкретную сеть: часть правил даёт ложные срабатывания в типовой корпоративной среде.",
  ],
  "tool-analysis-result-sheet-jpcert": [
    "Результаты поведенческого анализа утилит, применяемых в атаках.",
    "Содержит перечень событий и артефактов для каждой утилиты. Используется для проверки полноты детектирования конкретного инструмента.",
  ],
  "cti-news-opml": [
    "Файл подписок по информационной безопасности.",
    "Импортируется в RSS-агрегатор и формирует перечень источников без ручного отбора.",
  ],
  "abuse-ch-malwarebazaar": [
    "Хранилище образцов ВПО с метаданными.",
    "Обеспечивает доступ к образцам и хешам для проверки правил и анализа семейств.",
  ],
  "tor": [
    "Список выходных узлов сети TOR.",
    "Применяется для выявления подключений через TOR, не характерных для рабочей сети.",
    "Список формируется автоматически и требует периодического обновления.",
  ],
  "uuid-generator-v4": [
    "Генератор идентификаторов UUID версии 4.",
    "Применяется при описании объектов интерфейсов и полей в правилах и документации.",
  ],
  "sans-threat-hunting": [
    "Материал SANS о построении планов охоты.",
    "Связывает охоту с расследованием: определяет последовательность проверок и форму представления результата.",
  ],
  "sans-soc": [
    "Материал SANS о роли аналитика в SOC.",
    "Описывает представление результатов работы аналитика в форматах, применимых для управления SOC.",
  ],
  "sans-hunting": [
    "Материал SANS о построении программы охоты на угрозы.",
    "Рассматривает уровни зрелости, метрики и порядок развития программы.",
  ],
  "tryhackme-volatility-room": [
    "Практическое задание по анализу памяти средствами Volatility.",
    "Содержит задачи на разбор процессов, сетевых соединений и внедрённого кода в дампе памяти.",
  ],
  "tryhackme-forensics-room": [
    "Практическое задание по основам форензики.",
    "Формирует базовые навыки интерпретации журналов и последовательности разбора системы.",
  ],
  "root-me-forensic-challenges": [
    "Набор задач по форензике и восстановлению данных.",
    "Позволяет отработать интерпретацию журналов и извлечение данных с обоснованием вывода.",
  ],
  "circl": [
    "Учебные материалы и образы от CERT Luxembourg.",
    "Содержит наборы образов диска, памяти и сетевых записей для практических упражнений.",
  ],
  "speedguide": [
    "Справочник соответствия портов и использующих их сервисов.",
    "Используется при анализе сетевых соединений: позволяет определить типовое назначение порта и связанные с ним сервисы.",
  ],
  "sans-appcompatcacheparser": [
    "Средство разбора ShimCache (AppCompatCache).",
    "Дополняет Prefetch сведениями о пути и времени изменения файла, в том числе удалённого.",
  ],
  "mftexplorer": [
    "Графическое средство просмотра $MFT.",
    "Обеспечивает просмотр структуры каталогов и метаданных файлов без выгрузки в таблицы.",
  ],
};

/* Соответствие id записи ключу в таблице описаний. */
export const DESCRIPTION_ALIASES = {
  "ransomware-response-plan": "ransomware-response",
  "incident-response-reference-guide": "ir-reference-guide",
  "linux-ir-first-response": "linux-incident-response",
  "cuckoo-sandbox": "cuckoo",
  "malware-traffic-analysis-net": "malware-traffic-analysis",
  "volatility-3": "volatility3",
  "volatility-2": "volatility2",
  "magnet-ram-capture": "magnet-ram",
  "fex-memory-imager": "fex-memory",
  "volatility3-inodes-plugin": "inodes-plugin",
  "volatility3-prefetch-plugin": "prefetch-plugin",
  "phishme-cofense": "phishme",
  "twitter-security-accounts": "twitter-accounts",
  "facebook-threatexchange": "threatexchange",
  "mft-explorer": "mft-explorer",
};

/* Применяем профессиональные формулировки к записям. */
for (const tool of TOOLS) {
  const next = DESCRIPTIONS[tool.id] || DESCRIPTIONS[DESCRIPTION_ALIASES[tool.id]];
  if (!next) continue;
  tool.summary = next[0];
  tool.why = next[1];
  if (next.length > 2) tool.note = next[2];
  else delete tool.note;
}

/* Приводим старые id разделов к новой таксономии: данные могли писать по прежним ключам. */
for (const tool of TOOLS) {
  if (GROUP_ALIASES[tool.group]) tool.group = GROUP_ALIASES[tool.group];
  if (FORENSICS_PARTS.has(tool.group)) tool.group = "forensics";
  if (tool.group === "hunts" || tool.group === "community") tool.group = "training";
  if (tool.group === "tips") tool.group = "ir";
}