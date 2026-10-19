# 🛡️ SOC Detection Rules

**Автор:** Захарчук Юрий Александрович  
**Роль:** Аналитик SOC 

Репозиторий содержит базу знаний и правила детектирования для аналитиков SOC. Здесь собраны Sigma/XP/Suricata, Sysmon/Auditd-правила, PoC-скрипты и материалы для триажа инцидентов.

## 📁 Структура сценария

Каждый сценарий — отдельная папка с двумя частями:

```
CVE-2017-0143_EternalBlue/
├── README.md                  разбор атаки: журналы, этапы трафика, поля событий
├── detection_rule/            правила детектирования
│   ├── sigma_rules/           Sigma (YAML)
│   ├── suricata_rules/        Suricata IDS
│   ├── sysmon_rules/          конфигурация Sysmon (XML)
│   ├── auditd_rules/          auditd (правила для Linux-сценариев)
│   ├── elk_rules/             экспорт правил Elastic (NDJSON)
│   └── XP_rule_…/             нормализация и корреляция MaxPatrol SIEM
└── triage/                    материалы для разбора инцидента
    ├── wireshark/             дампы PCAPNG: успех, провал, легитимная активность
    ├── windows_logs/          EVTX и выгрузки Sysmon
    ├── linux_logs/            журналы Linux и auditd
    ├── suricata_logs/         eve.json, fast.log, stats.log
    └── output_cli_poc/        вывод эксплойта из терминала
```

Сайт сам находит правила и материалы по этим папкам: достаточно положить файл в нужное
место, регистрировать ничего не нужно.

---

## 🕵️ Threat Intelligence Reports

Полезные площадки с аналитическими отчётами, исследованиями APT-группировок и Threat Intelligence-фидами от ведущих российских ИБ-вендоров:

- 🟢 **[Kaspersky Threat Intelligence](https://www.kaspersky.ru/enterprise-security/threat-intelligence)** — сервисы и отчёты Kaspersky по анализу угроз, APT-репорты, TI-фиды
- 🔴 **[PT ESC Threat Intelligence](https://ptsecurity.com/research/pt-esc-threat-intelligence/)** — исследования Positive Technologies Expert Security Center
- 🟣 **[F6 Research Hub](https://www.f6.ru/resources/research-hub/)** — база исследований и отчётов F6 (ex. F.A.C.C.T. / Group-IB)
- 🔵 **[BI.ZONE Research](https://bi.zone/expertise/research/)** — аналитические материалы и отчёты BI.ZONE

---


## 🖥️ Hosts (Lab Environment)

| IP               | Hostname | Role / OS                  | Notes                                      |
| :--------------- | :------- | :-------------------------- | :------------------------------------------ |
| **192.168.0.10**  | `dc01`   | Windows Server — Domain Controller (primary) | Основной DC, источник событий 4624/4662, DRSUAPI |
| **192.168.0.100** | `dc02`   | Windows Server — Domain Controller (secondary) | Вторичный DC / реплика                      |
| **192.168.0.15**  | —        | Windows 10/11 Desktop       | Рабочая станция, точка входа для клиентских атак (PetitPotam, EternalBlue) |
| **192.168.0.30**  | —        | Kali Linux                  | Атакующая машина / хост для PoC и инструментов (Impacket, Responder и т.д.) |

---

## 📋 Information about CVE

| CVE / Technique    | Title                                                           | Description                                                                                                                                                                                                          | Link                                                                                              |
| :----------------- | :-------------------------------------------------------------- | :------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | :------------------------------------------------------------------------------------------------ |
| **CVE-2017-0143**  | Windows SMB Remote Code Execution Vulnerability *(EternalBlue)* | Уязвимость SMBv1 в Windows, позволяющая удалённому атакующему выполнить произвольный код с помощью специально сформированных SMB-пакетов.                                                                            | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2017-0143) · [Detection](./CVE-2017-0143_EternalBlue)  |
| **CVE-2021-36942** | Windows EFS RPC Service Vulnerability *(PetitPotam)*            | Уязвимость EFS RPC позволяет инициировать принудительную аутентификацию Windows-системы. В сочетании с NTLM Relay может использоваться для дальнейшей атаки на инфраструктуру Active Directory.                      | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2021-36942) · [Detection](./CVE-2021-36942_PetitPotam) |
| **CVE-2026-27944** | Nginx UI Vulnerability                                          | Уязвимость Nginx UI, для которой характерным сетевым индикатором в данном наборе правил является обращение к API endpoint `/api/backup`.                                                                             | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-27944) · [Detection](./CVE-2026-27944_Nginx%20UI) |
| **DCSync**         | DCSync / NTDS.dit Dump                                          | Техника получения учетных данных Active Directory посредством злоупотребления механизмом репликации каталога. Для обнаружения используются сетевые признаки DRSUAPI/DRSGetNCChanges и событие Windows Security 4662. | [MITRE T1003.006](https://attack.mitre.org/techniques/T1003/006/) · [Detection](./DCSync)         |

---

## 🔎 Detection

| Attack                          | Detection                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| :------------------------------ | :----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **EternalBlue (CVE-2017-0143)** | **Sysmon Event ID: 3**<br>  └─ Network connection<br><br>**Security Event ID: 4624**<br>  └─ An account was successfully logged on<br><br>**Network IOC**<br>  └─ `Trans2 Response: STATUS_INVALID_PARAMETER (0xc000000d)`                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| **PetitPotam (CVE-2021-36942)** | **Sysmon Event ID: 3**<br>  └─ `Initiated=false → DC:445`<br>  └─ `Initiated=true → Attacker:445`<br><br>**Sysmon Event ID: 18**<br>  └─ `PipeConnected`<br><br>**SMBClient Event ID: 30805**<br>  └─ `0xC00000C3`<br><br>**SMBClient Event ID: 30816**<br>  └─ `0xC00000CC`<br><br>**SMBClient Event ID: 31012**<br>  └─ `GUID {4141...}`<br><br>**SMBClient Event ID: 31013**<br>  └─ `0xC000A000`<br><br>**SMBServer Event ID: 551**<br>  └─ `0xc000006d`<br><br>**Security Event ID: 4624**<br>  └─ `LogonType=3, NULL SID`<br><br>**Network IOC**<br>  └─ `EfsRpcOpenFileRaw`<br>  └─ `WERR_BAD_NETPATH`<br>  └─ `NTLM Negotiate / Challenge / Authenticate`<br>  └─ `SMB TCP/445 (DC as client)` |
| **Nginx UI (CVE-2026-27944)**   | **HTTP Request**<br>  └─ `GET /api/backup`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| **DCSync (T1003.006)**          | **Security Event ID: 4624**<br>  └─ `Logon Type: 3`<br><br>**Security Event ID: 4662**<br>  └─ `ObjectServer: DS`<br>  └─ `AccessMask: 0x100`<br>  └─ `Properties: 1131f6aa-9c07-11d1-f79f-00c04fc2dcd2`<br>    └─ `Replicating Directory Changes All`<br><br>**DRSUAPI**<br>  └─ UUID: `e3514235-4b06-11d1-ab04-00c04fc2dcd2`<br>  └─ `DRSGetNCChanges (Opnum: 3)`                                                                                                                                                                                                                                                                                                                                    |

---

## 🌐 Network Detection

| Attack                          | Network IOC                                                                                                                                                                                                                                                                    |
| :------------------------------ | :----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **EternalBlue (CVE-2017-0143)** | **SMB Trans2 Response**<br>  └─ `NT Status: STATUS_INVALID_PARAMETER (0xc000000d)`                                                                                                                                                                                             |
| **PetitPotam (CVE-2021-36942)** | **EFS RPC**<br>  └─ `EfsRpcOpenFileRaw`<br>  └─ `WERR_BAD_NETPATH`<br><br>**NTLM**<br>  └─ `Negotiate / Challenge / Authenticate`<br><br>**SMB**<br>  └─ `TCP/445 (DC as client)`<br>  └─ `SMB2 Negotiate (Dialect 0x0202)`                                                    |
| **DCSync (T1003.006)**          | **RPC Endpoint Mapper**<br>  └─ `TCP/135`<br><br>**DRSUAPI**<br>  └─ UUID: `e3514235-4b06-11d1-ab04-00c04fc2dcd2`<br>  └─ `DRSGetNCChanges (Opnum: 3)`<br><br>**RPC**<br>  └─ Dynamic RPC port<br>  └─ `Auth Level: Packet Privacy`<br>  └─ Large fragmented DCE/RPC responses |
| **Nginx UI (CVE-2026-27944)**   | **HTTP Request**<br>  └─ `GET /api/backup`                                                                                                                                                                                                                                     |

---

## 💻 Host Detection

| Attack                          | Windows / Linux IOC                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| :------------------------------ | :----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **EternalBlue (CVE-2017-0143)** | **Sysmon Event ID: 3**<br>  └─ Network connection<br><br>**Security Event ID: 4624**<br>  └─ An account was successfully logged on                                                                                                                                                                                                                                                                                                                                                                                              |
| **PetitPotam (CVE-2021-36942)** | **Sysmon Event ID: 3**<br>  └─ `Initiated=false → DC:445`<br>  └─ `Initiated=true → Attacker:445`<br><br>**Sysmon Event ID: 18**<br>  └─ `PipeConnected`<br><br>**SMBClient Event ID: 30805**<br>  └─ `0xC00000C3`<br><br>**SMBClient Event ID: 30816**<br>  └─ `0xC00000CC`<br><br>**SMBClient Event ID: 31012**<br>  └─ `GUID {4141...}`<br><br>**SMBClient Event ID: 31013**<br>  └─ `0xC000A000`<br><br>**SMBServer Event ID: 551**<br>  └─ `0xc000006d`<br><br>**Security Event ID: 4624**<br>  └─ `LogonType=3, NULL SID` |
| **Nginx UI (CVE-2026-27944)**   | **HTTP Request**<br>  └─ `GET /api/backup`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| **DCSync (T1003.006)**          | **Security Event ID: 4624**<br>  └─ `Logon Type: 3`<br><br>**Security Event ID: 4662** — An operation was performed on an object<br>  └─ `ObjectServer: DS`<br>  └─ `AccessMask: 0x100`<br>  └─ `Properties: 1131f6aa-9c07-11d1-f79f-00c04fc2dcd2`<br>    └─ `Replicating Directory Changes All`                                                                                                                                                                                                                                |

---

## 📚 Attack Resources

| Attack                      | Resources                                                                                                                                               |
| :-------------------------- | :------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **Zerologon**               | [Habr — Zerologon](https://habr.com/ru/companies/bizone/articles/526168/)<br>[Habr — Zerologon](https://habr.com/ru/companies/rvision/articles/743142/) |
| **PetitPotam / NTLM Relay** | [Habr — PetitPotam / NTLM Relay](https://habr.com/ru/companies/ussc/articles/688682/)<br>[Hackndo — NTLM Relay](https://en.hackndo.com/ntlm-relay/)     |
| **DCSync**                  | [Habr — DCSync](https://habr.com/ru/companies/rvision/articles/709866/)<br>[Habr — DCSync](https://habr.com/ru/companies/rvision/articles/709942/)      |
| **EternalBlue (MS17-010)**  | [Habr — EternalBlue / MS17-010](https://habr.com/ru/companies/k2tech/articles/892202/)                                                                  |

---

## 🖥️ Веб-атлас (SOC Atlas)

Поверх репозитория работает FastAPI-приложение `app/` — интерактивный атлас правил и
индикаторов. Всё, что показывает сайт, берётся из файлов репозитория.

```bash
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000     # http://127.0.0.1:8000
```

| Раздел | Что делает |
| :--- | :--- |
| **Поиск по индикаторам** | Единый индекс: авторские IOC, технические фрагменты из README, названия сценариев и пояснения. Быстрые фильтры и фасеты по типу. |
| **Карта сценариев** | Сценарии с критичностью, платформой, тактиками ATT&CK, числом индикаторов, правил и материалов. Фильтры по критичности, платформе и тактике. |
| **Консоль сценария** | Вектор атаки, на что смотреть в логах, таблица стенда, группы Host / Network IOC с пояснениями, ссылки на источники, экспорт в CSV, ZIP и открытие README. |
| **Правила сценария** | Все правила из `detection_rule/`: Sigma, Suricata, Sysmon, auditd, ELK и XP (нормализация / корреляция). Вкладки по типам, просмотр кода, копирование одного правила или всего набора, скачивание файла. |
| **Материалы triage** | Файлы из `triage/` карточками для скачивания, по группам: дампы Wireshark, журналы Windows и Linux, логи Suricata, вывод PoC, хеши. На карточке — формат, имя файла, размер и сценарий прогона (metasploit / mimikatz). Поиск по имени, скачивание всего набора одним ZIP. |
| **База знаний** | README репозитория: список документов слева, текст по центру, содержание документа — в правой колонке с подсветкой текущего раздела. Листинги копируются, скриншоты открываются в лайтбоксе. |
| **Командная палитра** | `Ctrl + K` — поиск по сценариям, индикаторам, фрагментам и документам, плюс быстрые действия. |
| **Набор IOC** | Сбор индикаторов из поиска и сценариев в один список с копированием и выгрузкой в `.txt`. |
| **Инструменты** (`/tools`) | База знаний аналитика SOC: 193 записи в 10 разделах — threat hunting и методики (TaHiTI, HMM, hunts), сеть, уязвимости и бенчмарки, мониторинг и Event ID, техники атакующих и YARA, threat intelligence, реагирование и чек-листы, малварь и фишинг, форензика (общая, память, Windows, Linux), обучение. Плюс материалы из BlueTeam-Tools, Eric Zimmerman, Awesome Memory Forensics, DFIR Toolkit и Linux Incident Response. Фильтры по задаче, формату, платформе и источнику, поиск по описаниям. Данные — в `app/static/js/tools-data.js`. |

### Как атлас находит правила

| Тип | Что распознаётся |
| :--- | :--- |
| **Sigma** | папка `sigma_rules/`, файл `sigma.yml`, любой YAML с `title:` / `logsource:` / `detection:` |
| **Suricata** | папка `suricata_rules/`, файлы `*.rules` |
| **Sysmon** | папка `sysmon_rules/`, `sysmon.xml` |
| **auditd** | папка `auditd_rules/`, `audit.rules` |
| **ELK / Elastic** | папка `elk_rules/`, `*.ndjson` |
| **XP · нормализация** | папка `normalization_rule/` |
| **XP · корреляция** | папка `correlation_rule/`, файлы `rule.co`, `formula.xp` |
| **KUMA / MaxPatrol / Wazuh / Splunk** | файлы и папки с соответствующими именами; список типов — `RULE_KINDS` в `app/main.py` |

Служебные файлы (`metainfo.yaml`, `normalization_event.txt`, переводы `i18n`, каталоги
`tests/`) в список не попадают. Содержимое правила загружается только при открытии —
страница не утяжеляется, даже если правил в сценарии десятки.

### Как атлас находит материалы triage

Берутся все файлы из папки `triage/` сценария, группы — по подпапке: `wireshark`,
`windows_logs`, `linux_logs`, `suricata_logs`, `output_cli_poc` (вывод PoC), хеши.
Если логи разложены по инструментам (`suricata_logs/metasploit/eve.json` и
`suricata_logs/mimikatz/eve.json`), на карточке видно, к какому прогону относится файл.

Содержимое файлов в атласе не показывается: карточка — это ссылка на скачивание.
Открывают файлы в своих программах: `.pcapng` — Wireshark, `.evtx` — Просмотр событий
Windows, логи и JSON — текстовый редактор.

---

**© 2026 Захарчук Юрий Александрович** — Все права защищены.  
Данный материал подготовлен для внутреннего использования в SOC и образовательных целях.
