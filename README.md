# 🛡️ SOC Detection Rules

[![License: MIT](https://img.shields.io/badge/License-Educational-blue.svg)]()
[![Last Update](https://img.shields.io/badge/Last%20Update-June%202026-green.svg)]()
[![Rules Count](https://img.shields.io/badge/Rules-3%20CVE-orange.svg)]()

Репозиторий содержит базу знаний и правил детектирования для аналитиков SOC. Здесь собраны Sigma/XP/Suricata,Sysmon/Auditd-правила, PoC-скрипты и материалы для триажа инцидентов.

---

## 📊 Матрица детектирования (CVE + IOC)

> 💡 *Используйте `Ctrl + F` для поиска.*

| CVE (Название) | Описание / NVD | 🌐 IOC Network Traffic | 💻 IOC Windows / Linux Host |
| :--- | :--- | :--- | :--- |
| **CVE-2017-0143**<br>*(EternalBlue)* | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2017-0143) \| [📁 Папка](./CVE-2017-0143_EternalBlue) | `Trans2 Response: NT Status: STATUS_INVALID_PARAMETER (0xc000000d)` | `Sysmon ID: 3`<br>`Security ID: 4624` |
| **CVE-2021-36942**<br>*(PetitPotam)* | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2021-36942) \| [📁 Папка](./CVE-2021-36942_PetitPotam) |  `EFS Response: ERROR_BAD_NETPATH` | `Sysmon ID: 3, 18` |
| **CVE-2026-27944**<br>*(Nginx UI)* | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-27944) \| [📁 Папка](./CVE-2026-27944_Nginx%20UI) |  `GET "/api/backup"` | `GET "/api/backup"` |
| *
