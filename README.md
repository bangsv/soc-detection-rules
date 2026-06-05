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
 **CVE-2021-36942**<br>*(PetitPotam)* | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2021-36942) \| [📁 Папка](./CVE-2021-36942_PetitPotam) | `EfsRpcOpenFileRaw` (RPC-вызов)<br>`WERR_BAD_NETPATH` (RPC-ответ, главный IoC)<br>`NTLM Negotiate/Challenge/Authenticate`<br>`SMB port 445 (DC как клиент)`<br>`SMB2 Negotiate (Dialect 0x0202)` | `Sysmon ID: 3 (Initiated=false → DC:445)`<br>`Sysmon ID: 3 (Initiated=true → Attacker:445)`<br>`Sysmon ID: 18 (PipeConnected, \lsass)`<br>`SMBClient EID: 30805 (0xC00000C3)`<br>`SMBClient EID: 30816 (0xC00000CC)`<br>`SMBClient EID: 31012 (GUID {4141...})`<br>`SMBClient EID: 31013 (0xC000A000)`<br>`SMBServer EID: 551 (0xc000006d)`<br>`Security ID: 4624 (LogonType=3, NULL SID)` |
| **CVE-2026-27944**<br>*(Nginx UI)* | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-27944) \| [📁 Папка](./CVE-2026-27944_Nginx%20UI) |  `GET "/api/backup"` | `GET "/api/backup"` |
| *
