# Здесь укажи какие нормализованные события (одно или несколько) ты подаешь на вход правилу корреляции.
# События отделяются друг от друга символом новой строки. Каждое их них должно быть записано в строку.
{"action":"access","category.generic":"Directory Service Object","category.high":"System Management","category.low":"Manipulation","datafield2":"%%7688 {1131f6ad-9c07-11d1-f79f-00c04fc2dcd2} {19195a5b-6da0-11d0-afd3-00c04fd930c9}","datafield5":"0x100","event_src.category":"Operating system","event_src.fqdn":"dc01.work.local","event_src.hostname":"dc01","event_src.subsys":"Security","event_src.title":"windows","event_src.vendor":"microsoft","id":"PT_Microsoft_Windows_eventlog_4662_An_operation_was_performed_on_an_object","importance":"medium","msgid":"4662","object":"ds_object","object.name":"e1a8a6b0-92d8-4987-aae1-3fcdeea27ff8","object.type":"19195a5b-6da0-11d0-afd3-00c04fd930c9","status":"success","subject":"account","subject.account.domain":"work","subject.account.id":"S-1-5-21-2790878447-3455683389-983535108-1116","subject.account.name":"svc_replicator","subject.account.session_id":"3358641","time":"2026-06-19T21:15:36.645Z"}
{"action":"login","category.generic":"Operating System","category.high":"Access Management","category.low":"Communication","datafield6":"Network","datafield9":"NTLM","dst.fqdn":"dc01.work.local","dst.hostname":"dc01","event_src.category":"AAA","event_src.fqdn":"dc01.work.local","event_src.hostname":"dc01","event_src.subsys":"Security","event_src.title":"windows","event_src.vendor":"microsoft","id":"PT_Microsoft_Windows_eventlog_4624_An_account_was_successfully_logged_on","importance":"info","logon_auth_method":"remote","logon_service":"NtLmSsp","logon_type":3,"msgid":"4624","object":"system","src.ip":"192.168.0.30","src.port":43838,"status":"success","subject":"account","subject.account.domain":"work","subject.account.id":"S-1-5-21-2790878447-3455683389-983535108-1116","subject.account.name":"svc_replicator","subject.account.session_id":"3358584","time":"2026-06-19T21:15:36.550Z"}

# Тут будет твой модульный тест.
# Пример:
## создать для теста временную БД с табличными списками
# table_list default
## ожидаемое заполнение табличных списков
# table_list {"AD_Domain_Controllers":[{"ip":"8.8.8.8","hostname":"dc.contoso.com"}]}
## ожидаеммые события
# expect <число>|not|any {<через запятую пары "поле":"значение">}
    
table_list default
table_list {}
expect 1 {"correlation_name":"DCSync"}