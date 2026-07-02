# Здесь укажи какие нормализованные события (одно или несколько) ты подаешь на вход правилу корреляции.
# События отделяются друг от друга символом новой строки. Каждое их них должно быть записано в строку.
{"action":"login","event_src.category":"AAA","event_src.fqdn":"dc01.work.local","event_src.hostname":"dc01","event_src.subsys":"System","event_src.title":"netlogon","event_src.vendor":"microsoft","id":"Microsoft_Windows_eventlog_Common_System_5805_The_session_setup_from_the_computer_failed_to_authenticate","importance":"medium","msgid":"5805","object":"system","status":"failure","subject":"account","subject.account.name":"dc01","subject.type":"host","time":"2026-06-28T14:40:58.000Z"}
{"action":"modify","category.generic":"Account","category.high":"Users And Rights Management","category.low":"Manipulation","datafield2":"-","event_src.category":"Directory service","event_src.fqdn":"dc01.work.local","event_src.hostname":"dc01","event_src.subsys":"Security","event_src.title":"windows","event_src.vendor":"microsoft","id":"PT_Microsoft_Windows_eventlog_4742_A_computer_account_was_changed","importance":"low","msgid":"4742","object":"account","object.account.domain":"work","object.account.id":"S-1-5-21-2790878447-3455683389-983535108-1002","object.account.name":"dc01$","object.new_value":"_PasswordLastSet:28.06.2026_17:40:58;","object.property":"modified attributes","status":"success","subject":"account","subject.account.domain":"nt authority","subject.account.id":"S-1-5-7","subject.account.name":"анонимный вход","subject.account.session_id":"998","time":"2026-06-28T14:40:58.716Z"}

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
expect 1 {"correlation_name":"Zerologon"}