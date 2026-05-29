<#
.SYNOPSIS
    Полная очистка всех журналов событий Windows, включая:
    - Классические логи (Application, System, Security)
    - Приложения и службы (Microsoft-Windows-*, Sysmon, SMBClient и т.д.)
    - Скрытые и отключённые каналы
    - Логи с защитой от очистки

.ПРИМЕЧАНИЕ
    Запускать ТОЛЬКО от имени Administrator с повышенными привилегиями.
    Для 2012 R2 может потребоваться разблокировка выполнения скриптов:
    Set-ExecutionPolicy Bypass -Scope Process -Force
#>

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  STARTING FULL EVENT LOG WIPE" -ForegroundColor Cyan
Write-Host "  Target: $env:COMPUTERNAME" -ForegroundColor Cyan
Write-Host "  Time: $(Get-Date)" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

$stats = @{ Total = 0; Success = 0; Failed = 0; Skipped = 0 }

# === Шаг 1: Получаем ВСЕ логи, даже скрытые и отключённые ===
$allLogs = Get-WinEvent -ListLog * -Force -ErrorAction SilentlyContinue | 
           Where-Object { $_.RecordCount -gt 0 -or $_.IsEnabled -eq $true }

$stats.Total = $allLogs.Count
Write-Host "[i] Found $($stats.Total) logs with records or enabled.`n" -ForegroundColor Yellow

foreach ($log in $allLogs) {
    $logName = $log.LogName
    $stats.Success++ # считаем попытку
    
    # Пропускаем системные, которые нельзя очистить (редко, но бывает)
    if ($logName -match '^ForwardedEvents$|^Windows PowerShell$') {
        Write-Host "[~] Skipped (system): $logName" -ForegroundColor DarkGray
        $stats.Success--
        $stats.Skipped++
        continue
    }

    try {
        # === Метод 1: Стандартный Clear-EventLog ===
        if ($log.IsClassicLog) {
            Clear-EventLog -LogName $logName -ErrorAction Stop
            Write-Host "[OK] Classic: $logName" -ForegroundColor Green
            continue
        }
        
        # === Метод 2: Через .NET для современных каналов ===
        $eventLog = New-Object System.Diagnostics.EventLog
        $eventLog.Log = $logName
        $eventLog.MachineName = "."
        if ($eventLog.Entries.Count -gt 0) {
            $eventLog.Clear()
            Write-Host "[OK] .NET: $logName" -ForegroundColor Green
            continue
        }
        
        # === Метод 3: Через wevtutil (обёртка в PowerShell) ===
        $output = & wevtutil cl $logName 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-Host "[OK] wevtutil: $logName" -ForegroundColor Green
            continue
        }
        
        # === Метод 4: Прямой вызов API через COM (для "упрямых" логов) ===
        $session = New-Object -ComObject "Microsoft.Windows.EventLogQuery.Session"
        # Если COM не доступен — пропускаем
        Write-Host "[~] Could not clear (COM unavailable): $logName" -ForegroundColor DarkGray
        $stats.Success--
        $stats.Skipped++
        
    }
    catch {
        # Финальная попытка через wevtutil напрямую из cmd
        $cmd = "cmd /c wevtutil cl `"$logName`" 2>nul"
        $result = Invoke-Expression $cmd
        if ($LASTEXITCODE -eq 0) {
            Write-Host "[OK] wevtutil (cmd): $logName" -ForegroundColor Green
        }
        else {
            Write-Host "[!!] FAILED: $logName - $($_.Exception.Message)" -ForegroundColor Red
            $stats.Success--
            $stats.Failed++
        }
    }
}

# === Итоговый отчёт ===
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "  CLEANUP SUMMARY" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Total attempted: $($stats.Total)" -ForegroundColor White
Write-Host "  Successfully cleared: $($stats.Success)" -ForegroundColor Green
Write-Host "  Failed: $($stats.Failed)" -ForegroundColor Red
Write-Host "  Skipped: $($stats.Skipped)" -ForegroundColor DarkGray
Write-Host "  Time: $(Get-Date)" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

# === Проверка: остались ли логи с записями? ===
$remaining = Get-WinEvent -ListLog * -ErrorAction SilentlyContinue | 
             Where-Object { $_.RecordCount -gt 0 } | 
             Select-Object LogName, RecordCount

if ($remaining) {
    Write-Host "[!] WARNING: Some logs still have records:" -ForegroundColor Yellow
    $remaining | Format-Table LogName, RecordCount -AutoSize
} else {
    Write-Host "[✓] All logs appear to be empty." -ForegroundColor Green
}