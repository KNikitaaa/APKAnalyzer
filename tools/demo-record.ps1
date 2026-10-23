<#
  Автоматическая демонстрация APK AI Analyzer с записью видео.

  Скрипт сам управляет приложением внутри запущенного эмулятора через adb (ищет кнопки по тексту
  на экране и нажимает их) и записывает экран встроенным screenrecord. Мышь и клавиатура компьютера
  не используются — можно продолжать работать. Видео сохраняются в tools\demo\ (по сцене на файл).

  Запуск: двойной клик по tools\demo-record.bat (эмулятор должен быть запущен, приложение установлено).
#>
param([string]$Only = "")

$ErrorActionPreference = "Continue"
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$Root = Split-Path -Parent $PSScriptRoot
$Out = Join-Path $PSScriptRoot "demo"
$Tmp = Join-Path $env:TEMP "apk-demo-ui.xml"
New-Item -ItemType Directory -Force -Path $Out | Out-Null
$adb = Join-Path $env:LOCALAPPDATA "Android\Sdk\platform-tools\adb.exe"
if (-not (Test-Path $adb)) { Write-Host "Не найден adb: $adb"; exit 1 }

function Log($m) { Write-Host ("[{0}] {1}" -f (Get-Date -Format "HH:mm:ss"), $m) }
function Adb { & $adb @args 2>$null }
function Pause-Demo([double]$s) { Start-Sleep -Milliseconds ([int]($s * 1000)) }

# ---------------------------------------------------------------- устройство
$dev = (Adb devices) -match "^emulator-\d+\s+device|^\S+\s+device$"
if (-not $dev) { Log "Эмулятор не найден. Запустите его в Android Studio (Device Manager → ▶) и повторите."; exit 1 }
$size = ((Adb shell wm size) -join " ") -replace '.*?(\d+)x(\d+).*', '$1 $2'
$W, $H = $size.Split(" ") | ForEach-Object { [int]$_ }
Log "Экран устройства: ${W}x${H}"

if (-not ((Adb shell pm list packages com.apkanalyzer) -match "com.apkanalyzer")) {
    $apk = Join-Path $Root "app\build\outputs\apk\debug\app-debug.apk"
    if (-not (Test-Path $apk)) { Log "Приложение не установлено и не собрано. Нажмите Run ▶ в Android Studio."; exit 1 }
    Log "Устанавливаю приложение..."; Adb install -r $apk | Out-Null
}

# Образцы на устройство
Adb shell mkdir -p /sdcard/Download/apk-samples | Out-Null
Get-ChildItem (Join-Path $Root "samples") -Recurse -Filter *.apk -File -ErrorAction SilentlyContinue |
    ForEach-Object { Adb push $_.FullName "/sdcard/Download/apk-samples/$($_.Name)" | Out-Null }
Adb shell content call --method scan_volume --uri content://media --arg external_primary | Out-Null

# Показывать касания на видео
$oldTouches = (Adb shell settings get system show_touches) -join ""
Adb shell settings put system show_touches 1 | Out-Null

# ---------------------------------------------------------------- работа с экраном
function Get-Nodes {
    for ($i = 0; $i -lt 4; $i++) {
        Adb shell uiautomator dump /sdcard/apk-demo-ui.xml | Out-Null
        Adb pull /sdcard/apk-demo-ui.xml $Tmp | Out-Null
        try {
            [xml]$x = Get-Content $Tmp -Raw -Encoding UTF8
            return $x.SelectNodes("//node")
        } catch { Pause-Demo 0.7 }
    }
    return @()
}

function Find-Node([string]$pattern) {
    foreach ($n in Get-Nodes) {
        $t = [string]$n.text; $d = [string]$n.'content-desc'
        if (($t -and $t -match $pattern) -or ($d -and $d -match $pattern)) { return $n }
    }
    return $null
}

function Center($n) {
    $m = [regex]::Match([string]$n.bounds, '\[(\d+),(\d+)\]\[(\d+),(\d+)\]')
    return @((([int]$m.Groups[1].Value + [int]$m.Groups[3].Value) / 2), (([int]$m.Groups[2].Value + [int]$m.Groups[4].Value) / 2))
}

function Tap-Node($n) { $c = Center $n; Adb shell input tap ([int]$c[0]) ([int]$c[1]) | Out-Null }

function Tap-Text([string]$pattern, [int]$timeout = 10) {
    $deadline = (Get-Date).AddSeconds($timeout)
    while ((Get-Date) -lt $deadline) {
        $n = Find-Node $pattern
        if ($n) { Tap-Node $n; return $true }
        Pause-Demo 0.7
    }
    Log "  не нашёл на экране: $pattern"
    return $false
}

function Wait-Text([string]$pattern, [int]$timeout = 60) {
    $deadline = (Get-Date).AddSeconds($timeout)
    while ((Get-Date) -lt $deadline) { if (Find-Node $pattern) { return $true }; Pause-Demo 1 }
    Log "  не дождался: $pattern"
    return $false
}

function Swipe-Up([double]$fraction = 0.4, [int]$ms = 700) {
    $x = [int]($W / 2); $y1 = [int]($H * 0.75); $y2 = [int]($H * (0.75 - $fraction))
    Adb shell input swipe $x $y1 $x $y2 $ms | Out-Null
}

function Scroll-Top {
    $x = [int]($W / 2)
    for ($i = 0; $i -lt 8; $i++) { Adb shell input swipe $x ([int]($H * 0.3)) $x ([int]($H * 0.85)) 150 | Out-Null }
    Pause-Demo 0.8
}

function Scroll-To([string]$pattern, [int]$max = 20) {
    Scroll-Top
    for ($i = 0; $i -lt $max; $i++) {
        $n = Find-Node $pattern
        if ($n) {
            $c = Center $n
            if ($c[1] -lt $H * 0.85) { return $n }
        }
        Swipe-Up 0.35 600
        Pause-Demo 0.6
    }
    return $null
}

function Back { Adb shell input keyevent 4 | Out-Null; Pause-Demo 1 }

function Go-Home {
    for ($i = 0; $i -lt 6; $i++) {
        if (Find-Node '^Выбрать APK$') { return }
        Back
    }
    Adb shell am start -n com.apkanalyzer/.MainActivity | Out-Null
    Pause-Demo 2
}

function Pick-File([string]$name) {
    if (-not (Tap-Text '^Выбрать APK$')) { return $false }
    Pause-Demo 2
    $inFolder = $false
    $rootOpened = $false
    for ($i = 0; $i -lt 16; $i++) {
        $nodes = Get-Nodes
        $file = $nodes | Where-Object { [string]$_.text -eq $name } | Select-Object -First 1
        if ($file) { Tap-Node $file; return $true }
        # Уже внутри apk-samples (в строке пути есть «apk-samples»), — значит, файл ниже: листаем.
        $inside = $nodes | Where-Object { [string]$_.text -match '^0\d-.*\.apk$' } | Select-Object -First 1
        if ($inside) { $inFolder = $true }
        if (-not $inFolder) {
            $folder = $nodes | Where-Object { [string]$_.text -eq "apk-samples" } | Select-Object -First 1
            if ($folder) { Tap-Node $folder; $inFolder = $true; Pause-Demo 1.5; continue }
            if (-not $rootOpened) {
                $root = $nodes | Where-Object { [string]$_.text -match '^(Downloads|Загрузки|Download)$' } | Select-Object -First 1
                if ($root) { Tap-Node $root; $rootOpened = $true; Pause-Demo 1.5; continue }
                $menu = $nodes | Where-Object { [string]$_.'content-desc' -match 'Show roots|корнев|navigation|навигац|Меню|menu' } | Select-Object -First 1
                if ($menu) { Tap-Node $menu; Pause-Demo 1.2; continue }
            }
        }
        Swipe-Up 0.35 600; Pause-Demo 1
    }
    Log "  не удалось выбрать файл $name в окне выбора"
    Back
    return $false
}

# ---------------------------------------------------------------- запись сцен
$script:rec = $null
function Start-Scene([string]$name, [string]$title) {
    Log "Сцена: $title"
    $remote = "/sdcard/apk-demo-$name.mp4"
    Adb shell rm -f $remote | Out-Null
    $script:rec = Start-Process -FilePath $adb -ArgumentList @("shell", "screenrecord", "--bit-rate", "8000000", "--time-limit", "175", $remote) -PassThru -WindowStyle Hidden
    Pause-Demo 1.5
}
function Stop-Scene([string]$name) {
    Pause-Demo 1
    Adb shell pkill -INT screenrecord | Out-Null
    if ($script:rec) { $null = $script:rec.WaitForExit(15000) }
    Pause-Demo 2
    $local = Join-Path $Out "$name.mp4"
    Adb pull "/sdcard/apk-demo-$name.mp4" $local | Out-Null
    Adb shell rm -f "/sdcard/apk-demo-$name.mp4" | Out-Null
    if (Test-Path $local) { Log "  сохранено: $local" } else { Log "  ВНИМАНИЕ: видео сцены $name не сохранилось" }
}
function Want([string]$name) { return (-not $Only) -or ($Only -split ',' -contains $name) }

try {
    Adb shell am force-stop com.apkanalyzer | Out-Null
    Adb shell am start -n com.apkanalyzer/.MainActivity | Out-Null
    Pause-Demo 3

    if (Want "01") {
        Start-Scene "01-analiz-podozritelnogo-apk" "главный экран → выбор файла → анализ → высокий риск и доказательства"
        Go-Home; Pause-Demo 2.5
        if (Pick-File "01-suspicious-sms-autostart.apk") {
            Wait-Text 'Высокий риск' 90 | Out-Null
            Pause-Demo 3
            $f = Scroll-To 'Похоже на кражу SMS'
            if ($f) { Tap-Node $f; Pause-Demo 3 }
            for ($i = 0; $i -lt 10; $i++) { Swipe-Up 0.3 900; Pause-Demo 1.6 }
        }
        Stop-Scene "01-analiz-podozritelnogo-apk"
    }

    if (Want "02") {
        Start-Scene "02-pdf-otchet" "просмотр PDF-отчёта в приложении"
        $b = Scroll-To 'Открыть PDF-отчёт'
        if ($b) {
            Tap-Node $b; Pause-Demo 4
            for ($i = 0; $i -lt 3; $i++) { Swipe-Up 0.45 900; Pause-Demo 1.5 }
            Tap-Text '^\+$' 5 | Out-Null; Pause-Demo 2.5
            Swipe-Up 0.3 800; Pause-Demo 1.5
            Tap-Text '^−$' 5 | Out-Null; Pause-Demo 1.5
            Back; Pause-Demo 1.5
        }
        Stop-Scene "02-pdf-otchet"
    }

    if (Want "03") {
        Start-Scene "03-ai-obyasnenie" "AI-объяснение: согласие и предпросмотр отправляемых данных"
        $b = Scroll-To 'Получить AI-объяснение|Обновить объяснение'
        if ($b) {
            Tap-Node $b; Pause-Demo 3
            if (Find-Node 'Отправить факты в AI|Предпросмотр отправки') {
                Pause-Demo 3
                for ($i = 0; $i -lt 2; $i++) { Swipe-Up 0.2 800; Pause-Demo 1.5 }
                Tap-Text '^Отмена$' 5 | Out-Null
            } elseif (Find-Node 'Открыть настройки AI') {
                Pause-Demo 2
                Tap-Text 'Открыть настройки AI' 5 | Out-Null; Pause-Demo 2.5
                if (Tap-Text 'Добавить профиль' 5) { Pause-Demo 3; Swipe-Up 0.25 800; Pause-Demo 2; Tap-Text '^Отмена$' 5 | Out-Null }
                Pause-Demo 1.5; Back
            }
        }
        Stop-Scene "03-ai-obyasnenie"
    }

    if (Want "04") {
        Start-Scene "04-istoriya" "история анализов и сохранённый отчёт"
        Go-Home; Pause-Demo 1.5
        if (Tap-Text 'История анализов') {
            Pause-Demo 3
            if (Tap-Text 'com\.example\.sample' 8) { Pause-Demo 3; Swipe-Up 0.35 900; Pause-Demo 2; Back }
            Pause-Demo 1.5; Back
        }
        Stop-Scene "04-istoriya"
    }

    if (Want "05") {
        Start-Scene "05-problemnye-fajly" "чистый файл, zip-bomb и «не APK»: приложение не падает"
        Go-Home
        if (Pick-File "02-clean-launcher.apk") { Wait-Text 'Низкий риск' 60 | Out-Null; Pause-Demo 3.5; Go-Home }
        if (Pick-File "05-zip-bomb.apk") { Wait-Text 'Недостаточно данных' 90 | Out-Null; Pause-Demo 3.5; Go-Home }
        if (Pick-File "06-not-an-apk.apk") { Wait-Text 'не принят|не является APK' 60 | Out-Null; Pause-Demo 3.5; Go-Home }
        Stop-Scene "05-problemnye-fajly"
    }

    if (Want "06") {
        Start-Scene "06-nastrojki" "настройки AI, приватность и срок хранения истории"
        Go-Home
        if (Tap-Text 'Настройки AI и приватность') {
            Pause-Demo 3
            for ($i = 0; $i -lt 4; $i++) { Swipe-Up 0.3 900; Pause-Demo 1.5 }
            Back
        }
        Stop-Scene "06-nastrojki"
    }
} finally {
    Adb shell pkill -INT screenrecord | Out-Null
    if ($oldTouches -match '^\s*0') { Adb shell settings put system show_touches 0 | Out-Null }
    Adb shell rm -f /sdcard/apk-demo-ui.xml | Out-Null
}

Log "Готово. Видео: $Out"
Start-Process explorer.exe $Out
