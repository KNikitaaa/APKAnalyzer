# Декларация QUERY_ALL_PACKAGES для Google Play

С Android 11 приложение по умолчанию не видит другие установленные пакеты (package visibility).
APK AI Analyzer проверяет установленные приложения на признаки вредоносного поведения, поэтому
ему нужен полный список пакетов. В манифесте объявлено `android.permission.QUERY_ALL_PACKAGES`.

Google Play разрешает это разрешение только для одобренных сценариев. Антивирусы и сканеры
безопасности (*device security / anti-malware*) входят в этот список, но перед публикацией
нужно заполнить декларацию в Play Console:
**Policy → App content → Permissions declaration → QUERY_ALL_PACKAGES**.

## Текст для формы (на английском, как требует Play Console)

**Core purpose of the app:**
APK AI Analyzer is an on-device security scanner. Users check APK files and apps installed on
their device for signs of malicious or risky behavior (dangerous permissions, exported components,
SMS/accessibility abuse, packers, hidden payloads, suspicious network indicators).

**Why the app needs broad package visibility:**
Scanning installed apps is the core feature. Malware often has no launcher icon and hides as
a background service, so a `<queries>` element limited to launcher intents would miss exactly the
apps that need checking. The app lists installed packages only when the user opens the
"Installed apps" screen, and reads an app's APK only after the user selects it.

**How the data is used:**
The package list and APK contents are analyzed locally on the device. They are not sent to any
server, sold or shared. The optional AI explanation sends only a short set of findings from the
report (never the APK or the package list), and only after explicit user consent for each request.

**Video demonstration:**
Record a short screen capture: Home → "Check installed apps" → choose an app → report with
evidence → "Uninstall" opens the system confirmation dialog.

## Если декларацию не одобрят

Удалите разрешение из манифеста сборки для Play (или добавьте `tools:node="remove"` в манифест
отдельного варианта сборки). Приложение продолжит работать:

* через `<queries>` останутся видны приложения с иконкой в лаунчере;
* экран «Установленные приложения» покажет предупреждение, что видны не все приложения;
* любое приложение по-прежнему можно проверить, выбрав его APK-файл.

## Что приложение не делает

* Не удаляет приложения само: кнопка «Удалить» открывает системное окно Android
  (`ACTION_DELETE`), удаление подтверждает пользователь. Для этого объявлено
  `REQUEST_DELETE_PACKAGES`.
* Не отключает и не останавливает приложения: для этого есть переход в системные
  «Сведения о приложении».
* Не копирует APK установленных приложений: они читаются на месте и только на чтение.
