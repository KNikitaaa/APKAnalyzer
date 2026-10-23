package com.apkanalyzer.rules

import com.apkanalyzer.analyzer.archive.ArchiveAnomalyType
import com.apkanalyzer.analyzer.contents.PayloadKind
import com.apkanalyzer.analyzer.dex.ApiCategory
import com.apkanalyzer.analyzer.manifest.ComponentType
import com.apkanalyzer.analyzer.strings.IndicatorExtractor
import com.apkanalyzer.analyzer.strings.IndicatorType
import com.apkanalyzer.rules.ApkFacts.Companion.ARCHIVE
import com.apkanalyzer.rules.ApkFacts.Companion.MANIFEST
import com.apkanalyzer.rules.ApkFacts.Companion.SIGNATURE
import com.apkanalyzer.rules.BehaviorCategory.CODE_LOADING
import com.apkanalyzer.rules.BehaviorCategory.DATA_COLLECTION
import com.apkanalyzer.rules.BehaviorCategory.DEVICE_CONTROL
import com.apkanalyzer.rules.BehaviorCategory.EVASION
import com.apkanalyzer.rules.BehaviorCategory.HYGIENE
import com.apkanalyzer.rules.BehaviorCategory.NETWORK
import com.apkanalyzer.rules.BehaviorCategory.PERSISTENCE
import com.apkanalyzer.rules.BehaviorCategory.PHISHING_OVERLAY
import com.apkanalyzer.rules.BehaviorCategory.PRIVILEGE
import com.apkanalyzer.rules.BehaviorCategory.SMS_CALLS
import com.apkanalyzer.rules.BehaviorCategory.SURVEILLANCE

/**
 * Набор правил версии [RuleCatalog.VERSION].
 *
 * Принципы весов:
 *  - распространённые разрешения (камера, контакты, геолокация) — 3–6 очков: сами по себе ничего не доказывают;
 *  - редкие и мощные возможности (Accessibility, Device Admin, скрытый код, трюки против анализа) — 12–35;
 *  - связки признаков, описывающие типичное вредоносное поведение, — 25–55.
 * Любое изменение правил или весов обязано менять VERSION — это записывается в отчёт.
 */
object RuleCatalog {
    const val VERSION = "2026.10.1"

    private fun hit(evidence: List<Evidence>, confidence: Float = 1f): Hit? =
        if (evidence.isEmpty()) null else Hit(evidence, confidence)

    private fun signal(
        id: String, title: String, description: String, category: BehaviorCategory, weight: Int,
        informational: Boolean = false, check: (ApkFacts) -> Hit?,
    ) = Rule(id, title, description, category, weight, RuleKind.SIGNAL, informational, emptyList(), check)

    private fun combo(
        id: String, title: String, description: String, category: BehaviorCategory, weight: Int,
        vararg requires: Set<String>,
    ) = Rule(id, title, description, category, weight, RuleKind.COMBINATION, false, requires.toList())

    private val SUSPICIOUS_TLDS = setOf(
        "top", "xyz", "tk", "ml", "ga", "cf", "gq", "pw", "icu", "click", "link", "work", "cc", "su", "onion",
        "buzz", "rest", "cyou", "monster", "lol", "sbs", "cfd", "zip", "mov",
    )
    private val DYNAMIC_DNS = listOf("duckdns.org", "no-ip.", "ddns.net", "ngrok", "serveo.net", "dynu.", "hopto.org", "zapto.org")
    private val MESSENGER_C2 = listOf("api.telegram.org", "discord.com/api/webhooks", "discordapp.com/api/webhooks", "hooks.slack.com")
    private val BOOT_ACTIONS = listOf(
        "android.intent.action.BOOT_COMPLETED", "android.intent.action.LOCKED_BOOT_COMPLETED",
        "android.intent.action.QUICKBOOT_POWERON", "com.htc.intent.action.QUICKBOOT_POWERON",
    )

    val signals: List<Rule> = listOf(
        // ---------------------------------------------------------------- SMS и звонки
        signal("SMS_READ", "Чтение SMS", "Приложение может читать или перехватывать входящие SMS — в них приходят коды подтверждения банков.", SMS_CALLS, 8) { f ->
            hit(
                f.permissionEvidence("READ_SMS", "RECEIVE_SMS", "RECEIVE_MMS", "RECEIVE_WAP_PUSH") +
                    f.componentsWithAction("android.provider.Telephony.SMS_RECEIVED").map { f.componentEvidence(it, "ловит входящие SMS") } +
                    f.indicatorEvidence(f.indicatorsOf(IndicatorType.CONTENT_URI).filter { it.value.startsWith("content://sms", true) || it.value.startsWith("content://mms", true) }),
            )
        },
        signal("SMS_SEND", "Отправка SMS", "Приложение может отправлять SMS без участия пользователя — в том числе на платные номера.", SMS_CALLS, 10) { f ->
            val perm = f.permissionEvidence("SEND_SMS")
            val api = f.apiEvidence(f.apis("Landroid/telephony/SmsManager;", "sendTextMessage", "sendMultipartTextMessage", "sendDataMessage"))
            hit(perm + api, if (perm.isNotEmpty() && api.isNotEmpty()) 1f else 0.7f)
        },
        signal("CALLS_ACCESS", "Доступ к звонкам", "Чтение журнала звонков, совершение или перехват вызовов.", SMS_CALLS, 6) { f ->
            hit(f.permissionEvidence("READ_CALL_LOG", "WRITE_CALL_LOG", "PROCESS_OUTGOING_CALLS", "CALL_PHONE", "ANSWER_PHONE_CALLS"))
        },

        // ---------------------------------------------------------------- Слежка
        signal("MIC_RECORD", "Запись звука", "Доступ к микрофону.", SURVEILLANCE, 5) { f ->
            hit(f.permissionEvidence("RECORD_AUDIO") + if (f.hasPermission("RECORD_AUDIO")) f.apiEvidence(f.apis(ApiCategory.AUDIO_RECORD)) else emptyList())
        },
        signal("CAMERA_ACCESS", "Камера", "Доступ к камере.", SURVEILLANCE, 3) { f -> hit(f.permissionEvidence("CAMERA")) },
        signal("LOCATION_ANY", "Геолокация", "Доступ к местоположению.", SURVEILLANCE, 3) { f ->
            hit(f.permissionEvidence("ACCESS_FINE_LOCATION", "ACCESS_COARSE_LOCATION"))
        },
        signal("LOCATION_BACKGROUND", "Геолокация в фоне", "Отслеживание местоположения, даже когда приложение закрыто.", SURVEILLANCE, 10) { f ->
            hit(f.permissionEvidence("ACCESS_BACKGROUND_LOCATION"))
        },
        signal("SCREEN_CAPTURE", "Захват экрана", "Код для записи или трансляции содержимого экрана.", SURVEILLANCE, 8) { f ->
            hit(f.apiEvidence(f.apis(ApiCategory.SCREEN_CAPTURE)))
        },
        signal("NOTIFICATION_LISTENER", "Чтение уведомлений", "Служба получает текст всех уведомлений, включая коды из SMS и мессенджеров.", SURVEILLANCE, 12) { f ->
            hit(f.componentsBoundBy("BIND_NOTIFICATION_LISTENER_SERVICE").map { f.componentEvidence(it) })
        },

        // ---------------------------------------------------------------- Сбор данных
        signal("CONTACTS_ACCOUNTS", "Контакты и аккаунты", "Доступ к списку контактов или аккаунтов на устройстве.", DATA_COLLECTION, 4) { f ->
            hit(f.permissionEvidence("READ_CONTACTS", "GET_ACCOUNTS"))
        },
        signal("DEVICE_IDS", "Идентификаторы устройства", "Чтение IMEI, IMSI, номера телефона или серийного номера SIM.", DATA_COLLECTION, 5) { f ->
            hit(f.permissionEvidence("READ_PHONE_STATE", "READ_PHONE_NUMBERS", "READ_PRIVILEGED_PHONE_STATE") + f.apiEvidence(f.apis(ApiCategory.TELEPHONY_ID)))
        },
        signal("CLIPBOARD_READ", "Чтение буфера обмена", "Код читает буфер обмена (там бывают пароли и адреса кошельков).", DATA_COLLECTION, 3) { f ->
            hit(f.apiEvidence(f.apis(ApiCategory.CLIPBOARD)))
        },

        // ---------------------------------------------------------------- Автозапуск и скрытность
        signal("BOOT_AUTOSTART", "Автозапуск при включении", "Приложение запускается само после перезагрузки телефона.", PERSISTENCE, 3) { f ->
            val receivers = BOOT_ACTIONS.flatMap { f.componentsWithAction(it, ComponentType.RECEIVER) }.distinct()
            hit(if (receivers.isEmpty()) emptyList() else f.permissionEvidence("RECEIVE_BOOT_COMPLETED") + receivers.map { f.componentEvidence(it, "запуск при загрузке") })
        },
        signal("NO_LAUNCHER_ICON", "Нет иконки в меню", "У приложения нет значка для запуска — пользователь может не знать, что оно установлено.", PERSISTENCE, 10) { f ->
            if (f.manifest != null && !f.hasLauncher) Hit(listOf(Evidence(MANIFEST, "нет activity с MAIN + LAUNCHER"))) else null
        },
        signal("HIDE_ICON_API", "Скрытие значка из кода", "Код умеет отключать свои компоненты — так обычно прячут иконку после первого запуска.", PERSISTENCE, 6) { f ->
            hit(f.apiEvidence(f.apis(ApiCategory.HIDE_ICON)))
        },

        // ---------------------------------------------------------------- Загрузка кода
        signal("DYNAMIC_CODE", "Загрузка кода во время работы", "Приложение может подгружать и выполнять код, которого нет в APK на момент проверки.", CODE_LOADING, 6) { f ->
            hit(f.apiEvidence(f.apis(ApiCategory.DYNAMIC_CODE)))
        },
        signal("INSTALL_PACKAGES", "Установка других приложений", "Может предлагать установить другие APK.", CODE_LOADING, 6) { f ->
            hit(f.permissionEvidence("REQUEST_INSTALL_PACKAGES", "INSTALL_PACKAGES", "DELETE_PACKAGES") + f.apiEvidence(f.apis(ApiCategory.PACKAGE_INSTALL)))
        },
        signal("HIDDEN_PAYLOAD", "Скрытый исполняемый код", "Внутри APK вне стандартных мест лежит DEX, APK или нативный файл — типичный приём «дропперов».", CODE_LOADING, 25) { f ->
            hit(f.hiddenPayloads.filter { it.kind != PayloadKind.MISNAMED }.map { Evidence(it.path, it.kind.labelRu) })
        },
        signal("HIDDEN_PAYLOAD_DISGUISED", "Код под видом картинки или данных", "Исполняемый файл замаскирован под изображение/данные — сильный признак сокрытия.", EVASION, 35) { f ->
            hit(f.hiddenPayloads.filter { it.kind == PayloadKind.MISNAMED }.map { Evidence(it.path, "на самом деле исполняемый код") })
        },

        // ---------------------------------------------------------------- Контроль устройства
        signal("ACCESSIBILITY_SERVICE", "Служба специальных возможностей", "Может читать экран и нажимать за пользователя в любых приложениях, включая банковские.", DEVICE_CONTROL, 18) { f ->
            val services = f.componentsBoundBy("BIND_ACCESSIBILITY_SERVICE")
            hit(if (services.isEmpty()) emptyList() else services.map { f.componentEvidence(it) } + f.apiEvidence(f.apis(ApiCategory.ACCESSIBILITY)))
        },
        signal("DEVICE_ADMIN", "Права администратора устройства", "Запрашивает права администратора — такое приложение сложно удалить.", DEVICE_CONTROL, 15) { f ->
            hit((f.componentsBoundBy("BIND_DEVICE_ADMIN") + f.componentsWithAction("android.app.action.DEVICE_ADMIN_ENABLED")).distinct().map { f.componentEvidence(it) })
        },
        signal("DEVICE_ADMIN_DESTRUCTIVE_API", "Блокировка или стирание устройства", "Код вызывает блокировку экрана, смену пароля или сброс данных.", DEVICE_CONTROL, 10) { f ->
            hit(f.apiEvidence(f.apis(ApiCategory.DEVICE_ADMIN)))
        },

        // ---------------------------------------------------------------- Фишинг и оверлеи
        signal("OVERLAY_WINDOWS", "Окна поверх других приложений", "Может рисовать поверх других приложений — так подделывают окна входа в банк.", PHISHING_OVERLAY, 6) { f ->
            hit(f.permissionEvidence("SYSTEM_ALERT_WINDOW"))
        },

        // ---------------------------------------------------------------- Сокрытие
        signal("PACKER", "Упаковщик / протектор", "Код упакован или защищён коммерческим протектором: настоящее содержимое скрыто от анализа. Используется и легальными приложениями.", EVASION, 15) { f ->
            hit(f.packers.map { Evidence(it.evidence, it.name) }, confidence = 0.7f)
        },
        signal("ARCHIVE_TRICKS", "Приёмы против анализаторов", "Структура APK намеренно искажена так, чтобы сломать инструменты проверки, но не установку.", EVASION, 25) { f ->
            val tricky = setOf(
                ArchiveAnomalyType.FAKE_ENCRYPTION_FLAG, ArchiveAnomalyType.UNSUPPORTED_COMPRESSION_METHOD,
                ArchiveAnomalyType.DUPLICATE_ENTRY, ArchiveAnomalyType.PATH_TRAVERSAL,
            )
            val renamed = f.manifest?.renamedAttributeCount ?: 0
            hit(
                f.report.archiveAnomalies.filter { it.type in tricky }.map { Evidence(ARCHIVE, it.detail) } +
                    if (renamed > 0) listOf(Evidence(MANIFEST, "подменённые имена атрибутов: $renamed")) else emptyList(),
            )
        },
        signal("HEAVY_OBFUSCATION", "Сильная обфускация", "Большинство классов переименовано в бессмысленные короткие имена. Обычно это R8/ProGuard, но затрудняет проверку.", EVASION, 4) { f ->
            val o = f.report.code?.obfuscation
            if (o != null && o.definedClasses >= 3 && o.shortNameRatio > 0.6f) {
                Hit(listOf(Evidence("DEX", "коротких имён классов: ${(o.shortNameRatio * 100).toInt()}% из ${o.definedClasses}")), 0.5f)
            } else null
        },

        // ---------------------------------------------------------------- Root и системные права
        signal("ROOT_COMMANDS", "Попытки получить root", "В коде есть команды или пути, связанные с root-доступом (su, Magisk).", PRIVILEGE, 10) { f ->
            val shell = f.indicatorsOf(IndicatorType.SHELL_COMMAND).filter { s ->
                val v = s.value.lowercase()
                v == "su" || v.startsWith("su ") || v.contains(" su ") || v.contains("/su") || v.contains("su -c")
            }
            val paths = f.indicatorsOf(IndicatorType.SUSPICIOUS_PATH).filter { it.value.contains("magisk", true) || it.value.contains("/su", true) }
            hit(f.indicatorEvidence(shell + paths))
        },
        signal("SHELL_EXEC", "Выполнение shell-команд", "Код запускает системные команды.", PRIVILEGE, 5) { f ->
            val api = f.apis(ApiCategory.SHELL_EXEC)
            val cmds = f.indicatorsOf(IndicatorType.SHELL_COMMAND)
            if (api.isEmpty() && cmds.isEmpty()) null else Hit(f.apiEvidence(api) + f.indicatorEvidence(cmds, 3), if (api.isNotEmpty()) 1f else 0.6f)
        },
        signal("SYSTEM_SHARED_UID", "Системный идентификатор", "Приложение претендует на общий UID с системными компонентами.", PRIVILEGE, 20) { f ->
            val uid = f.manifest?.sharedUserId
            if (uid != null && (uid.startsWith("android.uid.") || uid == "android.media")) Hit(listOf(Evidence(MANIFEST, "sharedUserId=$uid"))) else null
        },

        // ---------------------------------------------------------------- Сеть
        signal("NET_INTERNET", "Доступ в интернет", "Приложение может передавать данные в сеть.", NETWORK, 0, informational = true) { f ->
            hit(f.permissionEvidence("INTERNET"))
        },
        signal("HARDCODED_PUBLIC_IP", "Зашитые IP-адреса", "В коде указаны публичные IP-адреса — серверы, к которым обращаются в обход DNS.", NETWORK, 5) { f ->
            hit(f.indicatorEvidence(f.indicatorsOf(IndicatorType.IPV4).filter { !it.isPrivate }))
        },
        signal("SUSPICIOUS_DOMAINS", "Подозрительные домены", "Домены в зонах, популярных у злоумышленников, или динамический DNS.", NETWORK, 6) { f ->
            hit(f.indicatorEvidence(f.indicatorsOf(IndicatorType.DOMAIN).filter { d ->
                d.value.substringAfterLast('.') in SUSPICIOUS_TLDS || DYNAMIC_DNS.any { d.value.contains(it) }
            }))
        },
        signal("C2_MESSENGER_API", "Отправка данных через мессенджер", "Адрес API Telegram-бота или вебхука Discord/Slack — частый способ слива украденных данных.", NETWORK, 10) { f ->
            hit(f.indicatorEvidence(f.indicators.filter { i ->
                (i.type == IndicatorType.URL || i.type == IndicatorType.DOMAIN) && MESSENGER_C2.any { i.value.contains(it, ignoreCase = true) }
            }))
        },

        // ---------------------------------------------------------------- Качество сборки
        signal("DEBUGGABLE", "Отладочная сборка", "Приложение собрано в режиме отладки — так не публикуют в магазинах.", HYGIENE, 3) { f ->
            if (f.manifest?.application?.debuggable == true) Hit(listOf(Evidence(MANIFEST, "android:debuggable=true"))) else null
        },
        signal("DEBUG_CERTIFICATE", "Отладочный сертификат", "Подписано стандартным отладочным ключом Android SDK.", HYGIENE, 5) { f ->
            hit(f.report.signature?.certificates.orEmpty().filter { it.isAndroidDebug }.map { Evidence(SIGNATURE, it.subject) })
        },
        signal("AOSP_TEST_KEY", "Публичный тестовый ключ", "Подписано общедоступным тестовым ключом AOSP — такой подписью может воспользоваться кто угодно, в том числе чтобы выдать приложение за системное.", EVASION, 15) { f ->
            hit(f.report.signature?.certificates.orEmpty().filter { it.isAospTestKey }.map { Evidence(SIGNATURE, it.subject) })
        },
        signal("UNSIGNED", "Нет подписи", "APK не подписан — Android его не установит; возможно, это фрагмент или подделка.", HYGIENE, 8) { f ->
            val s = f.report.signature
            if (s != null && !s.isSigned) Hit(listOf(Evidence(SIGNATURE, "подпись не найдена"))) else null
        },
        signal("LOW_TARGET_SDK", "Устаревший targetSdk", "targetSdk ниже 23: разрешения выдаются при установке без отдельных запросов пользователю.", HYGIENE, 6) { f ->
            val t = f.targetSdk
            if (t != null && t < 23) Hit(listOf(Evidence(MANIFEST, "targetSdkVersion=$t"))) else null
        },
        signal("CLEARTEXT_HTTP", "Незашифрованный HTTP", "Разрешена передача данных без шифрования.", HYGIENE, 2) { f ->
            if (f.manifest?.application?.usesCleartextTraffic == true) Hit(listOf(Evidence(MANIFEST, "android:usesCleartextTraffic=true"))) else null
        },
        signal("EXPORTED_UNPROTECTED_PROVIDER", "Открытый провайдер данных", "Provider экспортирован без защитного разрешения — другие приложения могут читать его данные.", HYGIENE, 4) { f ->
            hit(f.components.filter { it.type == ComponentType.PROVIDER && it.exported && it.permission == null }.map { f.componentEvidence(it) })
        },
    )

    val combinations: List<Rule> = listOf(
        combo("COMBO_SMS_STEALER", "Похоже на кражу SMS", "Читает SMS, выходит в сеть и при этом скрывается или запускается сам — типичная схема перехвата банковских кодов.", SMS_CALLS, 45,
            setOf("SMS_READ"), setOf("NET_INTERNET"), setOf("BOOT_AUTOSTART", "NO_LAUNCHER_ICON", "HIDE_ICON_API", "NOTIFICATION_LISTENER")),
        combo("COMBO_SMS_FRAUD", "Похоже на SMS-мошенничество", "Может отправлять SMS и при этом скрывается или запускается сам — риск платных подписок.", SMS_CALLS, 40,
            setOf("SMS_SEND"), setOf("NO_LAUNCHER_ICON", "HIDE_ICON_API", "BOOT_AUTOSTART")),
        combo("COMBO_BANKER_ACCESSIBILITY", "Похоже на банковский троян", "Служба специальных возможностей вместе с оверлеями, SMS, уведомлениями или захватом экрана — классический набор банковских троянов.", DEVICE_CONTROL, 55,
            setOf("ACCESSIBILITY_SERVICE"), setOf("OVERLAY_WINDOWS", "SMS_READ", "NOTIFICATION_LISTENER", "SCREEN_CAPTURE")),
        combo("COMBO_SPYWARE", "Похоже на шпионское приложение", "Микрофон, камера, фоновая геолокация или захват экрана у приложения, которое прячет свою иконку.", SURVEILLANCE, 45,
            setOf("MIC_RECORD", "CAMERA_ACCESS", "LOCATION_BACKGROUND", "SCREEN_CAPTURE"), setOf("NO_LAUNCHER_ICON", "HIDE_ICON_API"), setOf("NET_INTERNET")),
        combo("COMBO_DROPPER", "Похоже на загрузчик вредоносного кода", "Подгружает или устанавливает код и при этом несёт скрытый исполняемый файл.", CODE_LOADING, 40,
            setOf("DYNAMIC_CODE", "INSTALL_PACKAGES"), setOf("HIDDEN_PAYLOAD", "HIDDEN_PAYLOAD_DISGUISED")),
        combo("COMBO_LOCKER", "Похоже на вымогателя-блокировщика", "Права администратора вместе с блокировкой устройства или окнами поверх всего.", DEVICE_CONTROL, 45,
            setOf("DEVICE_ADMIN"), setOf("DEVICE_ADMIN_DESTRUCTIVE_API", "OVERLAY_WINDOWS")),
        combo("COMBO_STEALTH_PERSISTENCE", "Скрытая работа в фоне", "Нет видимой иконки, но приложение запускается само при включении телефона.", PERSISTENCE, 25,
            setOf("NO_LAUNCHER_ICON", "HIDE_ICON_API"), setOf("BOOT_AUTOSTART")),
        combo("COMBO_OTP_INTERCEPT", "Перехват кодов подтверждения", "Читает уведомления и выходит в сеть вместе с доступом к SMS, специальными возможностями или отправкой через мессенджер.", SURVEILLANCE, 40,
            setOf("NOTIFICATION_LISTENER"), setOf("NET_INTERNET"), setOf("SMS_READ", "ACCESSIBILITY_SERVICE", "C2_MESSENGER_API")),
        combo("COMBO_ROOT_TOOLKIT", "Набор для получения root", "Команды root вместе с выполнением shell-команд или скрытым исполняемым кодом.", PRIVILEGE, 30,
            setOf("ROOT_COMMANDS"), setOf("SHELL_EXEC", "HIDDEN_PAYLOAD", "HIDDEN_PAYLOAD_DISGUISED")),
        combo("COMBO_DATA_EXFIL", "Сбор и отправка личных данных", "Собирает SMS, контакты, звонки или идентификаторы и содержит адреса подозрительных серверов.", DATA_COLLECTION, 30,
            setOf("SMS_READ", "CONTACTS_ACCOUNTS", "DEVICE_IDS", "CALLS_ACCESS"), setOf("C2_MESSENGER_API", "SUSPICIOUS_DOMAINS", "HARDCODED_PUBLIC_IP")),
    )

    val mitigations: List<Mitigation> = listOf(
        Mitigation(
            "MIT_DEFAULT_SMS_APP", "Похоже на SMS-клиент: может быть назначено приложением для SMS по умолчанию", 0.3f,
            appliesTo = { it.category == SMS_CALLS },
        ) { f ->
            f.components.firstOrNull {
                it.type == ComponentType.RECEIVER && "android.provider.Telephony.SMS_DELIVER" in it.allActions &&
                    it.permission == "android.permission.BROADCAST_SMS"
            }?.let { f.componentEvidence(it, "SMS_DELIVER") }
        },
        Mitigation(
            "MIT_DIALER_APP", "Похоже на приложение для звонков", 0.4f,
            appliesTo = { it.id == "CALLS_ACCESS" },
        ) { f ->
            f.components.firstOrNull { "android.intent.action.DIAL" in it.allActions }?.let { f.componentEvidence(it, "обрабатывает DIAL") }
        },
        Mitigation(
            "MIT_NO_ICON_BY_DESIGN", "Приложение без иконки по своей природе (клавиатура, обои, лаунчер, плагин)", 0.3f,
            appliesTo = { it.id == "NO_LAUNCHER_ICON" || it.id == "COMBO_STEALTH_PERSISTENCE" },
        ) { f ->
            (f.componentsBoundBy("BIND_INPUT_METHOD") + f.componentsBoundBy("BIND_WALLPAPER") + f.componentsBoundBy("BIND_DREAM_SERVICE"))
                .firstOrNull()?.let { f.componentEvidence(it) }
                ?: f.components.firstOrNull { c -> c.intentFilters.any { "android.intent.category.HOME" in it.categories } }
                    ?.let { f.componentEvidence(it, "домашний экран") }
        },
    )

    val all: List<Rule> = signals + combinations

    init {
        val ids = all.map { it.id }
        require(ids.size == ids.toSet().size) { "дубликаты ID правил" }
        val known = ids.toSet()
        combinations.forEach { c -> c.requires.flatten().forEach { require(it in known) { "${c.id} ссылается на неизвестное правило $it" } } }
    }

    /** Публичная проверка доменов — используется и в других местах (например, в AI-модуле). */
    fun isSuspiciousDomain(domain: String): Boolean =
        IndicatorExtractor.isPlausibleDomain(domain) &&
            (domain.substringAfterLast('.') in SUSPICIOUS_TLDS || DYNAMIC_DNS.any { domain.contains(it) })
}
