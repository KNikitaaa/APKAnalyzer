package com.apkanalyzer.analyzer.report

import com.apkanalyzer.analyzer.ApkAnalysisReport
import com.apkanalyzer.analyzer.StageStatus
import com.apkanalyzer.analyzer.strings.IndicatorType
import com.apkanalyzer.rules.PermissionCategory
import com.apkanalyzer.rules.categorizePermission
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.TimeZone

/** Важность строки — только для визуального выделения, это ещё не оценка риска. */
enum class FeatureEmphasis { NORMAL, NOTICE, WARNING }

data class FeatureItem(
    val title: String,
    val value: String? = null,
    val emphasis: FeatureEmphasis = FeatureEmphasis.NORMAL,
)

data class FeatureSection(
    val id: String,
    val title: String,
    val items: List<FeatureItem>,
)

/**
 * Превращает сырые факты анализа в список секций для экрана «Признаки» (этап 1 плана).
 * Здесь нет весов и выводов — только наглядное перечисление найденного.
 */
object RawFeatureFormatter {

    fun format(report: ApkAnalysisReport, timeZone: TimeZone = TimeZone.getDefault()): List<FeatureSection> {
        val sections = mutableListOf<FeatureSection>()

        sections += FeatureSection(
            "file", "Файл",
            listOf(
                FeatureItem("Имя", report.file.displayName),
                FeatureItem("Размер", humanBytes(report.file.sizeBytes)),
                FeatureItem("SHA-256", report.file.sha256),
                FeatureItem("Полнота анализа", "${(report.coverage * 100).toInt()}%",
                    if (report.coverage < 0.75f) FeatureEmphasis.WARNING else FeatureEmphasis.NORMAL),
                FeatureItem("Версия анализатора", report.analyzerVersion),
            ),
        )

        report.manifest?.let { m ->
            val items = mutableListOf(
                FeatureItem("Пакет", m.packageName),
                FeatureItem("Версия", listOfNotNull(m.versionName, m.versionCode?.let { "($it)" }).joinToString(" ").ifEmpty { "—" }),
                FeatureItem("Min SDK", m.minSdk?.let(::sdkLabel) ?: "—"),
                FeatureItem("Target SDK", m.targetSdk?.let(::sdkLabel) ?: "—"),
            )
            m.application.className?.let { items += FeatureItem("Класс Application", it) }
            m.sharedUserId?.let { items += FeatureItem("sharedUserId", it, FeatureEmphasis.NOTICE) }
            if (m.application.debuggable) items += FeatureItem("Отладочная сборка (debuggable)", "да", FeatureEmphasis.WARNING)
            if (m.application.testOnly) items += FeatureItem("Тестовая сборка (testOnly)", "да", FeatureEmphasis.NOTICE)
            if (m.application.usesCleartextTraffic == true) items += FeatureItem("Незашифрованный HTTP разрешён", "да", FeatureEmphasis.NOTICE)
            if (m.application.allowBackup != false) items += FeatureItem("Резервное копирование данных", if (m.application.allowBackup == true) "разрешено" else "по умолчанию")
            if (!m.hasLauncherActivity) items += FeatureItem("Нет иконки в лаунчере", "нет активности MAIN/LAUNCHER", FeatureEmphasis.WARNING)
            if (m.renamedAttributeCount > 0) items += FeatureItem("Подменённые имена атрибутов", m.renamedAttributeCount.toString(), FeatureEmphasis.WARNING)
            if (m.truncated) items += FeatureItem("Манифест повреждён", "прочитан частично", FeatureEmphasis.WARNING)
            sections += FeatureSection("package", "Приложение", items)

            val perms = m.usesPermissions.map { p ->
                val cat = categorizePermission(p.name)
                FeatureItem(
                    p.name.removePrefix("android.permission."),
                    cat.takeIf { it != PermissionCategory.OTHER }?.labelRu,
                    when {
                        cat.baseWeight >= 8 -> FeatureEmphasis.WARNING
                        cat.baseWeight >= 5 -> FeatureEmphasis.NOTICE
                        else -> FeatureEmphasis.NORMAL
                    },
                )
            }.sortedByDescending { it.emphasis.ordinal }
            sections += FeatureSection("permissions", "Разрешения (${perms.size})", perms.ifEmpty { listOf(FeatureItem("Разрешения не запрашиваются")) })

            val comps = m.components.sortedByDescending { it.exported }.map { c ->
                val details = buildList {
                    add(c.type.labelRu)
                    if (c.exported) add(if (c.exportedExplicit) "exported" else "exported (по умолчанию)")
                    if (!c.enabled) add("отключён")
                    c.permission?.let { add("защищён: ${it.removePrefix("android.permission.")}") }
                    val actions = c.allActions
                    if (actions.isNotEmpty()) add(actions.joinToString(", ") { it.removePrefix("android.intent.action.") })
                    if (c.authorities.isNotEmpty()) add("authorities: ${c.authorities.joinToString()}")
                }.joinToString(" · ")
                FeatureItem(
                    c.name.removePrefix(m.packageName),
                    details,
                    if (c.exported && c.permission == null && c.enabled) FeatureEmphasis.NOTICE else FeatureEmphasis.NORMAL,
                )
            }
            val exportedCount = m.exportedComponents.size
            sections += FeatureSection("components", "Компоненты (${comps.size}, экспортировано $exportedCount)", comps.ifEmpty { listOf(FeatureItem("Компоненты не объявлены")) })
        }

        report.signature?.let { s ->
            val items = mutableListOf(
                FeatureItem("Схемы подписи", s.schemes.joinToString { it.label }.ifEmpty { "нет подписи" },
                    if (s.schemes.isEmpty()) FeatureEmphasis.WARNING else FeatureEmphasis.NORMAL),
            )
            val df = SimpleDateFormat("dd.MM.yyyy", Locale.forLanguageTag("ru")).apply { this.timeZone = timeZone }
            for (c in s.certificates) {
                items += FeatureItem("Сертификат", c.subject)
                items += FeatureItem("SHA-256 сертификата", c.sha256Fingerprint)
                items += FeatureItem("Действителен", "${df.format(Date(c.notBeforeMs))} — ${df.format(Date(c.notAfterMs))}")
                items += FeatureItem("Ключ", listOfNotNull(c.publicKeyAlgorithm, c.publicKeyBits?.let { "$it бит" }, c.signatureAlgorithm).joinToString(" · "))
                if (c.isAndroidDebug) items += FeatureItem("Отладочный сертификат Android", "да", FeatureEmphasis.WARNING)
                if (c.isAospTestKey) items += FeatureItem("Публичный тестовый ключ AOSP", "да", FeatureEmphasis.WARNING)
            }
            s.warnings.forEach { items += FeatureItem("Предупреждение", it, FeatureEmphasis.NOTICE) }
            sections += FeatureSection("signature", "Подпись", items)
        }

        report.code?.let { code ->
            val items = mutableListOf(
                FeatureItem("DEX-файлов", code.dexFiles.size.toString()),
                FeatureItem("Классов определено", code.obfuscation.definedClasses.toString()),
                FeatureItem("Строк просмотрено", code.stringsScanned.toString()),
                FeatureItem("Короткие имена классов", "${(code.obfuscation.shortNameRatio * 100).toInt()}%",
                    if (code.obfuscation.shortNameRatio > 0.5f) FeatureEmphasis.NOTICE else FeatureEmphasis.NORMAL),
            )
            code.apiUsages.sortedBy { it.api.category.ordinal }.forEach { u ->
                items += FeatureItem(u.api.displayName, "${u.api.category.labelRu}: ${u.api.descriptionRu}", FeatureEmphasis.NOTICE)
            }
            sections += FeatureSection("code", "Код и чувствительные API (${code.apiUsages.size})", items)
        }

        val byType = report.indicators.groupBy { it.type }
        val net = buildList {
            byType[IndicatorType.DOMAIN].orEmpty().forEach { add(FeatureItem(it.value, it.source)) }
            byType[IndicatorType.IPV4].orEmpty().forEach {
                add(FeatureItem(it.value, if (it.isPrivate) "локальный адрес · ${it.source}" else it.source,
                    if (it.isPrivate) FeatureEmphasis.NORMAL else FeatureEmphasis.NOTICE))
            }
            byType[IndicatorType.URL].orEmpty().forEach { add(FeatureItem(it.value, it.source)) }
        }
        if (net.isNotEmpty()) sections += FeatureSection("network", "Сетевые адреса (${net.size})", net)

        val strings = buildList {
            byType[IndicatorType.SHELL_COMMAND].orEmpty().forEach { add(FeatureItem(it.value, "команда · ${it.source}", FeatureEmphasis.NOTICE)) }
            byType[IndicatorType.SUSPICIOUS_PATH].orEmpty().forEach { add(FeatureItem(it.value, "путь · ${it.source}", FeatureEmphasis.NOTICE)) }
            byType[IndicatorType.CONTENT_URI].orEmpty().forEach { add(FeatureItem(it.value, "content URI · ${it.source}")) }
        }
        if (strings.isNotEmpty()) sections += FeatureSection("strings", "Подозрительные строки (${strings.size})", strings)

        report.contents?.let { c ->
            val items = mutableListOf<FeatureItem>()
            c.packers.forEach { items += FeatureItem("Упаковщик: ${it.name}", it.evidence, FeatureEmphasis.WARNING) }
            c.hiddenPayloads.forEach {
                items += FeatureItem(it.path, "${it.kind.labelRu} · ${humanBytes(it.sizeBytes)}", FeatureEmphasis.WARNING)
            }
            if (c.abis.isNotEmpty()) items += FeatureItem("ABI", c.abis.joinToString())
            c.nativeLibraries.distinctBy { it.fileName }.forEach {
                items += FeatureItem(it.fileName, humanBytes(it.sizeBytes) + if (it.isElf == false) " · не ELF!" else "",
                    if (it.isElf == false) FeatureEmphasis.WARNING else FeatureEmphasis.NORMAL)
            }
            items += FeatureItem("Записей в архиве", c.totalEntries.toString())
            sections += FeatureSection("contents", "Содержимое и нативный код", items)
        }

        if (report.archiveAnomalies.isNotEmpty()) {
            sections += FeatureSection(
                "anomalies", "Аномалии структуры архива",
                report.archiveAnomalies.map { FeatureItem(it.detail, null, FeatureEmphasis.WARNING) },
            )
        }

        val limitations = report.stages.filter { it.status != StageStatus.OK }
        if (limitations.isNotEmpty() || report.indicatorsTruncated) {
            sections += FeatureSection(
                "limitations", "Ограничения анализа",
                limitations.map {
                    FeatureItem(it.stage.labelRu, listOfNotNull(it.status.labelRu, it.message).joinToString(" — "),
                        if (it.status == StageStatus.FAILED) FeatureEmphasis.WARNING else FeatureEmphasis.NOTICE)
                } + if (report.indicatorsTruncated) listOf(FeatureItem("Индикаторы", "показаны не все (лимит)")) else emptyList(),
            )
        }
        return sections
    }

    fun humanBytes(bytes: Long): String = when {
        bytes < 1024 -> "$bytes Б"
        bytes < 1024 * 1024 -> String.format(Locale.ROOT, "%.1f КБ", bytes / 1024.0)
        else -> String.format(Locale.ROOT, "%.1f МБ", bytes / (1024.0 * 1024.0))
    }

    private val SDK_NAMES = mapOf(
        21 to "5.0", 22 to "5.1", 23 to "6", 24 to "7.0", 25 to "7.1", 26 to "8.0", 27 to "8.1", 28 to "9",
        29 to "10", 30 to "11", 31 to "12", 32 to "12L", 33 to "13", 34 to "14", 35 to "15", 36 to "16", 37 to "17",
    )

    fun sdkLabel(sdk: Int): String = SDK_NAMES[sdk]?.let { "$sdk (Android $it)" } ?: sdk.toString()
}
