package com.apkanalyzer.rules

import com.apkanalyzer.analyzer.ApkAnalysisReport
import com.apkanalyzer.analyzer.contents.HiddenPayload
import com.apkanalyzer.analyzer.contents.PackerMatch
import com.apkanalyzer.analyzer.dex.ApiCategory
import com.apkanalyzer.analyzer.dex.ApiUsage
import com.apkanalyzer.analyzer.manifest.ComponentInfo
import com.apkanalyzer.analyzer.manifest.ComponentType
import com.apkanalyzer.analyzer.strings.IndicatorType
import com.apkanalyzer.analyzer.strings.StringIndicator

/**
 * Удобный для правил «срез» отчёта анализа: множества, поиск и готовые доказательства.
 * Правила работают только с этим классом, поэтому их легко тестировать и переиспользовать.
 */
class ApkFacts(val report: ApkAnalysisReport) {

    val manifest = report.manifest
    val packageName: String = manifest?.packageName.orEmpty()
    val targetSdk: Int? = manifest?.targetSdk

    /** Разрешения в коротком виде (`READ_SMS`), плюс полные имена для нестандартных. */
    val permissions: Set<String> = manifest?.permissionNames.orEmpty()
        .mapTo(LinkedHashSet()) { it.removePrefix(ANDROID_PERMISSION) }

    val components: List<ComponentInfo> = manifest?.components.orEmpty()
    val hasLauncher: Boolean = manifest?.hasLauncherActivity ?: true

    val apiUsages: List<ApiUsage> = report.code?.apiUsages.orEmpty()
    val codeAvailable: Boolean = report.code != null

    val indicators: List<StringIndicator> = report.indicators
    val packers: List<PackerMatch> = report.contents?.packers.orEmpty()
    val hiddenPayloads: List<HiddenPayload> = report.contents?.hiddenPayloads.orEmpty()

    fun hasPermission(vararg names: String): Boolean = names.any { it in permissions }

    fun permissionEvidence(vararg names: String): List<Evidence> =
        names.filter { it in permissions }.map { Evidence(MANIFEST, "uses-permission ${fullPermission(it)}") }

    /** Компоненты, защищённые указанным системным разрешением (так объявляются Accessibility, Device Admin и т.п.). */
    fun componentsBoundBy(permission: String): List<ComponentInfo> =
        components.filter { it.permission == fullPermission(permission) }

    fun componentsWithAction(action: String, type: ComponentType? = null): List<ComponentInfo> =
        components.filter { (type == null || it.type == type) && action in it.allActions }

    fun componentEvidence(c: ComponentInfo, note: String? = null): Evidence =
        Evidence(MANIFEST, buildString {
            append("<${c.type.tag}> ${c.name}")
            c.permission?.let { append(" · permission=${it.removePrefix(ANDROID_PERMISSION)}") }
            if (c.exported) append(" · exported")
            note?.let { append(" · $it") }
        })

    fun apis(category: ApiCategory): List<ApiUsage> = apiUsages.filter { it.api.category == category }

    fun apis(classDescriptor: String, vararg methods: String): List<ApiUsage> = apiUsages.filter {
        it.api.classDescriptor == classDescriptor && (methods.isEmpty() || it.api.methodName in methods)
    }

    fun apiEvidence(usages: List<ApiUsage>): List<Evidence> =
        usages.map { Evidence(it.dexFiles.joinToString(), "${it.api.displayName} — ${it.api.descriptionRu}") }

    fun indicatorsOf(type: IndicatorType): List<StringIndicator> = indicators.filter { it.type == type }

    fun indicatorEvidence(list: List<StringIndicator>, limit: Int = 5): List<Evidence> =
        list.take(limit).map { Evidence(it.source, it.value) } +
            if (list.size > limit) listOf(Evidence("…", "и ещё ${list.size - limit}")) else emptyList()

    companion object {
        const val MANIFEST = "Манифест"
        const val SIGNATURE = "Подпись"
        const val ARCHIVE = "Структура архива"
        private const val ANDROID_PERMISSION = "android.permission."

        fun fullPermission(short: String) = if (short.contains('.')) short else ANDROID_PERMISSION + short
    }
}
