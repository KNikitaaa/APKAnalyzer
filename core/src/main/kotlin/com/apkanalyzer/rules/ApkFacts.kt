package com.apkanalyzer.rules

import com.apkanalyzer.analyzer.ApkAnalysisReport
import com.apkanalyzer.analyzer.contents.HiddenPayload
import com.apkanalyzer.analyzer.contents.PackerMatch
import com.apkanalyzer.analyzer.dex.ApiCategory
import com.apkanalyzer.analyzer.dex.ApiUsage
import com.apkanalyzer.analyzer.dex.KnownLibraries
import com.apkanalyzer.analyzer.manifest.ComponentInfo
import com.apkanalyzer.analyzer.manifest.ComponentType
import com.apkanalyzer.analyzer.strings.IndicatorType
import com.apkanalyzer.analyzer.strings.StringIndicator

/**
 * Удобный для правил «срез» отчёта анализа: множества, поиск и готовые доказательства.
 * Правила работают только с этим классом, поэтому их легко тестировать и переиспользовать.
 */
class ApkFacts(val report: ApkAnalysisReport, val params: RuleParams = RuleParams.DEFAULT) {

    val manifest = report.manifest
    val packageName: String = manifest?.packageName.orEmpty()
    val targetSdk: Int? = manifest?.targetSdk
    val signerCheck: SignerCheck = TrustedSigners.check(manifest?.packageName, report.signature, params.trustedSigners)

    /** Разрешения в коротком виде (`READ_SMS`), плюс полные имена для нестандартных. */
    val permissions: Set<String> = manifest?.permissionNames.orEmpty()
        .mapTo(LinkedHashSet()) { it.removePrefix(ANDROID_PERMISSION) }

    val components: List<ComponentInfo> = manifest?.components.orEmpty()
    val hasLauncher: Boolean = manifest?.hasLauncherActivity ?: true

    /** Точки входа из лаунчера (activity и activity-alias с MAIN + LAUNCHER). */
    val launcherComponents: List<ComponentInfo> = components.filter {
        (it.type == ComponentType.ACTIVITY || it.type == ComponentType.ACTIVITY_ALIAS) && it.isLauncher && it.enabled
    }

    /** Все найденные чувствительные API, включая ссылки только из библиотек. */
    val allApiUsages: List<ApiUsage> = report.code?.apiUsages.orEmpty()

    /** API, которые вызывает код самого приложения, — только они говорят о его поведении (плюс опасные категории откуда угодно). */
    val apiUsages: List<ApiUsage> = allApiUsages.filter { it.inAppCode || it.api.category.countsInLibraries }
    val codeAvailable: Boolean = report.code != null

    /** Байткод разобран — API и компоненты привязаны к коду приложения. Без этого правила работают по таблицам DEX. */
    val bytecodeAttributed: Boolean = report.code?.bytecodeAttributed == true
    val componentsToggledByApp: Set<String> = report.code?.componentsToggledByApp.orEmpty()

    /** Все индикаторы, включая найденные только в коде библиотек. */
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

    /** Компонент объявлен библиотекой (например, androidx.work RescheduleReceiver). */
    fun isLibraryComponent(c: ComponentInfo): Boolean =
        KnownLibraries.isLibrary("L" + c.name.replace('.', '/') + ";", packageName)

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

    /**
     * Индикаторы типа [type]. По умолчанию — только из кода приложения: IP-адреса, команды и пути
     * в библиотеках (DNS-серверы, проверки root) о намерениях приложения не говорят.
     */
    fun indicatorsOf(type: IndicatorType, includeLibraries: Boolean = false): List<StringIndicator> =
        indicators.filter { it.type == type && (includeLibraries || !it.fromLibrary) }

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
