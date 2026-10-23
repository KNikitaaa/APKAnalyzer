package com.apkanalyzer.analyzer.manifest

enum class ComponentType(val tag: String, val labelRu: String) {
    ACTIVITY("activity", "Activity"),
    ACTIVITY_ALIAS("activity-alias", "Activity-alias"),
    SERVICE("service", "Service"),
    RECEIVER("receiver", "Receiver"),
    PROVIDER("provider", "Provider"),
}

data class IntentFilterInfo(
    val actions: List<String>,
    val categories: List<String>,
    val dataSchemes: List<String>,
    val dataHosts: List<String>,
    val dataMimeTypes: List<String>,
    val priority: Int?,
) {
    val isLauncher: Boolean
        get() = "android.intent.action.MAIN" in actions && "android.intent.category.LAUNCHER" in categories
}

data class ComponentInfo(
    val type: ComponentType,
    /** Полное имя класса (относительные имена вида `.Foo` раскрыты). */
    val name: String,
    /** Итоговое значение exported с учётом правил Android по умолчанию. */
    val exported: Boolean,
    /** Было ли exported указано явно (а не вычислено по умолчанию). */
    val exportedExplicit: Boolean,
    val enabled: Boolean,
    /** Разрешение, которым защищён компонент (android:permission). */
    val permission: String?,
    val intentFilters: List<IntentFilterInfo>,
    /** Только для provider. */
    val authorities: List<String> = emptyList(),
    val grantUriPermissions: Boolean = false,
    /** Только для activity-alias. */
    val targetActivity: String? = null,
    val process: String? = null,
    val directBootAware: Boolean = false,
    val foregroundServiceType: Int? = null,
) {
    val isLauncher: Boolean get() = intentFilters.any { it.isLauncher }
    val allActions: Set<String> get() = intentFilters.flatMapTo(LinkedHashSet()) { it.actions }
}

data class UsesPermission(
    val name: String,
    val maxSdkVersion: Int? = null,
)

data class DeclaredPermission(
    val name: String,
    val protectionLevel: Int?,
)

data class ApkManifest(
    val packageName: String,
    val versionCode: Long?,
    /** Может быть ссылкой на ресурс вида `@0x7f...`, если значение не задано строкой. */
    val versionName: String?,
    val minSdk: Int?,
    val targetSdk: Int?,
    val compileSdk: Int?,
    val sharedUserId: String?,
    val usesPermissions: List<UsesPermission>,
    val declaredPermissions: List<DeclaredPermission>,
    val components: List<ComponentInfo>,
    val application: ApplicationFlags,
    /** Сколько атрибутов имели подменённое имя (несоответствие resource ID) — признак обфускации манифеста. */
    val renamedAttributeCount: Int,
    val parseWarnings: List<String>,
    val truncated: Boolean,
) {
    val permissionNames: List<String> get() = usesPermissions.map { it.name }.distinct()
    val exportedComponents: List<ComponentInfo> get() = components.filter { it.exported && it.enabled }
    val hasLauncherActivity: Boolean
        get() = components.any {
            (it.type == ComponentType.ACTIVITY || it.type == ComponentType.ACTIVITY_ALIAS) && it.isLauncher
        }
}

data class ApplicationFlags(
    val className: String?,
    val label: String?,
    val debuggable: Boolean,
    /** null — не указано (по умолчанию в Android: true). */
    val allowBackup: Boolean?,
    /** null — не указано (по умолчанию true при targetSdk < 28). */
    val usesCleartextTraffic: Boolean?,
    val hasNetworkSecurityConfig: Boolean,
    val testOnly: Boolean,
    val extractNativeLibs: Boolean?,
)
