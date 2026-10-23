package com.apkanalyzer.analyzer.manifest

import com.apkanalyzer.analyzer.AnalysisLimits
import com.apkanalyzer.analyzer.MalformedApkException
import com.apkanalyzer.analyzer.axml.AttrValue
import com.apkanalyzer.analyzer.axml.BinaryXmlDocument
import com.apkanalyzer.analyzer.axml.BinaryXmlParser
import com.apkanalyzer.analyzer.axml.XmlElement

/** Превращает бинарный AndroidManifest.xml в типизированную модель [ApkManifest]. */
class ManifestParser(private val limits: AnalysisLimits = AnalysisLimits()) {

    fun parse(binaryXml: ByteArray): ApkManifest = fromDocument(BinaryXmlParser(limits).parse(binaryXml))

    fun fromDocument(doc: BinaryXmlDocument): ApkManifest {
        val root = doc.root ?: throw MalformedApkException("Манифест пуст")
        if (root.name != "manifest") throw MalformedApkException("Корневой элемент манифеста — '${root.name}', а не 'manifest'")

        val pkg = root.attr("package")?.asText()?.trim().orEmpty()
        if (pkg.isEmpty()) throw MalformedApkException("В манифесте не указано имя пакета")

        val usesSdk = root.childrenNamed("uses-sdk").firstOrNull()
        val minSdk = usesSdk?.attr("minSdkVersion")?.asSdkInt() ?: 1
        val targetSdk = usesSdk?.attr("targetSdkVersion")?.asSdkInt() ?: minSdk

        val usesPermissions = root.children
            .filter { it.name == "uses-permission" || it.name == "uses-permission-sdk-23" || it.name == "uses-permission-sdk-m" }
            .mapNotNull { el ->
                el.attr("name")?.asText()?.takeIf { it.isNotBlank() }
                    ?.let { UsesPermission(it.trim(), el.attr("maxSdkVersion")?.asInt()) }
            }
            .distinctBy { it.name }

        val declared = root.childrenNamed("permission").mapNotNull { el ->
            el.attr("name")?.asText()?.takeIf { it.isNotBlank() }
                ?.let { DeclaredPermission(it, el.attr("protectionLevel")?.asInt()) }
        }

        val app = root.childrenNamed("application").firstOrNull()
        val components = app?.children.orEmpty().mapNotNull { parseComponent(it, pkg, targetSdk) }

        val flags = ApplicationFlags(
            className = app?.attr("name")?.asText()?.let { resolveClass(pkg, it) },
            label = app?.attr("label")?.asText(),
            debuggable = app?.attr("debuggable")?.asBoolean() ?: false,
            allowBackup = app?.attr("allowBackup")?.asBoolean(),
            usesCleartextTraffic = app?.attr("usesCleartextTraffic")?.asBoolean(),
            hasNetworkSecurityConfig = app?.attr("networkSecurityConfig") != null,
            testOnly = app?.attr("testOnly")?.asBoolean() ?: false,
            extractNativeLibs = app?.attr("extractNativeLibs")?.asBoolean(),
        )

        return ApkManifest(
            packageName = pkg,
            versionCode = root.attr("versionCode")?.asInt()?.toLong()?.and(0xFFFFFFFFL),
            versionName = root.attr("versionName")?.asText(),
            minSdk = minSdk,
            targetSdk = targetSdk,
            compileSdk = root.attr("compileSdkVersion")?.asInt(),
            sharedUserId = root.attr("sharedUserId")?.asText(),
            usesPermissions = usesPermissions,
            declaredPermissions = declared,
            components = components,
            application = flags,
            renamedAttributeCount = doc.renamedAttributeCount,
            parseWarnings = doc.warnings,
            truncated = doc.truncated,
        )
    }

    private fun parseComponent(el: XmlElement, pkg: String, targetSdk: Int): ComponentInfo? {
        val type = ComponentType.entries.firstOrNull { it.tag == el.name } ?: return null
        val rawName = el.attr("name")?.asText()?.takeIf { it.isNotBlank() } ?: return null
        val filters = el.childrenNamed("intent-filter").map(::parseIntentFilter)
        val explicitExported = el.attr("exported")?.asBoolean()
        val exported = explicitExported ?: when (type) {
            // До Android 12 компонент с intent-filter по умолчанию экспортирован;
            // с targetSdk 31 без явного exported такой APK не установится, но для оценки риска
            // считаем его доступным извне.
            ComponentType.ACTIVITY, ComponentType.ACTIVITY_ALIAS,
            ComponentType.SERVICE, ComponentType.RECEIVER -> filters.isNotEmpty()
            // Provider экспортирован по умолчанию только при targetSdk <= 16.
            ComponentType.PROVIDER -> targetSdk <= 16
        }
        return ComponentInfo(
            type = type,
            name = resolveClass(pkg, rawName),
            exported = exported,
            exportedExplicit = explicitExported != null,
            enabled = el.attr("enabled")?.asBoolean() ?: true,
            permission = el.attr("permission")?.asText(),
            intentFilters = filters,
            authorities = el.attr("authorities")?.asText()?.split(';')?.map { it.trim() }?.filter { it.isNotEmpty() }.orEmpty(),
            grantUriPermissions = el.attr("grantUriPermissions")?.asBoolean() ?: false,
            targetActivity = el.attr("targetActivity")?.asText()?.let { resolveClass(pkg, it) },
            process = el.attr("process")?.asText(),
            directBootAware = el.attr("directBootAware")?.asBoolean() ?: false,
            foregroundServiceType = el.attr("foregroundServiceType")?.asInt(),
        )
    }

    private fun parseIntentFilter(el: XmlElement): IntentFilterInfo {
        fun values(tag: String, attr: String) =
            el.childrenNamed(tag).mapNotNull { it.attr(attr)?.asText()?.takeIf(String::isNotBlank) }.distinct()
        return IntentFilterInfo(
            actions = values("action", "name"),
            categories = values("category", "name"),
            dataSchemes = values("data", "scheme"),
            dataHosts = values("data", "host"),
            dataMimeTypes = values("data", "mimeType"),
            priority = el.attr("priority")?.asInt(),
        )
    }

    /** minSdk/targetSdk могут быть кодовым именем превью (строка) — тогда считаем это «будущей» версией. */
    private fun AttrValue.asSdkInt(): Int? = asInt() ?: (this as? AttrValue.Text)?.let { PREVIEW_SDK }

    companion object {
        private const val PREVIEW_SDK = 10_000

        fun resolveClass(pkg: String, name: String): String {
            val n = name.trim()
            return when {
                n.startsWith(".") -> pkg + n
                !n.contains('.') -> "$pkg.$n"
                else -> n
            }
        }
    }
}
