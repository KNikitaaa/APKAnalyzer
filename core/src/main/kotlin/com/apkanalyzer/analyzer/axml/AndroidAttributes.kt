package com.apkanalyzer.analyzer.axml

/**
 * Идентификаторы системных атрибутов android:* (framework public.xml).
 *
 * Android определяет атрибут манифеста по resource ID, а не по имени в пуле строк.
 * Вредоносные APK пользуются этим: подменяют имена в пуле, чтобы сбить статические
 * анализаторы. Поэтому имя сначала берём отсюда, а уже потом — из пула строк.
 */
object AndroidAttributes {
    private val byId: Map<Int, String> = mapOf(
        0x01010001 to "label",
        0x01010002 to "icon",
        0x01010003 to "name",
        0x01010006 to "permission",
        0x01010007 to "readPermission",
        0x01010008 to "writePermission",
        0x01010009 to "protectionLevel",
        0x0101000b to "sharedUserId",
        0x0101000e to "enabled",
        0x0101000f to "debuggable",
        0x01010010 to "exported",
        0x01010011 to "process",
        0x01010018 to "authorities",
        0x0101001b to "grantUriPermissions",
        0x0101001c to "priority",
        0x01010026 to "mimeType",
        0x01010027 to "scheme",
        0x01010028 to "host",
        0x01010029 to "port",
        0x0101002a to "path",
        0x0101002b to "pathPrefix",
        0x0101002c to "pathPattern",
        0x01010202 to "targetActivity",
        0x0101020c to "minSdkVersion",
        0x0101021b to "versionCode",
        0x0101021c to "versionName",
        0x01010270 to "targetSdkVersion",
        0x01010271 to "maxSdkVersion",
        0x01010272 to "testOnly",
        0x01010280 to "allowBackup",
        0x0101028e to "required",
        0x010102b7 to "installLocation",
        0x010104ea to "extractNativeLibs",
        0x010104ec to "usesCleartextTraffic",
        0x01010505 to "directBootAware",
        0x01010527 to "networkSecurityConfig",
        0x01010572 to "compileSdkVersion",
        0x01010599 to "foregroundServiceType",
    )

    private val byName: Map<String, Int> = byId.entries.associate { (k, v) -> v to k }

    fun nameFor(resourceId: Int): String? = byId[resourceId]

    fun idFor(name: String): Int? = byName[name]
}
