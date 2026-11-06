package com.apkanalyzer.installed

import java.text.Collator
import java.util.Locale

/** Источник установки приложения — по пакету установщика, который сообщает Android. */
enum class InstallerKind(val labelRu: String, val fromStore: Boolean) {
    STORE("Из магазина приложений", true),
    PREINSTALLED("Предустановлено", true),
    SIDELOADED("Установлено из файла", false),
    OTHER_APP("Установлено другим приложением", false),
    UNKNOWN("Источник неизвестен", false),
    ;

    companion object {
        /** Магазины, которые проверяют публикуемые приложения. */
        private val STORES = setOf(
            "com.android.vending", // Google Play
            "com.amazon.venezia", // Amazon Appstore
            "com.sec.android.app.samsungapps", // Galaxy Store
            "com.huawei.appmarket", // AppGallery
            "com.xiaomi.market", "com.xiaomi.mipicks", // GetApps
            "com.heytap.market", "com.oppo.market", // OPPO / realme
            "com.bbk.appstore", // vivo
            "ru.vk.store", // RuStore
            "org.fdroid.fdroid", // F-Droid
            "com.aurora.store", // Aurora Store (клиент Google Play)
        )

        /** Системный установщик: так ставятся APK, открытые из файлового менеджера или браузера. */
        private val PACKAGE_INSTALLERS = setOf(
            "com.android.packageinstaller",
            "com.google.android.packageinstaller",
            "com.samsung.android.packageinstaller",
            "com.miui.packageinstaller",
            "com.android.shell", // adb install
        )

        fun of(installer: String?, isSystem: Boolean): InstallerKind = when {
            installer == null -> if (isSystem) PREINSTALLED else UNKNOWN
            installer in STORES -> STORE
            installer in PACKAGE_INSTALLERS -> SIDELOADED
            else -> OTHER_APP
        }
    }
}

/** Сведения об установленном приложении для списка (без чтения самих APK). */
data class InstalledAppSummary(
    val packageName: String,
    val label: String,
    val versionName: String?,
    val versionCode: Long,
    val isSystem: Boolean,
    val installerPackage: String?,
    val lastUpdateMs: Long,
    val totalApkBytes: Long,
    /** Сколько дополнительных частей split APK у приложения. */
    val splitCount: Int,
) {
    val installer: InstallerKind get() = InstallerKind.of(installerPackage, isSystem)
}

enum class InstalledAppsSort(val labelRu: String) {
    /** Сначала то, что поставлено не из магазина, — такие приложения важнее проверить. */
    RISKY_SOURCE_FIRST("Сначала не из магазина"),
    NAME("По названию"),
    RECENTLY_UPDATED("Недавно обновлённые"),
}

data class InstalledAppsQuery(
    val text: String = "",
    val includeSystem: Boolean = false,
    val sort: InstalledAppsSort = InstalledAppsSort.RISKY_SOURCE_FIRST,
) {
    fun select(apps: List<InstalledAppSummary>): List<InstalledAppSummary> {
        val q = text.trim()
        val byName = compareBy(collator) { a: InstalledAppSummary -> a.label }
        val comparator = when (sort) {
            InstalledAppsSort.NAME -> byName
            InstalledAppsSort.RECENTLY_UPDATED -> compareByDescending<InstalledAppSummary> { it.lastUpdateMs }.then(byName)
            InstalledAppsSort.RISKY_SOURCE_FIRST -> compareBy<InstalledAppSummary> { it.installer.fromStore }.then(byName)
        }
        return apps
            .filter { includeSystem || !it.isSystem }
            .filter { q.isEmpty() || it.label.contains(q, ignoreCase = true) || it.packageName.contains(q, ignoreCase = true) }
            .sortedWith(comparator)
    }

    private companion object {
        val collator: Collator = Collator.getInstance(Locale.forLanguageTag("ru"))
    }
}
