package com.apkanalyzer.installed

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class InstalledAppsTest {

    private fun app(
        pkg: String,
        label: String = pkg.substringAfterLast('.'),
        system: Boolean = false,
        installer: String? = "com.android.vending",
        updated: Long = 0,
    ) = InstalledAppSummary(
        packageName = pkg,
        label = label,
        versionName = "1.0",
        versionCode = 1,
        isSystem = system,
        installerPackage = installer,
        lastUpdateMs = updated,
        totalApkBytes = 1000,
        splitCount = 0,
    )

    private val apps = listOf(
        app("com.example.bank", "Банк"),
        app("org.fdroid.app", "F-Droid клиент", installer = "org.fdroid.fdroid"),
        app("com.android.settings", "Настройки", system = true, installer = null),
        app("xyz.unknown.flash", "Фонарик", installer = null, updated = 50),
        app("com.files.downloaded", "Загруженное", installer = "com.google.android.packageinstaller", updated = 10),
    )

    @Test
    fun installerKindRecognisesStoresAndSideloading() {
        assertEquals(InstallerKind.STORE, InstallerKind.of("com.android.vending", isSystem = false))
        assertEquals(InstallerKind.STORE, InstallerKind.of("ru.vk.store", isSystem = false))
        assertEquals(InstallerKind.STORE, InstallerKind.of("org.fdroid.fdroid", isSystem = false))
        assertEquals(InstallerKind.SIDELOADED, InstallerKind.of("com.google.android.packageinstaller", isSystem = false))
        assertEquals(InstallerKind.SIDELOADED, InstallerKind.of("com.android.packageinstaller", isSystem = false))
        assertEquals(InstallerKind.UNKNOWN, InstallerKind.of(null, isSystem = false))
        assertEquals(InstallerKind.PREINSTALLED, InstallerKind.of(null, isSystem = true))
        assertEquals(InstallerKind.OTHER_APP, InstallerKind.of("org.telegram.messenger", isSystem = false))
    }

    @Test
    fun systemAppsHiddenByDefault() {
        val r = InstalledAppsQuery().select(apps)
        assertEquals(4, r.size)
        assertNull(r.firstOrNull { it.isSystem })
    }

    @Test
    fun searchMatchesLabelAndPackageIgnoringCase() {
        assertEquals(listOf("com.example.bank"), InstalledAppsQuery(text = "банк").select(apps).map { it.packageName })
        assertEquals(listOf("org.fdroid.app"), InstalledAppsQuery(text = "FDROID").select(apps).map { it.packageName })
        assertEquals(listOf("com.android.settings"), InstalledAppsQuery(text = "settings", includeSystem = true).select(apps).map { it.packageName })
    }

    @Test
    fun defaultSortPutsNotFromStoreFirstThenByName() {
        val r = InstalledAppsQuery().select(apps).map { it.label }
        assertEquals(listOf("Загруженное", "Фонарик", "F-Droid клиент", "Банк"), r)
    }

    @Test
    fun sortByNameAndByRecentUpdate() {
        assertEquals(
            listOf("F-Droid клиент", "Банк", "Загруженное", "Фонарик"),
            InstalledAppsQuery(sort = InstalledAppsSort.NAME).select(apps).map { it.label },
        )
        assertEquals(
            listOf("Фонарик", "Загруженное"),
            InstalledAppsQuery(sort = InstalledAppsSort.RECENTLY_UPDATED).select(apps).map { it.label }.take(2),
        )
    }
}
