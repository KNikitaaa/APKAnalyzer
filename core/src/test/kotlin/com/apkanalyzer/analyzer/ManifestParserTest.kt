package com.apkanalyzer.analyzer

import com.apkanalyzer.analyzer.axml.AndroidAttributes
import com.apkanalyzer.analyzer.manifest.ComponentType
import com.apkanalyzer.analyzer.manifest.ManifestParser
import com.apkanalyzer.testing.A
import com.apkanalyzer.testing.AxmlWriter
import com.apkanalyzer.testing.Fixtures
import com.apkanalyzer.testing.a
import com.apkanalyzer.testing.el
import com.apkanalyzer.testing.plain
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

class ManifestParserTest {

    private val parser = ManifestParser()

    @Test
    fun parsesPackageVersionsAndSdk_utf16() = checkBasics(utf8 = false)

    @Test
    fun parsesPackageVersionsAndSdk_utf8() = checkBasics(utf8 = true)

    private fun checkBasics(utf8: Boolean) {
        val m = parser.parse(AxmlWriter.write(Fixtures.suspiciousManifest(), utf8))
        assertEquals(Fixtures.PKG, m.packageName)
        assertEquals(42L, m.versionCode)
        assertEquals("1.2.3", m.versionName)
        assertEquals(21, m.minSdk)
        assertEquals(30, m.targetSdk)
        assertEquals(
            listOf("android.permission.READ_SMS", "android.permission.RECEIVE_BOOT_COMPLETED", "android.permission.INTERNET"),
            m.permissionNames,
        )
        assertTrue(m.application.debuggable)
        assertEquals(false, m.application.allowBackup)
        assertEquals("com.example.sample.App", m.application.className)
        assertFalse(m.truncated)
    }

    @Test
    fun resolvesComponentNamesAndExportedDefaults() {
        val m = parser.parse(AxmlWriter.write(Fixtures.suspiciousManifest(targetSdk = 30)))
        val byName = m.components.associateBy { it.name }

        val activity = byName.getValue("com.example.sample.SettingsActivity")
        assertEquals(ComponentType.ACTIVITY, activity.type)
        assertFalse("без intent-filter activity не экспортирована", activity.exported)

        val receiver = byName.getValue("com.example.sample.BootReceiver")
        assertTrue("receiver с intent-filter экспортирован по умолчанию", receiver.exported)
        assertFalse(receiver.exportedExplicit)
        assertEquals(setOf("android.intent.action.BOOT_COMPLETED"), receiver.allActions)

        val service = byName.getValue("com.example.sample.sync.SyncService")
        assertFalse(service.exported)
        assertTrue(service.exportedExplicit)

        val provider = byName.getValue("com.example.sample.DataProvider")
        assertFalse("provider при targetSdk > 16 не экспортирован по умолчанию", provider.exported)
        assertEquals(listOf("com.example.sample.data", "com.example.sample.files"), provider.authorities)

        assertFalse("нет MAIN/LAUNCHER", m.hasLauncherActivity)
        assertEquals(1, m.exportedComponents.size)
    }

    @Test
    fun detectsLauncherActivity() {
        val m = parser.parse(AxmlWriter.write(Fixtures.launcherManifest()))
        assertTrue(m.hasLauncherActivity)
        assertEquals(36, m.targetSdk)
    }

    @Test
    fun usesResourceIdInsteadOfObfuscatedPoolName() {
        // В пуле строк атрибут назван "zzz", но resource ID — android:exported. Android считает его exported.
        val exportedId = AndroidAttributes.idFor("exported")!!
        val manifest = el(
            "manifest", plain("package", "x.y"),
            children = listOf(
                el(
                    "application",
                    children = listOf(
                        el("service", a("name", ".S"), A("exported", true, resId = exportedId, poolName = "zzz")),
                    ),
                ),
            ),
        )
        val m = parser.parse(AxmlWriter.write(manifest))
        val s = m.components.single()
        assertTrue(s.exported)
        assertTrue(s.exportedExplicit)
        assertEquals(1, m.renamedAttributeCount)
    }

    @Test
    fun rejectsTextXmlAndGarbage() {
        expectMalformed("<?xml version=\"1.0\"?><manifest/>".toByteArray())
        expectMalformed(ByteArray(4))
        expectMalformed(ByteArray(200) { (it * 31).toByte() })
    }

    @Test
    fun truncatedManifestStillYieldsPartialData() {
        val bytes = AxmlWriter.write(Fixtures.suspiciousManifest())
        // Отрезаем хвост: часть элементов потеряна, но пакет и первые разрешения читаются.
        val cut = bytes.copyOf(bytes.size * 3 / 4)
        val m = try {
            parser.parse(cut)
        } catch (e: MalformedApkException) {
            fail("частично повреждённый манифест должен читаться: ${e.message}"); return
        }
        assertEquals(Fixtures.PKG, m.packageName)
        assertTrue(m.truncated)
    }

    @Test
    fun resolveClassNames() {
        assertEquals("a.b.C", ManifestParser.resolveClass("a.b", ".C"))
        assertEquals("a.b.C", ManifestParser.resolveClass("a.b", "C"))
        assertEquals("x.y.Z", ManifestParser.resolveClass("a.b", "x.y.Z"))
    }

    private fun expectMalformed(bytes: ByteArray) {
        try {
            parser.parse(bytes)
            fail("ожидалась ошибка разбора")
        } catch (e: MalformedApkException) {
            assertNotNull(e.message)
        }
    }
}
