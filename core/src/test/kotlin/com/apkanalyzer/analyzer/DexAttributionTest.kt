package com.apkanalyzer.analyzer

import com.apkanalyzer.analyzer.dex.ApiCategory
import com.apkanalyzer.analyzer.dex.DexInspector
import com.apkanalyzer.analyzer.dex.KnownLibraries
import com.apkanalyzer.analyzer.strings.IndicatorType
import com.apkanalyzer.testing.ApkBuilder
import com.apkanalyzer.testing.AxmlWriter
import com.apkanalyzer.testing.DexWriter
import com.apkanalyzer.testing.Fixtures
import com.apkanalyzer.testing.Insn
import com.apkanalyzer.testing.tempApk
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Код приложения отделяется от кода известных библиотек: вызов setComponentEnabledSetting
 * внутри androidx.work — не «скрытие иконки», а строка в okhttp3 — не адрес сервера злоумышленника.
 */
class DexAttributionTest {

    private val sms = Insn.Invoke("Landroid/telephony/SmsManager;", "sendTextMessage")
    private val hideIcon = Insn.Invoke("Landroid/content/pm/PackageManager;", "setComponentEnabledSetting")
    private val app = "Lcom/example/sample/Main;"
    private val workManager = "Landroidx/work/impl/utils/PackageManagerHelper;"

    private fun parse(dex: ByteArray, appPackage: String? = Fixtures.PKG) =
        DexInspector().parse("classes.dex", dex, appPackage = appPackage)

    private fun usages(dex: ByteArray, appPackage: String? = Fixtures.PKG) =
        DexInspector.matchApis(listOf("classes.dex" to parse(dex, appPackage)))

    @Test
    fun apiCalledFromAppCodeIsAttributedToApp() {
        val u = usages(DexWriter.write(code = mapOf(app to listOf(sms))))
        assertTrue(u.single { it.api.category == ApiCategory.SMS }.inAppCode)
    }

    @Test
    fun apiCalledOnlyFromLibraryIsMarkedAsLibrary() {
        val u = usages(DexWriter.write(code = mapOf(workManager to listOf(hideIcon), app to listOf(Insn.ConstString("hi")))))
        val usage = u.single { it.api.methodName == "setComponentEnabledSetting" }
        assertFalse(usage.inAppCode)
    }

    @Test
    fun typeOnlySignatureNeedsAppReference() {
        // ContextCompat из androidx хранит карту системных сервисов, включая MediaProjectionManager.
        val projection = "Landroid/media/projection/MediaProjectionManager;"
        val lib = usages(DexWriter.write(code = mapOf("Landroidx/core/content/ContextCompat;" to listOf(Insn.ConstClass(projection)), app to listOf(Insn.ConstString("x")))))
        assertFalse(lib.single { it.api.classDescriptor == projection }.inAppCode)

        val own = usages(DexWriter.write(code = mapOf(app to listOf(Insn.ConstClass(projection)))))
        assertTrue(own.single { it.api.classDescriptor == projection }.inAppCode)
    }

    @Test
    fun classesUnderManifestPackageAreAppCodeEvenWithLibraryLikePrefix() {
        val cls = "Lcom/google/android/gms/fake/Service;"
        assertTrue(usages(DexWriter.write(code = mapOf(cls to listOf(sms))), appPackage = "com.google.android.gms.fake").single().inAppCode)
        assertFalse(KnownLibraries.isLibrary(cls, appPackage = "com.google.android.gms.fake"))
        assertTrue(KnownLibraries.isLibrary(cls, appPackage = "org.other"))
    }

    @Test
    fun stringsFromLibraryCodeAreMarkedAsLibrary() {
        val dex = DexWriter.write(
            code = mapOf(
                app to listOf(Insn.ConstString("https://evil-gate.xyz/api")),
                "Lokhttp3/internal/publicsuffix/PublicSuffixDatabase;" to listOf(Insn.ConstString("https://library-only.top/list")),
            ),
        )
        val p = parse(dex)
        assertTrue(p.bytecodeAttributed)
        assertTrue("https://evil-gate.xyz/api" in p.appStrings)
        assertFalse("https://library-only.top/list" in p.appStrings)

        val apk = ApkBuilder.zip(listOf("AndroidManifest.xml" to AxmlWriter.write(Fixtures.launcherManifest()), "classes.dex" to dex))
        val report = (ApkAnalyzer().analyze(tempApk(apk), "a.apk") as AnalysisOutcome.Completed).report
        val domains = report.indicators.filter { it.type == IndicatorType.DOMAIN }.associate { it.value to it.fromLibrary }
        assertEquals(mapOf("evil-gate.xyz" to false, "library-only.top" to true), domains)
    }

    @Test
    fun payloadDataInsideCodeIsSkipped() {
        // Таблица switch стоит перед следующим методом; её данные похожи на invoke — их нельзя принимать за вызовы.
        // Метод №0 — setComponentEnabledSetting: если принять данные таблицы за invoke, он «вызовется» из приложения.
        val dex = DexWriter.write(
            methodRefs = listOf("Landroid/content/pm/PackageManager;" to "setComponentEnabledSetting"),
            code = mapOf(app to listOf(Insn.PackedSwitch(3), sms)),
        )
        val u = usages(dex)
        assertTrue(u.single { it.api.category == ApiCategory.SMS }.inAppCode)
        assertFalse(u.single { it.api.methodName == "setComponentEnabledSetting" }.inAppCode)
    }

    @Test
    fun dexWithoutCodeFallsBackToTables() {
        val p = parse(Fixtures.suspiciousDex())
        assertFalse(p.bytecodeAttributed)
        assertTrue(DexInspector.matchApis(listOf("classes.dex" to p)).all { it.inAppCode })
    }

    @Test
    fun brokenCodeOffsetDoesNotCrashAndFallsBack() {
        val p = parse(DexWriter.write(code = mapOf(app to listOf(sms)), corruptCodeOffset = true))
        assertFalse(p.bytecodeAttributed)
        assertTrue(DexInspector.matchApis(listOf("classes.dex" to p)).single().inAppCode)
    }
}
