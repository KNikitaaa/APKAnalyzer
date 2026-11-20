package com.apkanalyzer.analyzer

import com.apkanalyzer.analyzer.resources.ArscResolver
import com.apkanalyzer.report.ReportBuilder
import com.apkanalyzer.report.ReportJson
import com.apkanalyzer.rules.RiskEngine
import com.apkanalyzer.testing.ApkBuilder
import com.apkanalyzer.testing.ArscWriter
import com.apkanalyzer.testing.AxmlWriter
import com.apkanalyzer.testing.DexWriter
import com.apkanalyzer.testing.Ref
import com.apkanalyzer.testing.a
import com.apkanalyzer.testing.el
import com.apkanalyzer.testing.plain
import com.apkanalyzer.testing.tempApk
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test
import java.util.Random

class ArscResolverTest {

    private val appName = 0x7f010000
    private val alias = 0x7f010001
    private val version = 0x7f010002

    private val arsc = ArscWriter.write(linkedMapOf(
        "app_name" to mapOf("" to "Sample Bank", "ru" to "Пример Банк", "de" to "Beispielbank"),
        "alias" to mapOf("" to Ref(appName)),
        "version" to mapOf("" to "3.1.4"),
    ))

    @Test
    fun resolvesByPreferredLocaleThenDefault() {
        val r = ArscResolver.parse(arsc)!!
        assertEquals("Пример Банк", r.string(appName, listOf("ru", "en")))
        assertEquals("Sample Bank", r.string(appName, listOf("fr")))
        assertEquals("Beispielbank", r.string(appName, listOf("de")))
    }

    @Test
    fun followsReferences() {
        assertEquals("Пример Банк", ArscResolver.parse(arsc)!!.string(alias, listOf("ru")))
    }

    @Test
    fun selfReferenceLoopDoesNotHang() {
        val loop = ArscWriter.write(linkedMapOf("a" to mapOf("" to Ref(appName))))
        assertNull(ArscResolver.parse(loop)!!.string(appName, listOf("ru")))
    }

    @Test
    fun sparseTablesFromNewAapt2() {
        val sparse = ArscWriter.write(linkedMapOf("x" to mapOf("ru" to "икс"), "app_name" to mapOf("" to "Sparse", "ru" to "Разреженный")), sparse = true)
        assertEquals("Разреженный", ArscResolver.parse(sparse)!!.string(0x7f010001, listOf("ru")))
    }

    @Test
    fun unknownIdsAndGarbageGiveNull() {
        assertNull(ArscResolver.parse(arsc)!!.string(0x7f0100ff, listOf("ru")))
        assertNull(ArscResolver.parse(arsc)!!.string(0x01040000, listOf("ru")))
        assertNull(ArscResolver.parse(ByteArray(10)))
        val rnd = Random(7)
        repeat(300) {
            val broken = arsc.copyOf()
            repeat(6) { broken[rnd.nextInt(broken.size)] = rnd.nextInt(256).toByte() }
            ArscResolver.parse(broken)?.string(appName, listOf("ru")) // не должно падать
        }
    }

    @Test
    fun analyzerShowsHumanReadableLabelAndVersion() {
        val manifest = el("manifest", plain("package", "com.example.sample"), a("versionCode", 3), a("versionName", Ref(version)),
            children = listOf(el("application", a("label", Ref(appName)))))
        val apk = ApkBuilder.zip(listOf(
            "AndroidManifest.xml" to AxmlWriter.write(manifest),
            "classes.dex" to DexWriter.write(),
            "resources.arsc" to arsc,
        ))
        val report = (ApkAnalyzer().analyze(tempApk(apk), "bank.apk") as AnalysisOutcome.Completed).report
        assertEquals("Пример Банк", report.manifest!!.application.label)
        assertEquals("3.1.4", report.manifest!!.versionName)

        val doc = ReportBuilder.build(report, RiskEngine().assess(report), "0.7.0")
        assertEquals("Пример Банк", doc.app!!.label)
        assertEquals("Пример Банк", doc.title)
        assertEquals("Пример Банк", ReportJson.decode(ReportJson.encode(doc)).app!!.label)
    }

    @Test
    fun missingArscKeepsReferenceVisible() {
        val manifest = el("manifest", plain("package", "com.example.sample"), children = listOf(el("application", a("label", Ref(appName)))))
        val apk = ApkBuilder.zip(listOf("AndroidManifest.xml" to AxmlWriter.write(manifest), "classes.dex" to DexWriter.write()))
        val report = (ApkAnalyzer().analyze(tempApk(apk), "x.apk") as AnalysisOutcome.Completed).report
        assertEquals("@0x7f010000", report.manifest!!.application.label)
        assertEquals("com.example.sample", ReportBuilder.build(report, RiskEngine().assess(report), "0.7.0").title)
    }
}
