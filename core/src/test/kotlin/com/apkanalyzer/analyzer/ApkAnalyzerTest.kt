package com.apkanalyzer.analyzer

import com.apkanalyzer.analyzer.contents.PayloadKind
import com.apkanalyzer.analyzer.dex.ApiCategory
import com.apkanalyzer.analyzer.report.RawFeatureFormatter
import com.apkanalyzer.analyzer.strings.IndicatorType
import com.apkanalyzer.testing.ApkBuilder
import com.apkanalyzer.testing.AxmlWriter
import com.apkanalyzer.testing.Fixtures
import com.apkanalyzer.testing.tempApk
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.MessageDigest
import java.util.Random

class ApkAnalyzerTest {

    private val analyzer = ApkAnalyzer()

    private fun completed(bytes: ByteArray, analyzer: ApkAnalyzer = this.analyzer): ApkAnalysisReport {
        val outcome = analyzer.analyze(tempApk(bytes), "sample.apk")
        assertTrue("ожидался отчёт, получено $outcome", outcome is AnalysisOutcome.Completed)
        return (outcome as AnalysisOutcome.Completed).report
    }

    @Test
    fun fullAnalysisOfSuspiciousApk() {
        val bytes = Fixtures.suspiciousApk()
        val r = completed(bytes)

        assertEquals(MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }, r.file.sha256)
        assertEquals(bytes.size.toLong(), r.file.sizeBytes)
        assertEquals(1f, r.coverage, 0.001f)
        assertTrue(r.limitations.isEmpty())

        val m = r.manifest!!
        assertEquals(Fixtures.PKG, m.packageName)
        assertTrue("android.permission.READ_SMS" in m.permissionNames)

        assertTrue(r.signature!!.certificates.single().isAndroidDebug)

        val code = r.code!!
        assertEquals(2, code.dexFiles.size)
        assertTrue(code.apiUsages.any { it.api.category == ApiCategory.SMS })
        assertTrue(code.obfuscation.shortNameRatio > 0.5f)

        val values = r.indicators.groupBy({ it.type }, { it.value })
        assertTrue("evil-panel.xyz" in values.getValue(IndicatorType.DOMAIN))
        assertTrue("c2.badhost.top" in values.getValue(IndicatorType.DOMAIN))
        assertTrue("185.234.10.77" in values.getValue(IndicatorType.IPV4))
        assertTrue("91.215.85.3" in values.getValue(IndicatorType.IPV4))
        assertTrue(r.indicators.any { it.value == "c2.badhost.top" && it.source == "assets/config.json" })
        assertTrue("su" in values.getValue(IndicatorType.SHELL_COMMAND))

        val contents = r.contents!!
        assertEquals(listOf("classes.dex", "classes2.dex"), contents.dexFiles)
        assertEquals(setOf("arm64-v8a"), contents.abis)
        assertTrue(contents.packers.any { it.name.contains("Jiagu") })
        assertEquals(PayloadKind.MISNAMED, contents.hiddenPayloads.single { it.path == "assets/logo.png" }.kind)
    }

    @Test
    fun cleanApkHasLauncherAndNoWarnings() {
        val r = completed(Fixtures.cleanApk())
        assertTrue(r.manifest!!.hasLauncherActivity)
        assertTrue(r.code!!.apiUsages.isEmpty())
        assertTrue(r.contents!!.packers.isEmpty())
        assertTrue(r.contents!!.hiddenPayloads.isEmpty())
        assertTrue(r.archiveAnomalies.isEmpty())
    }

    @Test
    fun rejectsNonApkInputs() {
        assertRejected(RejectionKind.NOT_AN_APK, "просто текст, а не архив, совсем не APK......................".toByteArray())
        assertRejected(RejectionKind.NOT_AN_APK, ApkBuilder.zip(listOf("readme.txt" to "hi".toByteArray())))
        val apk = Fixtures.suspiciousApk()
        assertRejected(RejectionKind.CORRUPTED, apk.copyOf(apk.size / 2))
        val outcome = ApkAnalyzer(AnalysisLimits(maxApkBytes = 1000)).analyze(tempApk(apk))
        assertEquals(RejectionKind.TOO_LARGE, (outcome as AnalysisOutcome.Rejected).kind)
        val missing = ApkAnalyzer().analyze(java.io.File("/nonexistent/file.apk"))
        assertEquals(RejectionKind.NOT_FOUND, (missing as AnalysisOutcome.Rejected).kind)
    }

    @Test
    fun brokenDexReducesCoverageButAnalysisContinues() {
        val zip = ApkBuilder.zip(
            listOf(
                "AndroidManifest.xml" to AxmlWriter.write(Fixtures.launcherManifest()),
                "classes.dex" to "dex\n035\u0000broken".toByteArray(),
            ),
        )
        val r = completed(zip)
        assertNotNull(r.manifest)
        assertEquals(null, r.code)
        assertTrue(r.coverage < 0.8f)
        assertTrue(r.stages.any { it.stage == AnalysisStage.CODE && it.status == StageStatus.FAILED })
        assertTrue(r.limitations.isNotEmpty())
    }

    @Test
    fun zipBombInsideApkDoesNotExhaustMemory() {
        val zip = ApkBuilder.zip(
            listOf(
                "AndroidManifest.xml" to AxmlWriter.write(Fixtures.launcherManifest()),
                "classes.dex" to ByteArray(80 * 1024 * 1024),
            ),
        )
        val r = completed(zip)
        assertTrue(r.stages.any { it.stage == AnalysisStage.CODE && it.status == StageStatus.FAILED })
    }

    @Test
    fun cancellationStopsAnalysis() {
        var calls = 0
        expect<AnalysisCancelledException> {
            analyzer.analyze(tempApk(Fixtures.suspiciousApk()), cancel = { ++calls > 3 })
        }
    }

    @Test
    fun progressIsReportedForEveryStage() {
        val seen = mutableListOf<AnalysisStage>()
        var last = -1f
        analyzer.analyze(tempApk(Fixtures.suspiciousApk()), progress = { stage, f ->
            seen += stage
            assertTrue(f >= last)
            last = f
        })
        assertEquals(AnalysisStage.entries.toSet(), seen.toSet())
        assertEquals(1f, last, 0.0001f)
    }

    @Test
    fun sameFileGivesSameResult() {
        val bytes = Fixtures.suspiciousApk()
        val fixedClock = { 1_700_000_000_000L }
        val a = completed(bytes, ApkAnalyzer(clock = fixedClock))
        val b = completed(bytes, ApkAnalyzer(clock = fixedClock))
        assertEquals(a, b)
    }

    @Test
    fun formatterProducesSections() {
        val sections = RawFeatureFormatter.format(completed(Fixtures.suspiciousApk()))
        val ids = sections.map { it.id }
        for (id in listOf("file", "package", "permissions", "components", "signature", "code", "network", "strings", "contents")) {
            assertTrue("нет секции $id", id in ids)
        }
        assertTrue(sections.first { it.id == "package" }.items.any { it.title == "Нет иконки в лаунчере" })
    }

    /**
     * Фаззинг: тысячи случайно испорченных APK. Анализатор обязан вернуть результат
     * (отчёт или отказ), но никогда не упасть с неожиданным исключением.
     */
    @Test
    fun randomCorruptionNeverCrashes() {
        val base = Fixtures.suspiciousApk()
        val rnd = Random(20261022)
        val limits = AnalysisLimits(maxTotalInflatedBytes = 64L * 1024 * 1024)
        val fuzzAnalyzer = ApkAnalyzer(limits)
        var completed = 0
        var rejected = 0
        repeat(1500) { iteration ->
            val bytes = base.copyOf()
            when (iteration % 4) {
                0 -> repeat(1 + rnd.nextInt(8)) { bytes[rnd.nextInt(bytes.size)] = rnd.nextInt(256).toByte() }
                1 -> repeat(1 + rnd.nextInt(64)) { bytes[rnd.nextInt(bytes.size)] = rnd.nextInt(256).toByte() }
                2 -> { // порча 4-байтных полей (размеры/смещения)
                    repeat(1 + rnd.nextInt(4)) {
                        val p = rnd.nextInt(bytes.size - 4)
                        val v = if (rnd.nextBoolean()) -1 else rnd.nextInt()
                        for (k in 0 until 4) bytes[p + k] = (v ushr (8 * k)).toByte()
                    }
                }
                else -> Unit // обрезка — ниже
            }
            val input = if (iteration % 4 == 3) bytes.copyOf(1 + rnd.nextInt(bytes.size - 1)) else bytes
            val outcome = try {
                fuzzAnalyzer.analyze(tempApk(input))
            } catch (t: Throwable) {
                throw AssertionError("итерация $iteration: необработанное ${t::class.simpleName}: ${t.message}", t)
            }
            if (outcome is AnalysisOutcome.Completed) {
                completed++
                RawFeatureFormatter.format(outcome.report)
            } else {
                rejected++
            }
        }
        assertTrue(completed > 0)
        assertTrue(rejected > 0)
    }

    private fun assertRejected(kind: RejectionKind, bytes: ByteArray) {
        val outcome = analyzer.analyze(tempApk(bytes))
        assertTrue("ожидался отказ $kind, получено $outcome", outcome is AnalysisOutcome.Rejected)
        assertEquals(kind, (outcome as AnalysisOutcome.Rejected).kind)
    }
}
