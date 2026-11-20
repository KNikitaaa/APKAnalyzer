package com.apkanalyzer.analyzer

import com.apkanalyzer.analyzer.dex.ApiCategory
import com.apkanalyzer.analyzer.strings.IndicatorType
import com.apkanalyzer.testing.ApkBuilder
import com.apkanalyzer.testing.AxmlWriter
import com.apkanalyzer.testing.DexWriter
import com.apkanalyzer.testing.Fixtures
import com.apkanalyzer.testing.a
import com.apkanalyzer.testing.el
import com.apkanalyzer.testing.plain
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

class SplitApkTest {

    private fun file(name: String, bytes: ByteArray): File =
        File(createTempDir(), name).apply { writeBytes(bytes); deleteOnExit() }

    private fun createTempDir(): File = kotlin.io.path.createTempDirectory("split").toFile().apply { deleteOnExit() }

    private fun splitManifest(split: String) = AxmlWriter.write(
        el("manifest", plain("package", Fixtures.PKG), plain("split", split)),
    )

    private fun featureSplit() = ApkBuilder.zip(
        listOf(
            "AndroidManifest.xml" to splitManifest("feature"),
            "classes.dex" to DexWriter.write(
                strings = listOf("https://split-gate.xyz/collect"),
                methodRefs = listOf("Landroid/telephony/SmsManager;" to "sendTextMessage"),
                definedClasses = listOf("Lcom/example/sample/feature/Hidden;"),
            ),
        ),
    )

    private fun abiSplit() = ApkBuilder.zip(
        listOf(
            "AndroidManifest.xml" to splitManifest("config.arm64_v8a"),
            "lib/arm64-v8a/libjiagu_a64.so" to byteArrayOf(0x7F, 'E'.code.toByte(), 'L'.code.toByte(), 'F'.code.toByte()) + ByteArray(32),
        ),
    )

    private fun analyze(splits: List<File>): ApkAnalysisReport {
        val base = file("base.apk", Fixtures.cleanApk())
        val outcome = ApkAnalyzer().analyze(base, "base.apk", splits = splits)
        assertTrue("ожидался отчёт, получено $outcome", outcome is AnalysisOutcome.Completed)
        return (outcome as AnalysisOutcome.Completed).report
    }

    @Test
    fun codeFromFeatureSplitIsAnalyzed() {
        val r = analyze(listOf(file("split_feature.apk", featureSplit())))

        assertTrue(r.code!!.apiUsages.any { it.api.category == ApiCategory.SMS })
        assertTrue(r.contents!!.dexFiles.contains("split_feature.apk!classes.dex"))
        val domain = r.indicators.single { it.type == IndicatorType.DOMAIN && it.value == "split-gate.xyz" }
        assertEquals("split_feature.apk!classes.dex", domain.source)
        assertEquals(1f, r.coverage, 0.001f)
    }

    @Test
    fun splitFilesAreListedWithHashes() {
        val bytes = featureSplit()
        val r = analyze(listOf(file("split_feature.apk", bytes)))

        val split = r.splits.single()
        assertEquals("split_feature.apk", split.name)
        assertEquals(bytes.size.toLong(), split.sizeBytes)
        assertEquals(64, split.sha256.length)
        assertNull(split.error)

        val section = com.apkanalyzer.analyzer.report.RawFeatureFormatter.format(r).single { it.id == "splits" }
        assertEquals("split_feature.apk", section.items.single().title)
        assertTrue(section.items.single().value!!.contains(split.sha256))
    }

    @Test
    fun nativeLibrariesAndPackersFromConfigSplitAreFound() {
        val r = analyze(listOf(file("split_config.arm64_v8a.apk", abiSplit())))

        val lib = r.contents!!.nativeLibraries.single()
        assertEquals("arm64-v8a", lib.abi)
        assertEquals("split_config.arm64_v8a.apk!lib/arm64-v8a/libjiagu_a64.so", lib.path)
        assertTrue(r.contents!!.abis.contains("arm64-v8a"))
        assertTrue(r.contents!!.packers.any { it.name.contains("Jiagu") })
    }

    @Test
    fun corruptedSplitLowersCoverageButBaseIsStillAnalyzed() {
        val r = analyze(listOf(file("split_broken.apk", ByteArray(200) { 7 })))

        assertTrue(r.manifest != null && r.code != null)
        assertTrue(r.splits.single().error != null)
        assertTrue(r.coverage < 1f)
        assertTrue(r.limitations.any { it.contains("split_broken.apk") })
    }

    @Test
    fun withoutSplitsReportHasNoSplitSection() {
        val r = analyze(emptyList())
        assertTrue(r.splits.isEmpty())
        assertTrue(com.apkanalyzer.analyzer.report.RawFeatureFormatter.format(r).none { it.id == "splits" })
        assertFalse(r.contents!!.dexFiles.any { '!' in it })
    }
}
