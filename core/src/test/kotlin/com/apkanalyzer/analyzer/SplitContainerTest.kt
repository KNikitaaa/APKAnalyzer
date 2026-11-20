package com.apkanalyzer.analyzer

import com.apkanalyzer.analyzer.dex.ApiCategory
import com.apkanalyzer.testing.ApkBuilder
import com.apkanalyzer.testing.AxmlWriter
import com.apkanalyzer.testing.DexWriter
import com.apkanalyzer.testing.Fixtures
import com.apkanalyzer.testing.Insn
import com.apkanalyzer.testing.el
import com.apkanalyzer.testing.plain
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.security.MessageDigest

/** Контейнеры split APK: .apks (SAI, bundletool), .xapk (APKPure), .apkm (APKMirror). */
class SplitContainerTest {

    private val tmp: File = kotlin.io.path.createTempDirectory("containers").toFile().apply { deleteOnExit() }
    private val analyzer = ApkAnalyzer(tempDir = tmp)

    private fun split(name: String, dex: ByteArray? = null) = ApkBuilder.zip(
        listOfNotNull(
            "AndroidManifest.xml" to AxmlWriter.write(el("manifest", plain("package", Fixtures.PKG), plain("split", name))),
            dex?.let { "classes.dex" to it },
        ),
    )

    private val featureDex = DexWriter.write(code = mapOf("Lcom/example/sample/Pay;" to listOf(Insn.Invoke("Landroid/telephony/SmsManager;", "sendTextMessage"))))

    private fun analyze(name: String, bytes: ByteArray): AnalysisOutcome {
        val f = File(tmp, name).apply { writeBytes(bytes) }
        return analyzer.analyze(f, name)
    }

    private fun completed(name: String, bytes: ByteArray): ApkAnalysisReport {
        val o = analyze(name, bytes)
        assertTrue("ожидался отчёт: $o", o is AnalysisOutcome.Completed)
        return (o as AnalysisOutcome.Completed).report
    }

    private fun sha(b: ByteArray) = MessageDigest.getInstance("SHA-256").digest(b).joinToString("") { "%02x".format(it) }

    @Test
    fun saiApksIsAnalyzedAsBasePlusSplits() {
        val base = Fixtures.cleanApk()
        val container = ApkBuilder.zip(listOf("base.apk" to base, "split_feature.apk" to split("feature", featureDex)), stored = setOf("base.apk"))
        val r = completed("app.apks", container)

        assertEquals("APKS", r.containerFormat)
        assertEquals("app.apks", r.file.displayName)
        assertEquals(sha(container), r.file.sha256)
        assertEquals(Fixtures.PKG, r.manifest!!.packageName)
        assertEquals(listOf("base.apk", "split_feature.apk"), r.splits.map { it.name })
        assertEquals(sha(base), r.splits.first().sha256)
        assertTrue(r.code!!.apiUsages.any { it.api.category == ApiCategory.SMS })
        assertEquals(1f, r.coverage, 0.001f)
        val file = com.apkanalyzer.analyzer.report.RawFeatureFormatter.format(r).first { it.id == "file" }
        assertTrue(file.items.any { it.title == "Формат" && it.value!!.contains("APKS") })
    }

    @Test
    fun bundletoolApksUsesBaseMaster() {
        val container = ApkBuilder.zip(listOf(
            "toc.pb" to ByteArray(8),
            "splits/base-arm64_v8a.apk" to split("config.arm64_v8a"),
            "splits/base-master.apk" to Fixtures.cleanApk(),
        ))
        val r = completed("bundle.apks", container)
        assertEquals("splits/base-master.apk", r.splits.first().name)
        assertEquals(2, r.splits.size)
    }

    @Test
    fun xapkFindsBaseByPackageNameAndSkipsObb() {
        val container = ApkBuilder.zip(listOf(
            "manifest.json" to """{"package_name":"${Fixtures.PKG}","name":"Sample","split_apks":[]}""".toByteArray(),
            "config.arm64_v8a.apk" to split("config.arm64_v8a"),
            "${Fixtures.PKG}.apk" to Fixtures.cleanApk(),
            "icon.png" to ByteArray(10),
            "Android/obb/${Fixtures.PKG}/main.1.obb" to ByteArray(1000),
        ))
        val r = completed("app.xapk", container)
        assertEquals("XAPK", r.containerFormat)
        assertEquals("${Fixtures.PKG}.apk", r.splits.first().name)
        assertEquals(listOf("${Fixtures.PKG}.apk", "config.arm64_v8a.apk"), r.splits.map { it.name })
    }

    @Test
    fun apkmWithInfoJson() {
        val container = ApkBuilder.zip(listOf("info.json" to "{}".toByteArray(), "base.apk" to Fixtures.cleanApk(), "split_config.ru.apk" to split("config.ru")))
        assertEquals("APKM", completed("app.apkm", container).containerFormat)
    }

    @Test
    fun encryptedOrBrokenBaseIsRejectedWithExplanation() {
        val container = ApkBuilder.zip(listOf("info.json" to "{}".toByteArray(), "base.apk" to ByteArray(4096) { (it * 31).toByte() }))
        val o = analyze("enc.apkm", container)
        assertTrue(o is AnalysisOutcome.Rejected)
        assertTrue((o as AnalysisOutcome.Rejected).reason.contains("зашифрован"))
    }

    @Test
    fun dangerousNamesNeverEscapeTempDirAndTempFilesAreRemoved() {
        val container = ApkBuilder.zip(listOf("base.apk" to Fixtures.cleanApk(), "../../escape.apk" to split("x")))
        val before = tmp.walk().filter { it.isFile }.map { it.name }.toSet()
        val r = completed("evil.apks", container)
        assertTrue(r.splits.any { it.name == "../../escape.apk" })
        assertTrue(!File(tmp.parentFile.parentFile, "escape.apk").exists())
        val after = tmp.walk().filter { it.isFile }.map { it.name }.toSet()
        assertEquals("временные файлы должны удаляться", before + "evil.apks", after)
    }

    @Test
    fun plainZipWithoutApksIsStillNotAnApk() {
        val o = analyze("notes.zip", ApkBuilder.zip(listOf("readme.txt" to "hi".toByteArray())))
        assertEquals(RejectionKind.NOT_AN_APK, (o as AnalysisOutcome.Rejected).kind)
    }

    @Test
    fun regularApkHasNoContainerFormat() {
        assertNull(completed("plain.apk", Fixtures.cleanApk()).containerFormat)
    }
}
