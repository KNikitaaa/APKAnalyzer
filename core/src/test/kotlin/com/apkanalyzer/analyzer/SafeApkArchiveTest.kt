package com.apkanalyzer.analyzer

import com.apkanalyzer.analyzer.archive.ArchiveAnomalyType
import com.apkanalyzer.analyzer.archive.SafeApkArchive
import com.apkanalyzer.testing.ApkBuilder
import com.apkanalyzer.testing.tempApk
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.nio.ByteBuffer
import java.nio.ByteOrder

class SafeApkArchiveTest {

    @Test
    fun readsStoredAndDeflatedEntries() {
        val payload = ByteArray(10_000) { (it % 7).toByte() }
        val file = tempApk(ApkBuilder.zip(listOf("a.bin" to payload, "b.bin" to payload), stored = setOf("b.bin")))
        SafeApkArchive.open(file).use { zip ->
            assertEquals(2, zip.entries.size)
            assertArrayEquals(payload, zip.read(zip.find("a.bin")!!, 20_000))
            assertArrayEquals(payload, zip.read(zip.find("b.bin")!!, 20_000))
            assertArrayEquals(payload.copyOf(100), zip.read(zip.find("a.bin")!!, 100, truncate = true))
            assertTrue(zip.anomalies.isEmpty())
        }
    }

    @Test
    fun entryLimitIsEnforced() {
        val file = tempApk(ApkBuilder.zip(listOf("a.bin" to ByteArray(5000))))
        SafeApkArchive.open(file).use { zip ->
            expect<AnalysisLimitExceededException> { zip.read(zip.entries[0], 1000) }
        }
    }

    @Test
    fun zipBombIsDetectedByCompressionRatio() {
        // 64 МБ нулей сжимаются примерно в 1000 раз.
        val bomb = ByteArray(64 * 1024 * 1024)
        val file = tempApk(ApkBuilder.zip(listOf("bomb.bin" to bomb)))
        SafeApkArchive.open(file).use { zip ->
            val e = expect<AnalysisLimitExceededException> { zip.read(zip.entries[0], Int.MAX_VALUE - 16) }
            assertTrue(e.message!!.contains("zip-bomb"))
        }
    }

    @Test
    fun totalInflationBudgetIsEnforced() {
        val data = ByteArray(300_000) { (it * 13 % 251).toByte() }
        val file = tempApk(ApkBuilder.zip((1..5).map { "f$it" to data }))
        val limits = AnalysisLimits(maxTotalInflatedBytes = 1_000_000)
        SafeApkArchive.open(file, limits).use { zip ->
            expect<AnalysisLimitExceededException> { zip.entries.forEach { zip.read(it, 400_000) } }
        }
    }

    @Test
    fun rejectsNonZipTruncatedAndOversized() {
        expect<MalformedApkException> { SafeApkArchive.open(tempApk("not a zip at all, just text....................................".toByteArray())) }
        val zip = ApkBuilder.zip(listOf("a" to ByteArray(1000)))
        expect<MalformedApkException> { SafeApkArchive.open(tempApk(zip.copyOf(zip.size - 10))) }
        expect<AnalysisLimitExceededException> { SafeApkArchive.open(tempApk(zip), AnalysisLimits(maxApkBytes = 100)) }
        expect<AnalysisLimitExceededException> {
            SafeApkArchive.open(tempApk(ApkBuilder.zip((1..20).map { "e$it" to ByteArray(1) })), AnalysisLimits(maxZipEntries = 10))
        }
    }

    @Test
    fun detectsFakeEncryptionDuplicatesAndTraversal() {
        val bytes = ApkBuilder.zip(listOf("aa.txt" to "1".toByteArray(), "bb.txt" to "2".toByteArray(), "../evil.sh" to "x".toByteArray()))
        val bb = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN)
        val cdOffset = bb.getInt(bytes.size - 22 + 16)
        // Первая запись каталога: ставим флаг шифрования.
        bb.putShort(cdOffset + 8, (bb.getShort(cdOffset + 8).toInt() or 1).toShort())
        // Вторая запись: переименовываем "bb.txt" в "aa.txt" только в каталоге.
        val firstLen = 46 + bb.getShort(cdOffset + 28) + bb.getShort(cdOffset + 30) + bb.getShort(cdOffset + 32)
        val second = cdOffset + firstLen
        "aa.txt".toByteArray().copyInto(bytes, second + 46)

        SafeApkArchive.open(tempApk(bytes)).use { zip ->
            val types = zip.anomalies.map { it.type }.toSet()
            assertTrue(ArchiveAnomalyType.FAKE_ENCRYPTION_FLAG in types)
            assertTrue(ArchiveAnomalyType.DUPLICATE_ENTRY in types)
            assertTrue(ArchiveAnomalyType.PATH_TRAVERSAL in types)
            // Флаг шифрования игнорируется так же, как в Android: данные читаются.
            assertEquals("1", String(zip.read(zip.find("aa.txt")!!, 10)))
        }
    }

    @Test
    fun corruptedDeflateDataIsReportedNotCrashing() {
        // Плохо сжимаемые данные: сжатый поток занимает почти весь файл, порча попадает именно в него.
        val bytes = ApkBuilder.zip(listOf("a.bin" to ByteArray(50_000).also { java.util.Random(1).nextBytes(it) }))
        for (i in 40 until 200) bytes[i] = (bytes[i].toInt() xor 0x5A).toByte()
        SafeApkArchive.open(tempApk(bytes)).use { zip ->
            expect<MalformedApkException> { zip.read(zip.entries[0], 100_000) }
        }
    }
}

inline fun <reified T : Throwable> expect(block: () -> Unit): T {
    try {
        block()
    } catch (t: Throwable) {
        if (t is T) return t
        throw AssertionError("ожидалось ${T::class.simpleName}, получено ${t::class.simpleName}: ${t.message}", t)
    }
    fail("ожидалось исключение ${T::class.simpleName}")
    throw IllegalStateException()
}
