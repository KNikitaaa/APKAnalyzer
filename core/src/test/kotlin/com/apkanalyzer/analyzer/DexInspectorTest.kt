package com.apkanalyzer.analyzer

import com.apkanalyzer.analyzer.dex.ApiCategory
import com.apkanalyzer.analyzer.dex.DexInspector
import com.apkanalyzer.testing.DexWriter
import com.apkanalyzer.testing.Fixtures
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.nio.ByteBuffer
import java.nio.ByteOrder

class DexInspectorTest {

    private val inspector = DexInspector()

    @Test
    fun readsStringsTypesAndMethodRefs() {
        val p = inspector.parse("classes.dex", Fixtures.suspiciousDex())
        assertEquals("035", p.summary.version)
        assertTrue("https://evil-panel.xyz/api/upload?id=1" in p.strings)
        assertTrue("Landroid/telephony/SmsManager;" in p.types)
        assertTrue(("Landroid/telephony/SmsManager;" to "sendTextMessage") in p.methodRefs)
        assertEquals(4, p.definedClasses.size)
        assertFalse(p.summary.stringsTruncated)
    }

    @Test
    fun matchesSensitiveApis() {
        val p = inspector.parse("classes.dex", Fixtures.suspiciousDex())
        val categories = DexInspector.matchApis(listOf("classes.dex" to p)).map { it.api.category }.toSet()
        assertEquals(setOf(ApiCategory.SMS, ApiCategory.DYNAMIC_CODE, ApiCategory.HIDE_ICON), categories)
    }

    @Test
    fun classReferenceAloneDoesNotMatchMethodSignature() {
        // Ссылка на SmsManager есть, но sendTextMessage не вызывается — SMS-отправка не засчитывается.
        val dex = DexWriter.write(methodRefs = listOf("Landroid/telephony/SmsManager;" to "getDefault"))
        val apis = DexInspector.matchApis(listOf("classes.dex" to inspector.parse("classes.dex", dex)))
        assertTrue(apis.none { it.api.methodName == "sendTextMessage" })
    }

    @Test
    fun respectsStringBudget() {
        val dex = DexWriter.write(strings = (1..100).map { "s$it" })
        val p = inspector.parse("classes.dex", dex, stringBudget = 10)
        assertEquals(10, p.strings.size)
        assertTrue(p.summary.stringsTruncated)
    }

    @Test
    fun rejectsBadMagicAndOutOfRangeTables() {
        expect<MalformedApkException> { inspector.parse("x", ByteArray(0x70)) }
        val dex = Fixtures.suspiciousDex()
        val broken = dex.copyOf()
        ByteBuffer.wrap(broken).order(ByteOrder.LITTLE_ENDIAN).putInt(60, broken.size - 2) // string_ids за концом файла
        expect<MalformedApkException> { inspector.parse("x", broken) }
        val huge = dex.copyOf()
        ByteBuffer.wrap(huge).order(ByteOrder.LITTLE_ENDIAN).putInt(56, Int.MAX_VALUE)
        expect<MalformedApkException> { inspector.parse("x", huge) }
    }

    @Test
    fun decodesMutf8() {
        val bytes = byteArrayOf(3, 'a'.code.toByte(), 0xC3.toByte(), 0xA9.toByte(), 0xE2.toByte(), 0x82.toByte(), 0xAC.toByte(), 0)
        assertEquals("aé€", DexInspector.readMutf8(bytes, 0, 100))
        assertEquals(null, DexInspector.readMutf8(bytes, 100, 100))
    }
}
