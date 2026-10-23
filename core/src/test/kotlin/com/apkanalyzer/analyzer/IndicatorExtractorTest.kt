package com.apkanalyzer.analyzer

import com.apkanalyzer.analyzer.strings.IndicatorExtractor
import com.apkanalyzer.analyzer.strings.IndicatorType
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class IndicatorExtractorTest {

    private fun scan(vararg s: String): IndicatorExtractor = IndicatorExtractor().apply { s.forEach { scan(it, "test") } }
    private fun IndicatorExtractor.values(t: IndicatorType) = indicators.filter { it.type == t }.map { it.value }

    @Test
    fun extractsUrlsAndHosts() {
        val x = scan("Connecting to https://Evil-Panel.xyz:8443/api?q=1, then http://10.0.0.2/x")
        assertEquals(listOf("https://Evil-Panel.xyz:8443/api?q=1", "http://10.0.0.2/x"), x.values(IndicatorType.URL))
        assertEquals(listOf("evil-panel.xyz"), x.values(IndicatorType.DOMAIN))
        val ip = x.indicators.single { it.type == IndicatorType.IPV4 }
        assertEquals("10.0.0.2", ip.value)
        assertTrue(ip.isPrivate)
    }

    @Test
    fun packageNamesAndXmlNamespacesAreNotDomains() {
        val x = scan("com.google.android.gms", "org.apache.http.client", "http://schemas.android.com/apk/res/android", "MainActivity.java")
        assertTrue(x.values(IndicatorType.DOMAIN).isEmpty())
        assertTrue(x.values(IndicatorType.URL).isEmpty())
    }

    @Test
    fun bareDomainIsAccepted() {
        assertEquals(listOf("api.telegram-bot.ru"), scan("api.telegram-bot.ru").values(IndicatorType.DOMAIN))
    }

    @Test
    fun ipVersusVersionStrings() {
        val x = scan("version 1.2.3.4", "v2.0.0.1", "server=185.234.10.77", "999.1.1.1", "01.02.03.04")
        assertEquals(listOf("185.234.10.77"), x.values(IndicatorType.IPV4))
        assertFalse(x.indicators.single { it.type == IndicatorType.IPV4 }.isPrivate)
    }

    @Test
    fun shellCommandsPathsAndContentUris() {
        val x = scan("su", "/system/bin/sh -c chmod 777 /data/local/tmp/x", "pm install -r /sdcard/a.apk", "content://sms/inbox", "Summary")
        val shell = x.values(IndicatorType.SHELL_COMMAND)
        assertTrue("su" in shell)
        assertTrue(shell.any { it.startsWith("/system/bin/sh") })
        assertTrue(shell.any { it.startsWith("pm install") })
        assertFalse(shell.any { it == "Summary" })
        assertTrue(x.values(IndicatorType.SUSPICIOUS_PATH).isNotEmpty())
        assertEquals(listOf("content://sms/inbox"), x.values(IndicatorType.CONTENT_URI))
    }

    @Test
    fun limitsAndDeduplication() {
        val x = IndicatorExtractor(maxPerType = 3)
        repeat(10) { x.scan("http://host$it.example.com/", "s") }
        x.scan("http://host0.example.com/", "s")
        assertEquals(3, x.indicators.count { it.type == IndicatorType.URL })
        assertTrue(x.truncated)
    }
}
