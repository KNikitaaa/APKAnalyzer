package com.apkanalyzer.rules

import com.apkanalyzer.analyzer.AnalysisOutcome
import com.apkanalyzer.analyzer.ApkAnalyzer
import com.apkanalyzer.domain.model.RiskLevel
import com.apkanalyzer.testing.ApkBuilder
import com.apkanalyzer.testing.ApkSpec
import com.apkanalyzer.testing.AxmlWriter
import com.apkanalyzer.testing.Fixtures
import com.apkanalyzer.testing.component
import com.apkanalyzer.testing.tempApk
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class RiskEngineTest {

    private val engine = RiskEngine()

    private fun assessBytes(bytes: ByteArray): RiskAssessment {
        val outcome = ApkAnalyzer(clock = { 0L }).analyze(tempApk(bytes), "x.apk")
        return engine.assess((outcome as AnalysisOutcome.Completed).report)
    }

    @Test
    fun suspiciousSampleIsHighRisk() {
        val r = assessBytes(Fixtures.suspiciousApk())
        assertEquals(RiskLevel.High, r.level)
        assertTrue(r.score >= RiskEngine.HIGH_THRESHOLD)
        assertTrue("COMBO_SMS_STEALER" in r.triggeredRuleIds)
        assertTrue("HIDDEN_PAYLOAD_DISGUISED" in r.triggeredRuleIds)
        assertEquals(RuleKind.COMBINATION, r.matches.first().kind)
        assertEquals(RuleCatalog.VERSION, r.rulesVersion)
        assertTrue(r.levelReasonRu.contains("Похоже"))
    }

    @Test
    fun cleanSampleIsLowRisk() {
        val r = assessBytes(Fixtures.cleanApk())
        assertEquals(RiskLevel.Low, r.level)
        assertTrue(r.score < RiskEngine.ATTENTION_THRESHOLD)
    }

    @Test
    fun combinationOutweighsItsParts() {
        val parts = ApkSpec(permissions = listOf("INTERNET", "READ_SMS")).assess().score +
            ApkSpec(launcher = false).assess().score
        val combined = ApkSpec(permissions = listOf("INTERNET", "READ_SMS"), launcher = false).assess()
        assertTrue("связка ${combined.score} должна быть больше суммы частей $parts", combined.score > parts)
        assertNotEquals(RiskLevel.Low, combined.level)
    }

    @Test
    fun internetAloneMeansNothing() {
        val r = ApkSpec(permissions = listOf("INTERNET")).assess()
        assertTrue(r.matches.isEmpty())
    }

    @Test
    fun manyCommonPermissionsStayLow() {
        // Типичный мессенджер: камера, микрофон, контакты, геолокация, автозапуск, оверлеи, установка обновлений.
        val messenger = ApkSpec(
            permissions = listOf(
                "INTERNET", "CAMERA", "RECORD_AUDIO", "READ_CONTACTS", "ACCESS_FINE_LOCATION",
                "RECEIVE_BOOT_COMPLETED", "SYSTEM_ALERT_WINDOW", "REQUEST_INSTALL_PACKAGES", "READ_PHONE_STATE",
            ),
            components = listOf(component("receiver", ".Boot", actions = listOf("android.intent.action.BOOT_COMPLETED"))),
            apis = listOf("Ldalvik/system/DexClassLoader;" to "<init>", "Ljavax/crypto/Cipher;" to "getInstance"),
        ).assess()
        assertEquals("балл ${messenger.score}, причины ${messenger.triggeredRuleIds}", RiskLevel.Low, messenger.level)
        assertTrue(messenger.matches.size >= 8)
    }

    @Test
    fun defaultSmsAppIsMitigatedButEvidenceKept() {
        val smsReceiver = component("receiver", ".SmsDeliver", "BROADCAST_SMS", listOf("android.provider.Telephony.SMS_DELIVER"))
        val smsApp = ApkSpec(permissions = listOf("INTERNET", "READ_SMS", "RECEIVE_SMS", "SEND_SMS"), components = listOf(smsReceiver)).assess()
        val unknown = ApkSpec(permissions = listOf("INTERNET", "READ_SMS", "RECEIVE_SMS", "SEND_SMS")).assess()

        val mitigated = smsApp.matches.first { it.ruleId == "SMS_READ" }
        assertTrue(mitigated.mitigations.any { it.id == "MIT_DEFAULT_SMS_APP" })
        assertTrue(mitigated.evidence.isNotEmpty())
        assertTrue(mitigated.effectiveWeight < mitigated.baseWeight)
        assertTrue(smsApp.score < unknown.score)
    }

    @Test
    fun keyboardWithoutIconIsMitigated() {
        val ime = ApkSpec(launcher = false, components = listOf(component("service", ".Keyboard", "BIND_INPUT_METHOD", listOf("android.view.InputMethod")))).assess()
        val m = ime.matches.single { it.ruleId == "NO_LAUNCHER_ICON" }
        assertEquals("MIT_NO_ICON_BY_DESIGN", m.mitigations.single().id)
        assertEquals(RiskLevel.Low, ime.level)
    }

    @Test
    fun bankerIsHighRisk() {
        val r = ApkSpec(
            permissions = listOf("INTERNET", "SYSTEM_ALERT_WINDOW", "RECEIVE_SMS", "READ_SMS"),
            components = listOf(component("service", ".Acc", "BIND_ACCESSIBILITY_SERVICE")),
        ).assess()
        assertEquals(RiskLevel.High, r.level)
        assertEquals("COMBO_BANKER_ACCESSIBILITY", r.matches.first().ruleId)
    }

    @Test
    fun unreadableCodeIsInsufficient() {
        val zip = ApkBuilder.zip(
            listOf(
                "AndroidManifest.xml" to AxmlWriter.write(Fixtures.launcherManifest()),
                "classes.dex" to "dex\n035\u0000broken".toByteArray(),
            ),
        )
        val r = assessBytes(zip)
        assertEquals(RiskLevel.Insufficient, r.level)
        assertTrue(r.limitations.isNotEmpty())
    }

    @Test
    fun packedWithoutVisibleCodeIsInsufficient() {
        val elf = byteArrayOf(0x7F, 'E'.code.toByte(), 'L'.code.toByte(), 'F'.code.toByte()) + ByteArray(64)
        val r = ApkSpec(extraEntries = listOf("lib/arm64-v8a/libjiagu_a64.so" to elf)).assess()
        assertEquals(RiskLevel.Insufficient, r.level)
        assertTrue(r.levelReasonRu.contains("упаковщик"))
    }

    @Test
    fun resultIsDeterministic() {
        val report = ApkSpec(permissions = listOf("INTERNET", "READ_SMS"), launcher = false).report()
        assertEquals(engine.assess(report), engine.assess(report))
    }

    @Test
    fun scoreCombinationMath() {
        assertEquals(0, RiskEngine.combine(emptyList()))
        assertEquals(50, RiskEngine.combine(listOf(50f)))
        assertEquals(75, RiskEngine.combine(listOf(50f, 50f)))
        assertEquals(100, RiskEngine.combine(listOf(100f, 10f)))
        assertTrue(RiskEngine.combine(List(30) { 5f }) < 100)
    }

    @Test
    fun categoryScoresCoverAllMatches() {
        val r = assessBytes(Fixtures.suspiciousApk())
        assertEquals(r.matches.map { it.category }.toSet(), r.categoryScores.keys)
        assertTrue(r.categoryScores.values.all { it in 1..100 })
    }
}
