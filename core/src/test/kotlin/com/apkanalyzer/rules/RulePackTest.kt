package com.apkanalyzer.rules

import com.apkanalyzer.domain.model.RiskLevel
import com.apkanalyzer.rules.pack.RulePack
import com.apkanalyzer.rules.pack.RulePackException
import com.apkanalyzer.rules.pack.RulePackSigner
import com.apkanalyzer.rules.pack.RulePackVerifier
import com.apkanalyzer.testing.ApkSpec
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.security.KeyPair

/** Подписанные пакеты правил: обновление весов, порогов и списков без новой версии приложения. */
class RulePackTest {

    private val keys: KeyPair = RulePackSigner.generateKeyPair()
    private val otherKeys: KeyPair = RulePackSigner.generateKeyPair()
    private val verifier = RulePackVerifier(trustedKeys = listOf(RulePackSigner.publicKeyBase64(keys)))

    private fun pack(
        version: String = "2026.11.1",
        weights: Map<String, Int> = emptyMap(),
        disabled: Set<String> = emptySet(),
        high: Int? = null,
        tlds: Set<String>? = null,
    ) = RulePack(
        version = version,
        baseCatalog = RuleCatalog.VERSION,
        createdAtMs = 1_762_000_000_000L,
        notes = "тест",
        weightOverrides = weights,
        disabledRules = disabled,
        highThreshold = high,
        attentionThreshold = null,
        suspiciousTlds = tlds,
        dynamicDns = null,
        publicDns = null,
        messengerC2 = null,
    )

    private fun signed(p: RulePack, kp: KeyPair = keys) = RulePackSigner.sign(p, kp)

    @Test
    fun validPackIsAccepted() {
        val p = verifier.verify(signed(pack(weights = mapOf("SMS_SEND" to 20))))
        assertEquals("2026.11.1", p.version)
        assertEquals(20, p.weightOverrides["SMS_SEND"])
    }

    @Test
    fun tamperedPayloadIsRejected() {
        val text = signed(pack(weights = mapOf("SMS_SEND" to 20)))
        // Подменяем вес в подписанном payload (base64) — подпись должна перестать сходиться.
        val envelope = com.apkanalyzer.analyzer.util.Json.parse(text) as com.apkanalyzer.analyzer.util.JsonValue.Obj
        val payload = String(java.util.Base64.getDecoder().decode(envelope.str("payload")!!)).replace("\"SMS_SEND\": 20", "\"SMS_SEND\": 0")
        val forged = text.replace(envelope.str("payload")!!, java.util.Base64.getEncoder().encodeToString(payload.toByteArray()))
        expectRejected(forged, "подпись")
    }

    @Test
    fun packSignedByUnknownKeyIsRejected() {
        expectRejected(signed(pack(), otherKeys), "подпись")
    }

    @Test
    fun rollbackToOlderVersionIsRejected() {
        val older = signed(pack(version = "2026.10.5"))
        try {
            verifier.verify(older, installedVersion = "2026.11.1")
            fail()
        } catch (e: RulePackException) {
            assertTrue(e.message!!.contains("старее"))
        }
        // Та же версия разрешена (переустановка), новее — тоже.
        verifier.verify(signed(pack(version = "2026.11.1")), installedVersion = "2026.11.1")
        verifier.verify(signed(pack(version = "2026.11.10")), installedVersion = "2026.11.9")
    }

    @Test
    fun unknownRulesAndBadValuesAreRejected() {
        expectRejected(signed(pack(weights = mapOf("NO_SUCH_RULE" to 5))), "неизвестн")
        expectRejected(signed(pack(weights = mapOf("SMS_SEND" to 150))), "0..100")
        expectRejected(signed(pack(disabled = setOf("NOPE"))), "неизвестн")
        expectRejected(signed(pack(high = 10)), "порог")
    }

    @Test
    fun packForAnotherCatalogIsRejected() {
        expectRejected(signed(pack().copy(baseCatalog = "2025.01.1")), "набор правил")
    }

    @Test
    fun garbageIsRejected() {
        expectRejected("{}", "")
        expectRejected("not json", "")
    }

    @Test
    fun weightOverrideChangesScoreAndVersionIsRecorded() {
        val spec = ApkSpec(permissions = listOf("INTERNET", "SEND_SMS"), apis = listOf("Landroid/telephony/SmsManager;" to "sendTextMessage"))
        val base = RiskEngine().assess(spec.report())
        val params = verifier.verify(signed(pack(weights = mapOf("SMS_SEND" to 40)))).toParams()
        val tuned = RiskEngine(params = params).assess(spec.report())

        assertEquals(10, base.matches.single { it.ruleId == "SMS_SEND" }.baseWeight)
        assertEquals(40, tuned.matches.single { it.ruleId == "SMS_SEND" }.baseWeight)
        assertTrue(tuned.score > base.score)
        assertEquals("${RuleCatalog.VERSION}+2026.11.1", tuned.rulesVersion)
    }

    @Test
    fun disabledRuleDoesNotFireAndThresholdsApply() {
        val spec = ApkSpec(permissions = listOf("INTERNET", "SEND_SMS"), apis = listOf("Landroid/telephony/SmsManager;" to "sendTextMessage"))
        val params = verifier.verify(signed(pack(disabled = setOf("SMS_SEND")))).toParams()
        assertFalse("SMS_SEND" in RiskEngine(params = params).assess(spec.report()).triggeredRuleIds)

        // Порог «Высокого риска» снижен до балла отчёта уровня «Нужно внимание» — отчёт становится «Высоким».
        val report = com.apkanalyzer.testing.ApkSpec(
            permissions = listOf("INTERNET", "READ_CONTACTS"),
            dexStrings = listOf("http://185.234.10.77/upload"),
        ).report()
        val normal = RiskEngine().assess(report)
        val strict = RiskEngine(params = verifier.verify(signed(pack(high = normal.score))).toParams()).assess(report)
        assertTrue(normal.level !is RiskLevel.High)
        assertTrue(strict.level is RiskLevel.High)
    }

    @Test
    fun listOverridesAreUsedByRules() {
        val spec = ApkSpec(dexStrings = listOf("https://panel.example.shop/api"))
        assertFalse("SUSPICIOUS_DOMAINS" in spec.assess().triggeredRuleIds)
        val params = verifier.verify(signed(pack(tlds = RuleParams.DEFAULT.suspiciousTlds + "shop"))).toParams()
        assertTrue("SUSPICIOUS_DOMAINS" in RiskEngine(params = params).assess(spec.report()).triggeredRuleIds)
    }

    @Test
    fun versionComparisonIsNumeric() {
        assertTrue(RulePackVerifier.compareVersions("2026.11.10", "2026.11.9") > 0)
        assertTrue(RulePackVerifier.compareVersions("2026.10.2", "2026.10.2") == 0)
        assertTrue(RulePackVerifier.compareVersions("2026.9.1", "2026.10.1") < 0)
    }

    @Test
    fun builtInTrustedKeyIsAValidP256Key() {
        assertTrue(com.apkanalyzer.rules.pack.RulePackKeys.TRUSTED.isNotEmpty())
        for (k in com.apkanalyzer.rules.pack.RulePackKeys.TRUSTED) {
            val key = java.security.KeyFactory.getInstance("EC").generatePublic(java.security.spec.X509EncodedKeySpec(java.util.Base64.getDecoder().decode(k)))
            assertEquals(256, (key as java.security.interfaces.ECPublicKey).params.order.bitLength())
        }
        // Пакет, подписанный не этим ключом, встроенный проверяющий не примет.
        try { RulePackVerifier().verify(signed(pack())); fail() } catch (_: RulePackException) { }
    }

    @Test
    fun shippedExamplePackIsSignedByTrustedKey() {
        val text = javaClass.getResource("/rulepacks/example.rulepack")!!.readText()
        val p = RulePackVerifier().verify(text)
        assertEquals("2026.11.2", p.version)
        assertTrue("trycloudflare.com" in p.toParams().dynamicDns)
    }

    private fun expectRejected(text: String, fragment: String) {
        try {
            verifier.verify(text)
            fail("пакет принят")
        } catch (e: RulePackException) {
            assertTrue("сообщение «${e.message}» должно содержать «$fragment»", e.message!!.contains(fragment, ignoreCase = true))
        }
    }
}
