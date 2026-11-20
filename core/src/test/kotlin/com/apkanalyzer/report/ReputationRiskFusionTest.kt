package com.apkanalyzer.report

import com.apkanalyzer.reputation.HashReputation
import com.apkanalyzer.reputation.ReputationStatus
import com.apkanalyzer.testing.ApkSpec
import com.apkanalyzer.rules.SignerVerdict
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class ReputationRiskFusionTest {
    private val now = 1_800_000_000_000L
    private val base by lazy {
        val report = ApkSpec().report()
        ReportBuilder.build(report, com.apkanalyzer.rules.RiskEngine().assess(report), "0.6.0")
    }
    private fun rep(malicious: Int = 0, suspicious: Int = 0, harmless: Int = 0, undetected: Int = 60,
                    status: ReputationStatus = ReputationStatus.FOUND, scanMs: Long? = now - 86_400_000L,
                    sha256: String = base.file.sha256) = HashReputation(
        "VirusTotal", now, status, malicious, suspicious, harmless, undetected, null, scanMs,
        "https://www.virustotal.com/gui/file/$sha256", sha256,
    )

    @Test fun multipleDetectionsRaiseRiskAndSurviveHistoryRoundTrip() {
        val result = ReputationRiskFusion.apply(base, rep(malicious = 8, undetected = 52))
        assertEquals(RiskCode.HIGH, result.risk.code)
        assertEquals(base.risk, result.localRisk)
        assertTrue(result.recommendations.first().contains("Не устанавливайте"))
        assertEquals(result, ReportJson.decode(ReportJson.encode(result)))
    }

    @Test fun recheckAlwaysStartsFromLocalRisk() {
        val high = ReputationRiskFusion.apply(base, rep(malicious = 8, undetected = 52))
        val unknown = ReputationRiskFusion.apply(high, rep(status = ReputationStatus.NOT_FOUND))
        assertEquals(base.risk, unknown.risk)
        assertEquals(base.risk, unknown.localRisk)
        assertEquals(base.recommendations, unknown.recommendations)
    }

    @Test fun twoMaliciousDetectionsRequireAttention() {
        val result = ReputationRiskFusion.apply(base, rep(malicious = 2, undetected = 58))
        assertEquals(RiskCode.ATTENTION, result.risk.code)
    }

    @Test fun cleanReportOnlyDowngradesWeakAttention() {
        val attention = base.copy(risk = ReportRisk(RiskCode.ATTENTION, 55, "Локальные возможности", 1f))
        val clean = rep(harmless = 20, undetected = 40)
        val lowered = ReputationRiskFusion.apply(attention, clean)
        assertEquals(RiskCode.LOW, lowered.risk.code)
        assertEquals(55, lowered.localRisk!!.score)
        assertEquals(29, lowered.risk.score)
        assertEquals(RiskCode.ATTENTION, ReputationRiskFusion.apply(attention, rep()).risk.code)
        assertEquals(RiskCode.ATTENTION, ReputationRiskFusion.apply(attention, rep(harmless = 20, undetected = 40, scanMs = now - 181L * 86_400_000)).risk.code)
        assertEquals(RiskCode.HIGH, ReputationRiskFusion.apply(attention.copy(risk = attention.risk.copy(code = RiskCode.HIGH)), clean).risk.code)
    }

    @Test fun strongLocalEvidenceCannotBeErasedByCleanReport() {
        val strong = ReportFinding("COMBO_SPYWARE", "Связка", "", "Слежка", true, 45, 1f, 45f, emptyList(), emptyList())
        val attention = base.copy(risk = ReportRisk(RiskCode.ATTENTION, 55, "Связка", 1f), findings = listOf(strong))
        assertEquals(RiskCode.ATTENTION, ReputationRiskFusion.apply(attention, rep(harmless = 20, undetected = 40)).risk.code)
        val testKey = strong.copy(ruleId = "AOSP_TEST_KEY", combination = false)
        assertEquals(RiskCode.ATTENTION, ReputationRiskFusion.apply(attention.copy(findings = listOf(testKey)), rep(harmless = 20, undetected = 40)).risk.code)
    }

    @Test fun wrongHashCannotAffectRisk() {
        assertThrows(IllegalArgumentException::class.java) {
            ReputationRiskFusion.apply(base, rep(sha256 = "0".repeat(64)))
        }
    }

    @Test fun officialSignatureAndZeroDetectionsLowerYouTubeLikeScore() {
        val local = base.copy(risk = ReportRisk(RiskCode.ATTENTION, 55, "Возможности", 1f),
            findings = emptyList(), signerVerdict = SignerVerdict.OFFICIAL)
        val result = RiskFusion.withReputation(local, rep(undetected = 60))
        assertEquals(RiskCode.LOW, result.risk.code)
        assertEquals(24, result.risk.score)
        assertEquals(55, result.localRisk!!.score)
        assertEquals(result, ReportJson.decode(ReportJson.encode(result)))
        assertEquals(RiskCode.ATTENTION, RiskFusion.withReputation(local.copy(signerVerdict = SignerVerdict.UNKNOWN), rep()).risk.code)
    }

    @Test fun aiAdjustmentIsBoundedAndIndependentOfSourceOrder() {
        val finding = ReportFinding("CAMERA", "Камера", "", "Возможности", false, 10, 1f, 10f, emptyList(), emptyList())
        val local = base.copy(risk = ReportRisk(RiskCode.ATTENTION, 55, "Возможности", 1f), findings = listOf(finding))
        val ai = ReportAi("test", "model", now, emptyMap(), riskReview = AiRiskReview("lower", "high", listOf("CAMERA"), "Обычная функция"))
        val onlyAi = RiskFusion.withAi(local, ai)
        assertEquals(45, onlyAi.risk.score)
        val firstVt = RiskFusion.withAi(RiskFusion.withReputation(local, rep(harmless = 20, undetected = 40)), ai)
        val firstAi = RiskFusion.withReputation(onlyAi, rep(harmless = 20, undetected = 40))
        assertEquals(firstVt.risk, firstAi.risk)
        assertEquals(RiskCode.LOW, firstAi.risk.code)
        val strong = local.copy(findings = listOf(finding.copy(ruleId = "AOSP_TEST_KEY")))
        assertEquals(strong.risk, RiskFusion.withAi(strong, ai).risk)
    }
}
