package com.apkanalyzer.report

import com.apkanalyzer.reputation.HashReputation
import com.apkanalyzer.reputation.ReputationStatus
import com.apkanalyzer.rules.SignerVerdict

/** Пересчёт всегда начинается с локального вывода, независимо от порядка ответов источников. */
object RiskFusion {
    private const val MAX_AGE_MS = 180L * 24 * 60 * 60 * 1000
    private const val CLOCK_SKEW_MS = 24L * 60 * 60 * 1000
    private val BLOCK_CLEAN_DOWNGRADE = setOf(
        "AOSP_TEST_KEY", "DEBUG_CERTIFICATE", "UNSIGNED", "PACKER",
        "ARCHIVE_TRICKS", "HIDDEN_PAYLOAD", "HIDDEN_PAYLOAD_DISGUISED",
        "SIGNER_MISMATCH", "INVALID_SIGNATURE",
    )

    fun withReputation(doc: ReportDocument, reputation: HashReputation): ReportDocument {
        require(reputation.fileSha256 == doc.file.sha256) { "Репутация относится к другому SHA-256" }
        return recalculate(doc.copy(reputation = reputation))
    }

    fun withAi(doc: ReportDocument, ai: ReportAi): ReportDocument = recalculate(doc.copy(aiExplanation = ai))

    fun recalculate(doc: ReportDocument): ReportDocument {
        val local = doc.localRisk ?: doc.risk
        var risk = local
        val rep = doc.reputation?.takeIf { it.fileSha256 == doc.file.sha256 && it.status == ReputationStatus.FOUND }
        val age = rep?.lastAnalysisMs?.let { rep.checkedAtMs - it }
        val fresh = age != null && age in -CLOCK_SKEW_MS..MAX_AGE_MS
        val strongLocal = doc.findings.any {
            it.ruleId in BLOCK_CLEAN_DOWNGRADE || (it.combination && it.effectiveWeight >= 20f)
        } || doc.signerVerdict == SignerVerdict.MISMATCH

        if (rep != null && fresh) {
            val reason = "VirusTotal: ${rep.malicious} вредоносных и ${rep.suspicious} подозрительных из ${rep.engines} ответов; локально: ${local.labelRu.lowercase()}, ${local.score}/100."
            risk = when {
                rep.malicious >= 5 && rep.malicious * 10 >= rep.engines ->
                    local.copy(code = RiskCode.HIGH, score = maxOf(local.score, 70), reasonRu = reason)
                (rep.malicious >= 2 || rep.suspicious >= 3) && local.code != RiskCode.HIGH ->
                    local.copy(code = RiskCode.ATTENTION, score = maxOf(local.score, 30), reasonRu = reason)
                rep.malicious == 0 && rep.suspicious == 0 && rep.engines >= 30 &&
                    local.code == RiskCode.ATTENTION && !strongLocal &&
                    (rep.harmless >= 10 || doc.signerVerdict == SignerVerdict.OFFICIAL) -> {
                    val official = doc.signerVerdict == SignerVerdict.OFFICIAL
                    local.copy(
                        code = RiskCode.LOW,
                        score = if (official) minOf(local.score, 24) else minOf(local.score, 29),
                        reasonRu = if (official)
                            "Локально: ${local.score}/100; проверена официальная подпись разработчика; VirusTotal: 0 обнаружений из ${rep.engines} ответов. Это снижает риск, но не доказывает безопасность."
                        else
                            "Локально: ${local.score}/100; VirusTotal: 0 обнаружений, ${rep.harmless} отметок «безопасно» из ${rep.engines} ответов. Возможности приложения остаются в отчёте.",
                    )
                }
                else -> local
            }
        }

        val review = doc.aiExplanation?.riskReview
        val validRules = doc.findings.map { it.ruleId }.toSet()
        if (review != null && review.confidence == "high" && review.ruleIds.isNotEmpty() &&
            review.ruleIds.all { it in validRules } && !strongLocal) {
            risk = when {
                review.direction == "lower" && risk.code == RiskCode.ATTENTION &&
                    (rep == null || !fresh || rep.malicious == 0 && rep.suspicious == 0) -> {
                    val score = (risk.score - 10).coerceAtLeast(0)
                    risk.copy(
                        code = if (score <= 29) RiskCode.LOW else RiskCode.ATTENTION,
                        score = score,
                        reasonRu = risk.reasonRu + " AI предложил снизить балл на 10 по локальным находкам: ${review.reasonRu}",
                    )
                }
                review.direction == "raise" && risk.code == RiskCode.LOW &&
                    doc.findings.any { it.ruleId in review.ruleIds && it.effectiveWeight >= 10f } ->
                    risk.copy(code = RiskCode.ATTENTION, score = maxOf(risk.score + 10, 30),
                        reasonRu = risk.reasonRu + " AI указал на локальные находки: ${review.reasonRu}")
                else -> risk
            }
        }
        return doc.copy(
            schemaVersion = ReportDocument.SCHEMA_VERSION,
            localRisk = local,
            risk = risk,
            recommendations = Recommendations.forReport(risk, doc.findings),
        )
    }
}

object ReputationRiskFusion {
    fun apply(doc: ReportDocument, reputation: HashReputation): ReportDocument = RiskFusion.withReputation(doc, reputation)
}
