package com.apkanalyzer.report

import com.apkanalyzer.reputation.HashReputation
import com.apkanalyzer.reputation.ReputationStatus

/** Уточняет итоговый риск по репутации именно проверенного SHA-256, сохраняя локальный вывод. */
object ReputationRiskFusion {
    private const val MAX_AGE_MS = 180L * 24 * 60 * 60 * 1000
    private const val CLOCK_SKEW_MS = 24L * 60 * 60 * 1000
    private val BLOCK_CLEAN_DOWNGRADE = setOf(
        "AOSP_TEST_KEY", "DEBUG_CERTIFICATE", "UNSIGNED", "PACKER",
        "ARCHIVE_TRICKS", "HIDDEN_PAYLOAD", "HIDDEN_PAYLOAD_DISGUISED",
    )

    fun apply(doc: ReportDocument, reputation: HashReputation): ReportDocument {
        require(reputation.fileSha256 == doc.file.sha256) { "Репутация относится к другому SHA-256" }
        val local = doc.localRisk ?: doc.risk
        val scanAge = reputation.lastAnalysisMs?.let { reputation.checkedAtMs - it }
        val fresh = scanAge != null && scanAge in -CLOCK_SKEW_MS..MAX_AGE_MS
        val risk = if (reputation.status != ReputationStatus.FOUND || !fresh) local else {
            val reason = "VirusTotal: ${reputation.malicious} вредоносных и ${reputation.suspicious} подозрительных из ${reputation.engines} ответов; локально: ${local.labelRu.lowercase()}, ${local.score}/100."
            when {
                reputation.malicious >= 5 && reputation.malicious * 10 >= reputation.engines ->
                    local.copy(code = RiskCode.HIGH, score = maxOf(local.score, 70), reasonRu = reason)
                (reputation.malicious >= 2 || reputation.suspicious >= 3) && local.code != RiskCode.HIGH ->
                    local.copy(code = RiskCode.ATTENTION, score = maxOf(local.score, 30), reasonRu = reason)
                reputation.malicious == 0 && reputation.suspicious == 0 && reputation.engines >= 30 &&
                    reputation.harmless >= 10 && local.code == RiskCode.ATTENTION &&
                    doc.findings.none { it.ruleId in BLOCK_CLEAN_DOWNGRADE || (it.combination && it.effectiveWeight >= 20f) } ->
                    local.copy(code = RiskCode.LOW, score = minOf(local.score, 29), reasonRu =
                        "Локально: ${local.score}/100; VirusTotal: 0 обнаружений, ${reputation.harmless} отметок «безопасно» из ${reputation.engines} ответов. Возможности приложения остаются в отчёте.")
                else -> local
            }
        }
        return doc.copy(
            schemaVersion = ReportDocument.SCHEMA_VERSION,
            localRisk = local,
            risk = risk,
            reputation = reputation,
            recommendations = Recommendations.forReport(risk, doc.findings),
            aiExplanation = if (risk == doc.risk) doc.aiExplanation else null,
        )
    }
}
