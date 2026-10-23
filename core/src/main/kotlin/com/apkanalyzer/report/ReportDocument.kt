package com.apkanalyzer.report

import com.apkanalyzer.analyzer.report.FeatureSection
import com.apkanalyzer.domain.model.RiskLevel

/**
 * Итоговый отчёт в «готовом к показу» виде. Один и тот же документ используется для экрана результата,
 * истории (хранится как JSON), экспорта в JSON и PDF. Документ собирает само приложение из локальных
 * доказательств; AI (этап 4) может только добавить отдельно помеченное объяснение в [aiExplanation].
 */
data class ReportDocument(
    val schemaVersion: Int = SCHEMA_VERSION,
    val generatedAtMs: Long,
    val appVersion: String,
    val analyzerVersion: String,
    val rulesVersion: String,
    val file: ReportFile,
    val app: ReportApp?,
    val risk: ReportRisk,
    val findings: List<ReportFinding>,
    val recommendations: List<String>,
    val limitations: List<String>,
    val sections: List<FeatureSection>,
    /** Объяснение модели (этап 4). Не влияет на [risk] и [findings]. */
    val aiExplanation: ReportAi? = null,
) {
    val title: String get() = app?.packageName ?: file.name

    companion object {
        /** v2 — структурированное AI-объяснение. Отчёты v1 читаются. */
        const val SCHEMA_VERSION = 2
    }
}

data class ReportFile(val name: String, val sizeBytes: Long, val sha256: String)

data class ReportApp(
    val packageName: String,
    val versionName: String?,
    val versionCode: Long?,
    val minSdk: Int?,
    val targetSdk: Int?,
)

enum class RiskCode(val level: RiskLevel) {
    LOW(RiskLevel.Low),
    ATTENTION(RiskLevel.Attention),
    HIGH(RiskLevel.High),
    INSUFFICIENT(RiskLevel.Insufficient),
    ;

    companion object {
        fun of(level: RiskLevel): RiskCode = entries.first { it.level == level }
        fun parse(code: String?): RiskCode = entries.firstOrNull { it.name == code } ?: INSUFFICIENT
    }
}

data class ReportRisk(
    val code: RiskCode,
    val score: Int,
    val reasonRu: String,
    val coverage: Float,
) {
    val level: RiskLevel get() = code.level
    val labelRu: String get() = level.labelRu
}

data class ReportFinding(
    val ruleId: String,
    val titleRu: String,
    val descriptionRu: String,
    val categoryRu: String,
    val combination: Boolean,
    val baseWeight: Int,
    val confidence: Float,
    val effectiveWeight: Float,
    val mitigations: List<String>,
    val evidence: List<ReportEvidence>,
)

data class ReportEvidence(val source: String, val detail: String)
