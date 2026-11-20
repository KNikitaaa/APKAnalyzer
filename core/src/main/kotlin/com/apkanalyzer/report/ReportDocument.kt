package com.apkanalyzer.report

import com.apkanalyzer.analyzer.report.FeatureSection
import com.apkanalyzer.domain.model.RiskLevel
import com.apkanalyzer.rules.SignerVerdict

/**
 * Итоговый отчёт в «готовом к показу» виде. Один и тот же документ используется для экрана результата,
 * истории (хранится как JSON), экспорта в JSON и PDF. Локальные доказательства собирает само приложение;
 * внешние источники могут уточнить итог, сохраняя [localRisk] и локальные доказательства.
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
    /** Объяснение и ограниченная рекомендация модели. Не меняет [findings]. */
    val aiExplanation: ReportAi? = null,
    /** Части split APK, проанализированные вместе с основным файлом (у установленных приложений). */
    val splits: List<ReportFile> = emptyList(),
    /** Репутация по SHA-256 во внешнем сервисе (по запросу пользователя). */
    val reputation: com.apkanalyzer.reputation.HashReputation? = null,
    /** Исходная локальная оценка до уточнения внешними источниками. */
    val localRisk: ReportRisk? = null,
    /** Результат криптографической проверки сертификата по встроенному каталогу. */
    val signerVerdict: SignerVerdict = SignerVerdict.UNKNOWN,
) {
    /** Название для заголовков: имя приложения из ресурсов, иначе пакет, иначе имя файла. */
    val title: String get() = app?.label?.takeIf { !it.startsWith("@") } ?: app?.packageName ?: file.name

    companion object {
        /** v5 — проверенная подпись и структурированная рекомендация AI. Старые отчёты читаются. */
        const val SCHEMA_VERSION = 5
    }
}

data class ReportFile(val name: String, val sizeBytes: Long, val sha256: String)

data class ReportApp(
    val packageName: String,
    val versionName: String?,
    val versionCode: Long?,
    val minSdk: Int?,
    val targetSdk: Int?,
    /** Название приложения (android:label, из resources.arsc). */
    val label: String? = null,
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
