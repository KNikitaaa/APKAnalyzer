package com.apkanalyzer.analyzer

import com.apkanalyzer.analyzer.archive.ArchiveAnomaly
import com.apkanalyzer.analyzer.contents.ContentsSummary
import com.apkanalyzer.analyzer.dex.ApiUsage
import com.apkanalyzer.analyzer.dex.DexFileSummary
import com.apkanalyzer.analyzer.manifest.ApkManifest
import com.apkanalyzer.analyzer.signature.SignatureInfo
import com.apkanalyzer.analyzer.strings.StringIndicator

/** Этапы локального анализа. Вес определяет вклад этапа в «полноту анализа». */
enum class AnalysisStage(val labelRu: String, val weight: Int) {
    VALIDATION("Проверка файла", 0),
    HASH("Подсчёт SHA-256", 1),
    ARCHIVE("Структура архива", 1),
    MANIFEST("Манифест", 4),
    SIGNATURE("Цифровая подпись", 2),
    CONTENTS("Содержимое архива", 1),
    CODE("Код (DEX)", 4),
    ASSETS("Строки в ресурсах", 1),
}

enum class StageStatus(val labelRu: String) {
    OK("выполнен"),
    PARTIAL("выполнен частично"),
    FAILED("не выполнен"),
    SKIPPED("пропущен"),
}

data class StageResult(
    val stage: AnalysisStage,
    val status: StageStatus,
    val message: String? = null,
)

data class FileInfo(
    val displayName: String,
    val sizeBytes: Long,
    val sha256: String,
)

data class ObfuscationInfo(
    val definedClasses: Int,
    /** Доля классов с короткими (1–2 символа) именами — типичный след R8/ProGuard или обфускатора. */
    val shortNameRatio: Float,
)

data class CodeSummary(
    val dexFiles: List<DexFileSummary>,
    val apiUsages: List<ApiUsage>,
    val obfuscation: ObfuscationInfo,
    val stringsScanned: Int,
)

/**
 * «Сырые» факты об APK, собранные локально без запуска и установки.
 * Оценку риска по этим фактам строит движок правил (этап 2).
 */
data class ApkAnalysisReport(
    val analyzerVersion: String,
    val analyzedAtMs: Long,
    val durationMs: Long,
    val file: FileInfo,
    val manifest: ApkManifest?,
    val signature: SignatureInfo?,
    val contents: ContentsSummary?,
    val code: CodeSummary?,
    val indicators: List<StringIndicator>,
    val indicatorsTruncated: Boolean,
    val archiveAnomalies: List<ArchiveAnomaly>,
    val stages: List<StageResult>,
) {
    /** Полнота анализа 0..1 с учётом веса этапов (частичный этап засчитывается наполовину). */
    val coverage: Float
        get() {
            val relevant = stages.filter { it.stage.weight > 0 && it.status != StageStatus.SKIPPED }
            val total = AnalysisStage.entries.sumOf { it.weight }
            if (total == 0) return 0f
            val got = relevant.sumOf {
                when (it.status) {
                    StageStatus.OK -> it.stage.weight * 2
                    StageStatus.PARTIAL -> it.stage.weight
                    else -> 0
                }
            }
            return (got.toFloat() / (total * 2)).coerceIn(0f, 1f)
        }

    val limitations: List<String>
        get() = stages.filter { it.status != StageStatus.OK }
            .map { "${it.stage.labelRu}: ${it.status.labelRu}" + (it.message?.let { m -> " — $m" } ?: "") }
}

enum class RejectionKind {
    NOT_FOUND,
    TOO_LARGE,
    NOT_AN_APK,
    CORRUPTED,
    ZIP_BOMB,
}

sealed class AnalysisOutcome {
    data class Completed(val report: ApkAnalysisReport) : AnalysisOutcome()

    /** Файл не принят к анализу (не APK, повреждён до неузнаваемости, слишком велик). */
    data class Rejected(val kind: RejectionKind, val reason: String) : AnalysisOutcome()
}

/** Слушатель прогресса: текущий этап и общая доля выполнения 0..1. */
fun interface AnalysisProgressListener {
    fun onProgress(stage: AnalysisStage, fraction: Float)

    companion object {
        val NONE = AnalysisProgressListener { _, _ -> }
    }
}
