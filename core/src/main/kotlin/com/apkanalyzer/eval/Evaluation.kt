package com.apkanalyzer.eval

import com.apkanalyzer.analyzer.AnalysisOutcome
import com.apkanalyzer.analyzer.ApkAnalyzer
import com.apkanalyzer.domain.model.RiskLevel
import com.apkanalyzer.rules.RiskEngine
import com.apkanalyzer.rules.RuleCatalog
import java.io.File
import java.util.Locale

/**
 * Замер качества на размеченном наборе (критерий готовности MVP):
 * доля ложных срабатываний (FP), пропусков (FN) и файлов с неполным анализом.
 *
 * Набор — папка с подпапками `malicious/` и `benign/` с APK-файлами.
 * Запуск: `./gradlew :core:evaluate -Psamples=<папка>`.
 */
enum class GroundTruth { MALICIOUS, BENIGN }

data class LabeledSample(val file: File, val truth: GroundTruth)

object LabeledSet {
    fun fromDirectory(root: File): List<LabeledSample> = GroundTruth.entries.flatMap { truth ->
        File(root, truth.name.lowercase()).listFiles().orEmpty()
            .filter { it.isFile && it.extension.equals("apk", ignoreCase = true) }
            .sortedBy { it.name }
            .map { LabeledSample(it, truth) }
    }
}

data class SampleResult(
    val name: String,
    val truth: GroundTruth,
    /** null — файл отклонён до оценки (повреждён, не APK, сработал защитный лимит). */
    val level: RiskLevel?,
    val score: Int,
    val coverage: Float,
    val rejectedReason: String?,
    val topRules: List<String>,
) {
    val incomplete: Boolean get() = level == null || level is RiskLevel.Insufficient
}

/** Какой уровень риска считать «обнаружением». */
enum class DetectionPolicy(val labelRu: String) {
    HIGH_ONLY("Обнаружение = «Высокий риск»"),
    ATTENTION_OR_HIGH("Обнаружение = «Нужно внимание» или «Высокий риск»"),
    ;

    fun detects(level: RiskLevel): Boolean = when (this) {
        HIGH_ONLY -> level is RiskLevel.High
        ATTENTION_OR_HIGH -> level is RiskLevel.High || level is RiskLevel.Attention
    }
}

/** Файлы с неполным анализом в FP/FN не входят — они считаются отдельно. */
data class Metrics(
    val total: Int,
    val incomplete: Int,
    val truePositives: Int,
    val falsePositives: Int,
    val trueNegatives: Int,
    val falseNegatives: Int,
) {
    val falsePositiveRate: Double get() = ratio(falsePositives, falsePositives + trueNegatives)
    val falseNegativeRate: Double get() = ratio(falseNegatives, falseNegatives + truePositives)
    val precision: Double get() = ratio(truePositives, truePositives + falsePositives)
    val recall: Double get() = ratio(truePositives, truePositives + falseNegatives)
    val incompleteRate: Double get() = ratio(incomplete, total)

    companion object {
        fun of(results: List<SampleResult>, policy: DetectionPolicy): Metrics {
            val complete = results.filterNot { it.incomplete }
            fun count(truth: GroundTruth, detected: Boolean) =
                complete.count { it.truth == truth && policy.detects(it.level!!) == detected }
            return Metrics(
                total = results.size,
                incomplete = results.size - complete.size,
                truePositives = count(GroundTruth.MALICIOUS, true),
                falsePositives = count(GroundTruth.BENIGN, true),
                trueNegatives = count(GroundTruth.BENIGN, false),
                falseNegatives = count(GroundTruth.MALICIOUS, false),
            )
        }

        private fun ratio(a: Int, b: Int): Double = if (b == 0) Double.NaN else a.toDouble() / b
    }
}

data class EvaluationReport(
    val rulesVersion: String,
    val analyzerVersion: String,
    val results: List<SampleResult>,
) {
    val metrics: Map<DetectionPolicy, Metrics> = DetectionPolicy.entries.associateWith { Metrics.of(results, it) }

    fun markdown(): String = buildString {
        appendLine("# Замер качества анализатора")
        appendLine()
        appendLine("Правила $rulesVersion · анализатор $analyzerVersion · файлов: ${results.size} " +
            "(вредоносных: ${results.count { it.truth == GroundTruth.MALICIOUS }}, безопасных: ${results.count { it.truth == GroundTruth.BENIGN }})")
        for ((policy, m) in metrics) {
            appendLine()
            appendLine("## ${policy.labelRu}")
            appendLine()
            appendLine("| Метрика | Значение |")
            appendLine("|---|---|")
            appendLine("| Ложные срабатывания (FPR) | ${pct(m.falsePositiveRate)} (${m.falsePositives} из ${m.falsePositives + m.trueNegatives}) |")
            appendLine("| Пропуски (FNR) | ${pct(m.falseNegativeRate)} (${m.falseNegatives} из ${m.falseNegatives + m.truePositives}) |")
            appendLine("| Точность (precision) | ${pct(m.precision)} |")
            appendLine("| Полнота обнаружения (recall) | ${pct(m.recall)} |")
            appendLine("| Неполный анализ | ${pct(m.incompleteRate)} (${m.incomplete} из ${m.total}) |")
        }
        val errors = results.filter { r ->
            r.incomplete || (r.truth == GroundTruth.BENIGN && DetectionPolicy.ATTENTION_OR_HIGH.detects(r.level!!)) ||
                (r.truth == GroundTruth.MALICIOUS && !DetectionPolicy.HIGH_ONLY.detects(r.level!!))
        }
        if (errors.isNotEmpty()) {
            appendLine()
            appendLine("## Файлы, на которые стоит посмотреть")
            appendLine()
            appendLine("| Файл | Разметка | Результат | Балл | Сработавшие правила |")
            appendLine("|---|---|---|---|---|")
            for (r in errors) {
                val result = r.level?.labelRu ?: "отклонён: ${r.rejectedReason}"
                appendLine("| ${r.name} | ${r.truth.name.lowercase()} | $result | ${r.score} | ${r.topRules.joinToString(", ").ifEmpty { "—" }} |")
            }
        }
    }

    fun csv(): String = buildString {
        appendLine("file,truth,level,score,coverage,rejected,top_rules")
        for (r in results) {
            appendLine(listOf(
                r.name, r.truth.name.lowercase(), r.level?.labelEn ?: "", r.score.toString(),
                "%.2f".format(Locale.ROOT, r.coverage), r.rejectedReason.orEmpty(), r.topRules.joinToString(" "),
            ).joinToString(",") { csvCell(it) })
        }
    }

    private fun pct(v: Double) = if (v.isNaN()) "—" else "%.1f%%".format(Locale.ROOT, v * 100)
    private fun csvCell(s: String) = if (s.any { it == ',' || it == '"' || it == '\n' }) "\"" + s.replace("\"", "\"\"") + "\"" else s
}

class Evaluator(
    private val analyzer: ApkAnalyzer = ApkAnalyzer(),
    private val engine: RiskEngine = RiskEngine(),
) {
    fun run(samples: List<LabeledSample>, onEach: (SampleResult) -> Unit = {}): EvaluationReport {
        val results = samples.map { s ->
            val result = when (val outcome = analyzer.analyze(s.file, s.file.name)) {
                is AnalysisOutcome.Rejected -> SampleResult(s.file.name, s.truth, null, 0, 0f, outcome.reason, emptyList())
                is AnalysisOutcome.Completed -> {
                    val a = engine.assess(outcome.report)
                    SampleResult(s.file.name, s.truth, a.level, a.score, a.coverage, null, a.triggeredRuleIds.take(5))
                }
            }
            onEach(result)
            result
        }
        return EvaluationReport(RuleCatalog.VERSION, ApkAnalyzer.ANALYZER_VERSION, results)
    }
}

/** Точка входа для `./gradlew :core:evaluate`. Аргументы: папка с набором, папка для отчёта. */
fun main(args: Array<String>) {
    val root = File(args.getOrNull(0) ?: "samples/eval")
    val out = File(args.getOrNull(1) ?: "build/evaluation").apply { mkdirs() }
    val samples = LabeledSet.fromDirectory(root)
    require(samples.isNotEmpty()) { "В ${root.absolutePath} нет APK в подпапках malicious/ и benign/" }
    val report = Evaluator().run(samples) { r -> println("${r.truth.name.lowercase().padEnd(9)} ${r.level?.labelRu ?: "отклонён"}  ${r.name}") }
    File(out, "evaluation.md").writeText(report.markdown())
    File(out, "evaluation.csv").writeText(report.csv())
    println()
    println(report.markdown())
    println("Отчёт: ${File(out, "evaluation.md").absolutePath}")
}
