package com.apkanalyzer.report

import com.apkanalyzer.analyzer.util.Json
import com.apkanalyzer.analyzer.util.JsonValue

/**
 * Экспорт отчёта в SARIF 2.1.0 — стандартный формат результатов статического анализа.
 * Его принимают GitHub Code Scanning, DefectDojo, SIEM/SOC-системы и плагины IDE.
 *
 * В SARIF попадают только локальные результаты (правила и доказательства); текст AI не включается —
 * машинный формат не должен смешивать проверяемые факты и сгенерированные пояснения.
 */
object SarifExporter {

    private const val SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
    private const val INFO_URI = "https://github.com/KNikitaaa/APKAnalyzer"

    fun encode(doc: ReportDocument): String = Json.write(toSarif(doc))

    private fun toSarif(doc: ReportDocument): JsonValue.Obj {
        // Одно правило на ruleId, в порядке первого появления — ruleIndex ссылается на этот список.
        val rules = doc.findings.distinctBy { it.ruleId }
        val ruleIndex = rules.withIndex().associate { (i, f) -> f.ruleId to i }

        val driver = JsonValue.Obj()
            .put("name", "APK AI Analyzer")
            .put("version", doc.appVersion)
            .put("informationUri", INFO_URI)
            .put("rules", JsonValue.Arr(rules.map { f ->
                JsonValue.Obj()
                    .put("id", f.ruleId)
                    .put("name", f.ruleId.lowercase().split('_').joinToString("") { it.replaceFirstChar(Char::uppercase) })
                    .put("shortDescription", text(f.titleRu))
                    .put("fullDescription", text(f.descriptionRu))
                    .put("defaultConfiguration", JsonValue.Obj().put("level", level(f.combination, f.baseWeight.toFloat())))
                    .put("properties", JsonValue.Obj()
                        .put("category", f.categoryRu)
                        .put("kind", if (f.combination) "combination" else "signal")
                        .put("baseWeight", f.baseWeight)
                        .put("tags", JsonValue.Arr(listOf(JsonValue.Str("security"), JsonValue.Str(f.categoryRu)))))
            }))

        val location = JsonValue.Obj().put("physicalLocation", JsonValue.Obj()
            .put("artifactLocation", JsonValue.Obj().put("uri", doc.file.name).put("index", 0)))

        val results = doc.findings.map { f ->
            JsonValue.Obj()
                .put("ruleId", f.ruleId)
                .put("ruleIndex", ruleIndex.getValue(f.ruleId))
                .put("level", level(f.combination, f.effectiveWeight))
                .put("message", text("${f.titleRu}. ${f.descriptionRu}"))
                .put("locations", JsonValue.Arr(listOf(location)))
                .put("properties", JsonValue.Obj()
                    .put("effectiveWeight", f.effectiveWeight.toDouble())
                    .put("confidence", f.confidence.toDouble())
                    .put("mitigations", JsonValue.Arr(f.mitigations.map { JsonValue.Str(it) }))
                    .put("evidence", JsonValue.Arr(f.evidence.map { e -> JsonValue.Obj().put("source", e.source).put("detail", e.detail) })))
        }

        val artifacts = listOf(doc.file) + doc.splits
        val run = JsonValue.Obj()
            .put("tool", JsonValue.Obj().put("driver", driver))
            .put("artifacts", JsonValue.Arr(artifacts.mapIndexed { i, f ->
                JsonValue.Obj()
                    .put("location", JsonValue.Obj().put("uri", f.name))
                    .put("length", f.sizeBytes)
                    .put("roles", JsonValue.Arr(listOf(JsonValue.Str(if (i == 0) "analysisTarget" else "referencedOnCommandLine"))))
                    .put("hashes", JsonValue.Obj().put("sha-256", f.sha256))
            }))
            .put("results", JsonValue.Arr(results))
            .put("invocations", JsonValue.Arr(listOf(JsonValue.Obj()
                .put("executionSuccessful", true)
                .put("endTimeUtc", java.time.Instant.ofEpochMilli(doc.generatedAtMs).toString())
                .put("toolExecutionNotifications", JsonValue.Arr(doc.limitations.map { l ->
                    JsonValue.Obj().put("level", "warning").put("message", text(l))
                }))
            )))
            .put("properties", JsonValue.Obj()
                .put("riskLevel", doc.risk.code.name)
                .put("riskLabel", doc.risk.labelRu)
                .put("riskScore", doc.risk.score)
                .put("coverage", doc.risk.coverage.toDouble())
                .put("rulesVersion", doc.rulesVersion)
                .put("analyzerVersion", doc.analyzerVersion)
                .apply {
                    doc.app?.packageName?.let { put("packageName", it) }
                    doc.localRisk?.let { put("localRiskLevel", it.code.name).put("localRiskScore", it.score) }
                    doc.reputation?.let { put("reputationProvider", it.provider).put("reputationMalicious", it.malicious).put("reputationSuspicious", it.suspicious) }
                })

        return JsonValue.Obj()
            .put("\$schema", SCHEMA)
            .put("version", "2.1.0")
            .put("runs", JsonValue.Arr(listOf(run)))
    }

    private fun text(s: String) = JsonValue.Obj().put("text", s)

    /** Связки и весомые признаки — error, средние — warning, остальное — note. */
    private fun level(combination: Boolean, weight: Float): String = when {
        combination || weight >= 25f -> "error"
        weight >= 8f -> "warning"
        else -> "note"
    }
}
