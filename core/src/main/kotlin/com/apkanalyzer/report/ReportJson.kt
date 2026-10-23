package com.apkanalyzer.report

import com.apkanalyzer.analyzer.report.FeatureEmphasis
import com.apkanalyzer.analyzer.report.FeatureItem
import com.apkanalyzer.analyzer.report.FeatureSection
import com.apkanalyzer.analyzer.util.Json
import com.apkanalyzer.analyzer.util.JsonException
import com.apkanalyzer.analyzer.util.JsonValue
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.TimeZone

/** JSON-формат отчёта (экспорт и хранение в истории). Порядок полей стабилен. */
object ReportJson {
    const val FORMAT = "apk-ai-analyzer-report"

    fun encode(doc: ReportDocument, pretty: Boolean = true): String = Json.write(toJson(doc), pretty)

    fun decode(text: String): ReportDocument {
        val root = Json.parse(text) as? JsonValue.Obj ?: throw JsonException("Отчёт должен быть объектом")
        if (root.str("format") != FORMAT) throw JsonException("Это не отчёт APK AI Analyzer")
        val schema = root.int("schemaVersion") ?: 0
        if (schema > ReportDocument.SCHEMA_VERSION) throw JsonException("Отчёт создан более новой версией приложения (схема $schema)")
        return fromJson(root)
    }

    private fun toJson(d: ReportDocument): JsonValue.Obj = JsonValue.Obj()
        .put("format", FORMAT)
        .put("schemaVersion", d.schemaVersion)
        .put("generatedAt", iso(d.generatedAtMs))
        .put("generatedAtMs", d.generatedAtMs)
        .put("appVersion", d.appVersion)
        .put("analyzerVersion", d.analyzerVersion)
        .put("rulesVersion", d.rulesVersion)
        .put("file", JsonValue.Obj().put("name", d.file.name).put("sizeBytes", d.file.sizeBytes).put("sha256", d.file.sha256))
        .put("app", d.app?.let {
            JsonValue.Obj().put("packageName", it.packageName).put("versionName", it.versionName)
                .put("versionCode", it.versionCode).put("minSdk", it.minSdk).put("targetSdk", it.targetSdk)
        })
        .put("risk", JsonValue.Obj().put("level", d.risk.code.name).put("label", d.risk.labelRu).put("score", d.risk.score)
            .put("reason", d.risk.reasonRu).put("coverage", round(d.risk.coverage)))
        .put("findings", JsonValue.Arr(d.findings.map { f ->
            JsonValue.Obj().put("ruleId", f.ruleId).put("title", f.titleRu).put("description", f.descriptionRu)
                .put("category", f.categoryRu).put("combination", f.combination).put("baseWeight", f.baseWeight)
                .put("confidence", round(f.confidence)).put("effectiveWeight", round(f.effectiveWeight))
                .put("mitigations", JsonValue.Arr(f.mitigations.map { JsonValue.Str(it) }))
                .put("evidence", JsonValue.Arr(f.evidence.map { JsonValue.Obj().put("source", it.source).put("detail", it.detail) }))
        }))
        .put("recommendations", JsonValue.Arr(d.recommendations.map { JsonValue.Str(it) }))
        .put("limitations", JsonValue.Arr(d.limitations.map { JsonValue.Str(it) }))
        .put("sections", JsonValue.Arr(d.sections.map { s ->
            JsonValue.Obj().put("id", s.id).put("title", s.title).put("items", JsonValue.Arr(s.items.map { i ->
                JsonValue.Obj().put("title", i.title).put("value", i.value).put("emphasis", i.emphasis.name)
            }))
        }))
        .put("aiExplanation", d.aiExplanation?.let { aiToJson(it) })

    private fun aiToJson(a: ReportAi): JsonValue.Obj = JsonValue.Obj()
        .put("note", "Текст сгенерирован языковой моделью и не влияет на оценку риска")
        .put("provider", a.provider)
        .put("model", a.model)
        .put("generatedAtMs", a.generatedAtMs)
        .put("promptVersions", JsonValue.Obj().also { o -> a.promptVersions.forEach { (k, v) -> o.put(k, v) } })
        .put("summary", a.summary)
        .put("findingNotes", JsonValue.Arr(a.findingNotes.map { JsonValue.Obj().put("ruleId", it.ruleId).put("text", it.text) }))
        .put("scenarios", JsonValue.Arr(a.scenarios.map {
            JsonValue.Obj().put("title", it.title).put("description", it.description).put("confidence", it.confidence)
                .put("ruleIds", JsonValue.Arr(it.ruleIds.map { id -> JsonValue.Str(id) }))
        }))
        .put("uncertainty", a.uncertainty)
        .put("actions", JsonValue.Arr(a.actions.map { JsonValue.Obj().put("priority", it.priority).put("action", it.action).put("why", it.why) }))
        .put("reportTitle", a.reportTitle)
        .put("reportSummary", a.reportSummary)
        .put("reportSections", JsonValue.Arr(a.reportSections.map { JsonValue.Obj().put("heading", it.heading).put("text", it.text) }))
        .put("errors", JsonValue.Obj().also { o -> a.errors.forEach { (k, v) -> o.put(k, v) } })

    private fun aiFromJson(o: JsonValue.Obj): ReportAi {
        fun strMap(key: String): Map<String, String> =
            (o[key] as? JsonValue.Obj)?.fields?.mapNotNull { (k, v) -> (v as? JsonValue.Str)?.let { k to it.value } }?.toMap().orEmpty()
        // Схема v1 хранила один текст в поле "text".
        val legacyText = o.str("text")
        return ReportAi(
            provider = o.str("provider").orEmpty(),
            model = o.str("model").orEmpty(),
            generatedAtMs = o.long("generatedAtMs") ?: 0L,
            promptVersions = strMap("promptVersions"),
            summary = o.str("summary") ?: legacyText,
            findingNotes = o.arr("findingNotes").map { AiFindingNote(it.str("ruleId").orEmpty(), it.str("text").orEmpty()) },
            scenarios = o.arr("scenarios").map {
                AiScenario(it.str("title").orEmpty(), it.str("description").orEmpty(), it.str("confidence") ?: "low",
                    it.arr("ruleIds").mapNotNull { id -> (id as? JsonValue.Str)?.value })
            },
            uncertainty = o.str("uncertainty"),
            actions = o.arr("actions").map { AiAction(it.int("priority") ?: 3, it.str("action").orEmpty(), it.str("why").orEmpty()) },
            reportTitle = o.str("reportTitle"),
            reportSummary = o.str("reportSummary"),
            reportSections = o.arr("reportSections").map { AiSection(it.str("heading").orEmpty(), it.str("text").orEmpty()) },
            errors = strMap("errors"),
        )
    }

    private fun fromJson(r: JsonValue.Obj): ReportDocument {
        val file = r.obj("file") ?: throw JsonException("Нет раздела file")
        val risk = r.obj("risk") ?: throw JsonException("Нет раздела risk")
        return ReportDocument(
            schemaVersion = r.int("schemaVersion") ?: 1,
            generatedAtMs = r.long("generatedAtMs") ?: 0L,
            appVersion = r.str("appVersion").orEmpty(),
            analyzerVersion = r.str("analyzerVersion").orEmpty(),
            rulesVersion = r.str("rulesVersion").orEmpty(),
            file = ReportFile(file.str("name").orEmpty(), file.long("sizeBytes") ?: 0L, file.str("sha256").orEmpty()),
            app = r.obj("app")?.let {
                ReportApp(it.str("packageName").orEmpty(), it.str("versionName"), it.long("versionCode"), it.int("minSdk"), it.int("targetSdk"))
            },
            risk = ReportRisk(
                code = RiskCode.parse(risk.str("level")),
                score = risk.int("score") ?: 0,
                reasonRu = risk.str("reason").orEmpty(),
                coverage = (risk.double("coverage") ?: 0.0).toFloat(),
            ),
            findings = r.arr("findings").map { f ->
                ReportFinding(
                    ruleId = f.str("ruleId").orEmpty(),
                    titleRu = f.str("title").orEmpty(),
                    descriptionRu = f.str("description").orEmpty(),
                    categoryRu = f.str("category").orEmpty(),
                    combination = f.bool("combination") ?: false,
                    baseWeight = f.int("baseWeight") ?: 0,
                    confidence = (f.double("confidence") ?: 1.0).toFloat(),
                    effectiveWeight = (f.double("effectiveWeight") ?: 0.0).toFloat(),
                    mitigations = f.arr("mitigations").mapNotNull { (it as? JsonValue.Str)?.value },
                    evidence = f.arr("evidence").map { ReportEvidence(it.str("source").orEmpty(), it.str("detail").orEmpty()) },
                )
            },
            recommendations = r.arr("recommendations").mapNotNull { (it as? JsonValue.Str)?.value },
            limitations = r.arr("limitations").mapNotNull { (it as? JsonValue.Str)?.value },
            sections = r.arr("sections").map { s ->
                FeatureSection(
                    id = s.str("id").orEmpty(),
                    title = s.str("title").orEmpty(),
                    items = s.arr("items").map { i ->
                        FeatureItem(
                            title = i.str("title").orEmpty(),
                            value = i.str("value"),
                            emphasis = FeatureEmphasis.entries.firstOrNull { it.name == i.str("emphasis") } ?: FeatureEmphasis.NORMAL,
                        )
                    },
                )
            },
            aiExplanation = r.obj("aiExplanation")?.let { aiFromJson(it) },
        )
    }

    /** Округление до 3 знаков, чтобы JSON был стабильным и читаемым. */
    private fun round(f: Float): Double = Math.round(f * 1000.0) / 1000.0

    private fun iso(ms: Long): String =
        SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'", Locale.ROOT).apply { timeZone = TimeZone.getTimeZone("UTC") }.format(Date(ms))
}
