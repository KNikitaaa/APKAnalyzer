package com.apkanalyzer.rules

import com.apkanalyzer.analyzer.ApkAnalysisReport
import com.apkanalyzer.domain.model.RiskLevel
import kotlin.math.roundToInt

/** Итог оценки риска: категория, балл, причины с доказательствами и ограничения. */
data class RiskAssessment(
    val level: RiskLevel,
    /** 0..100. */
    val score: Int,
    val rulesVersion: String,
    /** Объяснение, почему выбрана именно эта категория. */
    val levelReasonRu: String,
    /** Сработавшие правила, от самого весомого к наименее весомому (служебные признаки не включаются). */
    val matches: List<RuleMatch>,
    /** Балл по каждой поведенческой группе (только группы со срабатываниями). */
    val categoryScores: Map<BehaviorCategory, Int>,
    val coverage: Float,
    val limitations: List<String>,
) {
    val topReasons: List<RuleMatch> get() = matches.take(5)
    val triggeredRuleIds: List<String> get() = matches.map { it.ruleId }
}

/**
 * Движок правил. Детерминирован: одинаковый отчёт и одинаковая версия правил дают одинаковый результат.
 *
 * Формула: вклад правила = вес × уверенность × Π(смягчения); итог = 1 − Π(1 − вкладᵢ/100).
 * Такое объединение делает сильные связки важнее суммы слабых сигналов и не даёт баллу выйти за 100.
 */
class RiskEngine(
    private val rules: List<Rule> = RuleCatalog.all,
    private val mitigations: List<Mitigation> = RuleCatalog.mitigations,
    /** Пороги, веса и списки; по умолчанию встроенные, может прийти из подписанного пакета правил. */
    val params: RuleParams = RuleParams.DEFAULT,
) {
    val rulesVersion: String get() = params.version


    fun assess(report: ApkAnalysisReport): RiskAssessment {
        val facts = ApkFacts(report, params)

        // 1. Одиночные признаки
        val hits = LinkedHashMap<String, Hit>()
        val ruleErrors = mutableListOf<String>()
        val active = rules.filter { it.id !in params.disabledRules }
        for (rule in active.filter { it.kind == RuleKind.SIGNAL }) {
            try {
                rule.evaluateSignal(facts)?.let { hits[rule.id] = it }
            } catch (e: Exception) {
                ruleErrors += "${rule.id}: ${e.message ?: e.javaClass.simpleName}"
            }
        }

        // 2. Связки: из каждой группы должно сработать хотя бы одно правило
        for (rule in active.filter { it.kind == RuleKind.COMBINATION }) {
            // Простое переключение компонентов не доказывает скрытие значка. Для связок нужен
            // вызов, связанный с собственной точкой входа в лаунчере, или старый DEX без атрибуции.
            val parts = rule.requires.map { group -> group.mapNotNull { id ->
                hits[id]?.takeIf { hit -> id != "HIDE_ICON_API" || hit.confidence >= 1f }?.let { id to it }
            } }
            if (parts.any { it.isEmpty() }) continue
            val used = parts.flatten()
            hits[rule.id] = Hit(
                evidence = used.flatMap { it.second.evidence }.distinct(),
                confidence = used.minOf { it.second.confidence },
            )
        }

        // 3. Смягчающие контексты
        val activeMitigations = mitigations.mapNotNull { m -> m.evaluate(facts)?.let { m to it } }

        val byId = rules.associateBy { it.id }
        val matches = hits.mapNotNull { (id, hit) ->
            val rule = byId.getValue(id)
            if (rule.informational) return@mapNotNull null
            val applied = activeMitigations.filter { it.first.appliesTo(rule) }
                .map { (m, ev) -> AppliedMitigation(m.id, m.titleRu, m.factor, ev) }
            val factor = applied.fold(1f) { acc, m -> acc * m.factor }
            RuleMatch(
                ruleId = rule.id,
                titleRu = rule.titleRu,
                descriptionRu = rule.descriptionRu,
                category = rule.category,
                kind = rule.kind,
                baseWeight = params.weightOf(rule),
                confidence = hit.confidence,
                mitigations = applied,
                effectiveWeight = params.weightOf(rule) * hit.confidence * factor,
                evidence = hit.evidence,
            )
        }.sortedWith(compareByDescending<RuleMatch> { it.effectiveWeight }.thenBy { it.ruleId })

        val score = combine(matches.map { it.effectiveWeight })
        val categoryScores = matches.groupBy { it.category }
            .mapValues { (_, list) -> combine(list.map { it.effectiveWeight }) }
            .toSortedMap(compareBy { it.ordinal })

        val limitations = report.limitations + ruleErrors.map { "Правило $it не выполнено" }
        val (level, reason) = decideLevel(facts, score, matches, report.coverage)
        return RiskAssessment(level, score, rulesVersion, reason, matches, categoryScores, report.coverage, limitations)
    }

    private fun decideLevel(facts: ApkFacts, score: Int, matches: List<RuleMatch>, coverage: Float): Pair<RiskLevel, String> {
        val strong = matches.filter { it.kind == RuleKind.COMBINATION }.take(3).joinToString { "«${it.titleRu}»" }
        if (facts.manifest == null) {
            return RiskLevel.Insufficient to "Не удалось прочитать манифест — без него нельзя понять, что делает приложение."
        }
        if (score >= params.highThreshold) {
            val why = if (strong.isNotEmpty()) "Обнаружены сильные взаимосвязанные индикаторы: $strong." else "Обнаружено несколько весомых индикаторов."
            return RiskLevel.High to why
        }
        if (!facts.codeAvailable) {
            return RiskLevel.Insufficient to "Код приложения (DEX) не удалось разобрать — поведение нельзя оценить."
        }
        if (facts.packers.isNotEmpty() && facts.allApiUsages.isEmpty()) {
            return RiskLevel.Insufficient to "Код защищён упаковщиком (${facts.packers.first().name}): настоящее поведение скрыто от статического анализа."
        }
        if (coverage < MIN_COVERAGE) {
            return RiskLevel.Insufficient to "Анализ выполнен только на ${(coverage * 100).toInt()}% — данных недостаточно для вывода."
        }
        // «Нужно внимание» — только если есть хотя бы один весомый признак или связка:
        // набор обычных разрешений (камера, контакты, геолокация…) сам по себе тревогу не поднимает.
        if (score >= params.attentionThreshold && matches.any { it.effectiveWeight >= SIGNIFICANT_WEIGHT }) {
            val top = matches.take(3).joinToString { "«${it.titleRu}»" }
            return RiskLevel.Attention to "Есть признаки, требующие проверки: $top."
        }
        return RiskLevel.Low to if (matches.isEmpty()) "Подозрительных признаков не найдено." else "Явных опасных комбинаций не найдено; найденные признаки обычны для легальных приложений."
    }

    companion object {
        const val HIGH_THRESHOLD = 60
        const val ATTENTION_THRESHOLD = 30
        const val MIN_COVERAGE = 0.6f
        const val SIGNIFICANT_WEIGHT = 10f

        fun combine(weights: List<Float>): Int {
            val keep = weights.fold(1.0) { acc, w -> acc * (1.0 - (w.coerceIn(0f, 100f) / 100.0)) }
            return ((1.0 - keep) * 100).roundToInt()
        }
    }
}
