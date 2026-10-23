package com.apkanalyzer.report

/**
 * Объяснение языковой модели. Хранится отдельно от локальной оценки и всегда помечается как текст модели:
 * оно не может изменить категорию риска, балл или доказательства.
 */
data class ReportAi(
    val provider: String,
    val model: String,
    val generatedAtMs: Long,
    /** Тип запроса → версия промпта (для воспроизводимости). */
    val promptVersions: Map<String, String>,
    val summary: String? = null,
    val findingNotes: List<AiFindingNote> = emptyList(),
    val scenarios: List<AiScenario> = emptyList(),
    val uncertainty: String? = null,
    val actions: List<AiAction> = emptyList(),
    val reportTitle: String? = null,
    val reportSummary: String? = null,
    val reportSections: List<AiSection> = emptyList(),
    /** Запросы, которые не удались (тип → причина). */
    val errors: Map<String, String> = emptyMap(),
) {
    val isEmpty: Boolean
        get() = summary == null && findingNotes.isEmpty() && scenarios.isEmpty() && actions.isEmpty() && reportSummary == null
}

data class AiFindingNote(val ruleId: String, val text: String)
data class AiScenario(val title: String, val description: String, val confidence: String, val ruleIds: List<String>)
data class AiAction(val priority: Int, val action: String, val why: String)
data class AiSection(val heading: String, val text: String)
