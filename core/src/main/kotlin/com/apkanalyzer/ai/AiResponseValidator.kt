package com.apkanalyzer.ai

import com.apkanalyzer.analyzer.util.Json
import com.apkanalyzer.analyzer.util.JsonException
import com.apkanalyzer.analyzer.util.JsonValue
import com.apkanalyzer.report.AiAction
import com.apkanalyzer.report.AiFindingNote
import com.apkanalyzer.report.AiScenario
import com.apkanalyzer.report.AiSection

/** Проверенный фрагмент ответа одного запроса. */
sealed class AiPart {
    data class Explain(val summary: String, val notes: List<AiFindingNote>) : AiPart()
    data class Behavior(val scenarios: List<AiScenario>, val uncertainty: String?) : AiPart()
    data class Actions(val actions: List<AiAction>) : AiPart()
    data class Summary(val title: String?, val summary: String, val sections: List<AiSection>) : AiPart()
}

/**
 * Строгая проверка ответа модели: только JSON фиксированной схемы, только известные ruleId,
 * ограничение длины, без ссылок и управляющих символов. Некорректный ответ отклоняется целиком.
 */
object AiResponseValidator {
    private const val MAX_TEXT = 900
    private val URL = Regex("(?i)\\b(?:https?|ftp)://\\S+|\\bwww\\.\\S+")
    private val CONTROL = Regex("[\\p{Cc}\\p{Cf}&&[^\\n]]")
    private val CONFIDENCE = setOf("low", "medium", "high")

    fun parse(type: AiRequestType, content: String, allowedRuleIds: Set<String>): AiPart {
        val obj = extractJson(content)
        return when (type) {
            AiRequestType.EXPLAIN_FINDINGS -> {
                val summary = text(obj.str("summary")) ?: fail("нет поля summary")
                val notes = obj.arr("findings").mapNotNull { n ->
                    val id = n.str("ruleId")?.trim() ?: return@mapNotNull null
                    if (id !in allowedRuleIds) return@mapNotNull null // модель не может «добавить» находки
                    text(n.str("explanation"))?.let { AiFindingNote(id, it) }
                }.distinctBy { it.ruleId }.take(20)
                AiPart.Explain(summary, notes)
            }
            AiRequestType.INFER_BEHAVIOR -> {
                val scenarios = obj.arr("scenarios").mapNotNull { s ->
                    val title = text(s.str("title"), 120) ?: return@mapNotNull null
                    val desc = text(s.str("description")) ?: return@mapNotNull null
                    val conf = s.str("confidence")?.lowercase()?.takeIf { it in CONFIDENCE } ?: "low"
                    val ids = s.arr("evidenceRuleIds").mapNotNull { (it as? JsonValue.Str)?.value }.filter { it in allowedRuleIds }
                    if (ids.isEmpty() && allowedRuleIds.isNotEmpty()) return@mapNotNull null // сценарий без доказательств отбрасываем
                    AiScenario(title, desc, conf, ids.distinct())
                }.take(6)
                if (obj["scenarios"] !is JsonValue.Arr) fail("нет поля scenarios")
                AiPart.Behavior(scenarios, text(obj.str("uncertainty")))
            }
            AiRequestType.RECOMMENDATIONS -> {
                if (obj["actions"] !is JsonValue.Arr) fail("нет поля actions")
                val actions = obj.arr("actions").mapNotNull { a ->
                    val action = text(a.str("action"), 300) ?: return@mapNotNull null
                    AiAction((a.int("priority") ?: 3).coerceIn(1, 5), action, text(a.str("why"), 400).orEmpty())
                }.sortedBy { it.priority }.take(7)
                AiPart.Actions(actions)
            }
            AiRequestType.REPORT_SUMMARY -> {
                val summary = text(obj.str("summary"), 1500) ?: fail("нет поля summary")
                val sections = obj.arr("sections").mapNotNull { s ->
                    val h = text(s.str("heading"), 100) ?: return@mapNotNull null
                    text(s.str("text"))?.let { AiSection(h, it) }
                }.take(4)
                AiPart.Summary(text(obj.str("title"), 80), summary, sections)
            }
        }
    }

    /** Достаёт JSON-объект из ответа: допускает обёртку ```json … ``` и текст вокруг. */
    fun extractJson(content: String): JsonValue.Obj {
        val trimmed = content.trim().removePrefix("﻿")
        val start = trimmed.indexOf('{')
        val end = trimmed.lastIndexOf('}')
        if (start < 0 || end <= start) fail("ответ не содержит JSON")
        return try {
            Json.parse(trimmed.substring(start, end + 1), maxDepth = 16, maxLength = 200_000) as? JsonValue.Obj
        } catch (e: JsonException) {
            null
        } ?: fail("ответ не является корректным JSON-объектом")
    }

    private fun text(s: String?, max: Int = MAX_TEXT): String? {
        if (s == null) return null
        var t = CONTROL.replace(s, "")
        t = URL.replace(t, "[ссылка удалена]")
        t = t.trim()
        if (t.isEmpty()) return null
        return if (t.length > max) t.take(max - 1) + "…" else t
    }

    private fun fail(why: String): Nothing = throw AiException("Модель вернула некорректный ответ: $why")
}
