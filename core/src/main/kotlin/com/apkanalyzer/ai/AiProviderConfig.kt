package com.apkanalyzer.ai

/**
 * Поддерживаемые провайдеры. Все используют OpenAI-совместимый протокол Chat Completions
 * (у Gemini — официальный совместимый эндпоинт), поэтому клиент один, а отличия — в настройках.
 */
enum class AiProviderType(
    val displayName: String,
    val defaultBaseUrl: String,
    /** Поддерживает ли `response_format: {"type": "json_object"}`. */
    val supportsJsonMode: Boolean,
    /** Подсказка моделей, если список с сервера получить не удалось. */
    val suggestedModels: List<String>,
) {
    DEEPSEEK("DeepSeek", "https://api.deepseek.com/v1", true, listOf("deepseek-chat", "deepseek-reasoner")),
    OPENAI("OpenAI", "https://api.openai.com/v1", true, listOf("gpt-4.1-mini", "gpt-4.1", "gpt-4o-mini")),
    GEMINI("Google Gemini", "https://generativelanguage.googleapis.com/v1beta/openai", true, listOf("gemini-2.5-flash", "gemini-2.5-pro")),
    CUSTOM("Совместимый API (OpenAI-формат)", "", false, emptyList()),
}

/**
 * Профиль AI: провайдер + адрес + модель. Ключ API в профиле НЕ хранится — только его псевдоним,
 * сам ключ лежит отдельно в зашифрованном хранилище (Android Keystore).
 */
data class AiProfileConfig(
    val id: String,
    val displayName: String,
    val providerType: AiProviderType,
    val baseUrl: String,
    val modelId: String?,
    val keyAlias: String,
    val isActive: Boolean = false,
) {
    val resolvedBaseUrl: String
        get() = baseUrl.ifBlank { providerType.defaultBaseUrl }.trimEnd('/')

    /** Хост, куда уйдут данные (показывается пользователю перед отправкой). */
    val destinationHost: String
        get() = resolvedBaseUrl.substringAfter("://").substringBefore('/').substringBefore(':')

    companion object {
        fun defaultKeyAlias(profileId: String) = "ai_key_$profileId"

        /** Отправка разрешена только по HTTPS (ключ и факты нельзя передавать открытым текстом). */
        fun isAllowedBaseUrl(url: String): Boolean {
            val u = url.trim().lowercase()
            if (!u.startsWith("https://")) return false
            val host = u.removePrefix("https://").substringBefore('/').substringBefore(':')
            return host.isNotEmpty() && host.contains('.') && host.none { it.isWhitespace() || it == '@' }
        }
    }
}

/** Отдельные версионируемые запросы (раздел плана «Специализированные AI-запросы»). */
enum class AiRequestType(val promptVersion: String, val titleRu: String) {
    EXPLAIN_FINDINGS("v1", "Объяснение находок"),
    INFER_BEHAVIOR("v1", "Предполагаемое поведение"),
    RECOMMENDATIONS("v1", "Рекомендации"),
    REPORT_SUMMARY("v1", "Текст отчёта"),
}

/** Короткий подозрительный фрагмент, выбранный локальным анализатором для AI. */
data class SuspiciousFragment(
    val content: String,
    val reason: String,
    val type: String,
)
