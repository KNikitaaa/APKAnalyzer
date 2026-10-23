package com.apkanalyzer.ai

import com.apkanalyzer.analyzer.util.Json
import com.apkanalyzer.analyzer.util.JsonException
import com.apkanalyzer.analyzer.util.JsonValue

/** HTTP-ответ транспортного уровня. */
data class HttpResult(val code: Int, val body: String)

/** Сетевой транспорт. Реализация в приложении (HTTPS), в тестах — подделка. Должен соблюдать таймауты. */
fun interface AiTransport {
    /** @throws java.io.IOException при сетевой ошибке или таймауте. */
    fun send(method: String, url: String, headers: Map<String, String>, body: String?): HttpResult
}

/**
 * @param retryable временная ошибка — можно повторить;
 * @param fatal ошибка настройки (ключ, адрес, оплата) — остальные запросы тоже не пройдут.
 */
class AiException(
    message: String,
    val retryable: Boolean = false,
    val httpCode: Int? = null,
    val fatal: Boolean = false,
) : RuntimeException(message)

/** OpenAI-совместимый протокол Chat Completions — общий для DeepSeek, OpenAI, Gemini и совместимых API. */
object OpenAiCompatibleProtocol {

    fun headers(apiKey: String): Map<String, String> = mapOf(
        "Authorization" to "Bearer $apiKey",
        "Content-Type" to "application/json; charset=utf-8",
        "Accept" to "application/json",
    )

    fun chatBody(model: String, system: String, user: String, jsonMode: Boolean, temperature: Double = 0.2): String {
        val body = JsonValue.Obj()
            .put("model", model)
            .put("temperature", temperature)
            .put("max_tokens", 1800)
            .put("messages", JsonValue.Arr(listOf(
                JsonValue.Obj().put("role", "system").put("content", system),
                JsonValue.Obj().put("role", "user").put("content", user),
            )))
        if (jsonMode) body.put("response_format", JsonValue.Obj().put("type", "json_object"))
        return Json.write(body, pretty = false)
    }

    /** Текст ответа модели из choices[0].message.content. */
    fun parseChatContent(body: String): String {
        val root = try {
            Json.parse(body) as? JsonValue.Obj
        } catch (e: JsonException) {
            null
        } ?: throw AiException("Сервер вернул не JSON")
        val choice = root.arr("choices").firstOrNull() as? JsonValue.Obj ?: throw AiException(errorMessage(body) ?: "В ответе нет choices")
        val content = choice.obj("message")?.str("content")
        if (content.isNullOrBlank()) throw AiException("Модель вернула пустой ответ (finish_reason=${choice.str("finish_reason")})")
        return content
    }

    fun parseModels(body: String): List<String> = try {
        (Json.parse(body) as? JsonValue.Obj)?.arr("data").orEmpty().mapNotNull { it.str("id") }
            .map { it.removePrefix("models/") }.distinct().sorted()
    } catch (e: JsonException) {
        emptyList()
    }

    fun errorMessage(body: String): String? = try {
        val root = Json.parse(body)
        val err = when (root) {
            is JsonValue.Obj -> root.obj("error")
            is JsonValue.Arr -> (root.items.firstOrNull() as? JsonValue.Obj)?.obj("error")
            else -> null
        }
        err?.str("message")?.take(300)
    } catch (e: JsonException) {
        null
    }

    /** Понятное сообщение по HTTP-коду (тексты ошибок сервера не показываем целиком — они могут быть длинными). */
    fun describeHttpError(code: Int, body: String): AiException {
        val serverMsg = errorMessage(body)?.let { ": $it" }.orEmpty()
        return when (code) {
            400 -> AiException("Сервер отклонил запрос (400)$serverMsg", httpCode = code)
            401, 403 -> AiException("Неверный или отозванный API-ключ ($code)$serverMsg", httpCode = code, fatal = true)
            404 -> AiException("Адрес или модель не найдены (404)$serverMsg", httpCode = code, fatal = true)
            402 -> AiException("Недостаточно средств на счёте провайдера (402)$serverMsg", httpCode = code, fatal = true)
            408 -> AiException("Сервер не дождался запроса (408)", retryable = true, httpCode = code)
            429 -> AiException("Превышен лимит запросов (429)$serverMsg", retryable = true, httpCode = code)
            in 500..599 -> AiException("Ошибка на стороне провайдера ($code)", retryable = true, httpCode = code)
            else -> AiException("Неожиданный ответ сервера ($code)$serverMsg", httpCode = code)
        }
    }
}
