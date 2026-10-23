package com.apkanalyzer.ai

import com.apkanalyzer.report.ReportAi
import java.io.IOException

/**
 * Клиент AI: один профиль (провайдер + модель + ключ), четыре версионируемых запроса,
 * повтор при временных ошибках, проверка каждого ответа. Ошибка одного запроса не отменяет остальные.
 */
class AiClient(
    private val transport: AiTransport,
    private val profile: AiProfileConfig,
    private val apiKey: String,
    private val clock: () -> Long = System::currentTimeMillis,
    private val sleeper: (Long) -> Unit = { Thread.sleep(it) },
    private val maxRetries: Int = 1,
) {
    init {
        require(AiProfileConfig.isAllowedBaseUrl(profile.resolvedBaseUrl)) { "Разрешены только адреса https://" }
    }

    private val model: String get() = profile.modelId?.takeIf { it.isNotBlank() } ?: throw AiException("В профиле не выбрана модель")

    /** Проверка подключения без данных APK: список моделей (или понятная ошибка). */
    fun testConnection(): List<String> {
        val r = call("GET", "${profile.resolvedBaseUrl}/models", null)
        if (r.code !in 200..299) throw OpenAiCompatibleProtocol.describeHttpError(r.code, r.body)
        return OpenAiCompatibleProtocol.parseModels(r.body)
    }

    fun request(type: AiRequestType, facts: AiFacts): AiPart {
        val system = AiPrompts.system(type)
        val user = AiPrompts.user(type, facts)
        var jsonMode = profile.providerType.supportsJsonMode
        var attempt = 0
        while (true) {
            try {
                val r = call("POST", "${profile.resolvedBaseUrl}/chat/completions", OpenAiCompatibleProtocol.chatBody(model, system, user, jsonMode))
                if (r.code == 400 && jsonMode) {
                    // Некоторые модели не поддерживают JSON-режим — повторяем без него, ответ всё равно проверяется.
                    jsonMode = false
                    continue
                }
                if (r.code !in 200..299) throw OpenAiCompatibleProtocol.describeHttpError(r.code, r.body)
                val content = OpenAiCompatibleProtocol.parseChatContent(r.body)
                return AiResponseValidator.parse(type, content, facts.triggeredRuleIds)
            } catch (e: AiException) {
                if (!e.retryable || attempt >= maxRetries) throw e
            }
            attempt++
            sleeper(1500L * attempt)
        }
    }

    fun explain(facts: AiFacts, types: List<AiRequestType> = AiRequestType.entries): ReportAi {
        var ai = ReportAi(
            provider = profile.providerType.displayName,
            model = model,
            generatedAtMs = clock(),
            promptVersions = types.associate { it.name to it.promptVersion },
        )
        val errors = LinkedHashMap<String, String>()
        for (type in types) {
            try {
                ai = when (val part = request(type, facts)) {
                    is AiPart.Explain -> ai.copy(summary = part.summary, findingNotes = part.notes)
                    is AiPart.Behavior -> ai.copy(scenarios = part.scenarios, uncertainty = part.uncertainty)
                    is AiPart.Actions -> ai.copy(actions = part.actions)
                    is AiPart.Summary -> ai.copy(reportTitle = part.title, reportSummary = part.summary, reportSections = part.sections)
                }
            } catch (e: AiException) {
                errors[type.name] = e.message ?: "ошибка"
                if (e.fatal) break // неверный ключ/адрес/модель — остальные запросы тоже не пройдут
            }
        }
        return ai.copy(errors = errors)
    }

    private fun call(method: String, url: String, body: String?): HttpResult = try {
        transport.send(method, url, OpenAiCompatibleProtocol.headers(apiKey), body)
    } catch (e: IOException) {
        throw AiException("Нет связи с сервером: ${e.message ?: e.javaClass.simpleName}", retryable = true)
    }
}
