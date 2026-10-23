package com.apkanalyzer.data.ai

import com.apkanalyzer.ai.AiClient
import com.apkanalyzer.ai.AiFacts
import com.apkanalyzer.ai.AiFactsBuilder
import com.apkanalyzer.ai.AiPrivacyOptions
import com.apkanalyzer.ai.AiProfileConfig
import com.apkanalyzer.ai.AiTransport
import com.apkanalyzer.report.ReportAi
import com.apkanalyzer.report.ReportDocument
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/** Связывает профиль, ключ из Keystore, факты отчёта и сетевой клиент. */
class AiService(
    private val secrets: SecretStore,
    private val transport: AiTransport = HttpsAiTransport(),
) {
    fun facts(doc: ReportDocument, privacy: AiPrivacyOptions): AiFacts = AiFactsBuilder.build(doc, privacy)

    fun hasKey(profile: AiProfileConfig): Boolean = secrets.has(profile.keyAlias)

    suspend fun explain(profile: AiProfileConfig, facts: AiFacts): ReportAi = withContext(Dispatchers.IO) {
        val key = secrets.get(profile.keyAlias) ?: error("Для профиля «${profile.displayName}» не сохранён API-ключ")
        AiClient(transport, profile, key).explain(facts)
    }

    /** Проверка подключения без данных APK. Ключ можно передать ещё не сохранённым (из формы). */
    suspend fun testConnection(profile: AiProfileConfig, keyOverride: String?): List<String> = withContext(Dispatchers.IO) {
        val key = keyOverride?.takeIf { it.isNotBlank() } ?: secrets.get(profile.keyAlias) ?: error("Введите API-ключ")
        AiClient(transport, profile.copy(modelId = profile.modelId ?: "-"), key).testConnection()
    }
}
