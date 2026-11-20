package com.apkanalyzer.data.reputation

import com.apkanalyzer.data.ai.HttpsAiTransport
import com.apkanalyzer.data.ai.SecretStore
import com.apkanalyzer.reputation.HashReputation
import com.apkanalyzer.reputation.VirusTotalSource
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * Проверка SHA-256 во внешнем сервисе репутации (сейчас — VirusTotal). Отправляется только хеш:
 * ни APK, ни имя пакета, ни список приложений не уходят. Ключ хранится зашифрованным в [SecretStore].
 */
class ReputationService(private val secrets: SecretStore) {

    fun hasKey(): Boolean = secrets.has(KEY_ALIAS)

    fun saveKey(key: String) = secrets.put(KEY_ALIAS, key.trim())

    fun removeKey() = secrets.remove(KEY_ALIAS)

    suspend fun lookup(sha256: String): HashReputation = withContext(Dispatchers.IO) {
        val key = secrets.get(KEY_ALIAS) ?: error("Не задан API-ключ VirusTotal")
        VirusTotalSource(HttpsAiTransport(readTimeoutMs = 20_000, maxResponseBytes = 4 * 1024 * 1024), key).lookup(sha256)
    }

    companion object {
        const val KEY_ALIAS = "reputation_virustotal"
        const val HOST = "www.virustotal.com"

        /** Открываем только ссылки на сам сервис — отчёт мог прийти из чужого JSON-файла. */
        fun isSafeLink(url: String): Boolean = url.startsWith("https://$HOST/")
    }
}
