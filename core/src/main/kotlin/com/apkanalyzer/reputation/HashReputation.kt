package com.apkanalyzer.reputation

import com.apkanalyzer.ai.AiTransport
import com.apkanalyzer.ai.HttpResult
import com.apkanalyzer.analyzer.util.Json
import com.apkanalyzer.analyzer.util.JsonException
import com.apkanalyzer.analyzer.util.JsonValue
import java.io.IOException

enum class ReputationStatus { FOUND, NOT_FOUND }

enum class ReputationVerdict(val labelRu: String) {
    MALICIOUS("Антивирусы считают файл вредоносным"),
    SUSPICIOUS("Отдельные антивирусы считают файл подозрительным"),
    CLEAN("Антивирусы не нашли угроз"),
    UNKNOWN("Файл с таким хешем сервису не известен"),
}

/**
 * Репутация файла по SHA-256 во внешнем сервисе. Отдельна от локальной оценки: не меняет
 * ни уровень риска, ни балл, ни доказательства — только показывается рядом с ними.
 */
data class HashReputation(
    val provider: String,
    val checkedAtMs: Long,
    val status: ReputationStatus,
    val malicious: Int,
    val suspicious: Int,
    val harmless: Int,
    val undetected: Int,
    /** Название угрозы по классификации сервиса (очищено и обрезано). */
    val threatLabel: String?,
    val lastAnalysisMs: Long?,
    /** Ссылка на страницу файла в сервисе. */
    val link: String,
) {
    /** Сколько антивирусных движков дали ответ. */
    val engines: Int get() = malicious + suspicious + harmless + undetected

    val verdict: ReputationVerdict
        get() = when {
            status == ReputationStatus.NOT_FOUND -> ReputationVerdict.UNKNOWN
            malicious >= 3 -> ReputationVerdict.MALICIOUS
            malicious >= 1 || suspicious >= 2 -> ReputationVerdict.SUSPICIOUS
            else -> ReputationVerdict.CLEAN
        }
}

class ReputationException(message: String, val fatal: Boolean = false) : Exception(message)

/**
 * Общий интерфейс сервисов репутации по хешу (план: «чтобы позже подключать дополнительные источники
 * независимо от основного анализатора»). Реализация обязана отправлять только SHA-256.
 */
interface HashReputationSource {
    val name: String

    /** @throws IllegalArgumentException если передан не SHA-256; [ReputationException] — ошибка сервиса или сети. */
    fun lookup(sha256: String): HashReputation
}

/**
 * VirusTotal API v3: `GET /api/v3/files/{sha256}`. Файл не загружается — если сервис его не видел,
 * ответ «не известен». Ключ пользователя идёт только в заголовке `x-apikey`, только по HTTPS.
 */
class VirusTotalSource(
    private val transport: AiTransport,
    private val apiKey: String,
    private val clock: () -> Long = System::currentTimeMillis,
) : HashReputationSource {

    override val name: String = "VirusTotal"

    override fun lookup(sha256: String): HashReputation {
        require(isSha256(sha256)) { "Ожидается SHA-256 в нижнем регистре" }
        val result: HttpResult = try {
            transport.send("GET", "$API/files/$sha256", mapOf("x-apikey" to apiKey, "accept" to "application/json"), null)
        } catch (e: IOException) {
            throw ReputationException("Нет связи с VirusTotal: ${e.message ?: e.javaClass.simpleName}")
        }
        val link = "$GUI/file/$sha256"
        return when (result.code) {
            200 -> parse(result.body, link)
            404 -> HashReputation(name, clock(), ReputationStatus.NOT_FOUND, 0, 0, 0, 0, null, null, link)
            401, 403 -> throw ReputationException("VirusTotal не принял API-ключ — проверьте его в настройках", fatal = true)
            429 -> throw ReputationException("Превышен лимит запросов VirusTotal (бесплатный ключ — 4 запроса в минуту и 500 в день). Попробуйте позже")
            else -> throw ReputationException("VirusTotal ответил ошибкой ${result.code}")
        }
    }

    private fun parse(body: String, link: String): HashReputation {
        val root = try {
            Json.parse(body, maxLength = 4 * 1024 * 1024)
        } catch (e: JsonException) {
            throw ReputationException("Некорректный ответ VirusTotal")
        }
        val attrs = root.obj("data")?.obj("attributes") ?: throw ReputationException("В ответе VirusTotal нет данных о файле")
        val stats = attrs.obj("last_analysis_stats") ?: throw ReputationException("В ответе VirusTotal нет результатов проверки")
        fun count(key: String) = (stats.long(key) ?: 0L).coerceIn(0L, MAX_ENGINES).toInt()
        return HashReputation(
            provider = name,
            checkedAtMs = clock(),
            status = ReputationStatus.FOUND,
            malicious = count("malicious"),
            suspicious = count("suspicious"),
            harmless = count("harmless"),
            undetected = count("undetected"),
            threatLabel = attrs.obj("popular_threat_classification")?.str("suggested_threat_label")?.let(::sanitize),
            lastAnalysisMs = attrs.long("last_analysis_date")?.takeIf { it > 0 }?.times(1000),
            link = link,
        )
    }

    companion object {
        private const val API = "https://www.virustotal.com/api/v3"
        private const val GUI = "https://www.virustotal.com/gui"
        private const val MAX_ENGINES = 500L
        private val SHA256 = Regex("^[0-9a-f]{64}$")

        fun isSha256(s: String): Boolean = SHA256.matches(s)

        /** Название угрозы — чужой текст: убираем управляющие символы и ограничиваем длину. */
        fun sanitize(s: String): String? =
            s.filter { !it.isISOControl() }.replace(Regex("\\s+"), " ").trim().take(80).ifEmpty { null }
    }
}
