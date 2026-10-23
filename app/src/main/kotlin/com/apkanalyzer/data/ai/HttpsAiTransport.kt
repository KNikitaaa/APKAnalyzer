package com.apkanalyzer.data.ai

import com.apkanalyzer.ai.AiTransport
import com.apkanalyzer.ai.HttpResult
import java.io.IOException
import java.io.InputStream
import java.net.URL
import javax.net.ssl.HttpsURLConnection

/** HTTPS-транспорт на стандартных средствах Android: таймауты, ограничение размера ответа, без редиректов. */
class HttpsAiTransport(
    private val connectTimeoutMs: Int = 15_000,
    private val readTimeoutMs: Int = 90_000,
    private val maxResponseBytes: Int = 2 * 1024 * 1024,
) : AiTransport {

    override fun send(method: String, url: String, headers: Map<String, String>, body: String?): HttpResult {
        val conn = URL(url).openConnection() as? HttpsURLConnection ?: throw IOException("Разрешены только адреса https://")
        try {
            conn.requestMethod = method
            conn.connectTimeout = connectTimeoutMs
            conn.readTimeout = readTimeoutMs
            // Редиректы не выполняем: ключ API не должен уйти на другой адрес.
            conn.instanceFollowRedirects = false
            conn.useCaches = false
            headers.forEach { (k, v) -> conn.setRequestProperty(k, v) }
            if (body != null) {
                val bytes = body.toByteArray(Charsets.UTF_8)
                conn.doOutput = true
                conn.setFixedLengthStreamingMode(bytes.size)
                conn.outputStream.use { it.write(bytes) }
            }
            val code = conn.responseCode
            if (code in 300..399) return HttpResult(code, "{\"error\":{\"message\":\"Сервер перенаправляет запрос — для безопасности это запрещено\"}}")
            val stream = if (code >= 400) conn.errorStream else conn.inputStream
            return HttpResult(code, stream?.let { readLimited(it) }.orEmpty())
        } finally {
            conn.disconnect()
        }
    }

    private fun readLimited(input: InputStream): String = input.use { s ->
        val out = java.io.ByteArrayOutputStream()
        val buf = ByteArray(16 * 1024)
        while (true) {
            val n = s.read(buf)
            if (n < 0) break
            out.write(buf, 0, n)
            if (out.size() > maxResponseBytes) throw IOException("Слишком большой ответ сервера")
        }
        out.toString(Charsets.UTF_8.name())
    }
}
