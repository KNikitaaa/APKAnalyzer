package com.apkanalyzer.data.rules

import android.content.Context
import android.net.Uri
import com.apkanalyzer.rules.RiskEngine
import com.apkanalyzer.rules.RuleCatalog
import com.apkanalyzer.rules.RuleParams
import com.apkanalyzer.rules.pack.RulePack
import com.apkanalyzer.rules.pack.RulePackException
import com.apkanalyzer.rules.pack.RulePackVerifier
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.withContext
import java.io.File

/** Какой набор правил сейчас действует. */
data class RulePackStatus(
    /** null — встроенный набор. */
    val pack: RulePack?,
    val rulesVersion: String,
    /** Почему сохранённый пакет не применён (например, не прошёл проверку после обновления приложения). */
    val problem: String? = null,
)

/**
 * Подписанные пакеты правил: загрузка из файла, хранение во внутренней папке, проверка подписи
 * при каждом запуске. Откат на более старую версию запрещён даже после «Вернуть встроенные»:
 * самая новая когда-либо принятая версия запоминается.
 */
class RulePackRepository(private val context: Context) {

    private val file = File(context.filesDir, "rules/active.rulepack")
    private val prefs = context.getSharedPreferences("rule_packs", Context.MODE_PRIVATE)
    private val verifier = RulePackVerifier()

    private val _status = MutableStateFlow(load())
    val status: StateFlow<RulePackStatus> = _status.asStateFlow()

    /** Движок с действующими параметрами. */
    val riskEngine: RiskEngine get() = RiskEngine(params = params(_status.value.pack))

    suspend fun install(uri: Uri): Result<RulePack> = withContext(Dispatchers.IO) {
        runCatching {
            val text = context.contentResolver.openInputStream(uri)?.use { input ->
                val bytes = input.readNBytesCompat(MAX_FILE + 1)
                if (bytes.size > MAX_FILE) throw RulePackException("Файл слишком большой для пакета правил")
                String(bytes, Charsets.UTF_8)
            } ?: throw RulePackException("Не удалось прочитать файл")
            val pack = verifier.verify(text, installedVersion = prefs.getString(KEY_MAX_VERSION, null))
            file.parentFile?.mkdirs()
            val tmp = File(file.parentFile, "incoming.tmp")
            tmp.writeText(text)
            if (!tmp.renameTo(file)) {
                file.writeText(text)
                tmp.delete()
            }
            prefs.edit().putString(KEY_MAX_VERSION, pack.version).apply()
            _status.value = RulePackStatus(pack, params(pack).version)
            pack
        }
    }

    suspend fun reset() = withContext(Dispatchers.IO) {
        file.delete()
        _status.value = RulePackStatus(null, RuleCatalog.VERSION)
    }

    private fun load(): RulePackStatus {
        if (!file.isFile) return RulePackStatus(null, RuleCatalog.VERSION)
        return try {
            val pack = verifier.verify(file.readText())
            RulePackStatus(pack, params(pack).version)
        } catch (e: Exception) {
            // Например, приложение обновилось и встроенный каталог стал новее пакета — работаем на встроенных правилах.
            RulePackStatus(null, RuleCatalog.VERSION, problem = e.message ?: e.javaClass.simpleName)
        }
    }

    private fun params(pack: RulePack?): RuleParams = pack?.toParams() ?: RuleParams.DEFAULT

    private fun java.io.InputStream.readNBytesCompat(limit: Int): ByteArray {
        val out = java.io.ByteArrayOutputStream()
        val buf = ByteArray(16 * 1024)
        while (out.size() < limit) {
            val n = read(buf, 0, minOf(buf.size, limit - out.size()))
            if (n < 0) break
            out.write(buf, 0, n)
        }
        return out.toByteArray()
    }

    private companion object {
        const val KEY_MAX_VERSION = "max_installed_version"
        const val MAX_FILE = 1024 * 1024
    }
}
