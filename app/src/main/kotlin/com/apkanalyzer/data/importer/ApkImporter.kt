package com.apkanalyzer.data.importer

import android.content.Context
import android.net.Uri
import android.provider.OpenableColumns
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.withContext
import java.io.File
import java.io.FileNotFoundException
import java.io.IOException
import java.util.UUID
import kotlin.coroutines.coroutineContext

data class ImportedApk(
    /** Временная копия в закрытой папке приложения (cacheDir/imports). */
    val file: File,
    val displayName: String,
    val sizeBytes: Long,
    val sourceUri: Uri,
)

sealed interface ImportResult {
    data class Success(val apk: ImportedApk) : ImportResult
    data class Failure(val reason: String) : ImportResult
}

/**
 * Копирует выбранный пользователем файл во временную закрытую папку приложения.
 *
 * Зачем копия: анализатору нужен произвольный доступ к файлу (центральный каталог ZIP в конце),
 * а content:// поток даёт только последовательное чтение. Копия живёт только на время анализа
 * и удаляется сразу после него. Файл не устанавливается и не исполняется.
 */
class ApkImporter(
    private val context: Context,
    private val maxBytes: Long,
) {
    private val importsDir: File
        get() = File(context.cacheDir, "imports").apply { mkdirs() }

    suspend fun importApk(uri: Uri): ImportResult = withContext(Dispatchers.IO) {
        val (name, declaredSize) = queryMeta(uri)
        if (declaredSize != null && declaredSize > maxBytes) {
            return@withContext ImportResult.Failure(
                "Файл слишком большой: ${declaredSize / MB} МБ (максимум ${maxBytes / MB} МБ)",
            )
        }
        val target = File(importsDir, "${UUID.randomUUID()}.apk")
        try {
            val input = context.contentResolver.openInputStream(uri)
                ?: return@withContext ImportResult.Failure("Не удалось открыть файл")
            var copied = 0L
            input.use { src ->
                target.outputStream().use { dst ->
                    val buf = ByteArray(BUFFER)
                    while (true) {
                        coroutineContext.ensureActive()
                        val n = src.read(buf)
                        if (n < 0) break
                        copied += n
                        if (copied > maxBytes) {
                            target.delete()
                            return@withContext ImportResult.Failure("Файл больше допустимых ${maxBytes / MB} МБ")
                        }
                        dst.write(buf, 0, n)
                    }
                }
            }
            if (!startsWithZipMagic(target)) {
                target.delete()
                return@withContext ImportResult.Failure("Выбранный файл не является APK (нет сигнатуры ZIP)")
            }
            ImportResult.Success(ImportedApk(target, name ?: target.name, copied, uri))
        } catch (e: FileNotFoundException) {
            target.delete()
            ImportResult.Failure("Файл не найден или доступ к нему запрещён")
        } catch (e: SecurityException) {
            target.delete()
            ImportResult.Failure("Нет доступа к файлу")
        } catch (e: IOException) {
            target.delete()
            ImportResult.Failure("Ошибка чтения файла: ${e.message}")
        } catch (t: Throwable) {
            target.delete()
            throw t
        }
    }

    /** Удаляет все временные копии. */
    fun clearAll() {
        File(context.cacheDir, "imports").listFiles()?.forEach { it.delete() }
    }

    private fun queryMeta(uri: Uri): Pair<String?, Long?> {
        return try {
            val projection = arrayOf(OpenableColumns.DISPLAY_NAME, OpenableColumns.SIZE)
            context.contentResolver.query(uri, projection, null, null, null)?.use { c ->
                if (!c.moveToFirst()) {
                    null to null
                } else {
                    val nameIdx = c.getColumnIndex(OpenableColumns.DISPLAY_NAME)
                    val sizeIdx = c.getColumnIndex(OpenableColumns.SIZE)
                    val name = if (nameIdx >= 0 && !c.isNull(nameIdx)) c.getString(nameIdx) else null
                    val size = if (sizeIdx >= 0 && !c.isNull(sizeIdx)) c.getLong(sizeIdx) else null
                    sanitizeName(name) to size
                }
            } ?: (null to null)
        } catch (_: Exception) {
            null to null
        }
    }

    private fun startsWithZipMagic(file: File): Boolean = file.inputStream().use { s ->
        val head = ByteArray(4)
        s.read(head) == 4 && head[0] == 'P'.code.toByte() && head[1] == 'K'.code.toByte() &&
            head[2] == 3.toByte() && head[3] == 4.toByte()
    }

    companion object {
        private const val BUFFER = 256 * 1024
        private const val MB = 1024 * 1024

        /** Имя файла только для отображения: без путей, управляющих символов и с ограничением длины. */
        fun sanitizeName(name: String?): String? =
            name?.substringAfterLast('/')?.substringAfterLast('\\')
                ?.filter { !it.isISOControl() && it != '‮' && it != '‭' }
                ?.trim()?.take(120)?.ifEmpty { null }
    }
}
