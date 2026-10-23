package com.apkanalyzer.data.export

import android.content.ActivityNotFoundException
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.provider.DocumentsContract
import android.provider.Settings
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * Действия с файлом и установленным приложением. Всё — только через штатные сценарии Android
 * с участием пользователя: свой диалог подтверждения + удаление через провайдер документов,
 * системный диалог удаления приложения, системные настройки приложения.
 */
class DeviceActions(private val context: Context) {

    /** Можно ли удалить выбранный файл через провайдер документов. */
    suspend fun canDeleteSource(uri: Uri): Boolean = withContext(Dispatchers.IO) {
        if (!DocumentsContract.isDocumentUri(context, uri)) return@withContext false
        try {
            context.contentResolver.query(uri, arrayOf(DocumentsContract.Document.COLUMN_FLAGS), null, null, null)?.use { c ->
                c.moveToFirst() && (c.getInt(0) and DocumentsContract.Document.FLAG_SUPPORTS_DELETE) != 0
            } ?: false
        } catch (_: Exception) {
            false
        }
    }

    suspend fun deleteSource(uri: Uri): Result<Unit> = withContext(Dispatchers.IO) {
        runCatching {
            check(DocumentsContract.deleteDocument(context.contentResolver, uri)) { "Провайдер файлов отказал в удалении" }
        }
    }

    /** Системный диалог удаления приложения (если оно установлено). */
    fun uninstallIntent(packageName: String): Intent =
        Intent(Intent.ACTION_DELETE, Uri.parse("package:$packageName"))

    /** Системная страница «О приложении». */
    fun appDetailsIntent(packageName: String): Intent =
        Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, Uri.parse("package:$packageName"))
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)

    fun tryStart(launch: () -> Unit): Boolean = try {
        launch(); true
    } catch (_: ActivityNotFoundException) {
        false
    } catch (_: SecurityException) {
        false
    }
}
