package com.apkanalyzer.data.export

import android.content.Context
import android.content.Intent
import android.net.Uri
import androidx.core.content.FileProvider
import com.apkanalyzer.report.ReportDocument
import com.apkanalyzer.report.ReportJson
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File

enum class ExportFormat(val mime: String, val extension: String) {
    PDF("application/pdf", "pdf"),
    JSON("application/json", "json"),
}

/** Сохранение отчёта в выбранный пользователем файл (SAF) и отправка через «Поделиться». */
class ReportExporter(private val context: Context) {

    fun suggestedFileName(doc: ReportDocument, format: ExportFormat): String {
        val base = (doc.app?.packageName ?: doc.file.name.substringBeforeLast('.'))
            .replace(Regex("[^A-Za-z0-9._-]"), "_").take(60)
        return "apk-report_${base}_${doc.file.sha256.take(8)}.${format.extension}"
    }

    suspend fun writeTo(uri: Uri, doc: ReportDocument, format: ExportFormat) = withContext(Dispatchers.IO) {
        val out = context.contentResolver.openOutputStream(uri, "wt") ?: error("Не удалось открыть файл для записи")
        out.use { write(doc, format, it) }
    }

    /** Готовит временный файл и возвращает Intent «Поделиться». */
    suspend fun shareIntent(doc: ReportDocument, format: ExportFormat): Intent = withContext(Dispatchers.IO) {
        val dir = File(context.cacheDir, "reports").apply { mkdirs() }
        dir.listFiles()?.forEach { it.delete() } // старые временные отчёты не копим
        val file = File(dir, suggestedFileName(doc, format))
        file.outputStream().use { write(doc, format, it) }
        val uri = FileProvider.getUriForFile(context, "${context.packageName}.fileprovider", file)
        val send = Intent(Intent.ACTION_SEND)
            .setType(format.mime)
            .putExtra(Intent.EXTRA_STREAM, uri)
            .putExtra(Intent.EXTRA_SUBJECT, "Отчёт APK AI Analyzer: ${doc.title}")
            .addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
        Intent.createChooser(send, "Поделиться отчётом")
    }

    /** PDF для просмотра внутри приложения (во временной папке, перезаписывается при каждом открытии). */
    suspend fun renderPreview(doc: ReportDocument): File = withContext(Dispatchers.IO) {
        val dir = File(context.cacheDir, "preview").apply { mkdirs() }
        val file = File(dir, "report.pdf")
        file.outputStream().use { PdfReportRenderer().render(doc, it) }
        file
    }

    private fun write(doc: ReportDocument, format: ExportFormat, out: java.io.OutputStream) {
        when (format) {
            ExportFormat.PDF -> PdfReportRenderer().render(doc, out)
            ExportFormat.JSON -> out.write(ReportJson.encode(doc).toByteArray(Charsets.UTF_8))
        }
    }
}
