package com.apkanalyzer.data.history

import com.apkanalyzer.data.local.database.dao.AnalysisDao
import com.apkanalyzer.data.local.database.entity.AnalysisEntity
import com.apkanalyzer.report.ReportDocument
import com.apkanalyzer.report.ReportJson
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.withContext

/**
 * История анализов на устройстве. Хранится только отчёт (JSON), сам APK — никогда.
 */
class HistoryRepository(private val dao: AnalysisDao) {

    fun observe(): Flow<List<AnalysisEntity>> = dao.observeAll()

    suspend fun save(doc: ReportDocument): Long = withContext(Dispatchers.IO) {
        dao.insert(
            AnalysisEntity(
                fileName = doc.file.name,
                sha256 = doc.file.sha256,
                fileSizeBytes = doc.file.sizeBytes,
                packageName = doc.app?.packageName.orEmpty(),
                versionName = doc.app?.versionName,
                versionCode = doc.app?.versionCode,
                minSdk = doc.app?.minSdk,
                targetSdk = doc.app?.targetSdk,
                riskLevelOrdinal = doc.risk.level.ordinal,
                riskScore = doc.risk.score,
                rulesVersion = doc.rulesVersion,
                analyzedAtMs = doc.generatedAtMs,
                reportJson = ReportJson.encode(doc, pretty = false),
                aiUsed = doc.aiExplanation != null,
                aiProviderName = doc.aiExplanation?.provider,
            ),
        )
    }

    /** null — записи нет или отчёт не читается (например, создан будущей версией приложения). */
    suspend fun load(id: Long): ReportDocument? = withContext(Dispatchers.IO) {
        val json = dao.getById(id)?.reportJson ?: return@withContext null
        runCatching { ReportJson.decode(json) }.getOrNull()
    }

    /** Обновляет сохранённый отчёт (например, после получения AI-объяснения). */
    suspend fun update(id: Long, doc: ReportDocument) = withContext(Dispatchers.IO) {
        dao.updateReport(id, ReportJson.encode(doc, pretty = false), doc.aiExplanation != null, doc.aiExplanation?.provider)
    }

    /** Удаляет записи старше [days] дней (0 — ничего не удаляет). */
    suspend fun purgeOlderThan(days: Int, nowMs: Long = System.currentTimeMillis()): Int = withContext(Dispatchers.IO) {
        if (days <= 0) 0 else dao.deleteOlderThan(nowMs - days * 24L * 60 * 60 * 1000)
    }

    suspend fun delete(id: Long) = withContext(Dispatchers.IO) { dao.deleteById(id) }

    suspend fun clear() = withContext(Dispatchers.IO) { dao.deleteAll() }
}
