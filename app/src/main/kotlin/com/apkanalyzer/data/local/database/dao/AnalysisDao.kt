package com.apkanalyzer.data.local.database.dao

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.Query
import com.apkanalyzer.data.local.database.entity.AnalysisEntity
import kotlinx.coroutines.flow.Flow

@Dao
interface AnalysisDao {

    @Query("SELECT * FROM analysis_history ORDER BY analyzed_at DESC")
    fun observeAll(): Flow<List<AnalysisEntity>>

    @Query("SELECT * FROM analysis_history WHERE id = :id")
    suspend fun getById(id: Long): AnalysisEntity?

    @Insert
    suspend fun insert(entity: AnalysisEntity): Long

    @Query("UPDATE analysis_history SET report_json = :json, ai_used = :aiUsed, ai_provider_name = :provider WHERE id = :id")
    suspend fun updateReport(id: Long, json: String, aiUsed: Boolean, provider: String?)

    @Query("DELETE FROM analysis_history WHERE id = :id")
    suspend fun deleteById(id: Long)

    @Query("DELETE FROM analysis_history")
    suspend fun deleteAll()

    @Query("DELETE FROM analysis_history WHERE analyzed_at < :olderThanMs")
    suspend fun deleteOlderThan(olderThanMs: Long): Int
}
