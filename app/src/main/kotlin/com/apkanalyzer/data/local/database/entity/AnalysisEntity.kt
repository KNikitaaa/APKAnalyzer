package com.apkanalyzer.data.local.database.entity

import androidx.room.ColumnInfo
import androidx.room.Entity
import androidx.room.Index
import androidx.room.PrimaryKey

@Entity(
    tableName = "analysis_history",
    indices = [Index(value = ["sha256"]), Index(value = ["analyzed_at"])]
)
data class AnalysisEntity(

    @PrimaryKey(autoGenerate = true)
    val id: Long = 0,

    @ColumnInfo(name = "file_name")
    val fileName: String,

    @ColumnInfo(name = "sha256")
    val sha256: String,

    @ColumnInfo(name = "file_size_bytes")
    val fileSizeBytes: Long,

    @ColumnInfo(name = "package_name")
    val packageName: String,

    @ColumnInfo(name = "version_name")
    val versionName: String?,

    @ColumnInfo(name = "version_code")
    val versionCode: Long?,

    @ColumnInfo(name = "min_sdk")
    val minSdk: Int?,

    @ColumnInfo(name = "target_sdk")
    val targetSdk: Int?,

    @ColumnInfo(name = "risk_level_ordinal")
    val riskLevelOrdinal: Int,

    @ColumnInfo(name = "risk_score")
    val riskScore: Int,

    @ColumnInfo(name = "rules_version")
    val rulesVersion: String,

    @ColumnInfo(name = "analyzed_at")
    val analyzedAtMs: Long,

    @ColumnInfo(name = "report_json")
    val reportJson: String?,

    @ColumnInfo(name = "ai_used")
    val aiUsed: Boolean = false,

    @ColumnInfo(name = "ai_provider_name")
    val aiProviderName: String? = null,
)
