package com.apkanalyzer.di

import android.content.Context
import android.os.Build
import com.apkanalyzer.analyzer.AnalysisLimits
import com.apkanalyzer.analyzer.ApkAnalyzer
import com.apkanalyzer.data.ai.AiService
import com.apkanalyzer.data.ai.SecretStore
import com.apkanalyzer.data.export.DeviceActions
import com.apkanalyzer.data.export.ReportExporter
import com.apkanalyzer.data.history.HistoryRepository
import com.apkanalyzer.data.installed.InstalledAppsRepository
import com.apkanalyzer.data.reputation.ReputationService
import com.apkanalyzer.data.rules.RulePackRepository
import com.apkanalyzer.data.importer.ApkImporter
import com.apkanalyzer.data.local.database.AppDatabase
import com.apkanalyzer.data.settings.SettingsRepository
import com.apkanalyzer.rules.RiskEngine

/**
 * Простой контейнер зависимостей (ручное внедрение). Граф пока небольшой; при росте проекта
 * его можно заменить на Hilt без изменения остального кода.
 */
class AppContainer(context: Context) {
    private val appContext = context.applicationContext

    val limits: AnalysisLimits = AnalysisLimits()
    /** Вложенные APK из контейнеров .apks/.xapk/.apkm распаковываются в закрытый кэш приложения и удаляются после анализа. */
    val analyzer: ApkAnalyzer = ApkAnalyzer(limits, tempDir = java.io.File(appContext.cacheDir, "containers").apply { mkdirs() })
    val importer: ApkImporter = ApkImporter(appContext, limits.maxApkBytes)
    /** Подписанные пакеты правил; движок всегда берёт действующие параметры. */
    val rulePacks: RulePackRepository by lazy { RulePackRepository(appContext) }
    val riskEngine: RiskEngine get() = rulePacks.riskEngine

    val database: AppDatabase by lazy { AppDatabase.create(appContext) }
    val history: HistoryRepository by lazy { HistoryRepository(database.analysisDao()) }
    val exporter: ReportExporter = ReportExporter(appContext)
    val deviceActions: DeviceActions = DeviceActions(appContext)
    val installedApps: InstalledAppsRepository = InstalledAppsRepository(appContext)

    val settings: SettingsRepository = SettingsRepository(appContext)
    val secrets: SecretStore by lazy { SecretStore(appContext) }
    val ai: AiService by lazy { AiService(secrets) }
    val reputation: ReputationService by lazy { ReputationService(secrets) }

    val appVersion: String by lazy {
        try {
            val info = if (Build.VERSION.SDK_INT >= 33) {
                appContext.packageManager.getPackageInfo(appContext.packageName, android.content.pm.PackageManager.PackageInfoFlags.of(0))
            } else {
                @Suppress("DEPRECATION")
                appContext.packageManager.getPackageInfo(appContext.packageName, 0)
            }
            info.versionName ?: "?"
        } catch (_: Exception) {
            "?"
        }
    }
}
