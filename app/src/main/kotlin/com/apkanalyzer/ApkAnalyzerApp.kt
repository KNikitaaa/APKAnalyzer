package com.apkanalyzer

import android.app.Application
import com.apkanalyzer.di.AppContainer
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch

class ApkAnalyzerApp : Application() {

    lateinit var container: AppContainer
        private set

    /** Область для коротких фоновых задач уровня приложения. */
    val appScope = CoroutineScope(SupervisorJob() + Dispatchers.Default)

    override fun onCreate() {
        super.onCreate()
        container = AppContainer(this)
        // Временные копии APK от прошлых запусков (например, после аварийного завершения) не храним.
        Thread({ container.importer.clearAll() }, "imports-cleanup").start()
        // Автоочистка истории по сроку хранения из настроек.
        appScope.launch {
            runCatching { container.history.purgeOlderThan(container.settings.current().historyRetentionDays) }
        }
    }
}
