package com.apkanalyzer.ui.analysis

import android.net.Uri
import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.createSavedStateHandle
import androidx.lifecycle.viewModelScope
import androidx.lifecycle.viewmodel.initializer
import androidx.lifecycle.viewmodel.viewModelFactory
import com.apkanalyzer.analyzer.AnalysisCancelledException
import com.apkanalyzer.analyzer.AnalysisOutcome
import com.apkanalyzer.analyzer.AnalysisStage
import com.apkanalyzer.di.AppContainer
import com.apkanalyzer.data.importer.ImportResult
import com.apkanalyzer.report.ReportBuilder
import com.apkanalyzer.report.ReportDocument
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

sealed interface AnalysisUiState {
    data object Importing : AnalysisUiState
    data class Running(val fileName: String, val stage: AnalysisStage, val progress: Float) : AnalysisUiState
    data class Done(
        val doc: ReportDocument,
        /** Выбранный пользователем файл — для кнопки «Удалить файл»; null для установленного приложения. */
        val sourceUri: Uri?,
        /** ID записи в истории; null — сохранить не удалось. */
        val historyId: Long?,
    ) : AnalysisUiState
    data class Rejected(val reason: String) : AnalysisUiState
    data class Failed(val message: String) : AnalysisUiState
    data object Cancelled : AnalysisUiState
}

class AnalysisViewModel(
    savedStateHandle: SavedStateHandle,
    private val c: AppContainer,
) : ViewModel() {

    /** Источник: выбранный файл или установленное приложение (этап 5). */
    private val uri: Uri? = savedStateHandle.get<String>(ARG_URI)?.let(Uri::parse)
    private val installedPackage: String? = savedStateHandle.get<String>(ARG_PKG)

    init {
        require(uri != null || installedPackage != null) { "Не передан ни файл, ни пакет" }
    }

    private val _state = MutableStateFlow<AnalysisUiState>(AnalysisUiState.Importing)
    val state: StateFlow<AnalysisUiState> = _state.asStateFlow()

    private var job: Job? = null

    init {
        start()
    }

    fun start() {
        job?.cancel()
        job = viewModelScope.launch { run() }
    }

    /** Отчёт обновился (например, добавлено AI-объяснение). */
    fun replaceDoc(doc: ReportDocument) {
        val s = _state.value
        if (s is AnalysisUiState.Done) _state.value = s.copy(doc = doc)
    }

    fun cancel() {
        job?.cancel()
        _state.value = AnalysisUiState.Cancelled
    }

    /** Что анализируем: файл во временной папке (удаляется после анализа) или APK установленного приложения. */
    private class Target(val file: java.io.File, val displayName: String, val splits: List<java.io.File>, val temporary: Boolean)

    private suspend fun prepare(): Target? {
        installedPackage?.let { pkg ->
            _state.value = AnalysisUiState.Running(pkg, AnalysisStage.VALIDATION, 0f)
            val files = c.installedApps.apkFiles(pkg)
            if (files == null) {
                _state.value = AnalysisUiState.Rejected(INSTALLED_UNAVAILABLE)
                return null
            }
            return Target(files.base, "${files.label} ($pkg)", files.splits, temporary = false)
        }
        _state.value = AnalysisUiState.Importing
        return when (val r = c.importer.importApk(checkNotNull(uri))) {
            is ImportResult.Success -> Target(r.apk.file, r.apk.displayName, emptyList(), temporary = true)
            is ImportResult.Failure -> {
                _state.value = AnalysisUiState.Rejected(r.reason)
                null
            }
        }
    }

    private suspend fun run() {
        val target = prepare() ?: return
        try {
            val doc = withContext(Dispatchers.Default) {
                val ctx = currentCoroutineContext()
                val outcome = c.analyzer.analyze(
                    file = target.file,
                    displayName = target.displayName,
                    cancel = { !ctx.isActive },
                    progress = { stage, fraction ->
                        _state.value = AnalysisUiState.Running(target.displayName, stage, fraction)
                    },
                    splits = target.splits,
                )
                when (outcome) {
                    is AnalysisOutcome.Completed -> ReportBuilder.build(outcome.report, c.riskEngine.assess(outcome.report), c.appVersion)
                    is AnalysisOutcome.Rejected -> {
                        _state.value = AnalysisUiState.Rejected(outcome.reason)
                        null
                    }
                }
            } ?: return
            // История — необязательная часть: ошибка сохранения не должна скрывать результат.
            val historyId = runCatching { c.history.save(doc) }.getOrNull()
            _state.value = AnalysisUiState.Done(doc, uri, historyId)
        } catch (e: AnalysisCancelledException) {
            _state.value = AnalysisUiState.Cancelled
        } catch (e: CancellationException) {
            _state.value = AnalysisUiState.Cancelled
            throw e
        } catch (e: Exception) {
            _state.value = AnalysisUiState.Failed(e.message ?: e.javaClass.simpleName)
        } finally {
            // Удаляем только свою временную копию — файлы установленного приложения не трогаем.
            if (target.temporary) target.file.delete()
        }
    }

    companion object {
        const val ARG_URI = "uri"
        const val ARG_PKG = "pkg"
        private const val INSTALLED_UNAVAILABLE =
            "Приложение не найдено или его APK недоступен для чтения. Возможно, оно уже удалено."

        fun factory(container: AppContainer): ViewModelProvider.Factory = viewModelFactory {
            initializer { AnalysisViewModel(createSavedStateHandle(), container) }
        }
    }
}
