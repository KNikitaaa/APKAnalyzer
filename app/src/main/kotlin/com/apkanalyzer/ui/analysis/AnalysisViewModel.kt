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
        /** Выбранный пользователем файл — для кнопки «Удалить файл». */
        val sourceUri: Uri,
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

    private val uri: Uri = Uri.parse(checkNotNull(savedStateHandle.get<String>(ARG_URI)) { "Не передан URI файла" })

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

    private suspend fun run() {
        _state.value = AnalysisUiState.Importing
        val imported = when (val r = c.importer.importApk(uri)) {
            is ImportResult.Success -> r.apk
            is ImportResult.Failure -> {
                _state.value = AnalysisUiState.Rejected(r.reason)
                return
            }
        }
        try {
            val doc = withContext(Dispatchers.Default) {
                val ctx = currentCoroutineContext()
                val outcome = c.analyzer.analyze(
                    file = imported.file,
                    displayName = imported.displayName,
                    cancel = { !ctx.isActive },
                    progress = { stage, fraction ->
                        _state.value = AnalysisUiState.Running(imported.displayName, stage, fraction)
                    },
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
            imported.file.delete()
        }
    }

    companion object {
        const val ARG_URI = "uri"

        fun factory(container: AppContainer): ViewModelProvider.Factory = viewModelFactory {
            initializer { AnalysisViewModel(createSavedStateHandle(), container) }
        }
    }
}
