package com.apkanalyzer.ui.report

import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.viewModelScope
import androidx.lifecycle.viewmodel.initializer
import androidx.lifecycle.viewmodel.viewModelFactory
import com.apkanalyzer.ai.AiFacts
import com.apkanalyzer.ai.AiProfileConfig
import com.apkanalyzer.di.AppContainer
import com.apkanalyzer.report.ReportDocument
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

sealed interface AiUiState {
    data object Idle : AiUiState
    /** Нет профиля или ключа — нужно открыть настройки. */
    data object NeedsSetup : AiUiState
    /** Предпросмотр: ровно эти данные уйдут на [host]. */
    data class Preview(
        val profile: AiProfileConfig,
        val facts: AiFacts,
        val firstTime: Boolean,
    ) : AiUiState
    data class Running(val providerName: String) : AiUiState
    data class Failed(val message: String) : AiUiState
}

/**
 * Получение AI-объяснения для отчёта. Ничего не отправляется без явного согласия: при первом запросе
 * (и всегда, если включён предпросмотр) пользователь видит точный JSON и адрес назначения.
 */
class AiExplainViewModel(private val c: AppContainer) : ViewModel() {

    private val _state = MutableStateFlow<AiUiState>(AiUiState.Idle)
    val state: StateFlow<AiUiState> = _state.asStateFlow()

    /** Обновлённый документ с AI-объяснением (экран заменяет им текущий). */
    private val _updated = MutableStateFlow<ReportDocument?>(null)
    val updated: StateFlow<ReportDocument?> = _updated.asStateFlow()

    private var job: Job? = null
    private var historyId: Long? = null

    fun request(doc: ReportDocument, historyId: Long?) {
        this.historyId = historyId
        if (job?.isActive == true) return
        job = viewModelScope.launch {
            val s = c.settings.current()
            val profile = s.activeProfile
            if (profile == null || profile.modelId.isNullOrBlank() || !c.ai.hasKey(profile)) {
                _state.value = AiUiState.NeedsSetup
                return@launch
            }
            val facts = c.ai.facts(doc, s.privacy)
            if (!s.aiConsentGiven || s.alwaysPreview) {
                _state.value = AiUiState.Preview(profile, facts, firstTime = !s.aiConsentGiven)
            } else {
                send(doc, profile, facts)
            }
        }
    }

    fun confirm(doc: ReportDocument, preview: AiUiState.Preview, dontPreviewAgain: Boolean) {
        job = viewModelScope.launch {
            c.settings.setConsent(true)
            if (dontPreviewAgain) c.settings.setAlwaysPreview(false)
            send(doc, preview.profile, preview.facts)
        }
    }

    fun dismiss() {
        _state.value = AiUiState.Idle
    }

    fun cancel() {
        job?.cancel()
        _state.value = AiUiState.Idle
    }

    private suspend fun send(doc: ReportDocument, profile: AiProfileConfig, facts: AiFacts) {
        _state.value = AiUiState.Running(profile.providerType.displayName)
        try {
            val ai = c.ai.explain(profile, facts)
            if (ai.isEmpty) {
                _state.value = AiUiState.Failed(ai.errors.values.firstOrNull() ?: "Модель не вернула пригодного ответа")
                return
            }
            // Оценка риска и доказательства не меняются — добавляется только отдельное объяснение модели.
            val newDoc = doc.copy(aiExplanation = ai)
            historyId?.let { id -> runCatching { c.history.update(id, newDoc) } }
            _updated.value = newDoc
            _state.value = if (ai.errors.isEmpty()) AiUiState.Idle else AiUiState.Failed("Часть запросов не удалась: " + ai.errors.values.first())
        } catch (e: CancellationException) {
            _state.value = AiUiState.Idle
            throw e
        } catch (e: Exception) {
            _state.value = AiUiState.Failed(e.message ?: e.javaClass.simpleName)
        }
    }

    companion object {
        fun factory(c: AppContainer): ViewModelProvider.Factory = viewModelFactory { initializer { AiExplainViewModel(c) } }
    }
}
