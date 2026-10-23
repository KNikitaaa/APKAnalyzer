package com.apkanalyzer.ui.history

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.createSavedStateHandle
import androidx.lifecycle.viewModelScope
import androidx.lifecycle.viewmodel.initializer
import androidx.lifecycle.viewmodel.viewModelFactory
import com.apkanalyzer.data.local.database.entity.AnalysisEntity
import com.apkanalyzer.di.AppContainer
import com.apkanalyzer.report.ReportDocument
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch

class HistoryViewModel(private val c: AppContainer) : ViewModel() {

    /** null — ещё загружается. */
    val items: StateFlow<List<AnalysisEntity>?> = c.history.observe()
        .map<List<AnalysisEntity>, List<AnalysisEntity>?> { it }
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), null)

    fun delete(id: Long) {
        viewModelScope.launch { c.history.delete(id) }
    }

    fun clear() {
        viewModelScope.launch { c.history.clear() }
    }

    companion object {
        fun factory(c: AppContainer): ViewModelProvider.Factory = viewModelFactory { initializer { HistoryViewModel(c) } }
    }
}

sealed interface SavedReportState {
    data object Loading : SavedReportState
    data class Loaded(val doc: ReportDocument) : SavedReportState
    data object Missing : SavedReportState
}

class SavedReportViewModel(handle: SavedStateHandle, private val c: AppContainer) : ViewModel() {
    private val id: Long = checkNotNull(handle.get<Long>(ARG_ID)) { "Нет ID отчёта" }

    private val _state = MutableStateFlow<SavedReportState>(SavedReportState.Loading)
    val state: StateFlow<SavedReportState> = _state.asStateFlow()

    init {
        viewModelScope.launch {
            _state.value = c.history.load(id)?.let { SavedReportState.Loaded(it) } ?: SavedReportState.Missing
        }
    }

    val reportId: Long get() = id

    fun replaceDoc(doc: ReportDocument) {
        _state.value = SavedReportState.Loaded(doc)
    }

    fun delete(onDone: () -> Unit) {
        viewModelScope.launch {
            c.history.delete(id)
            onDone()
        }
    }

    companion object {
        const val ARG_ID = "id"

        fun factory(c: AppContainer): ViewModelProvider.Factory = viewModelFactory {
            initializer { SavedReportViewModel(createSavedStateHandle(), c) }
        }
    }
}
