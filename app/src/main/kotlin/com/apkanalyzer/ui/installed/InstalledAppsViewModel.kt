package com.apkanalyzer.ui.installed

import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.viewModelScope
import androidx.lifecycle.viewmodel.initializer
import androidx.lifecycle.viewmodel.viewModelFactory
import com.apkanalyzer.di.AppContainer
import com.apkanalyzer.installed.InstalledAppSummary
import com.apkanalyzer.installed.InstalledAppsQuery
import com.apkanalyzer.installed.InstalledAppsSort
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch

data class InstalledAppsUiState(
    /** null — список ещё загружается. */
    val apps: List<InstalledAppSummary>?,
    val query: InstalledAppsQuery,
    /** false — Android показывает приложению не все пакеты (package visibility). */
    val seesAllPackages: Boolean,
    val error: String? = null,
)

class InstalledAppsViewModel(private val c: AppContainer) : ViewModel() {

    private val all = MutableStateFlow<List<InstalledAppSummary>?>(null)
    private val error = MutableStateFlow<String?>(null)
    private val query = MutableStateFlow(InstalledAppsQuery())
    private var loading: Job? = null

    val state: StateFlow<InstalledAppsUiState> = combine(all, query, error) { apps, q, err ->
        InstalledAppsUiState(apps?.let(q::select), q, c.installedApps.seesAllPackages, err)
    }.stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), InstalledAppsUiState(null, InstalledAppsQuery(), true))

    /** Перечитывает список (например, после возврата из системного окна удаления). Старый список виден до обновления. */
    fun refresh() {
        if (loading?.isActive == true) return
        loading = viewModelScope.launch {
            runCatching { c.installedApps.list() }
                .onSuccess { all.value = it; error.value = null }
                .onFailure { error.value = it.message ?: it.javaClass.simpleName }
        }
    }

    fun setText(text: String) = query.update { it.copy(text = text) }
    fun setIncludeSystem(include: Boolean) = query.update { it.copy(includeSystem = include) }
    fun setSort(sort: InstalledAppsSort) = query.update { it.copy(sort = sort) }

    companion object {
        fun factory(c: AppContainer): ViewModelProvider.Factory = viewModelFactory { initializer { InstalledAppsViewModel(c) } }
    }
}
