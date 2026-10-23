package com.apkanalyzer.ui.settings

import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.viewModelScope
import androidx.lifecycle.viewmodel.initializer
import androidx.lifecycle.viewmodel.viewModelFactory
import com.apkanalyzer.ai.AiProfileConfig
import com.apkanalyzer.ai.AiProviderType
import com.apkanalyzer.data.settings.AppSettings
import com.apkanalyzer.di.AppContainer
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch
import java.util.UUID

/** Черновик профиля в редакторе. Ключ хранится только в памяти до сохранения. */
data class ProfileDraft(
    val id: String,
    val isNew: Boolean,
    val name: String,
    val provider: AiProviderType,
    val baseUrl: String,
    val model: String,
    val apiKey: String = "",
    val hasSavedKey: Boolean = false,
    val testing: Boolean = false,
    val testResult: String? = null,
    val testOk: Boolean = false,
    val availableModels: List<String> = emptyList(),
) {
    val effectiveBaseUrl: String get() = baseUrl.ifBlank { provider.defaultBaseUrl }
    val urlValid: Boolean get() = AiProfileConfig.isAllowedBaseUrl(effectiveBaseUrl)
    val canSave: Boolean get() = name.isNotBlank() && model.isNotBlank() && urlValid && (apiKey.isNotBlank() || hasSavedKey)

    fun toConfig() = AiProfileConfig(
        id = id,
        displayName = name.trim(),
        providerType = provider,
        baseUrl = if (provider == AiProviderType.CUSTOM) baseUrl.trim() else baseUrl.trim().takeIf { it != provider.defaultBaseUrl }.orEmpty(),
        modelId = model.trim(),
        keyAlias = AiProfileConfig.defaultKeyAlias(id),
    )
}

class SettingsViewModel(private val c: AppContainer) : ViewModel() {

    val settings: StateFlow<AppSettings?> = c.settings.settings.stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), null)

    private val _draft = MutableStateFlow<ProfileDraft?>(null)
    val draft: StateFlow<ProfileDraft?> = _draft.asStateFlow()

    fun newProfile() {
        val id = UUID.randomUUID().toString().take(8)
        val p = AiProviderType.DEEPSEEK
        _draft.value = ProfileDraft(id, true, p.displayName, p, "", p.suggestedModels.firstOrNull().orEmpty())
    }

    fun edit(profile: AiProfileConfig) {
        _draft.value = ProfileDraft(
            id = profile.id, isNew = false, name = profile.displayName, provider = profile.providerType,
            baseUrl = profile.baseUrl, model = profile.modelId.orEmpty(), hasSavedKey = c.secrets.has(profile.keyAlias),
        )
    }

    fun updateDraft(transform: (ProfileDraft) -> ProfileDraft) {
        _draft.value = _draft.value?.let(transform)?.copy(testResult = null)
    }

    fun closeEditor() {
        _draft.value = null
    }

    /** Проверка подключения: запрос списка моделей, без каких-либо данных APK. */
    fun testConnection() {
        val d = _draft.value ?: return
        _draft.value = d.copy(testing = true, testResult = null)
        viewModelScope.launch {
            val result = runCatching { c.ai.testConnection(d.toConfig(), d.apiKey) }
            _draft.value = _draft.value?.copy(
                testing = false,
                testOk = result.isSuccess,
                testResult = result.fold(
                    onSuccess = { models -> if (models.isEmpty()) "Подключение работает" else "Подключение работает · моделей: ${models.size}" },
                    onFailure = { it.message ?: it.javaClass.simpleName },
                ),
                availableModels = result.getOrNull().orEmpty(),
            )
        }
    }

    fun saveDraft() {
        val d = _draft.value ?: return
        if (!d.canSave) return
        viewModelScope.launch {
            val config = d.toConfig()
            if (d.apiKey.isNotBlank()) c.secrets.put(config.keyAlias, d.apiKey.trim())
            c.settings.saveProfile(config, makeActive = d.isNew)
            _draft.value = null
        }
    }

    fun deleteProfile(profile: AiProfileConfig) {
        viewModelScope.launch {
            c.secrets.remove(profile.keyAlias)
            c.settings.deleteProfile(profile.id)
        }
    }

    fun setActive(profile: AiProfileConfig) = viewModelScope.launch { c.settings.setActive(profile.id) }
    fun setAlwaysPreview(v: Boolean) = viewModelScope.launch { c.settings.setAlwaysPreview(v) }
    fun setIncludeDomains(v: Boolean) = viewModelScope.launch { c.settings.setIncludeDomains(v) }
    fun setIncludePackage(v: Boolean) = viewModelScope.launch { c.settings.setIncludePackageName(v) }
    fun revokeConsent() = viewModelScope.launch {
        c.settings.setConsent(false)
        c.settings.setAlwaysPreview(true)
    }
    fun setRetention(days: Int) = viewModelScope.launch {
        c.settings.setHistoryRetentionDays(days)
        c.history.purgeOlderThan(days)
    }

    companion object {
        fun factory(c: AppContainer): ViewModelProvider.Factory = viewModelFactory { initializer { SettingsViewModel(c) } }
    }
}
