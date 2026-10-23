package com.apkanalyzer.data.settings

import android.content.Context
import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.booleanPreferencesKey
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.intPreferencesKey
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import com.apkanalyzer.ai.AiPrivacyOptions
import com.apkanalyzer.ai.AiProfileConfig
import com.apkanalyzer.ai.AiProviderType
import com.apkanalyzer.analyzer.util.Json
import com.apkanalyzer.analyzer.util.JsonValue
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.map

private val Context.settingsStore: DataStore<Preferences> by preferencesDataStore(name = "settings")

data class AppSettings(
    val profiles: List<AiProfileConfig> = emptyList(),
    val activeProfileId: String? = null,
    /** Пользователь один раз явно согласился на отправку фактов в AI. */
    val aiConsentGiven: Boolean = false,
    /** Показывать состав данных перед каждой отправкой. */
    val alwaysPreview: Boolean = true,
    val includeDomains: Boolean = false,
    val includePackageName: Boolean = true,
    /** Срок хранения истории в днях; 0 — бессрочно. */
    val historyRetentionDays: Int = 0,
) {
    val activeProfile: AiProfileConfig? get() = profiles.firstOrNull { it.id == activeProfileId } ?: profiles.firstOrNull()
    val privacy: AiPrivacyOptions get() = AiPrivacyOptions(includeDomains, includePackageName)
}

/** Настройки, профили AI и согласия (DataStore). Ключи API здесь НЕ хранятся — см. SecretStore. */
class SettingsRepository(private val context: Context) {

    private object Keys {
        val PROFILES = stringPreferencesKey("ai_profiles")
        val ACTIVE = stringPreferencesKey("ai_active_profile")
        val CONSENT = booleanPreferencesKey("ai_consent")
        val PREVIEW = booleanPreferencesKey("ai_always_preview")
        val DOMAINS = booleanPreferencesKey("ai_include_domains")
        val PACKAGE = booleanPreferencesKey("ai_include_package")
        val RETENTION = intPreferencesKey("history_retention_days")
    }

    val settings: Flow<AppSettings> = context.settingsStore.data.map { p ->
        AppSettings(
            profiles = decodeProfiles(p[Keys.PROFILES]),
            activeProfileId = p[Keys.ACTIVE],
            aiConsentGiven = p[Keys.CONSENT] ?: false,
            alwaysPreview = p[Keys.PREVIEW] ?: true,
            includeDomains = p[Keys.DOMAINS] ?: false,
            includePackageName = p[Keys.PACKAGE] ?: true,
            historyRetentionDays = p[Keys.RETENTION] ?: 0,
        )
    }

    suspend fun current(): AppSettings = settings.first()

    suspend fun saveProfile(profile: AiProfileConfig, makeActive: Boolean) = context.settingsStore.edit { p ->
        val list = decodeProfiles(p[Keys.PROFILES]).filter { it.id != profile.id } + profile
        p[Keys.PROFILES] = encodeProfiles(list)
        if (makeActive || p[Keys.ACTIVE] == null) p[Keys.ACTIVE] = profile.id
    }

    suspend fun deleteProfile(id: String) = context.settingsStore.edit { p ->
        val list = decodeProfiles(p[Keys.PROFILES]).filter { it.id != id }
        p[Keys.PROFILES] = encodeProfiles(list)
        if (p[Keys.ACTIVE] == id) {
            list.firstOrNull()?.let { p[Keys.ACTIVE] = it.id } ?: p.remove(Keys.ACTIVE)
        }
    }

    suspend fun setActive(id: String) = context.settingsStore.edit { it[Keys.ACTIVE] = id }
    suspend fun setConsent(value: Boolean) = context.settingsStore.edit { it[Keys.CONSENT] = value }
    suspend fun setAlwaysPreview(value: Boolean) = context.settingsStore.edit { it[Keys.PREVIEW] = value }
    suspend fun setIncludeDomains(value: Boolean) = context.settingsStore.edit { it[Keys.DOMAINS] = value }
    suspend fun setIncludePackageName(value: Boolean) = context.settingsStore.edit { it[Keys.PACKAGE] = value }
    suspend fun setHistoryRetentionDays(days: Int) = context.settingsStore.edit { it[Keys.RETENTION] = days.coerceAtLeast(0) }

    private fun encodeProfiles(list: List<AiProfileConfig>): String = Json.write(
        JsonValue.Arr(list.map {
            JsonValue.Obj().put("id", it.id).put("name", it.displayName).put("provider", it.providerType.name)
                .put("baseUrl", it.baseUrl).put("model", it.modelId).put("keyAlias", it.keyAlias)
        }),
        pretty = false,
    )

    private fun decodeProfiles(text: String?): List<AiProfileConfig> {
        if (text.isNullOrBlank()) return emptyList()
        return runCatching {
            (Json.parse(text) as JsonValue.Arr).items.mapNotNull { o ->
                val id = o.str("id") ?: return@mapNotNull null
                AiProfileConfig(
                    id = id,
                    displayName = o.str("name").orEmpty(),
                    providerType = AiProviderType.entries.firstOrNull { it.name == o.str("provider") } ?: AiProviderType.CUSTOM,
                    baseUrl = o.str("baseUrl").orEmpty(),
                    modelId = o.str("model"),
                    keyAlias = o.str("keyAlias") ?: AiProfileConfig.defaultKeyAlias(id),
                )
            }
        }.getOrDefault(emptyList())
    }
}
