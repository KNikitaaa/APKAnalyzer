package com.apkanalyzer.ui.settings

import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.AssistChip
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import com.apkanalyzer.ApkAnalyzerApp
import com.apkanalyzer.R
import com.apkanalyzer.ai.AiProfileConfig
import com.apkanalyzer.ai.AiProviderType
import com.apkanalyzer.data.settings.AppSettings
import com.apkanalyzer.ui.theme.RiskColors

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SettingsRoute(onBack: () -> Unit) {
    val app = LocalContext.current.applicationContext as ApkAnalyzerApp
    val vm: SettingsViewModel = viewModel(factory = SettingsViewModel.factory(app.container))
    val settings by vm.settings.collectAsStateWithLifecycle()
    val draft by vm.draft.collectAsStateWithLifecycle()

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.settings_title)) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(painterResource(R.drawable.ic_arrow_back), contentDescription = stringResource(R.string.analysis_back))
                    }
                },
            )
        },
    ) { padding ->
        Box(Modifier.fillMaxSize().padding(padding)) {
            val s = settings
            if (s == null) {
                CircularProgressIndicator(Modifier.align(Alignment.Center))
            } else {
                SettingsContent(s, vm)
            }
        }
    }
    draft?.let { ProfileEditorDialog(it, vm) }
}

@Composable
private fun SettingsContent(s: AppSettings, vm: SettingsViewModel) {
    LazyColumn(contentPadding = PaddingValues(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        item {
            SettingsCard(stringResource(R.string.settings_ai_profiles)) {
                Text(stringResource(R.string.settings_ai_profiles_hint), style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
                if (s.profiles.isEmpty()) {
                    Text(stringResource(R.string.settings_no_profiles), style = MaterialTheme.typography.bodyMedium)
                }
                s.profiles.forEach { p ->
                    val active = s.activeProfile?.id == p.id
                    Row(
                        Modifier
                            .fillMaxWidth()
                            .selectable(selected = active, role = Role.RadioButton, onClick = { vm.setActive(p) })
                            .padding(vertical = 4.dp),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        RadioButton(selected = active, onClick = null)
                        Column(Modifier.weight(1f).padding(start = 8.dp)) {
                            Text(p.displayName, style = MaterialTheme.typography.bodyLarge)
                            Text("${p.providerType.displayName} · ${p.modelId.orEmpty()} · ${p.destinationHost}", style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                        }
                        TextButton(onClick = { vm.edit(p) }) { Text(stringResource(R.string.settings_edit)) }
                        IconButton(onClick = { vm.deleteProfile(p) }) {
                            Icon(painterResource(R.drawable.ic_delete), contentDescription = stringResource(R.string.settings_delete_profile))
                        }
                    }
                }
                Button(onClick = vm::newProfile, modifier = Modifier.fillMaxWidth()) { Text(stringResource(R.string.settings_add_profile)) }
            }
        }
        item {
            SettingsCard(stringResource(R.string.settings_privacy)) {
                SwitchRow(stringResource(R.string.settings_always_preview), stringResource(R.string.settings_always_preview_hint), s.alwaysPreview, vm::setAlwaysPreview)
                HorizontalDivider()
                SwitchRow(stringResource(R.string.settings_include_domains), stringResource(R.string.settings_include_domains_hint), s.includeDomains, vm::setIncludeDomains)
                HorizontalDivider()
                SwitchRow(stringResource(R.string.settings_include_package), stringResource(R.string.settings_include_package_hint), s.includePackageName, vm::setIncludePackage)
                HorizontalDivider()
                Text(
                    stringResource(if (s.aiConsentGiven) R.string.settings_consent_given else R.string.settings_consent_not_given),
                    style = MaterialTheme.typography.bodyMedium,
                )
                if (s.aiConsentGiven) {
                    OutlinedButton(onClick = { vm.revokeConsent() }, modifier = Modifier.fillMaxWidth()) { Text(stringResource(R.string.settings_revoke_consent)) }
                }
            }
        }
        item {
            SettingsCard(stringResource(R.string.settings_history)) {
                Text(stringResource(R.string.settings_retention_hint), style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
                listOf(0 to R.string.settings_retention_forever, 30 to R.string.settings_retention_30, 90 to R.string.settings_retention_90, 365 to R.string.settings_retention_365)
                    .forEach { (days, label) ->
                        Row(
                            Modifier
                                .fillMaxWidth()
                                .selectable(selected = s.historyRetentionDays == days, role = Role.RadioButton, onClick = { vm.setRetention(days) })
                                .padding(vertical = 2.dp),
                            verticalAlignment = Alignment.CenterVertically,
                        ) {
                            RadioButton(selected = s.historyRetentionDays == days, onClick = null)
                            Text(stringResource(label), modifier = Modifier.padding(start = 8.dp))
                        }
                    }
            }
        }
    }
}

@Composable
private fun SettingsCard(title: String, content: @Composable () -> Unit) {
    Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text(title, style = MaterialTheme.typography.titleMedium, modifier = Modifier.semantics { heading() })
            content()
        }
    }
}

@Composable
private fun SwitchRow(title: String, hint: String, checked: Boolean, onChange: (Boolean) -> Unit) {
    Row(
        Modifier
            .fillMaxWidth()
            .clickable(role = Role.Switch) { onChange(!checked) }
            .padding(vertical = 4.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Column(Modifier.weight(1f)) {
            Text(title, style = MaterialTheme.typography.bodyLarge)
            Text(hint, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
        Switch(checked = checked, onCheckedChange = null)
    }
}

@Composable
private fun ProfileEditorDialog(d: ProfileDraft, vm: SettingsViewModel) {
    AlertDialog(
        onDismissRequest = vm::closeEditor,
        title = { Text(stringResource(if (d.isNew) R.string.settings_new_profile else R.string.settings_edit_profile)) },
        text = {
            Column(Modifier.verticalScroll(rememberScrollState()), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                Text(stringResource(R.string.settings_provider), style = MaterialTheme.typography.labelLarge)
                AiProviderType.entries.forEach { p ->
                    Row(
                        Modifier
                            .fillMaxWidth()
                            .selectable(selected = d.provider == p, role = Role.RadioButton, onClick = {
                                vm.updateDraft {
                                    it.copy(
                                        provider = p,
                                        name = if (it.name == it.provider.displayName || it.name.isBlank()) p.displayName else it.name,
                                        model = if (it.model.isBlank() || it.model in it.provider.suggestedModels) p.suggestedModels.firstOrNull().orEmpty() else it.model,
                                        baseUrl = "",
                                        availableModels = emptyList(),
                                    )
                                }
                            }),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        RadioButton(selected = d.provider == p, onClick = null)
                        Text(p.displayName, modifier = Modifier.padding(start = 8.dp))
                    }
                }
                OutlinedTextField(
                    value = d.name, onValueChange = { v -> vm.updateDraft { it.copy(name = v) } },
                    label = { Text(stringResource(R.string.settings_profile_name)) }, singleLine = true, modifier = Modifier.fillMaxWidth(),
                )
                OutlinedTextField(
                    value = d.baseUrl, onValueChange = { v -> vm.updateDraft { it.copy(baseUrl = v) } },
                    label = { Text(stringResource(R.string.settings_base_url)) },
                    placeholder = { Text(d.provider.defaultBaseUrl.ifBlank { "https://…/v1" }) },
                    isError = !d.urlValid,
                    supportingText = { if (!d.urlValid) Text(stringResource(R.string.settings_https_only)) else Text(stringResource(R.string.settings_destination, d.toConfig().destinationHost)) },
                    singleLine = true,
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Uri, autoCorrectEnabled = false),
                    modifier = Modifier.fillMaxWidth(),
                )
                OutlinedTextField(
                    value = d.apiKey, onValueChange = { v -> vm.updateDraft { it.copy(apiKey = v) } },
                    label = { Text(stringResource(R.string.settings_api_key)) },
                    placeholder = { if (d.hasSavedKey) Text(stringResource(R.string.settings_key_saved)) },
                    supportingText = { Text(stringResource(R.string.settings_key_hint)) },
                    singleLine = true,
                    visualTransformation = PasswordVisualTransformation(),
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password, autoCorrectEnabled = false),
                    modifier = Modifier.fillMaxWidth(),
                )
                OutlinedTextField(
                    value = d.model, onValueChange = { v -> vm.updateDraft { it.copy(model = v) } },
                    label = { Text(stringResource(R.string.settings_model)) }, singleLine = true, modifier = Modifier.fillMaxWidth(),
                )
                val suggestions = d.availableModels.ifEmpty { d.provider.suggestedModels }
                if (suggestions.isNotEmpty()) {
                    Row(Modifier.horizontalScroll(rememberScrollState()), horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                        suggestions.take(30).forEach { m -> AssistChip(onClick = { vm.updateDraft { it.copy(model = m) } }, label = { Text(m) }) }
                    }
                }
                OutlinedButton(
                    onClick = vm::testConnection,
                    enabled = !d.testing && d.urlValid && (d.apiKey.isNotBlank() || d.hasSavedKey),
                    modifier = Modifier.fillMaxWidth(),
                ) { Text(stringResource(if (d.testing) R.string.settings_testing else R.string.settings_test_connection)) }
                d.testResult?.let { Text(it, color = if (d.testOk) RiskColors.Low else RiskColors.High, style = MaterialTheme.typography.bodyMedium) }
                Text(stringResource(R.string.settings_test_hint), style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
        },
        confirmButton = { TextButton(onClick = vm::saveDraft, enabled = d.canSave) { Text(stringResource(R.string.settings_save)) } },
        dismissButton = { TextButton(onClick = vm::closeEditor) { Text(stringResource(R.string.report_cancel)) } },
    )
}

