package com.apkanalyzer.ui.report

import android.content.Intent
import android.net.Uri
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.viewModelScope
import androidx.lifecycle.viewmodel.initializer
import androidx.lifecycle.viewmodel.viewModelFactory
import com.apkanalyzer.R
import com.apkanalyzer.ui.components.IconBubble
import com.apkanalyzer.ui.components.SectionTitle
import com.apkanalyzer.ui.components.AppCard
import com.apkanalyzer.data.reputation.ReputationService
import com.apkanalyzer.di.AppContainer
import com.apkanalyzer.report.ReportDocument
import com.apkanalyzer.reputation.HashReputation
import com.apkanalyzer.reputation.ReputationException
import com.apkanalyzer.reputation.ReputationVerdict
import com.apkanalyzer.ui.theme.RiskColors
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

sealed interface ReputationUiState {
    data object Idle : ReputationUiState
    data object NeedsKey : ReputationUiState
    /** Подтверждение: ровно этот хеш уйдёт в сервис. */
    data class Confirm(val sha256: String) : ReputationUiState
    data object Running : ReputationUiState
    data class Failed(val message: String) : ReputationUiState
}

class ReputationViewModel(private val c: AppContainer) : ViewModel() {
    private val _state = MutableStateFlow<ReputationUiState>(ReputationUiState.Idle)
    val state: StateFlow<ReputationUiState> = _state.asStateFlow()

    private val _updated = MutableStateFlow<ReportDocument?>(null)
    val updated: StateFlow<ReportDocument?> = _updated.asStateFlow()

    fun request(doc: ReportDocument) {
        _state.value = if (!c.reputation.hasKey()) ReputationUiState.NeedsKey else ReputationUiState.Confirm(doc.file.sha256)
    }

    fun confirm(doc: ReportDocument, historyId: Long?) {
        _state.value = ReputationUiState.Running
        viewModelScope.launch {
            try {
                val rep = c.reputation.lookup(doc.file.sha256)
                // Локальная оценка не меняется: репутация хранится отдельным разделом отчёта.
                val newDoc = doc.copy(reputation = rep)
                historyId?.let { id -> runCatching { c.history.update(id, newDoc) } }
                _updated.value = newDoc
                _state.value = ReputationUiState.Idle
            } catch (e: CancellationException) {
                _state.value = ReputationUiState.Idle
                throw e
            } catch (e: ReputationException) {
                _state.value = ReputationUiState.Failed(e.message ?: "Ошибка сервиса")
            } catch (e: Exception) {
                _state.value = ReputationUiState.Failed(e.message ?: e.javaClass.simpleName)
            }
        }
    }

    fun dismiss() {
        _state.value = ReputationUiState.Idle
    }

    companion object {
        fun factory(c: AppContainer): ViewModelProvider.Factory = viewModelFactory { initializer { ReputationViewModel(c) } }
    }
}

@Composable
fun ReputationCard(
    doc: ReportDocument,
    state: ReputationUiState,
    onRequest: () -> Unit,
    onOpenSettings: () -> Unit,
) {
    val context = LocalContext.current
    AppCard {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                IconBubble(R.drawable.ic_globe, tint = MaterialTheme.colorScheme.onSecondaryContainer, container = MaterialTheme.colorScheme.secondaryContainer, size = 36.dp)
                SectionTitle(stringResource(R.string.reputation_title))
            }
            doc.reputation?.let { rep -> ReputationResult(rep) } ?: Text(
                stringResource(R.string.reputation_intro),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            when (state) {
                ReputationUiState.Running -> Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    CircularProgressIndicator(Modifier.size(20.dp), strokeWidth = 2.dp)
                    Text(stringResource(R.string.reputation_running))
                }
                ReputationUiState.NeedsKey -> {
                    Text(stringResource(R.string.reputation_needs_key), style = MaterialTheme.typography.bodyMedium)
                    OutlinedButton(onClick = onOpenSettings, modifier = Modifier.fillMaxWidth()) { Text(stringResource(R.string.reputation_open_settings)) }
                }
                is ReputationUiState.Failed -> Text(state.message, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodyMedium)
                else -> {}
            }
            if (state != ReputationUiState.Running && state != ReputationUiState.NeedsKey) {
                OutlinedButton(onClick = onRequest, modifier = Modifier.fillMaxWidth()) {
                    Text(stringResource(if (doc.reputation == null) R.string.reputation_check else R.string.reputation_recheck))
                }
            }
            doc.reputation?.link?.takeIf { ReputationService.isSafeLink(it) }?.let { link ->
                TextButton(onClick = {
                    runCatching { context.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(link)).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)) }
                }) { Text(stringResource(R.string.reputation_open_link)) }
            }
        }
    }
}

@Composable
private fun ReputationResult(rep: HashReputation) {
    val color = when (rep.verdict) {
        ReputationVerdict.MALICIOUS -> RiskColors.High
        ReputationVerdict.SUSPICIOUS -> RiskColors.Attention
        ReputationVerdict.CLEAN -> RiskColors.Low
        ReputationVerdict.UNKNOWN -> MaterialTheme.colorScheme.onSurfaceVariant
    }
    Text(rep.verdict.labelRu, style = MaterialTheme.typography.titleSmall, color = color)
    if (rep.verdict != ReputationVerdict.UNKNOWN) {
        Text(
            stringResource(R.string.reputation_counts, rep.malicious, rep.suspicious, rep.engines),
            style = MaterialTheme.typography.bodyMedium,
        )
    } else {
        Text(stringResource(R.string.reputation_unknown_hint), style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
    }
    rep.threatLabel?.let { Text(stringResource(R.string.reputation_threat, it), style = MaterialTheme.typography.bodyMedium) }
    val fmt = SimpleDateFormat("dd.MM.yyyy HH:mm", Locale.forLanguageTag("ru"))
    Text(
        stringResource(R.string.reputation_meta, rep.provider, fmt.format(Date(rep.checkedAtMs))) +
            (rep.lastAnalysisMs?.let { " · " + stringResource(R.string.reputation_last_scan, fmt.format(Date(it))) } ?: ""),
        style = MaterialTheme.typography.labelSmall,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
    )
    Text(stringResource(R.string.reputation_separate), style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
}

@Composable
fun ReputationConsentDialog(sha256: String, onSend: () -> Unit, onDismiss: () -> Unit) {
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(stringResource(R.string.reputation_consent_title)) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(stringResource(R.string.reputation_consent_body, ReputationService.HOST))
                Text(sha256, fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.bodySmall)
            }
        },
        confirmButton = { TextButton(onClick = onSend) { Text(stringResource(R.string.reputation_consent_send)) } },
        dismissButton = { TextButton(onClick = onDismiss) { Text(stringResource(R.string.report_cancel)) } },
    )
}
