package com.apkanalyzer.ui.report

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Checkbox
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.apkanalyzer.R
import com.apkanalyzer.report.ReportAi
import com.apkanalyzer.report.ReportDocument
import com.apkanalyzer.ui.theme.RiskColors

/** Карточка AI-объяснения: кнопка запроса, ход, ошибки и сам текст модели (с явной пометкой). */
@Composable
fun AiCard(
    doc: ReportDocument,
    state: AiUiState,
    onRequest: () -> Unit,
    onCancel: () -> Unit,
    onOpenSettings: () -> Unit,
) {
    Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
            Text(stringResource(R.string.ai_title), style = MaterialTheme.typography.titleMedium, modifier = Modifier.semantics { heading() })
            val ai = doc.aiExplanation
            if (ai != null) {
                AiBadge(ai)
                AiExplanationBody(doc, ai)
            } else {
                Text(stringResource(R.string.ai_intro), style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
            when (state) {
                is AiUiState.Running -> {
                    Text(stringResource(R.string.ai_running, state.providerName), style = MaterialTheme.typography.bodyMedium)
                    LinearProgressIndicator(Modifier.fillMaxWidth())
                    OutlinedButton(onClick = onCancel, modifier = Modifier.fillMaxWidth()) { Text(stringResource(R.string.analysis_cancel)) }
                }
                AiUiState.NeedsSetup -> {
                    Text(stringResource(R.string.ai_needs_setup), style = MaterialTheme.typography.bodyMedium, color = RiskColors.Attention)
                    Button(onClick = onOpenSettings, modifier = Modifier.fillMaxWidth()) { Text(stringResource(R.string.ai_open_settings)) }
                }
                is AiUiState.Failed -> {
                    Text(state.message, style = MaterialTheme.typography.bodyMedium, color = RiskColors.High)
                    OutlinedButton(onClick = onRequest, modifier = Modifier.fillMaxWidth()) { Text(stringResource(R.string.analysis_retry)) }
                    TextButton(onClick = onOpenSettings) { Text(stringResource(R.string.ai_open_settings)) }
                }
                else -> Button(onClick = onRequest, modifier = Modifier.fillMaxWidth()) {
                    Text(stringResource(if (ai == null) R.string.ai_request else R.string.ai_refresh))
                }
            }
        }
    }
}

@Composable
private fun AiBadge(ai: ReportAi) {
    Text(
        stringResource(R.string.ai_badge, ai.provider, ai.model),
        style = MaterialTheme.typography.labelSmall,
        color = MaterialTheme.colorScheme.primary,
        modifier = Modifier
            .border(1.dp, MaterialTheme.colorScheme.primary.copy(alpha = 0.5f), RoundedCornerShape(6.dp))
            .padding(horizontal = 8.dp, vertical = 4.dp),
    )
}

@Composable
private fun AiExplanationBody(doc: ReportDocument, ai: ReportAi) {
    val titles = doc.findings.associate { it.ruleId to it.titleRu }
    ai.summary?.let { Text(it, style = MaterialTheme.typography.bodyLarge) }
    if (ai.scenarios.isNotEmpty()) {
        SubTitle(stringResource(R.string.ai_scenarios))
        ai.scenarios.forEach { s ->
            Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
                Text(s.title + " · " + confidenceRu(s.confidence), style = MaterialTheme.typography.bodyLarge, fontWeight = FontWeight.SemiBold)
                Text(s.description, style = MaterialTheme.typography.bodyMedium)
                if (s.ruleIds.isNotEmpty()) {
                    Text(
                        stringResource(R.string.ai_based_on, s.ruleIds.joinToString { titles[it] ?: it }),
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }
        }
        ai.uncertainty?.let { Text(stringResource(R.string.ai_uncertainty, it), style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant) }
    }
    if (ai.actions.isNotEmpty()) {
        SubTitle(stringResource(R.string.ai_actions))
        ai.actions.forEachIndexed { i, a ->
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Text("${i + 1}.", color = MaterialTheme.colorScheme.primary)
                Column {
                    Text(a.action, style = MaterialTheme.typography.bodyLarge)
                    if (a.why.isNotBlank()) Text(a.why, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
            }
        }
    }
    if (ai.findingNotes.isNotEmpty()) {
        SubTitle(stringResource(R.string.ai_findings))
        ai.findingNotes.forEach { n ->
            Column {
                Text(titles[n.ruleId] ?: n.ruleId, style = MaterialTheme.typography.bodyMedium, fontWeight = FontWeight.SemiBold)
                Text(n.text, style = MaterialTheme.typography.bodyMedium)
            }
        }
    }
    if (ai.errors.isNotEmpty()) {
        Text(
            stringResource(R.string.ai_partial, ai.errors.size),
            style = MaterialTheme.typography.labelSmall,
            color = RiskColors.Attention,
        )
    }
}

@Composable
private fun SubTitle(text: String) {
    Text(text, style = MaterialTheme.typography.titleSmall, modifier = Modifier.padding(top = 4.dp).semantics { heading() })
}

private fun confidenceRu(c: String) = when (c) {
    "high" -> "уверенность высокая"
    "medium" -> "уверенность средняя"
    else -> "уверенность низкая"
}

/** Согласие и предпросмотр: точный JSON, адрес назначения, что не отправляется. */
@Composable
fun AiConsentDialog(
    preview: AiUiState.Preview,
    onSend: (dontPreviewAgain: Boolean) -> Unit,
    onDismiss: () -> Unit,
) {
    var agreed by remember { mutableStateOf(!preview.firstTime) }
    var dontAsk by remember { mutableStateOf(false) }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(stringResource(if (preview.firstTime) R.string.ai_consent_title else R.string.ai_preview_title)) },
        text = {
            Column(
                Modifier
                    .verticalScroll(rememberScrollState()),
                verticalArrangement = Arrangement.spacedBy(10.dp),
            ) {
                Text(stringResource(R.string.ai_consent_destination, preview.profile.destinationHost, preview.profile.providerType.displayName, preview.profile.modelId.orEmpty()))
                Text(stringResource(R.string.ai_consent_what), style = MaterialTheme.typography.bodyMedium)
                Text(stringResource(R.string.ai_consent_not_sent), style = MaterialTheme.typography.bodyMedium, color = RiskColors.Low)
                Text(stringResource(R.string.ai_consent_json, preview.facts.fragmentCount), style = MaterialTheme.typography.labelSmall)
                SelectionContainer {
                    Text(
                        preview.facts.toJsonString(),
                        fontFamily = FontFamily.Monospace,
                        style = MaterialTheme.typography.bodySmall,
                        modifier = Modifier
                            .fillMaxWidth()
                            .heightIn(max = 260.dp)
                            .background(MaterialTheme.colorScheme.surfaceVariant, RoundedCornerShape(8.dp))
                            .verticalScroll(rememberScrollState())
                            .horizontalScroll(rememberScrollState())
                            .padding(8.dp),
                    )
                }
                if (preview.firstTime) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Checkbox(checked = agreed, onCheckedChange = { agreed = it })
                        Text(stringResource(R.string.ai_consent_agree), style = MaterialTheme.typography.bodyMedium)
                    }
                }
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Checkbox(checked = dontAsk, onCheckedChange = { dontAsk = it })
                    Text(stringResource(R.string.ai_consent_dont_preview), style = MaterialTheme.typography.bodyMedium)
                }
            }
        },
        confirmButton = { TextButton(onClick = { onSend(dontAsk) }, enabled = agreed) { Text(stringResource(R.string.ai_send)) } },
        dismissButton = { TextButton(onClick = onDismiss) { Text(stringResource(R.string.report_cancel)) } },
    )
}
