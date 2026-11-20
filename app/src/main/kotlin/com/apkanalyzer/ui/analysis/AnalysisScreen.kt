package com.apkanalyzer.ui.analysis

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import com.apkanalyzer.ApkAnalyzerApp
import com.apkanalyzer.R
import com.apkanalyzer.ui.components.AppCard
import com.apkanalyzer.ui.components.IconBubble
import com.apkanalyzer.analyzer.AnalysisStage
import com.apkanalyzer.ui.report.ReportContent
import com.apkanalyzer.ui.theme.RiskColors
import kotlinx.coroutines.launch

@Composable
fun AnalysisRoute(onBack: () -> Unit, onOpenSettings: () -> Unit) {
    val app = LocalContext.current.applicationContext as ApkAnalyzerApp
    val vm: AnalysisViewModel = viewModel(factory = AnalysisViewModel.factory(app.container))
    val state by vm.state.collectAsStateWithLifecycle()
    AnalysisScreen(
        state = state,
        onCancel = vm::cancel,
        onRetry = vm::start,
        onBack = onBack,
        onDocChanged = vm::replaceDoc,
        onOpenSettings = onOpenSettings,
    )
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AnalysisScreen(
    state: AnalysisUiState,
    onCancel: () -> Unit,
    onRetry: () -> Unit,
    onBack: () -> Unit,
    onDocChanged: (com.apkanalyzer.report.ReportDocument) -> Unit,
    onOpenSettings: () -> Unit,
) {
    val snackbar = remember { SnackbarHostState() }
    val scope = rememberCoroutineScope()
    Scaffold(
        snackbarHost = { SnackbarHost(snackbar) },
        topBar = {
            TopAppBar(
                title = { Text(stringResource(if (state is AnalysisUiState.Done) R.string.analysis_title_report else R.string.analysis_title)) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(painterResource(R.drawable.ic_arrow_back), contentDescription = stringResource(R.string.analysis_back))
                    }
                },
            )
        },
    ) { padding ->
        Box(
            Modifier
                .fillMaxSize()
                .padding(padding),
        ) {
            when (state) {
                AnalysisUiState.Importing -> ProgressContent(stringResource(R.string.analysis_importing), null, null, onCancel)
                is AnalysisUiState.Running -> ProgressContent(state.fileName, state.stage, state.progress, onCancel)
                is AnalysisUiState.Done -> ReportContent(
                    doc = state.doc,
                    sourceUri = state.sourceUri,
                    onMessage = { msg -> scope.launch { snackbar.showSnackbar(msg) } },
                    historyId = state.historyId,
                    onDocChanged = onDocChanged,
                    onOpenSettings = onOpenSettings,
                    autoVirusTotal = state.useVirusTotal,
                    autoAi = state.useAi,
                )
                is AnalysisUiState.Rejected -> MessageContent(
                    title = stringResource(R.string.analysis_rejected_title),
                    message = state.reason,
                    primary = stringResource(R.string.analysis_try_another) to onBack,
                )
                is AnalysisUiState.Failed -> MessageContent(
                    title = stringResource(R.string.analysis_error_title),
                    message = state.message,
                    primary = stringResource(R.string.analysis_try_another) to onBack,
                    secondary = stringResource(R.string.analysis_retry) to onRetry,
                )
                AnalysisUiState.Cancelled -> MessageContent(
                    title = stringResource(R.string.analysis_cancelled),
                    message = null,
                    primary = stringResource(R.string.analysis_back) to onBack,
                    secondary = stringResource(R.string.analysis_retry) to onRetry,
                )
            }
        }
    }
}

@Composable
private fun ProgressContent(title: String, stage: AnalysisStage?, progress: Float?, onCancel: () -> Unit) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(horizontal = 24.dp, vertical = 16.dp),
        verticalArrangement = Arrangement.spacedBy(20.dp),
    ) {
        Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(20.dp)) {
            Box(Modifier.size(72.dp), contentAlignment = Alignment.Center) {
                if (progress == null) {
                    CircularProgressIndicator(Modifier.fillMaxSize(), strokeWidth = 5.dp, trackColor = MaterialTheme.colorScheme.surfaceContainerHighest)
                } else {
                    CircularProgressIndicator(progress = { progress }, modifier = Modifier.fillMaxSize(), strokeWidth = 5.dp, trackColor = MaterialTheme.colorScheme.surfaceContainerHighest)
                }
                Icon(painterResource(R.drawable.ic_shield), contentDescription = null, tint = MaterialTheme.colorScheme.primary, modifier = Modifier.size(30.dp))
            }
            Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(2.dp)) {
                Text(stringResource(R.string.analysis_checking), style = MaterialTheme.typography.labelLarge, color = MaterialTheme.colorScheme.primary)
                Text(title, style = MaterialTheme.typography.titleLarge, maxLines = 2, overflow = TextOverflow.Ellipsis)
                Text(stringResource(R.string.analysis_offline_note), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
        }
        if (stage != null) {
            AppCard {
                Column(Modifier.padding(vertical = 8.dp)) {
                    AnalysisStage.entries.forEach { s ->
                        val done = s.ordinal < stage.ordinal
                        val current = s == stage
                        Row(
                            Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 10.dp),
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.spacedBy(14.dp),
                        ) {
                            Box(Modifier.size(24.dp), contentAlignment = Alignment.Center) {
                                when {
                                    done -> Box(
                                        Modifier.size(22.dp).background(RiskColors.LowBackground, CircleShape),
                                        contentAlignment = Alignment.Center,
                                    ) { Icon(painterResource(R.drawable.ic_check), contentDescription = null, tint = RiskColors.Low, modifier = Modifier.size(16.dp)) }
                                    current -> CircularProgressIndicator(Modifier.size(20.dp), strokeWidth = 2.5.dp)
                                    else -> Box(Modifier.size(10.dp).background(MaterialTheme.colorScheme.outlineVariant, CircleShape))
                                }
                            }
                            Text(
                                s.labelRu,
                                style = if (current) MaterialTheme.typography.titleSmall else MaterialTheme.typography.bodyLarge,
                                color = if (done || current) MaterialTheme.colorScheme.onSurface else MaterialTheme.colorScheme.onSurfaceVariant,
                                // Текущий этап объявляется экранным диктором по мере смены.
                                modifier = if (current) Modifier.semantics { liveRegion = LiveRegionMode.Polite } else Modifier,
                            )
                        }
                    }
                }
            }
        } else {
            LinearProgressIndicator(Modifier.fillMaxWidth())
        }
        Spacer(Modifier.weight(1f))
        OutlinedButton(onClick = onCancel, modifier = Modifier.fillMaxWidth().height(48.dp)) {
            Text(stringResource(R.string.analysis_cancel))
        }
    }
}

@Composable
fun MessageContent(
    title: String,
    message: String?,
    primary: Pair<String, () -> Unit>,
    secondary: Pair<String, () -> Unit>? = null,
) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(24.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        Spacer(Modifier.height(24.dp))
        IconBubble(R.drawable.ic_description, tint = MaterialTheme.colorScheme.onSecondaryContainer, container = MaterialTheme.colorScheme.secondaryContainer, size = 64.dp)
        Text(title, style = MaterialTheme.typography.headlineSmall)
        if (message != null) {
            Text(message, style = MaterialTheme.typography.bodyLarge, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
        Spacer(Modifier.weight(1f))
        Button(onClick = primary.second, modifier = Modifier.fillMaxWidth().height(48.dp)) { Text(primary.first) }
        if (secondary != null) {
            OutlinedButton(onClick = secondary.second, modifier = Modifier.fillMaxWidth().height(48.dp)) { Text(secondary.first) }
        }
    }
}
