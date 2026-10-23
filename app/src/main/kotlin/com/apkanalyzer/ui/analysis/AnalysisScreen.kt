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
                title = { Text(stringResource(R.string.analysis_title)) },
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
            .padding(24.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        Text(title, style = MaterialTheme.typography.titleLarge, maxLines = 2, overflow = TextOverflow.Ellipsis)
        if (progress == null) {
            LinearProgressIndicator(modifier = Modifier.fillMaxWidth())
        } else {
            LinearProgressIndicator(progress = { progress }, modifier = Modifier.fillMaxWidth())
        }
        if (stage != null) {
            Text(
                stage.labelRu,
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.semantics { liveRegion = LiveRegionMode.Polite },
            )
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                AnalysisStage.entries.forEach { s ->
                    val done = s.ordinal < stage.ordinal
                    val current = s == stage
                    Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                        Box(
                            Modifier
                                .size(10.dp)
                                .background(
                                    when {
                                        done -> RiskColors.Low
                                        current -> MaterialTheme.colorScheme.primary
                                        else -> MaterialTheme.colorScheme.surfaceVariant
                                    },
                                    CircleShape,
                                ),
                        )
                        Text(
                            s.labelRu,
                            style = MaterialTheme.typography.bodyLarge,
                            color = if (done || current) MaterialTheme.colorScheme.onSurface else MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                }
            }
        }
        Spacer(Modifier.weight(1f))
        OutlinedButton(onClick = onCancel, modifier = Modifier.fillMaxWidth()) {
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
        Text(title, style = MaterialTheme.typography.headlineMedium)
        if (message != null) {
            Text(message, style = MaterialTheme.typography.bodyLarge, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
        Spacer(Modifier.height(8.dp))
        Button(onClick = primary.second, modifier = Modifier.fillMaxWidth()) { Text(primary.first) }
        if (secondary != null) {
            OutlinedButton(onClick = secondary.second, modifier = Modifier.fillMaxWidth()) { Text(secondary.first) }
        }
    }
}
