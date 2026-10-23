package com.apkanalyzer.ui.history

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import com.apkanalyzer.ApkAnalyzerApp
import com.apkanalyzer.R
import com.apkanalyzer.data.local.database.entity.AnalysisEntity
import com.apkanalyzer.domain.model.RiskLevel
import com.apkanalyzer.ui.analysis.MessageContent
import com.apkanalyzer.ui.analysis.color
import com.apkanalyzer.ui.report.ReportContent
import com.apkanalyzer.ui.theme.RiskColors
import kotlinx.coroutines.launch
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun HistoryRoute(onBack: () -> Unit, onOpen: (Long) -> Unit) {
    val app = LocalContext.current.applicationContext as ApkAnalyzerApp
    val vm: HistoryViewModel = viewModel(factory = HistoryViewModel.factory(app.container))
    val items by vm.items.collectAsStateWithLifecycle()
    var confirmClear by remember { mutableStateOf(false) }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.history_title)) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(painterResource(R.drawable.ic_arrow_back), contentDescription = stringResource(R.string.analysis_back))
                    }
                },
                actions = {
                    if (!items.isNullOrEmpty()) {
                        TextButton(onClick = { confirmClear = true }) { Text(stringResource(R.string.history_clear)) }
                    }
                },
            )
        },
    ) { padding ->
        Box(Modifier.fillMaxSize().padding(padding)) {
            val list = items
            when {
                list == null -> CircularProgressIndicator(Modifier.align(Alignment.Center))
                list.isEmpty() -> Text(
                    stringResource(R.string.history_empty),
                    style = MaterialTheme.typography.bodyLarge,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.align(Alignment.Center).padding(32.dp),
                )
                else -> LazyColumn(
                    contentPadding = PaddingValues(16.dp),
                    verticalArrangement = Arrangement.spacedBy(10.dp),
                ) {
                    items(list, key = { it.id }) { e -> HistoryRow(e, onOpen = { onOpen(e.id) }, onDelete = { vm.delete(e.id) }) }
                }
            }
        }
    }

    if (confirmClear) {
        AlertDialog(
            onDismissRequest = { confirmClear = false },
            title = { Text(stringResource(R.string.history_clear_title)) },
            text = { Text(stringResource(R.string.history_clear_text)) },
            confirmButton = {
                TextButton(onClick = { confirmClear = false; vm.clear() }) { Text(stringResource(R.string.history_clear), color = RiskColors.High) }
            },
            dismissButton = { TextButton(onClick = { confirmClear = false }) { Text(stringResource(R.string.report_cancel)) } },
        )
    }
}

@Composable
private fun HistoryRow(e: AnalysisEntity, onOpen: () -> Unit, onDelete: () -> Unit) {
    val level = RiskLevel.fromOrdinal(e.riskLevelOrdinal)
    val date = remember(e.analyzedAtMs) { SimpleDateFormat("dd.MM.yyyy HH:mm", Locale.forLanguageTag("ru")).format(Date(e.analyzedAtMs)) }
    Card(
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
        modifier = Modifier
            .fillMaxWidth()
            .clickable(role = Role.Button, onClick = onOpen),
    ) {
        Row(
            Modifier.padding(start = 16.dp, top = 12.dp, bottom = 12.dp, end = 4.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Box(Modifier.size(12.dp).background(level.color(), CircleShape))
            Column(Modifier.weight(1f).semantics(mergeDescendants = true) {}, verticalArrangement = Arrangement.spacedBy(2.dp)) {
                Text(
                    e.packageName.ifBlank { e.fileName },
                    style = MaterialTheme.typography.titleMedium,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
                Text(
                    level.labelRu + if (level != RiskLevel.Insufficient) " · ${e.riskScore}/100" else "",
                    style = MaterialTheme.typography.bodyMedium,
                    color = level.color(),
                )
                Text(
                    "$date · ${e.fileName}",
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
            }
            IconButton(onClick = onDelete) {
                Icon(painterResource(R.drawable.ic_delete), contentDescription = stringResource(R.string.history_delete_item))
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SavedReportRoute(onBack: () -> Unit, onOpenSettings: () -> Unit) {
    val app = LocalContext.current.applicationContext as ApkAnalyzerApp
    val vm: SavedReportViewModel = viewModel(factory = SavedReportViewModel.factory(app.container))
    val state by vm.state.collectAsStateWithLifecycle()
    val snackbar = remember { SnackbarHostState() }
    val scope = rememberCoroutineScope()

    Scaffold(
        snackbarHost = { SnackbarHost(snackbar) },
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.history_report_title)) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(painterResource(R.drawable.ic_arrow_back), contentDescription = stringResource(R.string.analysis_back))
                    }
                },
                actions = {
                    if (state is SavedReportState.Loaded) {
                        IconButton(onClick = { vm.delete(onBack) }) {
                            Icon(painterResource(R.drawable.ic_delete), contentDescription = stringResource(R.string.history_delete_item))
                        }
                    }
                },
            )
        },
    ) { padding ->
        Box(Modifier.fillMaxSize().padding(padding)) {
            when (val s = state) {
                SavedReportState.Loading -> CircularProgressIndicator(Modifier.align(Alignment.Center))
                SavedReportState.Missing -> MessageContent(
                    title = stringResource(R.string.history_missing),
                    message = null,
                    primary = stringResource(R.string.analysis_back) to onBack,
                )
                is SavedReportState.Loaded -> ReportContent(
                    doc = s.doc,
                    sourceUri = null,
                    onMessage = { msg -> scope.launch { snackbar.showSnackbar(msg) } },
                    historyId = vm.reportId,
                    onDocChanged = vm::replaceDoc,
                    onOpenSettings = onOpenSettings,
                )
            }
        }
    }
}
