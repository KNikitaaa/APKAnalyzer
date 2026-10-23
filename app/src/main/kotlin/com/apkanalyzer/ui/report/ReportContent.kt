package com.apkanalyzer.ui.report

import android.net.Uri
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
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
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import com.apkanalyzer.ApkAnalyzerApp
import com.apkanalyzer.R
import com.apkanalyzer.analyzer.report.FeatureEmphasis
import com.apkanalyzer.analyzer.report.FeatureItem
import com.apkanalyzer.analyzer.report.FeatureSection
import com.apkanalyzer.analyzer.report.RawFeatureFormatter
import com.apkanalyzer.data.export.ExportFormat
import com.apkanalyzer.report.ReportDocument
import com.apkanalyzer.ui.analysis.EvidenceCard
import com.apkanalyzer.ui.analysis.RecommendationsCard
import com.apkanalyzer.ui.analysis.RiskCard
import com.apkanalyzer.ui.theme.RiskColors
import kotlinx.coroutines.launch
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * Полный отчёт: оценка, рекомендации, действия, доказательства, сведения о файле, все признаки.
 * Используется и для свежего анализа, и для отчёта из истории.
 *
 * @param sourceUri выбранный пользователем файл (только для свежего анализа) — для кнопки «Удалить файл».
 */
@Composable
fun ReportContent(
    doc: ReportDocument,
    sourceUri: Uri?,
    onMessage: (String) -> Unit,
    historyId: Long?,
    onDocChanged: (ReportDocument) -> Unit,
    onOpenSettings: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val container = (LocalContext.current.applicationContext as ApkAnalyzerApp).container
    val aiVm: AiExplainViewModel = viewModel(
        key = "ai-${doc.file.sha256}-${doc.generatedAtMs}",
        factory = AiExplainViewModel.factory(container),
    )
    val aiState by aiVm.state.collectAsStateWithLifecycle()
    val updated by aiVm.updated.collectAsStateWithLifecycle()
    LaunchedEffect(updated) { updated?.let(onDocChanged) }
    (aiState as? AiUiState.Preview)?.let { preview ->
        AiConsentDialog(
            preview = preview,
            onSend = { dontPreview -> aiVm.confirm(doc, preview, dontPreview) },
            onDismiss = aiVm::dismiss,
        )
    }

    LazyColumn(
        modifier = modifier.fillMaxSize(),
        contentPadding = PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        item(key = "risk") { RiskCard(doc) }
        item(key = "recommendations") { RecommendationsCard(doc.recommendations) }
        item(key = "ai") {
            AiCard(
                doc = doc,
                state = aiState,
                onRequest = { aiVm.request(doc, historyId) },
                onCancel = aiVm::cancel,
                onOpenSettings = onOpenSettings,
            )
        }
        item(key = "actions") { ReportActionsCard(doc, sourceUri, onMessage) }
        item(key = "evidence") { EvidenceCard(doc.findings) }
        item(key = "file") { FileCard(doc) }
        if (doc.limitations.isNotEmpty()) {
            item(key = "limitations") {
                SectionCard(FeatureSection("limits", stringResource(R.string.report_limitations), doc.limitations.map { FeatureItem(it, null, FeatureEmphasis.NOTICE) }))
            }
        }
        item(key = "raw-title") {
            Text(
                stringResource(R.string.analysis_raw_title),
                style = MaterialTheme.typography.titleLarge,
                modifier = Modifier
                    .padding(top = 8.dp, start = 4.dp)
                    .semantics { heading() },
            )
        }
        items(doc.sections, key = { "s-" + it.id }) { section -> SectionCard(section) }
    }
}

@Composable
private fun ReportActionsCard(doc: ReportDocument, sourceUri: Uri?, onMessage: (String) -> Unit) {
    val context = LocalContext.current
    val container = (context.applicationContext as ApkAnalyzerApp).container
    val scope = rememberCoroutineScope()
    val savedOk = stringResource(R.string.report_saved)
    val saveFailed = stringResource(R.string.report_save_failed)
    val noApp = stringResource(R.string.report_no_handler)

    fun saver(format: ExportFormat) = ActivityResultContracts.CreateDocument(format.mime)
    val pdfLauncher = rememberLauncherForActivityResult(saver(ExportFormat.PDF)) { uri ->
        if (uri != null) scope.launch {
            runCatching { container.exporter.writeTo(uri, doc, ExportFormat.PDF) }
                .onSuccess { onMessage(savedOk) }.onFailure { onMessage("$saveFailed: ${it.message}") }
        }
    }
    val jsonLauncher = rememberLauncherForActivityResult(saver(ExportFormat.JSON)) { uri ->
        if (uri != null) scope.launch {
            runCatching { container.exporter.writeTo(uri, doc, ExportFormat.JSON) }
                .onSuccess { onMessage(savedOk) }.onFailure { onMessage("$saveFailed: ${it.message}") }
        }
    }

    val sharePdf: () -> Unit = {
        scope.launch {
            runCatching { container.exporter.shareIntent(doc, ExportFormat.PDF) }
                .onSuccess { intent -> if (!container.deviceActions.tryStart { context.startActivity(intent) }) onMessage(noApp) }
                .onFailure { onMessage("$saveFailed: ${it.message}") }
        }
    }
    var showPdf by remember { mutableStateOf(false) }
    if (showPdf) {
        PdfPreviewDialog(
            doc = doc,
            onDismiss = { showPdf = false },
            onSave = { pdfLauncher.launch(container.exporter.suggestedFileName(doc, ExportFormat.PDF)) },
            onShare = sharePdf,
        )
    }

    var canDeleteFile by remember(sourceUri) { mutableStateOf(false) }
    var confirmDelete by remember { mutableStateOf(false) }
    LaunchedEffect(sourceUri) {
        canDeleteFile = sourceUri != null && container.deviceActions.canDeleteSource(sourceUri)
    }

    Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text(stringResource(R.string.report_actions), style = MaterialTheme.typography.titleMedium, modifier = Modifier.semantics { heading() })
            Button(onClick = { showPdf = true }, modifier = Modifier.fillMaxWidth()) {
                Text(stringResource(R.string.report_open_pdf))
            }
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp), modifier = Modifier.fillMaxWidth()) {
                OutlinedButton(onClick = { pdfLauncher.launch(container.exporter.suggestedFileName(doc, ExportFormat.PDF)) }, modifier = Modifier.weight(1f)) {
                    Text(stringResource(R.string.report_export_pdf))
                }
                OutlinedButton(onClick = { jsonLauncher.launch(container.exporter.suggestedFileName(doc, ExportFormat.JSON)) }, modifier = Modifier.weight(1f)) {
                    Text(stringResource(R.string.report_export_json))
                }
            }
            OutlinedButton(
                onClick = sharePdf,
                modifier = Modifier.fillMaxWidth(),
            ) { Text(stringResource(R.string.report_share)) }

            if (canDeleteFile) {
                OutlinedButton(onClick = { confirmDelete = true }, modifier = Modifier.fillMaxWidth()) {
                    Text(stringResource(R.string.report_delete_file), color = RiskColors.High)
                }
            }
            doc.app?.packageName?.takeIf { it.isNotBlank() }?.let { pkg ->
                OutlinedButton(
                    onClick = { if (!container.deviceActions.tryStart { context.startActivity(container.deviceActions.uninstallIntent(pkg)) }) onMessage(noApp) },
                    modifier = Modifier.fillMaxWidth(),
                ) { Text(stringResource(R.string.report_uninstall_app)) }
                OutlinedButton(
                    onClick = { if (!container.deviceActions.tryStart { context.startActivity(container.deviceActions.appDetailsIntent(pkg)) }) onMessage(noApp) },
                    modifier = Modifier.fillMaxWidth(),
                ) { Text(stringResource(R.string.report_app_details)) }
                Text(
                    stringResource(R.string.report_installed_hint),
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
    }

    if (confirmDelete && sourceUri != null) {
        val deleted = stringResource(R.string.report_file_deleted)
        val failed = stringResource(R.string.report_file_delete_failed)
        AlertDialog(
            onDismissRequest = { confirmDelete = false },
            title = { Text(stringResource(R.string.report_delete_file_title)) },
            text = { Text(stringResource(R.string.report_delete_file_text, doc.file.name)) },
            confirmButton = {
                TextButton(onClick = {
                    confirmDelete = false
                    scope.launch {
                        container.deviceActions.deleteSource(sourceUri)
                            .onSuccess { canDeleteFile = false; onMessage(deleted) }
                            .onFailure { onMessage("$failed: ${it.message}") }
                    }
                }) { Text(stringResource(R.string.report_delete_confirm), color = RiskColors.High) }
            },
            dismissButton = { TextButton(onClick = { confirmDelete = false }) { Text(stringResource(R.string.report_cancel)) } },
        )
    }
}

@Composable
private fun FileCard(doc: ReportDocument) {
    val date = SimpleDateFormat("dd.MM.yyyy HH:mm", Locale.forLanguageTag("ru")).format(Date(doc.generatedAtMs))
    SectionCard(
        FeatureSection(
            "file-info", stringResource(R.string.report_file_section),
            listOf(
                FeatureItem(stringResource(R.string.report_file_name), doc.file.name),
                FeatureItem(stringResource(R.string.report_file_size), RawFeatureFormatter.humanBytes(doc.file.sizeBytes)),
                FeatureItem("SHA-256", doc.file.sha256),
                FeatureItem(stringResource(R.string.report_date), date),
                FeatureItem(stringResource(R.string.report_versions), "приложение ${doc.appVersion} · анализатор ${doc.analyzerVersion} · правила ${doc.rulesVersion}"),
            ),
        ),
    )
}

@Composable
fun SectionCard(section: FeatureSection) {
    Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)) {
        Column(Modifier.padding(vertical = 12.dp)) {
            Text(
                section.title,
                style = MaterialTheme.typography.titleMedium,
                modifier = Modifier
                    .padding(horizontal = 16.dp, vertical = 4.dp)
                    .semantics { heading() },
            )
            section.items.forEachIndexed { i, item ->
                if (i > 0) HorizontalDivider(Modifier.padding(horizontal = 16.dp), color = MaterialTheme.colorScheme.surfaceVariant)
                FeatureRow(item)
            }
        }
    }
}

@Composable
private fun FeatureRow(item: FeatureItem) {
    val accent: Color? = when (item.emphasis) {
        FeatureEmphasis.WARNING -> RiskColors.High
        FeatureEmphasis.NOTICE -> RiskColors.Attention
        FeatureEmphasis.NORMAL -> null
    }
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 16.dp, vertical = 8.dp),
        horizontalArrangement = Arrangement.spacedBy(10.dp),
    ) {
        Box(
            Modifier
                .padding(top = 6.dp)
                .size(8.dp)
                .background(accent ?: Color.Transparent, CircleShape),
        )
        SelectionContainer {
            Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
                val value = item.value
                val technical = value != null && value.length >= 40 && ' ' !in value
                Text(item.title, style = MaterialTheme.typography.bodyLarge)
                if (value != null) {
                    Text(
                        value,
                        style = MaterialTheme.typography.bodyMedium,
                        fontFamily = if (technical) FontFamily.Monospace else null,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }
        }
    }
}
