package com.apkanalyzer.ui.report

import android.net.Uri
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.width
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.FilledTonalIconButton
import androidx.compose.material3.Icon
import androidx.compose.ui.res.painterResource
import com.apkanalyzer.ui.components.SectionTitle
import com.apkanalyzer.ui.theme.CodeFont
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
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.LifecycleResumeEffect
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import com.apkanalyzer.ApkAnalyzerApp
import com.apkanalyzer.R
import com.apkanalyzer.ui.components.AppCard
import com.apkanalyzer.analyzer.report.FeatureEmphasis
import com.apkanalyzer.analyzer.report.FeatureItem
import com.apkanalyzer.analyzer.report.FeatureSection
import com.apkanalyzer.analyzer.report.RawFeatureFormatter
import com.apkanalyzer.data.export.ExportFormat
import com.apkanalyzer.data.installed.InstalledPackageState
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
    val repVm: ReputationViewModel = viewModel(
        key = "rep-${doc.file.sha256}-${doc.generatedAtMs}",
        factory = ReputationViewModel.factory(container),
    )
    val repState by repVm.state.collectAsStateWithLifecycle()
    val repUpdated by repVm.updated.collectAsStateWithLifecycle()
    LaunchedEffect(repUpdated) { repUpdated?.let(onDocChanged) }
    (repState as? ReputationUiState.Confirm)?.let {
        ReputationConsentDialog(sha256 = it.sha256, onSend = { repVm.confirm(doc, historyId) }, onDismiss = repVm::dismiss)
    }
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
        item(key = "reputation") {
            ReputationCard(doc = doc, state = repState, onRequest = { repVm.request(doc) }, onOpenSettings = onOpenSettings)
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
    val sarifLauncher = rememberLauncherForActivityResult(saver(ExportFormat.SARIF)) { uri ->
        if (uri != null) scope.launch {
            runCatching { container.exporter.writeTo(uri, doc, ExportFormat.SARIF) }
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

    // Состояние пакета перечитывается при каждом возвращении на экран — например, из системного окна удаления.
    val pkgName = doc.app?.packageName?.takeIf { it.isNotBlank() }
    var installed by remember(pkgName) { mutableStateOf<InstalledPackageState?>(null) }
    val uninstalledMsg = stringResource(R.string.report_app_uninstalled)
    LifecycleResumeEffect(pkgName) {
        val job = pkgName?.let { pkg ->
            scope.launch {
                val now = container.installedApps.state(pkg)
                if (installed?.installed == true && !now.installed) onMessage(uninstalledMsg)
                installed = now
            }
        }
        onPauseOrDispose { job?.cancel() }
    }

    var canDeleteFile by remember(sourceUri) { mutableStateOf(false) }
    var confirmDelete by remember { mutableStateOf(false) }
    LaunchedEffect(sourceUri) {
        canDeleteFile = sourceUri != null && container.deviceActions.canDeleteSource(sourceUri)
    }

    AppCard {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
            SectionTitle(stringResource(R.string.report_actions))
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp), modifier = Modifier.fillMaxWidth()) {
                Button(onClick = { showPdf = true }, modifier = Modifier.weight(1f).height(48.dp)) {
                    Icon(painterResource(R.drawable.ic_description), contentDescription = null, modifier = Modifier.size(18.dp))
                    Spacer(Modifier.width(8.dp))
                    Text(stringResource(R.string.report_open_pdf))
                }
                FilledTonalIconButton(onClick = sharePdf, modifier = Modifier.size(48.dp)) {
                    Icon(painterResource(R.drawable.ic_share), contentDescription = stringResource(R.string.report_share))
                }
            }
            Text(stringResource(R.string.report_save_as), style = MaterialTheme.typography.labelLarge, color = MaterialTheme.colorScheme.onSurfaceVariant)
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp), modifier = Modifier.fillMaxWidth()) {
                listOf(
                    ExportFormat.PDF to { pdfLauncher.launch(container.exporter.suggestedFileName(doc, ExportFormat.PDF)) },
                    ExportFormat.JSON to { jsonLauncher.launch(container.exporter.suggestedFileName(doc, ExportFormat.JSON)) },
                    ExportFormat.SARIF to { sarifLauncher.launch(container.exporter.suggestedFileName(doc, ExportFormat.SARIF)) },
                ).forEach { (format, save) ->
                    OutlinedButton(onClick = save, modifier = Modifier.weight(1f), contentPadding = PaddingValues(horizontal = 8.dp, vertical = 8.dp)) {
                        Icon(painterResource(R.drawable.ic_download), contentDescription = null, modifier = Modifier.size(16.dp))
                        Spacer(Modifier.width(6.dp))
                        Text(format.name)
                    }
                }
            }
            Text(stringResource(R.string.report_sarif_hint), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)

            val installedState = installed?.takeIf { it.installed }
            if (canDeleteFile || installedState != null) {
                HorizontalDivider(Modifier.padding(vertical = 4.dp), color = MaterialTheme.colorScheme.outlineVariant)
                Text(stringResource(R.string.report_device_actions), style = MaterialTheme.typography.labelLarge, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
            val dangerColors = ButtonDefaults.filledTonalButtonColors(
                containerColor = MaterialTheme.colorScheme.errorContainer,
                contentColor = MaterialTheme.colorScheme.onErrorContainer,
            )
            if (canDeleteFile) {
                FilledTonalButton(onClick = { confirmDelete = true }, colors = dangerColors, modifier = Modifier.fillMaxWidth()) {
                    Icon(painterResource(R.drawable.ic_delete), contentDescription = null, modifier = Modifier.size(18.dp))
                    Spacer(Modifier.width(8.dp))
                    Text(stringResource(R.string.report_delete_file))
                }
            }
            installedState?.let { st ->
                val pkg = doc.app?.packageName.orEmpty()
                if (!st.isSystem) {
                    FilledTonalButton(
                        onClick = { if (!container.deviceActions.tryStart { context.startActivity(container.deviceActions.uninstallIntent(pkg)) }) onMessage(noApp) },
                        colors = dangerColors,
                        modifier = Modifier.fillMaxWidth(),
                    ) {
                        Icon(painterResource(R.drawable.ic_delete), contentDescription = null, modifier = Modifier.size(18.dp))
                        Spacer(Modifier.width(8.dp))
                        Text(stringResource(R.string.report_uninstall_app))
                    }
                }
                OutlinedButton(
                    onClick = { if (!container.deviceActions.tryStart { context.startActivity(container.deviceActions.appDetailsIntent(pkg)) }) onMessage(noApp) },
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Icon(painterResource(R.drawable.ic_open_in), contentDescription = null, modifier = Modifier.size(18.dp))
                    Spacer(Modifier.width(8.dp))
                    Text(stringResource(R.string.report_app_details))
                }
                val hint = buildList {
                    add(stringResource(if (st.isSystem) R.string.report_installed_system_hint else R.string.report_installed_hint))
                    val analyzed = doc.app?.versionCode
                    if (analyzed != null && st.versionCode != null && analyzed != st.versionCode) {
                        add(stringResource(R.string.report_installed_other_version, st.versionName ?: st.versionCode.toString()))
                    }
                }.joinToString(" ")
                Text(hint, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
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
    AppCard {
        Column(Modifier.padding(vertical = 12.dp)) {
            SectionTitle(section.title, Modifier.padding(horizontal = 16.dp, vertical = 4.dp))
            section.items.forEachIndexed { i, item ->
                if (i > 0) HorizontalDivider(Modifier.padding(horizontal = 16.dp), color = MaterialTheme.colorScheme.outlineVariant)
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
            .padding(horizontal = 16.dp, vertical = 10.dp),
        horizontalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Box(
            Modifier
                .padding(top = 7.dp)
                .size(8.dp)
                .background(accent ?: MaterialTheme.colorScheme.outlineVariant, CircleShape),
        )
        SelectionContainer(Modifier.weight(1f)) {
            Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
                val value = item.value
                val technical = value != null && value.length >= 40 && ' ' !in value
                Text(item.title, style = MaterialTheme.typography.bodyLarge, color = accent ?: MaterialTheme.colorScheme.onSurface)
                if (value != null) {
                    Text(
                        value,
                        style = MaterialTheme.typography.bodyMedium,
                        fontFamily = if (technical) CodeFont else null,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }
        }
    }
}
