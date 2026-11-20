package com.apkanalyzer.ui.installed

import androidx.compose.foundation.Image
import androidx.compose.foundation.horizontalScroll
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
import androidx.compose.foundation.rememberScrollState
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.produceState
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.LifecycleResumeEffect
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import com.apkanalyzer.ApkAnalyzerApp
import com.apkanalyzer.R
import com.apkanalyzer.ui.components.Tag
import com.apkanalyzer.data.installed.InstalledAppsRepository
import com.apkanalyzer.installed.InstalledAppSummary
import com.apkanalyzer.installed.InstalledAppsSort
import com.apkanalyzer.ui.components.InfoCard
import com.apkanalyzer.ui.theme.RiskColors

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun InstalledAppsRoute(onBack: () -> Unit, onAnalyze: (String) -> Unit) {
    val app = LocalContext.current.applicationContext as ApkAnalyzerApp
    val vm: InstalledAppsViewModel = viewModel(factory = InstalledAppsViewModel.factory(app.container))
    val state by vm.state.collectAsStateWithLifecycle()

    // Список перечитывается при каждом возвращении на экран: приложение могли удалить или обновить.
    LifecycleResumeEffect(Unit) {
        vm.refresh()
        onPauseOrDispose { }
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.installed_title)) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(painterResource(R.drawable.ic_arrow_back), contentDescription = stringResource(R.string.analysis_back))
                    }
                },
            )
        },
    ) { padding ->
        Column(Modifier.fillMaxSize().padding(padding)) {
            Column(Modifier.padding(horizontal = 16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedTextField(
                    value = state.query.text,
                    onValueChange = vm::setText,
                    placeholder = { Text(stringResource(R.string.installed_search)) },
                    leadingIcon = { Icon(painterResource(R.drawable.ic_search), contentDescription = null) },
                    shape = MaterialTheme.shapes.extraLarge,
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                )
                Row(
                    Modifier.horizontalScroll(rememberScrollState()),
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    InstalledAppsSort.entries.forEach { sort ->
                        FilterChip(
                            selected = state.query.sort == sort,
                            onClick = { vm.setSort(sort) },
                            label = { Text(sort.labelRu) },
                        )
                    }
                    FilterChip(
                        selected = state.query.includeSystem,
                        onClick = { vm.setIncludeSystem(!state.query.includeSystem) },
                        label = { Text(stringResource(R.string.installed_show_system)) },
                    )
                }
                if (!state.seesAllPackages) {
                    InfoCard(
                        title = stringResource(R.string.installed_visibility_title),
                        body = stringResource(R.string.installed_visibility_body),
                        icon = R.drawable.ic_shield,
                    )
                }
            }

            Box(Modifier.fillMaxSize()) {
                val apps = state.apps
                when {
                    state.error != null && apps == null -> Text(
                        stringResource(R.string.installed_error, state.error.orEmpty()),
                        color = MaterialTheme.colorScheme.error,
                        modifier = Modifier.align(Alignment.Center).padding(32.dp),
                    )
                    apps == null -> CircularProgressIndicator(Modifier.align(Alignment.Center))
                    apps.isEmpty() -> Text(
                        stringResource(R.string.installed_empty),
                        style = MaterialTheme.typography.bodyLarge,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.align(Alignment.Center).padding(32.dp),
                    )
                    else -> LazyColumn(
                        contentPadding = PaddingValues(16.dp),
                        verticalArrangement = Arrangement.spacedBy(8.dp),
                    ) {
                        item(key = "count") {
                            Text(
                                stringResource(R.string.installed_count, apps.size),
                                style = MaterialTheme.typography.labelMedium,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                            )
                        }
                        items(apps, key = { it.packageName }) { a ->
                            InstalledAppRow(a, app.container.installedApps, onClick = { onAnalyze(a.packageName) })
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun InstalledAppRow(app: InstalledAppSummary, repo: InstalledAppsRepository, onClick: () -> Unit) {
    val sizePx = with(LocalDensity.current) { 40.dp.roundToPx() }
    val icon by produceState<ImageBitmap?>(null, app.packageName) {
        value = repo.icon(app.packageName, sizePx)?.asImageBitmap()
    }
    val installer = app.installer
    val sourceColor = if (installer.fromStore) MaterialTheme.colorScheme.onSurfaceVariant else RiskColors.Attention
    val sourceContainer = if (installer.fromStore) MaterialTheme.colorScheme.surfaceContainerHighest else RiskColors.AttentionBackground
    Surface(
        onClick = onClick,
        shape = MaterialTheme.shapes.medium,
        color = MaterialTheme.colorScheme.surfaceContainerLow,
        modifier = Modifier.fillMaxWidth(),
    ) {
        Row(
            Modifier.padding(horizontal = 16.dp, vertical = 12.dp).semantics(mergeDescendants = true) {},
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            Box(Modifier.size(44.dp), contentAlignment = Alignment.Center) {
                icon?.let { Image(it, contentDescription = null, modifier = Modifier.size(44.dp)) }
            }
            Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(3.dp)) {
                Text(app.label, style = MaterialTheme.typography.titleMedium, maxLines = 1, overflow = TextOverflow.Ellipsis)
                Text(
                    listOfNotNull(
                        app.versionName,
                        humanSize(app.totalApkBytes),
                        stringResource(R.string.installed_splits, app.splitCount).takeIf { app.splitCount > 0 },
                    ).joinToString(" · "),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
                Tag(installer.labelRu, sourceColor, sourceContainer)
            }
            Icon(painterResource(R.drawable.ic_chevron_right), contentDescription = null, tint = MaterialTheme.colorScheme.onSurfaceVariant)
        }
    }
}

private fun humanSize(bytes: Long): String = when {
    bytes >= 1024L * 1024 -> "%.1f МБ".format(bytes / (1024.0 * 1024))
    bytes >= 1024 -> "${bytes / 1024} КБ"
    else -> "$bytes Б"
}
