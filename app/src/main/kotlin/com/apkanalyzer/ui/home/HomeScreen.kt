package com.apkanalyzer.ui.home

import android.net.Uri
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.annotation.DrawableRes
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
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
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewModelScope
import androidx.lifecycle.viewmodel.compose.viewModel
import androidx.lifecycle.viewmodel.initializer
import androidx.lifecycle.viewmodel.viewModelFactory
import com.apkanalyzer.ApkAnalyzerApp
import com.apkanalyzer.R
import com.apkanalyzer.data.local.database.entity.AnalysisEntity
import com.apkanalyzer.di.AppContainer
import com.apkanalyzer.domain.model.RiskLevel
import com.apkanalyzer.ui.components.AppCard
import com.apkanalyzer.ui.components.IconBubble
import com.apkanalyzer.ui.components.IconLine
import com.apkanalyzer.ui.components.ScoreBadge
import com.apkanalyzer.ui.components.SectionTitle
import com.apkanalyzer.ui.theme.ApkAnalyzerTheme
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.stateIn
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/** MIME-типы, под которыми файловые менеджеры отдают APK и контейнеры. Содержимое всё равно проверяется после выбора. */
private val APK_MIME_TYPES = arrayOf(
    "application/vnd.android.package-archive",
    "application/octet-stream",
    "application/zip",
)

/** Последние проверки для главного экрана. */
class HomeViewModel(c: AppContainer) : ViewModel() {
    val recent: StateFlow<List<AnalysisEntity>> = c.history.observe()
        .map { it.take(RECENT_COUNT) }
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), emptyList())

    companion object {
        const val RECENT_COUNT = 3
        fun factory(c: AppContainer): ViewModelProvider.Factory = viewModelFactory { initializer { HomeViewModel(c) } }
    }
}

@Composable
fun HomeScreen(
    onApkPicked: (Uri) -> Unit,
    onOpenInstalled: () -> Unit,
    onOpenHistory: () -> Unit,
    onOpenSettings: () -> Unit,
    onOpenReport: (Long) -> Unit,
) {
    val app = LocalContext.current.applicationContext as ApkAnalyzerApp
    val vm: HomeViewModel = viewModel(factory = HomeViewModel.factory(app.container))
    val recent by vm.recent.collectAsStateWithLifecycle()
    val picker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri != null) onApkPicked(uri)
    }
    HomeContent(
        recent = recent,
        onPickClick = { picker.launch(APK_MIME_TYPES) },
        onInstalledClick = onOpenInstalled,
        onHistoryClick = onOpenHistory,
        onSettingsClick = onOpenSettings,
        onRecentClick = onOpenReport,
    )
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun HomeContent(
    recent: List<AnalysisEntity>,
    onPickClick: () -> Unit,
    onInstalledClick: () -> Unit,
    onHistoryClick: () -> Unit,
    onSettingsClick: () -> Unit,
    onRecentClick: (Long) -> Unit,
) {
    Scaffold(
        containerColor = MaterialTheme.colorScheme.surface,
        topBar = {
            TopAppBar(
                title = {
                    Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                        Icon(painterResource(R.drawable.ic_shield), contentDescription = null, tint = MaterialTheme.colorScheme.primary, modifier = Modifier.size(22.dp))
                        Text(stringResource(R.string.app_name), style = MaterialTheme.typography.titleMedium)
                    }
                },
                actions = {
                    IconButton(onClick = onSettingsClick) {
                        Icon(painterResource(R.drawable.ic_settings), contentDescription = stringResource(R.string.home_settings))
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(containerColor = MaterialTheme.colorScheme.surface),
            )
        },
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 16.dp)
                .padding(bottom = 24.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Spacer(Modifier.height(4.dp))
            Text(stringResource(R.string.home_title), style = MaterialTheme.typography.headlineLarge, modifier = Modifier.semantics { heading() })
            Text(
                stringResource(R.string.home_subtitle),
                style = MaterialTheme.typography.bodyLarge,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Spacer(Modifier.height(4.dp))

            ActionCard(
                icon = R.drawable.ic_file,
                title = stringResource(R.string.home_pick_apk),
                body = stringResource(R.string.home_pick_body),
                container = MaterialTheme.colorScheme.primary,
                content = MaterialTheme.colorScheme.onPrimary,
                bubble = MaterialTheme.colorScheme.onPrimary.copy(alpha = 0.16f),
                onClick = onPickClick,
            )
            ActionCard(
                icon = R.drawable.ic_apps,
                title = stringResource(R.string.home_installed),
                body = stringResource(R.string.home_installed_body),
                container = MaterialTheme.colorScheme.secondaryContainer,
                content = MaterialTheme.colorScheme.onSecondaryContainer,
                bubble = MaterialTheme.colorScheme.onSecondaryContainer.copy(alpha = 0.10f),
                onClick = onInstalledClick,
            )

            Spacer(Modifier.height(8.dp))
            Row(verticalAlignment = Alignment.CenterVertically) {
                SectionTitle(stringResource(if (recent.isEmpty()) R.string.home_how_title else R.string.home_recent), Modifier.weight(1f))
                if (recent.isNotEmpty()) TextButton(onClick = onHistoryClick) { Text(stringResource(R.string.home_all_history)) }
            }
            if (recent.isEmpty()) {
                HowItWorks()
            } else {
                AppCard {
                    recent.forEachIndexed { i, e ->
                        if (i > 0) HorizontalDivider(Modifier.padding(start = 72.dp), color = MaterialTheme.colorScheme.outlineVariant)
                        RecentRow(e, onClick = { onRecentClick(e.id) })
                    }
                }
            }

            Spacer(Modifier.height(4.dp))
            IconLine(R.drawable.ic_lock, stringResource(R.string.home_privacy))
        }
    }
}

@Composable
private fun ActionCard(
    @DrawableRes icon: Int,
    title: String,
    body: String,
    container: Color,
    content: Color,
    bubble: Color,
    onClick: () -> Unit,
) {
    Surface(
        onClick = onClick,
        shape = MaterialTheme.shapes.large,
        color = container,
        contentColor = content,
        modifier = Modifier.fillMaxWidth(),
    ) {
        Row(
            Modifier.padding(horizontal = 16.dp, vertical = 18.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            IconBubble(icon, tint = content, container = bubble, size = 48.dp)
            Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(2.dp)) {
                Text(title, style = MaterialTheme.typography.titleLarge, color = content)
                Text(body, style = MaterialTheme.typography.bodyMedium, color = content.copy(alpha = 0.82f))
            }
            Icon(painterResource(R.drawable.ic_chevron_right), contentDescription = null, tint = content.copy(alpha = 0.7f))
        }
    }
}

@Composable
private fun RecentRow(e: AnalysisEntity, onClick: () -> Unit) {
    val level = RiskLevel.fromOrdinal(e.riskLevelOrdinal)
    val date = remember(e.analyzedAtMs) { SimpleDateFormat("d MMM, HH:mm", Locale.forLanguageTag("ru")).format(Date(e.analyzedAtMs)) }
    Row(
        Modifier
            .fillMaxWidth()
            .clickable(role = Role.Button, onClick = onClick)
            .padding(horizontal = 16.dp, vertical = 12.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        ScoreBadge(level, e.riskScore, size = 40.dp)
        Column(Modifier.weight(1f)) {
            Text(e.appLabel ?: e.packageName.ifBlank { e.fileName }, style = MaterialTheme.typography.titleSmall, maxLines = 1, overflow = TextOverflow.Ellipsis)
            Text("${level.labelRu} · $date", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant, maxLines = 1)
        }
        Icon(painterResource(R.drawable.ic_chevron_right), contentDescription = null, tint = MaterialTheme.colorScheme.onSurfaceVariant)
    }
}

/** Три шага — это действительно последовательность, поэтому с номерами. */
@Composable
private fun HowItWorks() {
    AppCard {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(14.dp)) {
            listOf(R.string.home_step1, R.string.home_step2, R.string.home_step3).forEachIndexed { i, res ->
                Row(horizontalArrangement = Arrangement.spacedBy(14.dp), verticalAlignment = Alignment.Top) {
                    Box(
                        Modifier.size(28.dp).background(MaterialTheme.colorScheme.primaryContainer, CircleShape),
                        contentAlignment = Alignment.Center,
                    ) {
                        Text("${i + 1}", style = MaterialTheme.typography.labelLarge, color = MaterialTheme.colorScheme.onPrimaryContainer)
                    }
                    Text(stringResource(res), style = MaterialTheme.typography.bodyMedium, modifier = Modifier.padding(top = 4.dp))
                }
            }
        }
    }
}

@Preview(showBackground = true)
@Composable
private fun HomePreview() {
    ApkAnalyzerTheme(darkTheme = false) {
        HomeContent(recent = emptyList(), onPickClick = {}, onInstalledClick = {}, onHistoryClick = {}, onSettingsClick = {}, onRecentClick = {})
    }
}
