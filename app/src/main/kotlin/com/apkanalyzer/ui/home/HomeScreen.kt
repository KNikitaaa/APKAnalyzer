package com.apkanalyzer.ui.home

import android.net.Uri
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import com.apkanalyzer.R
import com.apkanalyzer.ui.components.InfoCard
import com.apkanalyzer.ui.theme.ApkAnalyzerTheme

/** MIME-типы, под которыми файловые менеджеры отдают APK. Содержимое всё равно проверяется после выбора. */
private val APK_MIME_TYPES = arrayOf(
    "application/vnd.android.package-archive",
    "application/octet-stream",
    "application/zip",
)

@Composable
fun HomeScreen(onApkPicked: (Uri) -> Unit, onOpenHistory: () -> Unit, onOpenSettings: () -> Unit) {
    val picker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri != null) onApkPicked(uri)
    }
    HomeContent(onPickClick = { picker.launch(APK_MIME_TYPES) }, onHistoryClick = onOpenHistory, onSettingsClick = onOpenSettings)
}

@Composable
private fun HomeContent(onPickClick: () -> Unit, onHistoryClick: () -> Unit, onSettingsClick: () -> Unit) {
    Scaffold { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 20.dp, vertical = 24.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            Icon(
                painterResource(R.drawable.ic_shield),
                contentDescription = null,
                tint = MaterialTheme.colorScheme.primary,
                modifier = Modifier.size(48.dp),
            )
            Text(stringResource(R.string.home_title), style = MaterialTheme.typography.headlineLarge)
            Text(
                stringResource(R.string.home_subtitle),
                style = MaterialTheme.typography.bodyLarge,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Spacer(Modifier.height(8.dp))
            Button(
                onClick = onPickClick,
                modifier = Modifier
                    .fillMaxWidth()
                    .height(56.dp),
            ) {
                Icon(painterResource(R.drawable.ic_file), contentDescription = null)
                Spacer(Modifier.size(8.dp))
                Text(stringResource(R.string.home_pick_apk), style = MaterialTheme.typography.titleMedium)
            }
            OutlinedButton(
                onClick = onHistoryClick,
                modifier = Modifier
                    .fillMaxWidth()
                    .height(52.dp),
            ) {
                Icon(painterResource(R.drawable.ic_history), contentDescription = null)
                Spacer(Modifier.size(8.dp))
                Text(stringResource(R.string.home_history))
            }
            OutlinedButton(
                onClick = onSettingsClick,
                modifier = Modifier
                    .fillMaxWidth()
                    .height(52.dp),
            ) {
                Icon(painterResource(R.drawable.ic_settings), contentDescription = null)
                Spacer(Modifier.size(8.dp))
                Text(stringResource(R.string.home_settings))
            }
            Spacer(Modifier.height(8.dp))
            InfoCard(
                title = stringResource(R.string.home_safety_title),
                body = stringResource(R.string.home_safety_body),
                icon = R.drawable.ic_shield,
            )
            InfoCard(
                title = stringResource(R.string.home_limits_title),
                body = stringResource(R.string.home_limits_body),
                icon = R.drawable.ic_file,
            )
            Text(
                stringResource(R.string.home_stage_note),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}

@Preview(showBackground = true)
@Composable
private fun HomePreview() {
    ApkAnalyzerTheme(darkTheme = true) { HomeContent(onPickClick = {}, onHistoryClick = {}, onSettingsClick = {}) }
}
