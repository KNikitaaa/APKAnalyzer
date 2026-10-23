package com.apkanalyzer.ui.report

import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.aspectRatio
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.Button
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Surface
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableFloatStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.produceState
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import com.apkanalyzer.ApkAnalyzerApp
import com.apkanalyzer.R
import com.apkanalyzer.data.export.PdfPages
import com.apkanalyzer.report.ReportDocument

/**
 * Полноэкранный просмотр PDF-отчёта внутри приложения — без сторонних программ просмотра.
 * Масштаб — кнопками «−/+» (100–250%), при увеличении страницу можно прокручивать по горизонтали.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun PdfPreviewDialog(
    doc: ReportDocument,
    onDismiss: () -> Unit,
    onSave: () -> Unit,
    onShare: () -> Unit,
) {
    val context = LocalContext.current
    val container = (context.applicationContext as ApkAnalyzerApp).container
    var pages by remember { mutableStateOf<PdfPages?>(null) }
    var error by remember { mutableStateOf<String?>(null) }
    var zoom by remember { mutableFloatStateOf(1f) }

    LaunchedEffect(doc) {
        runCatching { PdfPages(container.exporter.renderPreview(doc)) }
            .onSuccess { pages = it }
            .onFailure { error = it.message ?: it.javaClass.simpleName }
    }
    DisposableEffect(Unit) {
        onDispose { pages?.close() }
    }

    Dialog(
        onDismissRequest = onDismiss,
        properties = DialogProperties(usePlatformDefaultWidth = false, decorFitsSystemWindows = false),
    ) {
        Scaffold(
            topBar = {
                TopAppBar(
                    title = {
                        Text(
                            stringResource(R.string.pdf_preview_title),
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis,
                        )
                    },
                    navigationIcon = {
                        IconButton(onClick = onDismiss) {
                            Icon(painterResource(R.drawable.ic_arrow_back), contentDescription = stringResource(R.string.pdf_preview_close))
                        }
                    },
                    actions = {
                        IconButton(
                            onClick = { zoom = (zoom - 0.5f).coerceAtLeast(1f) },
                            enabled = zoom > 1f,
                        ) { Text("−", style = MaterialTheme.typography.titleLarge) }
                        Text(
                            "${(zoom * 100).toInt()}%",
                            style = MaterialTheme.typography.labelMedium,
                            maxLines = 1,
                            modifier = Modifier.semantics { contentDescription = "Масштаб ${(zoom * 100).toInt()} процентов" },
                        )
                        IconButton(
                            onClick = { zoom = (zoom + 0.5f).coerceAtMost(2.5f) },
                            enabled = zoom < 2.5f,
                        ) { Text("+", style = MaterialTheme.typography.titleLarge) }
                    },
                )
            },
            bottomBar = {
                Surface(tonalElevation = 3.dp) {
                    Row(
                        Modifier
                            .fillMaxWidth()
                            .navigationBarsPadding()
                            .padding(horizontal = 16.dp, vertical = 10.dp),
                        horizontalArrangement = Arrangement.spacedBy(12.dp),
                    ) {
                        OutlinedButton(onClick = onSave, modifier = Modifier.weight(1f)) {
                            Text(stringResource(R.string.pdf_preview_save), maxLines = 1)
                        }
                        Button(onClick = onShare, modifier = Modifier.weight(1f)) {
                            Text(stringResource(R.string.pdf_preview_share), maxLines = 1)
                        }
                    }
                }
            },
        ) { padding ->
            Box(
                Modifier
                    .fillMaxSize()
                    .padding(padding)
                    .background(Color(0xFF525659)),
            ) {
                val p = pages
                when {
                    error != null -> Text(
                        stringResource(R.string.pdf_preview_error, error ?: ""),
                        color = Color.White,
                        modifier = Modifier.align(Alignment.Center).padding(24.dp),
                    )
                    p == null -> CircularProgressIndicator(Modifier.align(Alignment.Center))
                    else -> PdfPagesList(p, zoom)
                }
            }
        }
    }
}

@Composable
private fun PdfPagesList(pages: PdfPages, zoom: Float) {
    val screenWidth = LocalConfiguration.current.screenWidthDp.dp
    val pageWidth = (screenWidth - 16.dp) * zoom
    val widthPx = with(LocalDensity.current) { pageWidth.roundToPx() }
    val hScroll = rememberScrollState()
    Box(
        Modifier
            .fillMaxSize()
            .horizontalScroll(hScroll, enabled = zoom > 1f),
    ) {
        LazyColumn(
            modifier = Modifier.width(pageWidth + 16.dp),
            contentPadding = PaddingValues(8.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            items(pages.pageCount) { index -> PdfPageImage(pages, index, widthPx) }
        }
    }
}

@Composable
private fun PdfPageImage(pages: PdfPages, index: Int, widthPx: Int) {
    val aspect by produceState(initialValue = 842f / 595f, pages, index) { value = pages.aspect(index) }
    val bitmap by produceState<android.graphics.Bitmap?>(initialValue = null, pages, index, widthPx) {
        value = pages.render(index, widthPx)
    }
    val description = stringResource(R.string.pdf_preview_page, index + 1, pages.pageCount)
    Box(
        Modifier
            .fillMaxWidth()
            .aspectRatio(1f / aspect)
            .background(Color.White),
    ) {
        val bmp = bitmap
        if (bmp != null) {
            Image(
                bitmap = bmp.asImageBitmap(),
                contentDescription = description,
                contentScale = ContentScale.FillWidth,
                modifier = Modifier.fillMaxSize(),
            )
        } else {
            CircularProgressIndicator(Modifier.align(Alignment.Center))
        }
    }
}
