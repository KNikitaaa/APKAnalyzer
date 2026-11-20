package com.apkanalyzer.ui.components

import androidx.annotation.DrawableRes
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import com.apkanalyzer.domain.model.RiskLevel
import com.apkanalyzer.ui.theme.RiskColors

/** Карточка раздела: тональная поверхность без тени (Material 3), скругление 16dp. */
@Composable
fun AppCard(
    modifier: Modifier = Modifier,
    container: Color = MaterialTheme.colorScheme.surfaceContainerLow,
    content: @Composable ColumnScope.() -> Unit,
) {
    Card(
        modifier = modifier.fillMaxWidth(),
        shape = MaterialTheme.shapes.medium,
        colors = CardDefaults.cardColors(containerColor = container, contentColor = MaterialTheme.colorScheme.onSurface),
        content = content,
    )
}

/** Заголовок раздела отчёта — с семантикой заголовка для TalkBack. */
@Composable
fun SectionTitle(text: String, modifier: Modifier = Modifier) {
    Text(
        text,
        style = MaterialTheme.typography.titleMedium,
        color = MaterialTheme.colorScheme.onSurface,
        modifier = modifier.semantics { heading() },
    )
}

/** Небольшая цветная метка (источник установки, «связка признаков», «AI»). */
@Composable
fun Tag(text: String, color: Color, container: Color, modifier: Modifier = Modifier) {
    Text(
        text,
        style = MaterialTheme.typography.labelMedium,
        color = color,
        maxLines = 1,
        modifier = modifier
            .background(container, MaterialTheme.shapes.extraSmall)
            .padding(horizontal = 8.dp, vertical = 3.dp),
    )
}

/** Иконка в круглой тональной подложке. */
@Composable
fun IconBubble(@DrawableRes icon: Int, tint: Color, container: Color, size: Dp = 40.dp) {
    Box(Modifier.size(size).background(container, CircleShape), contentAlignment = Alignment.Center) {
        Icon(painterResource(icon), contentDescription = null, tint = tint, modifier = Modifier.size(size * 0.55f))
    }
}

@Composable
fun RiskLevel.tint(): Color = when (this) {
    RiskLevel.Low -> RiskColors.Low
    RiskLevel.Attention -> RiskColors.Attention
    RiskLevel.High -> RiskColors.High
    RiskLevel.Insufficient -> RiskColors.Insufficient
}

@Composable
fun RiskLevel.container(): Color = when (this) {
    RiskLevel.Low -> RiskColors.LowBackground
    RiskLevel.Attention -> RiskColors.AttentionBackground
    RiskLevel.High -> RiskColors.HighBackground
    RiskLevel.Insufficient -> RiskColors.InsufficientBackground
}

/**
 * Круглый значок балла для списков: цвет уровня и число. Для «Недостаточно данных» — «?».
 */
@Composable
fun ScoreBadge(level: RiskLevel, score: Int, size: Dp = 44.dp) {
    Box(Modifier.size(size).background(level.container(), CircleShape), contentAlignment = Alignment.Center) {
        Text(
            if (level == RiskLevel.Insufficient) "?" else score.toString(),
            style = MaterialTheme.typography.labelLarge,
            color = level.tint(),
            textAlign = TextAlign.Center,
        )
    }
}

/**
 * Шкала-дуга балла (270°): дорожка, заполненная часть цвета уровня и отметки порогов 30 и 60.
 * Главный визуальный элемент отчёта.
 */
@Composable
fun ScoreDial(score: Int, color: Color, modifier: Modifier = Modifier, stroke: Dp = 12.dp, showValue: Boolean = true, center: @Composable () -> Unit = {}) {
    val track = MaterialTheme.colorScheme.surfaceContainerHighest
    val tick = MaterialTheme.colorScheme.outline
    Box(modifier, contentAlignment = Alignment.Center) {
        Canvas(Modifier.fillMaxSize()) {
            val w = stroke.toPx()
            val d = size.minDimension - w
            val topLeft = Offset((size.width - d) / 2, (size.height - d) / 2)
            val arc = Size(d, d)
            drawArc(track, startAngle = 135f, sweepAngle = 270f, useCenter = false, topLeft = topLeft, size = arc, style = Stroke(w, cap = StrokeCap.Round))
            if (showValue && score > 0) {
                drawArc(color, startAngle = 135f, sweepAngle = 270f * score.coerceIn(0, 100) / 100f, useCenter = false, topLeft = topLeft, size = arc, style = Stroke(w, cap = StrokeCap.Round))
            }
            // Отметки порогов «Нужно внимание» (30) и «Высокий риск» (60) — снаружи дуги.
            val r = d / 2
            val c = Offset(size.width / 2, size.height / 2)
            for (t in listOf(30, 60)) {
                val a = Math.toRadians((135.0 + 270.0 * t / 100))
                val inner = r + w * 0.7f
                val outer = r + w * 1.1f
                drawLine(
                    tick,
                    Offset(c.x + (inner * kotlin.math.cos(a)).toFloat(), c.y + (inner * kotlin.math.sin(a)).toFloat()),
                    Offset(c.x + (outer * kotlin.math.cos(a)).toFloat(), c.y + (outer * kotlin.math.sin(a)).toFloat()),
                    strokeWidth = 2.dp.toPx(),
                    cap = StrokeCap.Round,
                )
            }
        }
        center()
    }
}

/** Строка «иконка — текст» для пояснений. */
@Composable
fun IconLine(@DrawableRes icon: Int, text: String, tint: Color = MaterialTheme.colorScheme.onSurfaceVariant) {
    Row(horizontalArrangement = Arrangement.spacedBy(10.dp), verticalAlignment = Alignment.Top) {
        Icon(painterResource(icon), contentDescription = null, tint = tint, modifier = Modifier.padding(top = 2.dp).size(18.dp))
        Text(text, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
    }
}
