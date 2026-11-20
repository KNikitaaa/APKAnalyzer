package com.apkanalyzer.ui.theme

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.ColorScheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Shapes
import androidx.compose.material3.Typography
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.Immutable
import androidx.compose.runtime.ReadOnlyComposable
import androidx.compose.runtime.staticCompositionLocalOf
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

/*
 * Дизайн-система APK AI Analyzer.
 *
 * Фирменный цвет — «чернильный индиго»: он не спорит с семантическими цветами риска (зелёный / янтарный /
 * красный / серый), которые несут главный смысл приложения. Третичный (сливовый) цвет закреплён за текстом,
 * сгенерированным AI, — чтобы объяснение модели никогда не выглядело как вывод самого приложения.
 * Глубина передаётся тоном поверхностей (surfaceContainer*), а не тенями.
 */

private val LightColors: ColorScheme = lightColorScheme(
    primary = Color(0xFF3F4FB0),
    onPrimary = Color(0xFFFFFFFF),
    primaryContainer = Color(0xFFDFE1FF),
    onPrimaryContainer = Color(0xFF0E1A66),
    secondary = Color(0xFF5A5D72),
    onSecondary = Color(0xFFFFFFFF),
    secondaryContainer = Color(0xFFDFE1F9),
    onSecondaryContainer = Color(0xFF171B2C),
    tertiary = Color(0xFF7A4E92),
    onTertiary = Color(0xFFFFFFFF),
    tertiaryContainer = Color(0xFFF4DAFF),
    onTertiaryContainer = Color(0xFF30084A),
    error = Color(0xFFBA1A1A),
    onError = Color(0xFFFFFFFF),
    errorContainer = Color(0xFFFFDAD6),
    onErrorContainer = Color(0xFF410002),
    background = Color(0xFFF7F8FC),
    onBackground = Color(0xFF1A1B21),
    surface = Color(0xFFF7F8FC),
    onSurface = Color(0xFF1A1B21),
    surfaceVariant = Color(0xFFE2E3EE),
    onSurfaceVariant = Color(0xFF454652),
    surfaceContainerLowest = Color(0xFFFFFFFF),
    surfaceContainerLow = Color(0xFFF1F2F8),
    surfaceContainer = Color(0xFFEBEDF4),
    surfaceContainerHigh = Color(0xFFE5E7EF),
    surfaceContainerHighest = Color(0xFFDFE1EA),
    outline = Color(0xFF767684),
    outlineVariant = Color(0xFFC6C6D4),
    inverseSurface = Color(0xFF2F3036),
    inverseOnSurface = Color(0xFFF1F0F7),
    inversePrimary = Color(0xFFBAC3FF),
)

private val DarkColors: ColorScheme = darkColorScheme(
    primary = Color(0xFFBAC3FF),
    onPrimary = Color(0xFF1F2C7F),
    primaryContainer = Color(0xFF364597),
    onPrimaryContainer = Color(0xFFDFE1FF),
    secondary = Color(0xFFC3C5DD),
    onSecondary = Color(0xFF2C2F42),
    secondaryContainer = Color(0xFF424659),
    onSecondaryContainer = Color(0xFFDFE1F9),
    tertiary = Color(0xFFE6B5FF),
    onTertiary = Color(0xFF472060),
    tertiaryContainer = Color(0xFF603678),
    onTertiaryContainer = Color(0xFFF4DAFF),
    error = Color(0xFFFFB4AB),
    onError = Color(0xFF690005),
    errorContainer = Color(0xFF93000A),
    onErrorContainer = Color(0xFFFFDAD6),
    background = Color(0xFF111318),
    onBackground = Color(0xFFE3E2E9),
    surface = Color(0xFF111318),
    onSurface = Color(0xFFE3E2E9),
    surfaceVariant = Color(0xFF454652),
    onSurfaceVariant = Color(0xFFC6C6D4),
    surfaceContainerLowest = Color(0xFF0C0E13),
    surfaceContainerLow = Color(0xFF191B21),
    surfaceContainer = Color(0xFF1D1F25),
    surfaceContainerHigh = Color(0xFF282A30),
    surfaceContainerHighest = Color(0xFF33353B),
    outline = Color(0xFF90909E),
    outlineVariant = Color(0xFF454652),
    inverseSurface = Color(0xFFE3E2E9),
    inverseOnSurface = Color(0xFF2F3036),
    inversePrimary = Color(0xFF3F4FB0),
)

/** Цвета уровней риска: текстовый (контраст ≥ 4.5:1 на поверхностях) и фон-подложка. */
@Immutable
data class RiskPalette(
    val low: Color,
    val attention: Color,
    val high: Color,
    val insufficient: Color,
    val lowContainer: Color,
    val attentionContainer: Color,
    val highContainer: Color,
    val insufficientContainer: Color,
)

private val LightRisk = RiskPalette(
    low = Color(0xFF1B7A4B),
    attention = Color(0xFF9A5600),
    high = Color(0xFFC0262D),
    insufficient = Color(0xFF5B616E),
    lowContainer = Color(0xFFDDF4E6),
    attentionContainer = Color(0xFFFFEBD3),
    highContainer = Color(0xFFFFE1DE),
    insufficientContainer = Color(0xFFE6E8EE),
)

private val DarkRisk = RiskPalette(
    low = Color(0xFF6FD6A0),
    attention = Color(0xFFFFB866),
    high = Color(0xFFFF8E86),
    insufficient = Color(0xFFB2B8C4),
    lowContainer = Color(0xFF16352A),
    attentionContainer = Color(0xFF3D2A12),
    highContainer = Color(0xFF451E1E),
    insufficientContainer = Color(0xFF2A2D35),
)

private val LocalRiskPalette = staticCompositionLocalOf { LightRisk }

/** Семантические цвета риска для текущей темы. */
object RiskColors {
    val Low: Color @Composable @ReadOnlyComposable get() = LocalRiskPalette.current.low
    val Attention: Color @Composable @ReadOnlyComposable get() = LocalRiskPalette.current.attention
    val High: Color @Composable @ReadOnlyComposable get() = LocalRiskPalette.current.high
    val Insufficient: Color @Composable @ReadOnlyComposable get() = LocalRiskPalette.current.insufficient

    val LowBackground: Color @Composable @ReadOnlyComposable get() = LocalRiskPalette.current.lowContainer
    val AttentionBackground: Color @Composable @ReadOnlyComposable get() = LocalRiskPalette.current.attentionContainer
    val HighBackground: Color @Composable @ReadOnlyComposable get() = LocalRiskPalette.current.highContainer
    val InsufficientBackground: Color @Composable @ReadOnlyComposable get() = LocalRiskPalette.current.insufficientContainer
}

/** Шкала Material 3 (Roboto); крупные цифры балла — с моноширинными цифрами, чтобы не «прыгали». */
private val AppTypography = Typography(
    displayMedium = TextStyle(fontFamily = FontFamily.Default, fontWeight = FontWeight.SemiBold, fontSize = 44.sp, lineHeight = 52.sp, fontFeatureSettings = "tnum"),
    headlineLarge = TextStyle(fontFamily = FontFamily.Default, fontWeight = FontWeight.SemiBold, fontSize = 30.sp, lineHeight = 38.sp, letterSpacing = (-0.2).sp),
    headlineMedium = TextStyle(fontFamily = FontFamily.Default, fontWeight = FontWeight.SemiBold, fontSize = 26.sp, lineHeight = 34.sp),
    headlineSmall = TextStyle(fontFamily = FontFamily.Default, fontWeight = FontWeight.SemiBold, fontSize = 22.sp, lineHeight = 28.sp),
    titleLarge = TextStyle(fontFamily = FontFamily.Default, fontWeight = FontWeight.Medium, fontSize = 20.sp, lineHeight = 28.sp),
    titleMedium = TextStyle(fontFamily = FontFamily.Default, fontWeight = FontWeight.Medium, fontSize = 16.sp, lineHeight = 24.sp, letterSpacing = 0.1.sp),
    titleSmall = TextStyle(fontFamily = FontFamily.Default, fontWeight = FontWeight.Medium, fontSize = 14.sp, lineHeight = 20.sp, letterSpacing = 0.1.sp),
    bodyLarge = TextStyle(fontFamily = FontFamily.Default, fontWeight = FontWeight.Normal, fontSize = 16.sp, lineHeight = 24.sp, letterSpacing = 0.2.sp),
    bodyMedium = TextStyle(fontFamily = FontFamily.Default, fontWeight = FontWeight.Normal, fontSize = 14.sp, lineHeight = 20.sp, letterSpacing = 0.2.sp),
    bodySmall = TextStyle(fontFamily = FontFamily.Default, fontWeight = FontWeight.Normal, fontSize = 12.sp, lineHeight = 16.sp, letterSpacing = 0.3.sp),
    labelLarge = TextStyle(fontFamily = FontFamily.Default, fontWeight = FontWeight.Medium, fontSize = 14.sp, lineHeight = 20.sp, letterSpacing = 0.1.sp),
    labelMedium = TextStyle(fontFamily = FontFamily.Default, fontWeight = FontWeight.Medium, fontSize = 12.sp, lineHeight = 16.sp, letterSpacing = 0.4.sp, fontFeatureSettings = "tnum"),
    labelSmall = TextStyle(fontFamily = FontFamily.Default, fontWeight = FontWeight.Medium, fontSize = 11.sp, lineHeight = 16.sp, letterSpacing = 0.4.sp),
)

/** Иерархия формы: карточки 16dp, главный блок вердикта 28dp, диалоги 28dp. */
private val AppShapes = Shapes(
    extraSmall = RoundedCornerShape(6.dp),
    small = RoundedCornerShape(10.dp),
    medium = RoundedCornerShape(16.dp),
    large = RoundedCornerShape(20.dp),
    extraLarge = RoundedCornerShape(28.dp),
)

/** Шрифт для хешей и путей внутри APK — там, где важно различать символы. */
val CodeFont: FontFamily = FontFamily.Monospace

@Composable
fun ApkAnalyzerTheme(
    darkTheme: Boolean = isSystemInDarkTheme(),
    content: @Composable () -> Unit,
) {
    CompositionLocalProvider(LocalRiskPalette provides if (darkTheme) DarkRisk else LightRisk) {
        MaterialTheme(
            colorScheme = if (darkTheme) DarkColors else LightColors,
            typography = AppTypography,
            shapes = AppShapes,
            content = content,
        )
    }
}
