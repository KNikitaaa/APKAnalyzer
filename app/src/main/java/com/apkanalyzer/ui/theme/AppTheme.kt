package com.apkanalyzer.ui.theme

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.ColorScheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Typography
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.sp

private val Navy900 = Color(0xFF0D1B2A)
private val Navy800 = Color(0xFF1B2A3B)
private val Navy700 = Color(0xFF1E3A5F)
private val CyanAccent = Color(0xFF00D4D8)
private val CyanLight = Color(0xFF4DE8EB)
private val ErrorRed = Color(0xFFCF6679)
private val WarningAmber = Color(0xFFFFB74D)
private val SuccessGreen = Color(0xFF81C784)
private val OnSurface = Color(0xFFE8EDF3)
private val SurfaceVariant = Color(0xFF253347)

object RiskColors {
    val Low = SuccessGreen
    val Attention = WarningAmber
    val High = Color(0xFFF44336)
    val Insufficient = Color(0xFF9E9E9E)

    val LowBackground = Color(0x2081C784)
    val AttentionBackground = Color(0x20FFB74D)
    val HighBackground = Color(0x20F44336)
    val InsufficientBackground = Color(0x209E9E9E)
}

private val DarkColorScheme: ColorScheme = darkColorScheme(
    primary = CyanAccent,
    onPrimary = Navy900,
    primaryContainer = Navy700,
    onPrimaryContainer = CyanLight,
    secondary = CyanLight,
    onSecondary = Navy900,
    background = Navy900,
    onBackground = OnSurface,
    surface = Navy800,
    onSurface = OnSurface,
    surfaceVariant = SurfaceVariant,
    onSurfaceVariant = Color(0xFFB0BEC5),
    error = ErrorRed,
    onError = Color(0xFF1C0007),
)

private val LightColorScheme: ColorScheme = lightColorScheme(
    primary = Color(0xFF006A6B),
    onPrimary = Color.White,
    primaryContainer = Color(0xFF9CF1F3),
    onPrimaryContainer = Color(0xFF002021),
    secondary = Color(0xFF4A6363),
    onSecondary = Color.White,
    background = Color(0xFFF4FAFB),
    onBackground = Color(0xFF161D1D),
    surface = Color(0xFFF4FAFB),
    onSurface = Color(0xFF161D1D),
    error = Color(0xFFBA1A1A),
    onError = Color.White,
)

private val AppTypography = Typography(
    headlineLarge = TextStyle(
        fontFamily = FontFamily.Default,
        fontWeight = FontWeight.Bold,
        fontSize = 32.sp,
        lineHeight = 40.sp,
    ),
    headlineMedium = TextStyle(
        fontFamily = FontFamily.Default,
        fontWeight = FontWeight.SemiBold,
        fontSize = 24.sp,
        lineHeight = 32.sp,
    ),
    titleLarge = TextStyle(
        fontFamily = FontFamily.Default,
        fontWeight = FontWeight.SemiBold,
        fontSize = 20.sp,
        lineHeight = 28.sp,
    ),
    titleMedium = TextStyle(
        fontFamily = FontFamily.Default,
        fontWeight = FontWeight.Medium,
        fontSize = 16.sp,
        lineHeight = 24.sp,
    ),
    bodyLarge = TextStyle(
        fontFamily = FontFamily.Default,
        fontWeight = FontWeight.Normal,
        fontSize = 16.sp,
        lineHeight = 24.sp,
    ),
    bodyMedium = TextStyle(
        fontFamily = FontFamily.Default,
        fontWeight = FontWeight.Normal,
        fontSize = 14.sp,
        lineHeight = 20.sp,
    ),
    labelSmall = TextStyle(
        fontFamily = FontFamily.Monospace,
        fontWeight = FontWeight.Medium,
        fontSize = 11.sp,
        lineHeight = 16.sp,
        letterSpacing = 0.5.sp,
    ),
)

@Composable
fun ApkAnalyzerTheme(
    darkTheme: Boolean = isSystemInDarkTheme(),
    content: @Composable () -> Unit,
) {
    val colorScheme = if (darkTheme) DarkColorScheme else LightColorScheme
    MaterialTheme(
        colorScheme = colorScheme,
        typography = AppTypography,
        content = content,
    )
}
