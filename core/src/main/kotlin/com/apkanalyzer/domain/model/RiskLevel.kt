package com.apkanalyzer.domain.model

sealed class RiskLevel(
    val ordinal: Int,
    val labelRu: String,
    val labelEn: String,
) {
    object Low : RiskLevel(0, "Низкий риск", "Low Risk")
    object Attention : RiskLevel(1, "Нужно внимание", "Needs Attention")
    object High : RiskLevel(2, "Высокий риск", "High Risk")
    object Insufficient : RiskLevel(3, "Недостаточно данных", "Insufficient Data")

    companion object {
        fun fromOrdinal(ordinal: Int): RiskLevel = when (ordinal) {
            0 -> Low
            1 -> Attention
            2 -> High
            3 -> Insufficient
            else -> Insufficient
        }

        fun all(): List<RiskLevel> = listOf(Low, Attention, High, Insufficient)
    }
}

fun RiskLevel.isActionRequired(): Boolean =
    this is RiskLevel.High || this is RiskLevel.Attention

fun RiskLevel.sortWeight(): Int = when (this) {
    is RiskLevel.High -> 3
    is RiskLevel.Attention -> 2
    is RiskLevel.Insufficient -> 1
    is RiskLevel.Low -> 0
}
