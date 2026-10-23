package com.apkanalyzer.ui.analysis

import androidx.compose.animation.animateContentSize
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.stateDescription
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.apkanalyzer.R
import com.apkanalyzer.domain.model.RiskLevel
import com.apkanalyzer.report.ReportDocument
import com.apkanalyzer.report.ReportFinding
import com.apkanalyzer.ui.theme.RiskColors

fun RiskLevel.color(): Color = when (this) {
    RiskLevel.Low -> RiskColors.Low
    RiskLevel.Attention -> RiskColors.Attention
    RiskLevel.High -> RiskColors.High
    RiskLevel.Insufficient -> RiskColors.Insufficient
}

private fun RiskLevel.background(): Color = when (this) {
    RiskLevel.Low -> RiskColors.LowBackground
    RiskLevel.Attention -> RiskColors.AttentionBackground
    RiskLevel.High -> RiskColors.HighBackground
    RiskLevel.Insufficient -> RiskColors.InsufficientBackground
}

/** Главная карточка результата: категория риска, балл, причина выбора категории. */
@Composable
fun RiskCard(doc: ReportDocument) {
    val risk = doc.risk
    val accent = risk.level.color()
    Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)) {
        Column(
            Modifier
                .background(risk.level.background())
                .semantics(mergeDescendants = true) {}
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            Text(doc.title, style = MaterialTheme.typography.titleMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                Box(Modifier.size(14.dp).background(accent, CircleShape))
                Text(
                    risk.labelRu,
                    style = MaterialTheme.typography.headlineMedium,
                    color = accent,
                    fontWeight = FontWeight.Bold,
                    modifier = Modifier.semantics { heading() },
                )
            }
            if (risk.level != RiskLevel.Insufficient) {
                Text(stringResource(R.string.risk_score, risk.score), style = MaterialTheme.typography.bodyLarge)
                LinearProgressIndicator(
                    progress = { risk.score / 100f },
                    modifier = Modifier.fillMaxWidth(),
                    color = accent,
                    trackColor = MaterialTheme.colorScheme.surfaceVariant,
                )
            }
            Text(risk.reasonRu, style = MaterialTheme.typography.bodyLarge)
            Text(
                stringResource(R.string.risk_rules_version, doc.rulesVersion, (risk.coverage * 100).toInt()),
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}

@Composable
fun RecommendationsCard(items: List<String>) {
    if (items.isEmpty()) return
    Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text(stringResource(R.string.report_recommendations), style = MaterialTheme.typography.titleMedium, modifier = Modifier.semantics { heading() })
            items.forEachIndexed { i, r ->
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text("${i + 1}.", style = MaterialTheme.typography.bodyLarge, color = MaterialTheme.colorScheme.primary)
                    Text(r, style = MaterialTheme.typography.bodyLarge)
                }
            }
        }
    }
}

/** Список сработавших правил; каждое раскрывается в доказательства. */
@Composable
fun EvidenceCard(findings: List<ReportFinding>) {
    Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)) {
        Column(Modifier.padding(vertical = 12.dp)) {
            Text(
                stringResource(R.string.risk_evidence_title, findings.size),
                style = MaterialTheme.typography.titleMedium,
                modifier = Modifier
                    .padding(horizontal = 16.dp, vertical = 4.dp)
                    .semantics { heading() },
            )
            if (findings.isEmpty()) {
                Text(
                    stringResource(R.string.risk_no_findings),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.padding(horizontal = 16.dp, vertical = 8.dp),
                )
            }
            findings.forEachIndexed { i, f ->
                if (i > 0) HorizontalDivider(Modifier.padding(horizontal = 16.dp), color = MaterialTheme.colorScheme.surfaceVariant)
                FindingRow(f)
            }
        }
    }
}

@Composable
private fun FindingRow(f: ReportFinding) {
    var expanded by rememberSaveable(f.ruleId) { mutableStateOf(false) }
    val accent = when {
        f.effectiveWeight >= 25f -> RiskColors.High
        f.effectiveWeight >= 8f -> RiskColors.Attention
        else -> MaterialTheme.colorScheme.onSurfaceVariant
    }
    val stateText = stringResource(if (expanded) R.string.a11y_expanded else R.string.a11y_collapsed)
    Column(
        Modifier
            .fillMaxWidth()
            .clickable(role = Role.Button) { expanded = !expanded }
            .semantics { stateDescription = stateText }
            .animateContentSize()
            .padding(horizontal = 16.dp, vertical = 10.dp),
        verticalArrangement = Arrangement.spacedBy(4.dp),
    ) {
        Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(10.dp)) {
            Box(Modifier.size(8.dp).background(accent, CircleShape))
            Text(
                f.titleRu,
                style = MaterialTheme.typography.bodyLarge,
                fontWeight = if (f.combination) FontWeight.SemiBold else FontWeight.Normal,
                modifier = Modifier.weight(1f),
            )
            Text(
                "+${"%.0f".format(f.effectiveWeight)}",
                style = MaterialTheme.typography.labelSmall,
                color = accent,
                modifier = Modifier
                    .background(accent.copy(alpha = 0.12f), RoundedCornerShape(6.dp))
                    .padding(horizontal = 6.dp, vertical = 2.dp),
            )
        }
        Text(
            f.categoryRu + if (f.combination) " · " + stringResource(R.string.risk_combination) else "",
            style = MaterialTheme.typography.labelSmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        if (expanded) {
            Text(f.descriptionRu, style = MaterialTheme.typography.bodyMedium)
            f.mitigations.forEach {
                Text(stringResource(R.string.risk_mitigation, it), style = MaterialTheme.typography.bodyMedium, color = RiskColors.Low)
            }
            SelectionContainer {
                Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
                    f.evidence.forEach { e ->
                        Text(
                            "${e.source}: ${e.detail}",
                            style = MaterialTheme.typography.bodySmall,
                            fontFamily = FontFamily.Monospace,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                }
            }
            Text(
                stringResource(R.string.risk_rule_meta, f.ruleId, f.baseWeight) +
                    if (f.confidence < 1f) stringResource(R.string.risk_confidence, (f.confidence * 100).toInt()) else "",
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}
