package com.apkanalyzer.ui.analysis

import androidx.compose.animation.animateContentSize
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.IntrinsicSize
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.rotate
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.stateDescription
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.apkanalyzer.R
import com.apkanalyzer.domain.model.RiskLevel
import com.apkanalyzer.report.ReportDocument
import com.apkanalyzer.report.ReportFinding
import com.apkanalyzer.rules.SignerVerdict
import com.apkanalyzer.ui.components.AppCard
import com.apkanalyzer.ui.components.ScoreDial
import com.apkanalyzer.ui.components.SectionTitle
import com.apkanalyzer.ui.components.Tag
import com.apkanalyzer.ui.components.container
import com.apkanalyzer.ui.components.tint
import com.apkanalyzer.ui.theme.CodeFont
import com.apkanalyzer.ui.theme.RiskColors

@Composable
fun RiskLevel.color(): Color = tint()

/**
 * Вердикт — главный элемент отчёта: шкала балла с отметками порогов, уровень риска цветом и словами,
 * причина выбора уровня, версия правил и полнота анализа.
 */
@Composable
fun RiskCard(doc: ReportDocument) {
    val risk = doc.risk
    val accent = risk.level.tint()
    val insufficient = risk.level == RiskLevel.Insufficient
    val a11y = stringResource(R.string.risk_a11y, risk.labelRu, risk.score)
    Surface(
        shape = MaterialTheme.shapes.extraLarge,
        color = risk.level.container(),
        modifier = Modifier.fillMaxWidth(),
    ) {
        Column(Modifier.padding(20.dp), verticalArrangement = Arrangement.spacedBy(16.dp)) {
            Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
                Text(doc.title, style = MaterialTheme.typography.titleLarge, maxLines = 2, overflow = TextOverflow.Ellipsis)
                doc.app?.packageName?.takeIf { it.isNotBlank() && it != doc.title }?.let {
                    Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant, maxLines = 1, overflow = TextOverflow.Ellipsis)
                }
            }
            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(20.dp),
                modifier = Modifier.semantics(mergeDescendants = true) { contentDescription = a11y },
            ) {
                ScoreDial(
                    score = if (insufficient) 0 else risk.score,
                    color = accent,
                    showValue = !insufficient,
                    modifier = Modifier.size(128.dp),
                ) {
                    Column(horizontalAlignment = Alignment.CenterHorizontally) {
                        Text(if (insufficient) "?" else risk.score.toString(), style = MaterialTheme.typography.displayMedium, color = accent)
                        Text(stringResource(R.string.risk_of_100), style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    }
                }
                Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                    Text(
                        risk.labelRu,
                        style = MaterialTheme.typography.headlineSmall,
                        color = accent,
                        modifier = Modifier.semantics { heading() },
                    )
                    Text(risk.reasonRu, style = MaterialTheme.typography.bodyMedium)
                }
            }
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                val chip = MaterialTheme.colorScheme.surface.copy(alpha = 0.7f)
                Tag(stringResource(R.string.risk_rules_tag, doc.rulesVersion), MaterialTheme.colorScheme.onSurfaceVariant, chip)
                Tag(stringResource(R.string.risk_coverage_tag, (risk.coverage * 100).toInt()), MaterialTheme.colorScheme.onSurfaceVariant, chip)
            }
            doc.localRisk?.takeIf { it != risk }?.let { local ->
                Text("Локальная оценка: ${local.labelRu}, ${local.score}/100. Итог уточнён выбранными источниками.",
                    style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
            if (doc.signerVerdict == SignerVerdict.OFFICIAL) {
                Text("Подпись APK проверена и совпадает с сертификатом разработчика из каталога.",
                    style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
        }
    }
}

/** «Что делать» — упорядочено по важности, поэтому с номерами. */
@Composable
fun RecommendationsCard(items: List<String>) {
    if (items.isEmpty()) return
    AppCard {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            SectionTitle(stringResource(R.string.report_recommendations))
            items.forEachIndexed { i, r ->
                Row(horizontalArrangement = Arrangement.spacedBy(12.dp), verticalAlignment = Alignment.Top) {
                    Box(
                        Modifier.size(24.dp).background(MaterialTheme.colorScheme.primaryContainer, CircleShape),
                        contentAlignment = Alignment.Center,
                    ) {
                        Text("${i + 1}", style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.onPrimaryContainer)
                    }
                    Text(r, style = MaterialTheme.typography.bodyLarge, modifier = Modifier.weight(1f))
                }
            }
        }
    }
}

/** Причины вывода: каждое сработавшее правило раскрывается в доказательства. */
@Composable
fun EvidenceCard(findings: List<ReportFinding>) {
    AppCard {
        Column(Modifier.padding(vertical = 12.dp)) {
            SectionTitle(
                stringResource(R.string.risk_evidence_title, findings.size),
                Modifier.padding(horizontal = 16.dp, vertical = 4.dp),
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
                if (i > 0) HorizontalDivider(Modifier.padding(start = 32.dp, end = 16.dp), color = MaterialTheme.colorScheme.outlineVariant)
                FindingRow(f)
            }
        }
    }
}

@Composable
private fun FindingRow(f: ReportFinding) {
    var expanded by rememberSaveable(f.ruleId) { mutableStateOf(false) }
    val rotation by animateFloatAsState(if (expanded) 180f else 0f, label = "chevron")
    val accent = when {
        f.effectiveWeight >= 25f -> RiskColors.High
        f.effectiveWeight >= 8f -> RiskColors.Attention
        else -> MaterialTheme.colorScheme.outline
    }
    val stateText = stringResource(if (expanded) R.string.a11y_expanded else R.string.a11y_collapsed)
    Row(
        Modifier
            .fillMaxWidth()
            .height(IntrinsicSize.Min)
            .clickable(role = Role.Button) { expanded = !expanded }
            .semantics { stateDescription = stateText }
            .padding(start = 16.dp, end = 12.dp, top = 12.dp, bottom = 12.dp),
        horizontalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        // Полоса силы признака: красная — весомый, янтарная — заметный, серая — слабый.
        Box(Modifier.width(4.dp).fillMaxHeight().background(accent, RoundedCornerShape(2.dp)))
        Column(
            Modifier.weight(1f).animateContentSize(),
            verticalArrangement = Arrangement.spacedBy(4.dp),
        ) {
            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(
                    f.titleRu,
                    style = MaterialTheme.typography.bodyLarge,
                    fontWeight = if (f.combination) FontWeight.SemiBold else FontWeight.Normal,
                    modifier = Modifier.weight(1f),
                )
                Text("+${"%.0f".format(f.effectiveWeight)}", style = MaterialTheme.typography.labelMedium, color = accent)
                Icon(
                    painterResource(R.drawable.ic_expand_more),
                    contentDescription = null,
                    tint = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.size(20.dp).rotate(rotation),
                )
            }
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalAlignment = Alignment.CenterVertically) {
                Text(f.categoryRu, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                if (f.combination) {
                    Tag(stringResource(R.string.risk_combination), MaterialTheme.colorScheme.onSecondaryContainer, MaterialTheme.colorScheme.secondaryContainer)
                }
            }
            if (expanded) {
                Text(f.descriptionRu, style = MaterialTheme.typography.bodyMedium)
                f.mitigations.forEach {
                    Text(stringResource(R.string.risk_mitigation, it), style = MaterialTheme.typography.bodyMedium, color = RiskColors.Low)
                }
                SelectionContainer {
                    Column(
                        Modifier
                            .fillMaxWidth()
                            .background(MaterialTheme.colorScheme.surfaceContainerHigh, MaterialTheme.shapes.small)
                            .padding(10.dp),
                        verticalArrangement = Arrangement.spacedBy(4.dp),
                    ) {
                        f.evidence.forEach { e ->
                            Text(e.source, style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                            Text(e.detail, style = MaterialTheme.typography.bodySmall, fontFamily = CodeFont)
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
}
