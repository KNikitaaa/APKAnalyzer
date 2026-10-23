package com.apkanalyzer.report

import com.apkanalyzer.analyzer.ApkAnalysisReport
import com.apkanalyzer.analyzer.report.RawFeatureFormatter
import com.apkanalyzer.rules.RiskAssessment
import com.apkanalyzer.rules.RuleKind

object ReportBuilder {

    fun build(
        report: ApkAnalysisReport,
        risk: RiskAssessment,
        appVersion: String,
        generatedAtMs: Long = report.analyzedAtMs,
    ): ReportDocument = ReportDocument(
        generatedAtMs = generatedAtMs,
        appVersion = appVersion,
        analyzerVersion = report.analyzerVersion,
        rulesVersion = risk.rulesVersion,
        file = ReportFile(report.file.displayName, report.file.sizeBytes, report.file.sha256),
        app = report.manifest?.let { ReportApp(it.packageName, it.versionName, it.versionCode, it.minSdk, it.targetSdk) },
        risk = ReportRisk(RiskCode.of(risk.level), risk.score, risk.levelReasonRu, risk.coverage),
        findings = risk.matches.map { m ->
            ReportFinding(
                ruleId = m.ruleId,
                titleRu = m.titleRu,
                descriptionRu = m.descriptionRu,
                categoryRu = m.category.labelRu,
                combination = m.kind == RuleKind.COMBINATION,
                baseWeight = m.baseWeight,
                confidence = m.confidence,
                effectiveWeight = m.effectiveWeight,
                mitigations = m.mitigations.map { "${it.titleRu} (×${it.factor})" },
                evidence = m.evidence.map { ReportEvidence(it.source, it.detail) },
            )
        },
        recommendations = Recommendations.forAssessment(risk),
        limitations = risk.limitations,
        sections = RawFeatureFormatter.format(report),
    )
}
