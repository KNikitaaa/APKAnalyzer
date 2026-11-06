package com.apkanalyzer.eval

import com.apkanalyzer.domain.model.RiskLevel
import com.apkanalyzer.testing.Fixtures
import com.apkanalyzer.testing.tempApk
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

class EvaluationTest {

    private fun r(truth: GroundTruth, level: RiskLevel?) =
        SampleResult(name = "x", truth = truth, level = level, score = 0, coverage = 1f, rejectedReason = if (level == null) "битый" else null, topRules = emptyList())

    private val results = listOf(
        r(GroundTruth.MALICIOUS, RiskLevel.High), // TP при обоих порогах
        r(GroundTruth.MALICIOUS, RiskLevel.Attention), // FN при строгом пороге, TP при широком
        r(GroundTruth.MALICIOUS, RiskLevel.Low), // FN
        r(GroundTruth.MALICIOUS, RiskLevel.Insufficient), // неполный
        r(GroundTruth.BENIGN, RiskLevel.Low), // TN
        r(GroundTruth.BENIGN, RiskLevel.Low), // TN
        r(GroundTruth.BENIGN, RiskLevel.Attention), // FP только при широком пороге
        r(GroundTruth.BENIGN, null), // отклонён — неполный
    )

    @Test
    fun strictPolicyCountsOnlyHighAsDetection() {
        val m = Metrics.of(results, DetectionPolicy.HIGH_ONLY)
        assertEquals(1, m.truePositives)
        assertEquals(2, m.falseNegatives)
        assertEquals(0, m.falsePositives)
        assertEquals(3, m.trueNegatives)
        assertEquals(0.0, m.falsePositiveRate, 1e-9)
        assertEquals(2.0 / 3, m.falseNegativeRate, 1e-9)
    }

    @Test
    fun widePolicyCountsAttentionAsDetection() {
        val m = Metrics.of(results, DetectionPolicy.ATTENTION_OR_HIGH)
        assertEquals(2, m.truePositives)
        assertEquals(1, m.falseNegatives)
        assertEquals(1, m.falsePositives)
        assertEquals(2, m.trueNegatives)
        assertEquals(1.0 / 3, m.falsePositiveRate, 1e-9)
        assertEquals(2.0 / 3, m.precision, 1e-9)
    }

    @Test
    fun incompleteAnalysesAreExcludedAndReportedSeparately() {
        val m = Metrics.of(results, DetectionPolicy.HIGH_ONLY)
        assertEquals(8, m.total)
        assertEquals(2, m.incomplete)
        assertEquals(0.25, m.incompleteRate, 1e-9)
    }

    @Test
    fun emptyGroupsGiveNaNInsteadOfCrashing() {
        val m = Metrics.of(listOf(r(GroundTruth.BENIGN, RiskLevel.Low)), DetectionPolicy.HIGH_ONLY)
        assertTrue(m.falseNegativeRate.isNaN())
        assertEquals(0.0, m.falsePositiveRate, 1e-9)
    }

    @Test
    fun evaluatorAnalyzesLabeledFolders() {
        val root = kotlin.io.path.createTempDirectory("eval").toFile()
        File(root, "malicious").mkdirs()
        File(root, "benign").mkdirs()
        tempApk(Fixtures.suspiciousApk()).copyTo(File(root, "malicious/sms.apk"))
        tempApk(Fixtures.cleanApk()).copyTo(File(root, "benign/clean.apk"))
        File(root, "benign/readme.txt").writeText("не APK — пропускается")

        val report = Evaluator().run(LabeledSet.fromDirectory(root))

        assertEquals(2, report.results.size)
        val strict = report.metrics.getValue(DetectionPolicy.HIGH_ONLY)
        assertEquals(1, strict.truePositives)
        assertEquals(1, strict.trueNegatives)
        assertTrue(report.markdown().contains("| Ложные срабатывания (FPR) |"))
        assertEquals(3, report.csv().lines().filter { it.isNotBlank() }.size) // заголовок + 2 строки
        root.deleteRecursively()
    }
}
