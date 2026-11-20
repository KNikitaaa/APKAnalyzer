package com.apkanalyzer.report

import com.apkanalyzer.analyzer.AnalysisOutcome
import com.apkanalyzer.analyzer.ApkAnalyzer
import com.apkanalyzer.analyzer.util.Json
import com.apkanalyzer.analyzer.util.JsonValue
import com.apkanalyzer.rules.RiskEngine
import com.apkanalyzer.testing.Fixtures
import com.apkanalyzer.testing.tempApk
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class SarifTest {

    private val doc: ReportDocument = run {
        val report = (ApkAnalyzer(clock = { 1_761_000_000_000L }).analyze(tempApk(Fixtures.suspiciousApk()), "sample.apk") as AnalysisOutcome.Completed).report
        ReportBuilder.build(report, RiskEngine().assess(report), appVersion = "0.6.0")
    }
    private val sarif = Json.parse(SarifExporter.encode(doc)) as JsonValue.Obj
    private val run = sarif.arr("runs").single()

    @Test
    fun isSarif210() {
        assertEquals("2.1.0", sarif.str("version"))
        assertTrue(sarif.str("\$schema")!!.contains("sarif-2.1.0"))
        val driver = run.obj("tool")!!.obj("driver")!!
        assertEquals("APK AI Analyzer", driver.str("name"))
        assertEquals("0.6.0", driver.str("version"))
    }

    @Test
    fun everyFindingIsAResultWithAKnownRule() {
        val ruleIds = run.obj("tool")!!.obj("driver")!!.arr("rules").map { it.str("id") }
        val results = run.arr("results")
        assertEquals(doc.findings.size, results.size)
        assertEquals(doc.findings.map { it.ruleId }.toSet(), ruleIds.toSet())
        for ((i, r) in results.withIndex()) {
            assertEquals(ruleIds[r.int("ruleIndex")!!], r.str("ruleId"))
            assertTrue(r.str("level") in setOf("error", "warning", "note"))
            assertTrue(r.obj("message")!!.str("text")!!.isNotBlank())
            assertEquals("sample.apk", r.arr("locations").single().obj("physicalLocation")!!.obj("artifactLocation")!!.str("uri"))
            assertEquals(doc.findings[i].evidence.size, r.obj("properties")!!.arr("evidence").size)
        }
    }

    @Test
    fun combinationsAreErrors() {
        val combo = run.arr("results").first { it.str("ruleId") == "COMBO_SMS_STEALER" }
        assertEquals("error", combo.str("level"))
    }

    @Test
    fun artifactCarriesHashAndRunCarriesVerdict() {
        val artifact = run.arr("artifacts").single()
        assertEquals(doc.file.sha256, artifact.obj("hashes")!!.str("sha-256"))
        val props = run.obj("properties")!!
        assertEquals("HIGH", props.str("riskLevel"))
        assertEquals(doc.risk.score, props.int("riskScore"))
        assertEquals(doc.rulesVersion, props.str("rulesVersion"))
    }

    @Test
    fun aiTextIsNotIncluded() {
        val withAi = doc.copy(aiExplanation = ReportAi(provider = "X", model = "m", generatedAtMs = 0, promptVersions = emptyMap(), summary = "AI SAYS SAFE"))
        assertTrue(!SarifExporter.encode(withAi).contains("AI SAYS SAFE"))
    }
}
