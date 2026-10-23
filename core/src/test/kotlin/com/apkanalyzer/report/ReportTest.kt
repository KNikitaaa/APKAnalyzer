package com.apkanalyzer.report

import com.apkanalyzer.analyzer.AnalysisOutcome
import com.apkanalyzer.analyzer.ApkAnalyzer
import com.apkanalyzer.analyzer.util.Json
import com.apkanalyzer.analyzer.util.JsonException
import com.apkanalyzer.analyzer.util.JsonValue
import com.apkanalyzer.analyzer.expect
import com.apkanalyzer.domain.model.RiskLevel
import com.apkanalyzer.rules.RiskEngine
import com.apkanalyzer.testing.ApkSpec
import com.apkanalyzer.testing.Fixtures
import com.apkanalyzer.testing.tempApk
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class ReportTest {

    private fun document(bytes: ByteArray): ReportDocument {
        val report = (ApkAnalyzer(clock = { 1_761_000_000_000L }).analyze(tempApk(bytes), "sample.apk") as AnalysisOutcome.Completed).report
        return ReportBuilder.build(report, RiskEngine().assess(report), appVersion = "0.2.0")
    }

    @Test
    fun jsonRoundTripPreservesReport() {
        val doc = document(Fixtures.suspiciousApk())
        val json = ReportJson.encode(doc)
        val back = ReportJson.decode(json)
        assertEquals(doc.file, back.file)
        assertEquals(doc.app, back.app)
        assertEquals(doc.risk.code, back.risk.code)
        assertEquals(doc.risk.score, back.risk.score)
        assertEquals(doc.findings.map { it.ruleId }, back.findings.map { it.ruleId })
        assertEquals(doc.findings.map { it.evidence }, back.findings.map { it.evidence })
        assertEquals(doc.sections, back.sections)
        assertEquals(doc.recommendations, back.recommendations)
        // Повторная сериализация стабильна байт в байт.
        assertEquals(json, ReportJson.encode(back))
    }

    @Test
    fun jsonContainsReproducibilityFields() {
        val json = Json.parse(ReportJson.encode(document(Fixtures.suspiciousApk()))) as JsonValue.Obj
        assertEquals(ReportJson.FORMAT, json.str("format"))
        assertEquals(64, json.obj("file")!!.str("sha256")!!.length)
        assertTrue(json.str("rulesVersion")!!.isNotEmpty())
        assertTrue(json.str("analyzerVersion")!!.isNotEmpty())
        assertEquals("HIGH", json.obj("risk")!!.str("level"))
        assertTrue(json.arr("limitations").isEmpty())
        assertTrue(json.str("generatedAt")!!.endsWith("Z"))
    }

    @Test
    fun recommendationsMatchLevel() {
        val high = document(Fixtures.suspiciousApk())
        assertEquals(RiskLevel.High, high.risk.level)
        assertTrue(high.recommendations.first().contains("Не устанавливайте"))
        assertTrue(high.recommendations.any { it.contains("банк") })

        val low = document(Fixtures.cleanApk())
        assertEquals(RiskLevel.Low, low.risk.level)
        assertEquals(1, low.recommendations.size)

        val admin = document(ApkSpec(permissions = listOf("INTERNET", "SYSTEM_ALERT_WINDOW"), components = listOf(
            com.apkanalyzer.testing.component("receiver", ".Admin", "BIND_DEVICE_ADMIN"),
            com.apkanalyzer.testing.component("service", ".Acc", "BIND_ACCESSIBILITY_SERVICE"),
        )).bytes())
        assertTrue(admin.recommendations.any { it.contains("администратора") })
        assertTrue(admin.recommendations.any { it.contains("Специальные возможности") })
    }

    @Test
    fun rejectsForeignOrFutureJson() {
        expect<JsonException> { ReportJson.decode("{\"format\":\"other\"}") }
        expect<JsonException> { ReportJson.decode("{\"format\":\"${ReportJson.FORMAT}\",\"schemaVersion\":99}") }
        expect<JsonException> { ReportJson.decode("[1,2") }
    }

    @Test
    fun jsonEscapingAndParsing() {
        val tricky = "кавычка \" слэш \\ перевод\nстроки \u0001 и  "
        val v = JsonValue.Obj().put("s", tricky).put("n", -12.5).put("i", 1L shl 40).put("b", true).put("z", null as String?)
        val parsed = Json.parse(Json.write(v, pretty = false)) as JsonValue.Obj
        assertEquals(tricky, parsed.str("s"))
        assertEquals(-12.5, parsed.double("s".let { "n" })!!, 0.0)
        assertEquals(1L shl 40, parsed.long("i"))
        assertEquals(true, parsed.bool("b"))
        assertEquals(JsonValue.Null, parsed["z"])
        expect<JsonException> { Json.parse("[".repeat(100) + "]".repeat(100)) }
        expect<JsonException> { Json.parse("{\"a\":1} x") }
        expect<JsonException> { Json.parse("\"\u0001\"") }
    }
}
