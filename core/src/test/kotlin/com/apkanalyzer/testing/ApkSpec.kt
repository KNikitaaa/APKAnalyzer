package com.apkanalyzer.testing

import com.apkanalyzer.analyzer.AnalysisOutcome
import com.apkanalyzer.analyzer.ApkAnalysisReport
import com.apkanalyzer.analyzer.ApkAnalyzer
import com.apkanalyzer.rules.RiskAssessment
import com.apkanalyzer.rules.RiskEngine

/**
 * Короткое описание тестового APK для проверки правил:
 * ApkSpec(permissions = listOf("READ_SMS"), launcher = false).assess()
 */
data class ApkSpec(
    val permissions: List<String> = listOf("INTERNET"),
    val launcher: Boolean = true,
    val components: List<El> = emptyList(),
    val appAttrs: List<A> = emptyList(),
    val manifestAttrs: List<A> = emptyList(),
    val targetSdk: Int = 34,
    val dexStrings: List<String> = emptyList(),
    val apis: List<Pair<String, String>> = emptyList(),
    val definedClasses: List<String> = listOf("Lcom/example/app/MainActivity;", "Lcom/example/app/Worker;", "Lcom/example/app/Api;"),
    val extraEntries: List<Pair<String, ByteArray>> = emptyList(),
    val cert: String? = "dev-cert.der",
) {
    fun manifest(): El {
        val appChildren = buildList {
            if (launcher) add(
                el("activity", a("name", ".MainActivity"), a("exported", true), children = listOf(
                    el("intent-filter", children = listOf(
                        el("action", a("name", "android.intent.action.MAIN")),
                        el("category", a("name", "android.intent.category.LAUNCHER")),
                    )),
                )),
            )
            addAll(components)
        }
        return El(
            "manifest",
            listOf(plain("package", Fixtures.PKG), a("versionCode", 1), a("versionName", "1.0")) + manifestAttrs,
            listOf(el("uses-sdk", a("minSdkVersion", 21), a("targetSdkVersion", targetSdk))) +
                permissions.map { p -> el("uses-permission", a("name", if (p.contains('.')) p else "android.permission.$p")) } +
                El("application", appAttrs, appChildren),
        )
    }

    fun bytes(): ByteArray {
        val zip = ApkBuilder.zip(
            listOf(
                "AndroidManifest.xml" to AxmlWriter.write(manifest()),
                "classes.dex" to DexWriter.write(strings = dexStrings, methodRefs = apis, definedClasses = definedClasses),
            ) + extraEntries,
        )
        return if (cert == null) zip else ApkBuilder.withSigningBlock(zip, listOf(0x7109871a to ApkBuilder.v2SignerValue(listOf(resource(cert)))))
    }

    fun report(): ApkAnalysisReport {
        val outcome = ApkAnalyzer(clock = { 0L }).analyze(tempApk(bytes()), "spec.apk")
        return (outcome as? AnalysisOutcome.Completed)?.report ?: error("APK не проанализирован: $outcome")
    }

    fun assess(): RiskAssessment = RiskEngine().assess(report())
}

fun component(type: String, name: String, permission: String? = null, actions: List<String> = emptyList(), exported: Boolean? = null, categories: List<String> = emptyList()): El {
    val attrs = buildList {
        add(a("name", name))
        permission?.let { add(a("permission", if (it.contains('.')) it else "android.permission.$it")) }
        exported?.let { add(a("exported", it)) }
    }
    val filters = if (actions.isEmpty() && categories.isEmpty()) emptyList() else listOf(
        el("intent-filter", children = actions.map { el("action", a("name", it)) } + categories.map { el("category", a("name", it)) }),
    )
    return El(type, attrs, filters)
}
