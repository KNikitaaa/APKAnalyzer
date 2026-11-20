package com.apkanalyzer

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.apkanalyzer.analyzer.AnalysisOutcome
import com.apkanalyzer.analyzer.ApkAnalyzer
import org.junit.Assert.assertEquals
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class SignatureVerificationDeviceTest {
    @Test
    fun verifiesSignedApkOnDevice() {
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val apk = java.io.File(instrumentation.targetContext.cacheDir, "verified-clean.apk")
        instrumentation.context.assets.open("verified-clean.apk").use { input ->
            apk.outputStream().use(input::copyTo)
        }
        try {
            val result = ApkAnalyzer().analyze(apk) as AnalysisOutcome.Completed
            assertEquals(
                setOf("94801dc5999912e33b15e809dddaec669bc944cbc7b26ae3af40cace480103fe"),
                result.report.signature!!.verifiedSignerFingerprints,
            )
        } finally {
            apk.delete()
        }
    }
}
