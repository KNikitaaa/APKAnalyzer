package com.apkanalyzer.rules

import com.apkanalyzer.testing.ApkSpec
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class TrustedSignersTest {
    @Test
    fun verifiedDeveloperReducesOrdinaryCapabilitiesButNotAttackPatterns() {
        val raw = ApkSpec(
            permissions = listOf("INTERNET", "RECORD_AUDIO", "READ_SMS"),
            launcher = false,
        ).report()
        val signature = raw.signature!!
        val fingerprint = signature.certificates.single().sha256Fingerprint
        val params = RuleParams.DEFAULT.copy(trustedSigners = mapOf(
            raw.manifest!!.packageName to TrustedSigner(raw.manifest!!.packageName, "Test Developer", setOf(fingerprint)),
        ))
        val engine = RiskEngine(params = params)
        val unverified = engine.assess(raw)
        val verified = engine.assess(raw.copy(signature = signature.copy(verifiedSignerFingerprints = setOf(fingerprint))))

        assertFalse(unverified.matches.any { m -> m.mitigations.any { it.id == "MIT_VERIFIED_DEVELOPER" } })
        val ordinary = verified.matches.single { it.ruleId == "MIC_RECORD" }
        assertTrue(ordinary.mitigations.any { it.id == "MIT_VERIFIED_DEVELOPER" })
        assertEquals(unverified.matches.single { it.ruleId == "MIC_RECORD" }.effectiveWeight * 0.25f, ordinary.effectiveWeight, 0.001f)
        assertEquals(
            unverified.matches.single { it.ruleId == "COMBO_SMS_STEALER" }.effectiveWeight,
            verified.matches.single { it.ruleId == "COMBO_SMS_STEALER" }.effectiveWeight,
            0.001f,
        )
    }
}
