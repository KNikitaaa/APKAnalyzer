package com.apkanalyzer.analyzer

import com.apkanalyzer.analyzer.archive.SafeApkArchive
import com.apkanalyzer.analyzer.signature.SignatureInspector
import com.apkanalyzer.analyzer.signature.SignatureScheme
import com.apkanalyzer.testing.ApkBuilder
import com.apkanalyzer.testing.Fixtures
import com.apkanalyzer.testing.resource
import com.apkanalyzer.testing.tempApk
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class SignatureInspectorTest {

    private fun inspect(bytes: ByteArray) = SafeApkArchive.open(tempApk(bytes)).use { SignatureInspector().inspect(it) }

    @Test
    fun readsV1AndV2WithSameCertificate() {
        val s = inspect(Fixtures.cleanApk())
        assertEquals(setOf(SignatureScheme.V1, SignatureScheme.V2), s.schemes)
        val cert = s.certificates.single()
        assertTrue(cert.subject.contains("CN=Test Developer"))
        assertEquals(setOf(SignatureScheme.V1, SignatureScheme.V2), cert.foundIn)
        assertEquals("RSA", cert.publicKeyAlgorithm)
        assertEquals(2048, cert.publicKeyBits)
        assertTrue(cert.selfSigned)
        assertFalse(cert.isAndroidDebug)
        assertEquals(64, cert.sha256Fingerprint.length)
        assertTrue(s.warnings.isEmpty())
    }

    @Test
    fun detectsDebugCertificateInV3() {
        val zip = ApkBuilder.zip(listOf("AndroidManifest.xml" to ByteArray(10)))
        val signed = ApkBuilder.withSigningBlock(zip, listOf(SignatureInspector.V3_ID to ApkBuilder.v2SignerValue(listOf(resource("debug-cert.der")))))
        val s = inspect(signed)
        assertEquals(setOf(SignatureScheme.V3), s.schemes)
        assertTrue(s.certificates.single().isAndroidDebug)
    }

    @Test
    fun unsignedApk() {
        val s = inspect(ApkBuilder.zip(listOf("AndroidManifest.xml" to ByteArray(10))))
        assertFalse(s.isSigned)
        assertTrue(s.certificates.isEmpty())
    }

    @Test
    fun corruptedSigningBlockProducesWarningNotCrash() {
        val zip = ApkBuilder.zip(listOf("AndroidManifest.xml" to ByteArray(10)))
        val signed = ApkBuilder.withSigningBlock(zip, listOf(0x7109871a to ByteArray(40) { 0x7F }))
        val s = inspect(signed)
        assertFalse(s.isSigned)
        assertTrue(s.warnings.isNotEmpty())
    }

    @Test
    fun corruptedV1BlockProducesWarning() {
        val s = inspect(ApkBuilder.zip(listOf("AndroidManifest.xml" to ByteArray(10), "META-INF/CERT.RSA" to ByteArray(100) { 3 })))
        assertFalse(s.isSigned)
        assertTrue(s.warnings.single().contains("CERT.RSA"))
    }
}
