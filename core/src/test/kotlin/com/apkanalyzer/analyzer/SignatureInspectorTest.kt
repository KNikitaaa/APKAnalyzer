package com.apkanalyzer.analyzer

import com.apkanalyzer.analyzer.archive.SafeApkArchive
import com.apkanalyzer.analyzer.signature.SignatureInspector
import com.apkanalyzer.analyzer.signature.SignatureScheme
import com.apkanalyzer.testing.ApkBuilder
import com.apkanalyzer.testing.Fixtures
import com.apkanalyzer.testing.resource
import com.apkanalyzer.testing.tempApk
import com.apkanalyzer.rules.SignerVerdict
import com.apkanalyzer.rules.TrustedSigner
import com.apkanalyzer.rules.TrustedSigners
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

    @Test
    fun trustedSignerRequiresCryptographicallyValidApk() {
        val bytes = resource("verified-clean.apk")
        fun verified(data: ByteArray) = tempApk(data).let { file ->
            SafeApkArchive.open(file).use { SignatureInspector().inspect(it, file) }
        }
        val valid = verified(bytes)
        val fingerprint = "94801dc5999912e33b15e809dddaec669bc944cbc7b26ae3af40cace480103fe"
        assertEquals(setOf(fingerprint), valid.verifiedSignerFingerprints)
        val catalog = mapOf("com.example.sample" to TrustedSigner("com.example.sample", "Test", setOf(fingerprint)))
        assertEquals(SignerVerdict.OFFICIAL, TrustedSigners.check("com.example.sample", valid, catalog).verdict)
        assertEquals(SignerVerdict.MISMATCH, TrustedSigners.check("com.example.sample", valid, catalog.mapValues { (_, v) -> v.copy(certSha256 = setOf("0".repeat(64))) }).verdict)

        // Сертификат остаётся в блоке подписи, но изменённый файл уже не подписан им.
        val changed = bytes.clone()
        val first = SafeApkArchive.open(tempApk(changed)).use { it.entries.first { entry -> !entry.isDirectory } }
        val offset = first.localHeaderOffset.toInt()
        fun u16(at: Int) = (changed[at].toInt() and 255) or ((changed[at + 1].toInt() and 255) shl 8)
        val dataOffset = offset + 30 + u16(offset + 26) + u16(offset + 28)
        changed[dataOffset + 5] = (changed[dataOffset + 5].toInt() xor 1).toByte()
        val invalid = verified(changed)
        assertTrue(invalid.certificates.isNotEmpty())
        assertTrue(invalid.verifiedSignerFingerprints.isEmpty())
        assertEquals(SignerVerdict.UNVERIFIED, TrustedSigners.check("com.example.sample", invalid, catalog).verdict)
    }
}
