package com.apkanalyzer.analyzer.signature

import com.apkanalyzer.analyzer.AnalysisLimits
import com.apkanalyzer.analyzer.MalformedApkException
import com.apkanalyzer.analyzer.archive.SafeApkArchive
import com.apkanalyzer.analyzer.util.LeBytes
import java.io.ByteArrayInputStream
import java.security.MessageDigest
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate

enum class SignatureScheme(val label: String) {
    V1("v1 (JAR)"),
    V2("v2"),
    V3("v3"),
    V31("v3.1"),
}

data class CertificateInfo(
    val subject: String,
    val issuer: String,
    val serialNumberHex: String,
    val sha256Fingerprint: String,
    val notBeforeMs: Long,
    val notAfterMs: Long,
    val signatureAlgorithm: String,
    val publicKeyAlgorithm: String,
    val publicKeyBits: Int?,
    val selfSigned: Boolean,
    /** Стандартный отладочный сертификат Android SDK. */
    val isAndroidDebug: Boolean,
    /** Публичный тестовый ключ AOSP (testkey) — им может подписать APK кто угодно. */
    val isAospTestKey: Boolean,
    val foundIn: Set<SignatureScheme>,
)

data class SignatureInfo(
    val schemes: Set<SignatureScheme>,
    val certificates: List<CertificateInfo>,
    val warnings: List<String>,
) {
    val isSigned: Boolean get() = schemes.isNotEmpty()
}

/**
 * Извлекает сведения о подписи APK: какие схемы подписи присутствуют и какими сертификатами подписан файл.
 *
 * Важно: криптографическая проверка подписи здесь не выполняется — мы сообщаем, *кем заявлена* подпись.
 * Целостность APK проверит сам Android при установке; для оценки риска важны сертификат и схема.
 */
class SignatureInspector(private val limits: AnalysisLimits = AnalysisLimits()) {

    fun inspect(archive: SafeApkArchive): SignatureInfo {
        val warnings = mutableListOf<String>()
        val found = LinkedHashMap<String, Pair<X509Certificate, MutableSet<SignatureScheme>>>()
        val schemes = LinkedHashSet<SignatureScheme>()

        fun add(cert: X509Certificate, scheme: SignatureScheme) {
            val fp = sha256(cert.encoded)
            found.getOrPut(fp) { cert to mutableSetOf() }.second += scheme
        }

        // v1: META-INF/*.RSA|DSA|EC содержат PKCS#7 SignedData с сертификатами.
        val v1Blocks = archive.entries.filter { e ->
            val n = e.name.uppercase()
            n.startsWith("META-INF/") && n.count { it == '/' } == 1 &&
                (n.endsWith(".RSA") || n.endsWith(".DSA") || n.endsWith(".EC"))
        }
        for (e in v1Blocks) {
            try {
                val bytes = archive.read(e, MAX_PKCS7_BYTES)
                val certs = certificateFactory().generateCertificates(ByteArrayInputStream(bytes))
                certs.filterIsInstance<X509Certificate>().forEach { add(it, SignatureScheme.V1) }
                if (certs.isNotEmpty()) schemes += SignatureScheme.V1
            } catch (t: Exception) {
                warnings += "Не удалось прочитать v1-подпись ${e.name}: ${t.message ?: t.javaClass.simpleName}"
            }
        }

        // v2/v3: APK Signing Block перед центральным каталогом.
        try {
            readSigningBlock(archive)?.let { pairs ->
                for ((id, value) in pairs) {
                    val scheme = when (id) {
                        V2_ID -> SignatureScheme.V2
                        V3_ID -> SignatureScheme.V3
                        V31_ID -> SignatureScheme.V31
                        else -> null
                    } ?: continue
                    try {
                        val certs = parseSignersCertificates(value)
                        if (certs.isNotEmpty()) {
                            schemes += scheme
                            certs.forEach { add(it, scheme) }
                        } else {
                            warnings += "Блок подписи ${scheme.label} не содержит сертификатов"
                        }
                    } catch (t: Exception) {
                        warnings += "Повреждён блок подписи ${scheme.label}: ${t.message ?: t.javaClass.simpleName}"
                    }
                }
            }
        } catch (t: MalformedApkException) {
            warnings += "Повреждён APK Signing Block: ${t.message}"
        }

        val certificates = found.map { (fp, pair) -> describe(pair.first, fp, pair.second) }
        return SignatureInfo(schemes, certificates, warnings)
    }

    /** Возвращает пары (ID, значение) из APK Signing Block или null, если блока нет. */
    private fun readSigningBlock(archive: SafeApkArchive): List<Pair<Int, ByteArray>>? {
        val cdOffset = archive.centralDirectoryOffset
        if (cdOffset < FOOTER_SIZE) return null
        val footer = LeBytes(archive.readRange(cdOffset - FOOTER_SIZE, FOOTER_SIZE))
        if (footer.u64(8) != MAGIC_LO || footer.u64(16) != MAGIC_HI) return null
        val sizeInFooter = footer.u64(0)
        if (sizeInFooter < FOOTER_SIZE - 8 || sizeInFooter > limits.maxSigningBlockBytes) {
            throw MalformedApkException("Некорректный размер блока подписи: $sizeInFooter")
        }
        val totalSize = sizeInFooter + 8
        val blockStart = cdOffset - totalSize
        if (blockStart < 0) throw MalformedApkException("Блок подписи выходит за начало файла")
        val block = LeBytes(archive.readRange(blockStart, totalSize.toInt()))
        if (block.u64(0) != sizeInFooter) throw MalformedApkException("Размеры блока подписи не совпадают")

        val pairs = mutableListOf<Pair<Int, ByteArray>>()
        var p = 8
        val end = block.size - FOOTER_SIZE
        while (p + 12 <= end) {
            val len = block.u64(p)
            if (len < 4 || len > end - p - 8) throw MalformedApkException("Повреждена запись блока подписи")
            val id = block.s32(p + 8)
            val valueLen = (len - 4).toInt()
            pairs += id to block.bytes.copyOfRange(p + 12, p + 12 + valueLen)
            p += 8 + len.toInt()
            if (pairs.size > MAX_PAIRS) throw MalformedApkException("Слишком много записей в блоке подписи")
        }
        return pairs
    }

    /**
     * Структура v2/v3: length-prefixed последовательность signer,
     * signer → signed data → (digests, certificates, ...). Нам нужны только certificates.
     */
    private fun parseSignersCertificates(value: ByteArray): List<X509Certificate> {
        val result = mutableListOf<X509Certificate>()
        val signers = LpReader(value).sequence()
        for (signer in signers.take(MAX_SIGNERS)) {
            val signerReader = LpReader(signer)
            val signedData = signerReader.next()
            val sd = LpReader(signedData)
            sd.next() // digests
            val certs = sd.sequence()
            for (der in certs.take(MAX_CERTS)) {
                val cert = certificateFactory().generateCertificate(ByteArrayInputStream(der)) as X509Certificate
                result += cert
            }
        }
        return result
    }

    private fun describe(cert: X509Certificate, fp: String, schemes: Set<SignatureScheme>): CertificateInfo {
        val subject = cert.subjectX500Principal.name
        val issuer = cert.issuerX500Principal.name
        val key = cert.publicKey
        val bits = when (key) {
            is java.security.interfaces.RSAKey -> key.modulus.bitLength()
            is java.security.interfaces.ECKey -> key.params.order.bitLength()
            is java.security.interfaces.DSAKey -> key.params.p.bitLength()
            else -> null
        }
        return CertificateInfo(
            subject = subject,
            issuer = issuer,
            serialNumberHex = cert.serialNumber.toString(16),
            sha256Fingerprint = fp,
            notBeforeMs = cert.notBefore.time,
            notAfterMs = cert.notAfter.time,
            signatureAlgorithm = cert.sigAlgName,
            publicKeyAlgorithm = key.algorithm,
            publicKeyBits = bits,
            selfSigned = subject == issuer,
            isAndroidDebug = subject.contains("CN=Android Debug", ignoreCase = true),
            isAospTestKey = isAospTestSubject(subject),
            foundIn = schemes,
        )
    }

    private fun certificateFactory(): CertificateFactory = CertificateFactory.getInstance("X.509")

    /** Читатель length-prefixed (uint32 LE) последовательностей формата APK Signature Scheme. */
    private class LpReader(private val data: ByteArray) {
        private val le = LeBytes(data)
        private var pos = 0

        fun hasNext() = pos < data.size

        fun next(): ByteArray {
            if (pos + 4 > data.size) throw MalformedApkException("Обрыв данных подписи")
            val len = le.u32(pos)
            if (len > data.size - pos - 4) throw MalformedApkException("Длина поля подписи вне блока")
            val start = pos + 4
            pos = start + len.toInt()
            return data.copyOfRange(start, pos)
        }

        fun sequence(): List<ByteArray> {
            val inner = LpReader(next())
            val list = mutableListOf<ByteArray>()
            while (inner.hasNext()) list += inner.next()
            return list
        }
    }

    companion object {
        private const val FOOTER_SIZE = 24
        private const val MAGIC_LO = 0x20676953204b5041L // "APK Sig "
        private const val MAGIC_HI = 0x3234206b636f6c42L // "Block 42"
        const val V2_ID = 0x7109871a
        const val V3_ID = 0xf05368c0.toInt()
        const val V31_ID = 0x1b93ad61
        private const val MAX_PKCS7_BYTES = 1 * 1024 * 1024
        private const val MAX_PAIRS = 1024
        private const val MAX_SIGNERS = 16
        private const val MAX_CERTS = 16

        /**
         * Публичные тестовые ключи AOSP (testkey/platform/shared/media) имеют одинаковый subject.
         * Закрытые части этих ключей опубликованы, поэтому такая подпись ничего не гарантирует.
         */
        fun isAospTestSubject(subject: String): Boolean =
            subject.contains("CN=Android,") && subject.contains("OU=Android,") &&
                subject.contains("O=Android,") && subject.contains("L=Mountain View")

        fun sha256(bytes: ByteArray): String =
            MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }
    }
}
