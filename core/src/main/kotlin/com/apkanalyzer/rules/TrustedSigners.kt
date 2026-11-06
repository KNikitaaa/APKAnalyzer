package com.apkanalyzer.rules

import com.apkanalyzer.analyzer.signature.CertificateInfo

/**
 * Официальные подписи популярных приложений: имя пакета → разработчик и SHA-256 его сертификатов.
 *
 * Зачем: легальные приложения (YouTube, Telegram, банки) законно используют камеру, микрофон, автозапуск,
 * загрузку кода — по одним возможностям их не отличить от шпиона. Но подделать подпись разработчика
 * невозможно. Поэтому:
 *  - пакет из списка, подписанный официальным ключом, — сильный смягчающий фактор («это оригинал»);
 *  - пакет из списка, подписанный ЧУЖИМ ключом, — сильный признак риска: это модификация,
 *    перепакованная версия или троян под видом известного приложения.
 *
 * Встроенный список дополняется подписанными пакетами правил (поле `trustedSigners`).
 */
data class TrustedSigner(
    val packageName: String,
    val developer: String,
    /** SHA-256 сертификатов подписи (нижний регистр, без двоеточий). Любой из них считается официальным. */
    val certSha256: Set<String>,
    /** Названия приложения в лаунчере — чтобы заметить чужое приложение, которое выдаёт себя за это. */
    val labels: Set<String> = emptySet(),
) {
    /** Как назвать разработчика в отчёте. */
    val displayDeveloper: String get() = developer.ifBlank { "официальный разработчик $packageName" }
}

enum class SignerVerdict { OFFICIAL, MISMATCH, UNKNOWN }

data class SignerCheck(
    val verdict: SignerVerdict,
    val signer: TrustedSigner?,
    /** Сертификаты APK, с которыми сравнивали. */
    val apkCerts: List<CertificateInfo>,
)

object TrustedSigners {

    fun check(packageName: String?, certs: List<CertificateInfo>, catalog: Map<String, TrustedSigner>): SignerCheck {
        val known = packageName?.let { catalog[it] } ?: return SignerCheck(SignerVerdict.UNKNOWN, null, certs)
        if (certs.isEmpty()) return SignerCheck(SignerVerdict.MISMATCH, known, certs)
        // При ротации ключа (APK Signature Scheme v3) в APK могут быть и старый, и новый сертификаты:
        // достаточно совпадения любого из них, но ни одного постороннего «главного» сертификата быть не должно.
        val match = certs.any { it.sha256Fingerprint.lowercase() in known.certSha256 }
        return SignerCheck(if (match) SignerVerdict.OFFICIAL else SignerVerdict.MISMATCH, known, certs)
    }

    fun normalize(fp: String): String = fp.lowercase().filter { it.isDigit() || it in 'a'..'f' }

    fun isFingerprint(fp: String): Boolean = normalize(fp).length == 64 && normalize(fp) == fp
}
