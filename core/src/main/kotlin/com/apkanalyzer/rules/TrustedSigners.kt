package com.apkanalyzer.rules

import com.apkanalyzer.analyzer.signature.CertificateInfo
import com.apkanalyzer.analyzer.signature.SignatureInfo

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
 * Список сертификатов берётся из встроенного каталога. Совпадение учитывается только после
 * криптографической проверки подписи всего APK.
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

enum class SignerVerdict { OFFICIAL, MISMATCH, UNVERIFIED, UNKNOWN }

data class SignerCheck(
    val verdict: SignerVerdict,
    val signer: TrustedSigner?,
    /** Сертификаты APK, с которыми сравнивали. */
    val apkCerts: List<CertificateInfo>,
)

object TrustedSigners {

    fun check(packageName: String?, signature: SignatureInfo?, catalog: Map<String, TrustedSigner> = BuiltinSigners.ALL): SignerCheck {
        val certs = signature?.certificates.orEmpty()
        val known = packageName?.let { catalog[it] } ?: return SignerCheck(SignerVerdict.UNKNOWN, null, certs)
        val verified = signature?.verifiedSignerFingerprints.orEmpty()
        if (verified.isEmpty()) return SignerCheck(SignerVerdict.UNVERIFIED, known, certs)
        // Все действующие подписанты должны входить в каталог. Сторонний со-подписант не получает доверия.
        val match = verified.all { it in known.certSha256 }
        return SignerCheck(if (match) SignerVerdict.OFFICIAL else SignerVerdict.MISMATCH, known, certs)
    }

    fun normalize(fp: String): String = fp.lowercase().filter { it.isDigit() || it in 'a'..'f' }

    fun isFingerprint(fp: String): Boolean = normalize(fp).length == 64 && normalize(fp) == fp
}
