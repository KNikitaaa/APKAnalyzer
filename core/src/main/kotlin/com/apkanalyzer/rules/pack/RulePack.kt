package com.apkanalyzer.rules.pack

import com.apkanalyzer.analyzer.util.Json
import com.apkanalyzer.analyzer.util.JsonException
import com.apkanalyzer.analyzer.util.JsonValue
import com.apkanalyzer.rules.RuleCatalog
import com.apkanalyzer.rules.RuleParams
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.PublicKey
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import java.util.Base64

/**
 * Пакет правил — обновление *параметров* движка без новой версии приложения: веса, отключённые правила,
 * пороги и списки (подозрительные зоны, динамический DNS, публичные DNS, адреса мессенджеров для C2).
 * Логика правил остаётся в коде: пакет не может добавить исполняемое поведение.
 *
 * Пакет распространяется только в подписанном виде (ECDSA P-256 / SHA-256) и рассчитан на конкретную
 * версию встроенного каталога ([baseCatalog]).
 */
data class RulePack(
    val version: String,
    val baseCatalog: String,
    val createdAtMs: Long,
    val notes: String,
    val weightOverrides: Map<String, Int>,
    val disabledRules: Set<String>,
    val highThreshold: Int?,
    val attentionThreshold: Int?,
    val suspiciousTlds: Set<String>?,
    val dynamicDns: List<String>?,
    val publicDns: Set<String>?,
    val messengerC2: List<String>?,
) {
    /** Параметры движка: встроенные значения, поверх которых применён пакет. */
    fun toParams(base: RuleParams = RuleParams.DEFAULT): RuleParams = base.copy(
        version = "${base.version}+$version",
        highThreshold = highThreshold ?: base.highThreshold,
        attentionThreshold = attentionThreshold ?: base.attentionThreshold,
        weightOverrides = base.weightOverrides + weightOverrides,
        disabledRules = base.disabledRules + disabledRules,
        suspiciousTlds = suspiciousTlds ?: base.suspiciousTlds,
        dynamicDns = dynamicDns ?: base.dynamicDns,
        publicDns = publicDns ?: base.publicDns,
        messengerC2 = messengerC2 ?: base.messengerC2,
    )

    fun toJson(): String = Json.write(
        JsonValue.Obj()
            .put("version", version)
            .put("baseCatalog", baseCatalog)
            .put("createdAtMs", createdAtMs)
            .put("notes", notes)
            .put("weightOverrides", JsonValue.Obj().apply { weightOverrides.toSortedMap().forEach { (k, v) -> put(k, v) } })
            .put("disabledRules", strings(disabledRules.sorted()))
            .apply {
                highThreshold?.let { put("highThreshold", it) }
                attentionThreshold?.let { put("attentionThreshold", it) }
                suspiciousTlds?.let { put("suspiciousTlds", strings(it.sorted())) }
                dynamicDns?.let { put("dynamicDns", strings(it)) }
                publicDns?.let { put("publicDns", strings(it.sorted())) }
                messengerC2?.let { put("messengerC2", strings(it)) }
            },
    )

    companion object {
        private fun strings(items: List<String>) = JsonValue.Arr(items.map { JsonValue.Str(it) })

        fun fromJson(text: String): RulePack {
            val o = try {
                Json.parse(text, maxLength = MAX_PAYLOAD) as? JsonValue.Obj
            } catch (e: JsonException) {
                null
            } ?: throw RulePackException("Содержимое пакета повреждено")
            fun list(key: String): List<String>? = (o[key] as? JsonValue.Arr)?.items?.map {
                (it as? JsonValue.Str)?.value ?: throw RulePackException("В поле $key ожидаются строки")
            }
            return RulePack(
                version = o.str("version") ?: throw RulePackException("В пакете нет версии"),
                baseCatalog = o.str("baseCatalog") ?: throw RulePackException("В пакете не указан базовый набор правил"),
                createdAtMs = o.long("createdAtMs") ?: 0L,
                notes = o.str("notes").orEmpty().take(2000),
                weightOverrides = o.obj("weightOverrides")?.fields.orEmpty().mapValues { (k, v) ->
                    ((v as? JsonValue.Num)?.value?.toInt()) ?: throw RulePackException("Вес правила $k должен быть числом")
                },
                disabledRules = list("disabledRules").orEmpty().toSet(),
                highThreshold = o.int("highThreshold"),
                attentionThreshold = o.int("attentionThreshold"),
                suspiciousTlds = list("suspiciousTlds")?.toSet(),
                dynamicDns = list("dynamicDns"),
                publicDns = list("publicDns")?.toSet(),
                messengerC2 = list("messengerC2"),
            )
        }

        const val MAX_PAYLOAD = 512 * 1024
    }
}

class RulePackException(message: String) : Exception(message)

/** Подпись пакетов (инструмент разработчика правил; на телефоне не используется). */
object RulePackSigner {
    const val FORMAT = "apk-analyzer-rulepack"
    private const val ALGORITHM = "SHA256withECDSA"

    fun generateKeyPair(): KeyPair =
        KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()

    fun publicKeyBase64(kp: KeyPair): String = Base64.getEncoder().encodeToString(kp.public.encoded)
    fun privateKeyBase64(kp: KeyPair): String = Base64.getEncoder().encodeToString(kp.private.encoded)

    fun privateKeyFromBase64(b64: String): PrivateKey =
        KeyFactory.getInstance("EC").generatePrivate(PKCS8EncodedKeySpec(Base64.getDecoder().decode(b64.trim())))

    fun sign(pack: RulePack, kp: KeyPair): String = sign(pack, kp.private, kp.public)

    fun sign(pack: RulePack, privateKey: PrivateKey, publicKey: PublicKey): String {
        val payload = pack.toJson().toByteArray(Charsets.UTF_8)
        val sig = Signature.getInstance(ALGORITHM).apply { initSign(privateKey); update(payload) }.sign()
        return Json.write(
            JsonValue.Obj()
                .put("format", FORMAT)
                .put("formatVersion", 1)
                .put("keyId", keyId(publicKey.encoded))
                .put("payload", Base64.getEncoder().encodeToString(payload))
                .put("signature", Base64.getEncoder().encodeToString(sig)),
        )
    }

    fun keyId(spki: ByteArray): String =
        MessageDigest.getInstance("SHA-256").digest(spki).take(8).joinToString("") { "%02x".format(it) }

    internal const val SIGNATURE_ALGORITHM = ALGORITHM
}

/**
 * Проверка пакета на устройстве: формат, подпись доверенным ключом, совместимость с каталогом,
 * допустимость значений и защита от отката на старую версию.
 *
 * @param trustedKeys открытые ключи (X.509 SubjectPublicKeyInfo, base64), которым приложение доверяет.
 */
class RulePackVerifier(private val trustedKeys: List<String> = RulePackKeys.TRUSTED) {

    fun verify(text: String, installedVersion: String? = null): RulePack {
        if (text.length > RulePack.MAX_PAYLOAD * 2) throw RulePackException("Файл слишком большой для пакета правил")
        val env = try {
            Json.parse(text) as? JsonValue.Obj
        } catch (e: JsonException) {
            null
        } ?: throw RulePackException("Это не пакет правил APK AI Analyzer")
        if (env.str("format") != RulePackSigner.FORMAT) throw RulePackException("Это не пакет правил APK AI Analyzer")
        val payload = try {
            Base64.getDecoder().decode(env.str("payload") ?: "")
        } catch (e: IllegalArgumentException) {
            throw RulePackException("Содержимое пакета повреждено")
        }
        val signature = try {
            Base64.getDecoder().decode(env.str("signature") ?: "")
        } catch (e: IllegalArgumentException) {
            throw RulePackException("Подпись пакета повреждена")
        }
        if (payload.isEmpty() || signature.isEmpty()) throw RulePackException("Пакет не подписан — подпись обязательна")
        if (!trustedKeys.any { verifySignature(it, payload, signature) }) {
            throw RulePackException("Подпись пакета не подтверждена доверенным ключом — пакет не принят")
        }
        val pack = RulePack.fromJson(String(payload, Charsets.UTF_8))
        validate(pack)
        if (installedVersion != null && compareVersions(pack.version, installedVersion) < 0) {
            throw RulePackException("Пакет ${pack.version} старее установленного $installedVersion — откат правил запрещён")
        }
        return pack
    }

    private fun verifySignature(keyB64: String, payload: ByteArray, signature: ByteArray): Boolean = try {
        val key = KeyFactory.getInstance("EC").generatePublic(X509EncodedKeySpec(Base64.getDecoder().decode(keyB64)))
        Signature.getInstance(RulePackSigner.SIGNATURE_ALGORITHM).apply { initVerify(key); update(payload) }.verify(signature)
    } catch (e: Exception) {
        false
    }

    private fun validate(p: RulePack) {
        if (!VERSION.matches(p.version)) throw RulePackException("Некорректная версия пакета: ${p.version}")
        if (p.baseCatalog != RuleCatalog.VERSION) {
            throw RulePackException("Пакет рассчитан на набор правил ${p.baseCatalog}, а в приложении ${RuleCatalog.VERSION}")
        }
        val known = RuleCatalog.all.map { it.id }.toSet()
        (p.weightOverrides.keys + p.disabledRules).firstOrNull { it !in known }?.let {
            throw RulePackException("В пакете неизвестное правило: $it")
        }
        p.weightOverrides.entries.firstOrNull { it.value !in 0..100 }?.let {
            throw RulePackException("Вес правила ${it.key} вне 0..100: ${it.value}")
        }
        val high = p.highThreshold ?: RuleParams.DEFAULT.highThreshold
        val attention = p.attentionThreshold ?: RuleParams.DEFAULT.attentionThreshold
        if (attention !in 5..95 || high !in 10..100 || high <= attention) {
            throw RulePackException("Недопустимые пороги: «Нужно внимание» $attention, «Высокий риск» $high")
        }
        p.suspiciousTlds?.firstOrNull { !TLD.matches(it) }?.let { throw RulePackException("Некорректная доменная зона: $it") }
        p.publicDns?.firstOrNull { !IPV4.matches(it) }?.let { throw RulePackException("Некорректный IP: $it") }
        listOfNotNull(p.suspiciousTlds, p.dynamicDns, p.publicDns, p.messengerC2).forEach { list ->
            if (list.size > MAX_LIST) throw RulePackException("Слишком длинный список в пакете")
            if (list.any { it.isBlank() || it.length > 100 }) throw RulePackException("Некорректное значение в списке")
        }
    }

    companion object {
        private val VERSION = Regex("""^\d{1,6}(\.\d{1,6}){1,3}$""")
        private val TLD = Regex("^[a-z0-9-]{2,24}$")
        private val IPV4 = Regex("""^\d{1,3}(\.\d{1,3}){3}$""")
        private const val MAX_LIST = 2000

        /** Сравнение версий по числам: 2026.11.10 новее 2026.11.9. */
        fun compareVersions(a: String, b: String): Int {
            val x = a.split('.').map { it.toIntOrNull() ?: 0 }
            val y = b.split('.').map { it.toIntOrNull() ?: 0 }
            for (i in 0 until maxOf(x.size, y.size)) {
                val c = (x.getOrElse(i) { 0 }).compareTo(y.getOrElse(i) { 0 })
                if (c != 0) return c
            }
            return 0
        }
    }
}
