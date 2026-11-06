package com.apkanalyzer.rules.pack

import java.io.File
import java.security.KeyFactory
import java.security.KeyPair
import java.security.spec.X509EncodedKeySpec
import java.util.Base64

/**
 * Инструмент автора правил (запускается на компьютере, не на телефоне):
 *
 *  - `keygen <файл-ключа>` — новая пара ключей; открытый ключ добавить в [RulePackKeys.TRUSTED];
 *  - `sign <pack.json> <файл-ключа> <out.rulepack>` — проверить пакет и подписать его.
 *
 * Файл ключа содержит закрытый ключ — его нельзя класть в репозиторий.
 */
object RulePackTool {
    @JvmStatic
    fun main(args: Array<String>) {
        when (args.firstOrNull()) {
            "keygen" -> keygen(File(args.getOrNull(1) ?: usage()))
            "sign" -> sign(File(args.getOrNull(1) ?: usage()), File(args.getOrNull(2) ?: usage()), File(args.getOrNull(3) ?: usage()))
            else -> usage()
        }
    }

    private fun keygen(keyFile: File) {
        require(!keyFile.exists()) { "Файл ${keyFile.path} уже есть — не перезаписываю ключ" }
        val kp = RulePackSigner.generateKeyPair()
        keyFile.parentFile?.mkdirs()
        keyFile.writeText("public=${RulePackSigner.publicKeyBase64(kp)}\nprivate=${RulePackSigner.privateKeyBase64(kp)}\n")
        println("Ключ записан в ${keyFile.absolutePath} (держите его вне репозитория).")
        println("Открытый ключ для RulePackKeys.TRUSTED:\n${RulePackSigner.publicKeyBase64(kp)}")
    }

    private fun sign(packFile: File, keyFile: File, out: File) {
        val kp = readKeyPair(keyFile)
        val pack = RulePack.fromJson(packFile.readText())
        val signed = RulePackSigner.sign(pack, kp)
        // Проверяем результат тем же кодом, что и телефон (ключ должен быть в списке доверенных).
        val verified = RulePackVerifier(listOf(RulePackSigner.publicKeyBase64(kp))).verify(signed)
        out.writeText(signed)
        val trusted = RulePackSigner.publicKeyBase64(kp) in RulePackKeys.TRUSTED
        println("Пакет ${verified.version} подписан: ${out.absolutePath}")
        if (!trusted) println("ВНИМАНИЕ: этого ключа нет в RulePackKeys.TRUSTED — приложение пакет не примет.")
    }

    fun readKeyPair(keyFile: File): KeyPair {
        val fields = keyFile.readLines().mapNotNull { line -> line.split('=', limit = 2).takeIf { it.size == 2 }?.let { it[0].trim() to it[1].trim() } }.toMap()
        val pub = KeyFactory.getInstance("EC").generatePublic(X509EncodedKeySpec(Base64.getDecoder().decode(fields.getValue("public"))))
        return KeyPair(pub, RulePackSigner.privateKeyFromBase64(fields.getValue("private")))
    }

    private fun usage(): Nothing {
        System.err.println("Использование: keygen <файл-ключа> | sign <pack.json> <файл-ключа> <out.rulepack>")
        throw IllegalArgumentException("неверные аргументы")
    }
}
