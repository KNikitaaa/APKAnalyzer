package com.apkanalyzer.rules.pack

/**
 * Открытые ключи, которыми должны быть подписаны пакеты правил. Закрытый ключ хранится у автора правил
 * вне репозитория. Чтобы сменить ключ: `gradlew :core:rulePackKeygen`, добавить новый открытый ключ сюда,
 * выпустить версию приложения, и только потом подписывать пакеты новым ключом.
 */
object RulePackKeys {
    val TRUSTED: List<String> = listOf(
        // Ключ автора правил, создан 23.10.2026 (keyId в каждом подписанном пакете).
        "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEOr874tM2zhdlXRtKlgddXni3itRrllhHKvCTmV1BBQN1n4xvJ12ojCF6KAeJ+gm7SNgpfd2uYv0aUPxIDdqDoA==",
    )
}
