package com.apkanalyzer.rules

/**
 * Настраиваемые параметры движка: пороги, переопределения весов и списки, по которым работают правила.
 * Встроенные значения — [DEFAULT]; подписанный пакет правил ([com.apkanalyzer.rules.pack.RulePack])
 * может их обновить без выпуска новой версии приложения. Логика правил при этом не меняется.
 */
data class RuleParams(
    /** Версия, которая записывается в отчёт: версия каталога или «каталог+пакет». */
    val version: String,
    val highThreshold: Int,
    val attentionThreshold: Int,
    val weightOverrides: Map<String, Int>,
    val disabledRules: Set<String>,
    /** Доменные зоны, популярные у злоумышленников. */
    val suspiciousTlds: Set<String>,
    /** Сервисы динамического DNS и туннелей (подстроки). */
    val dynamicDns: List<String>,
    /** Публичные DNS-резолверы: их IP не считаются «зашитым сервером». */
    val publicDns: Set<String>,
    /** Адреса мессенджеров, которые используют как канал слива данных (подстроки). */
    val messengerC2: List<String>,
    /** Официальные подписи популярных приложений: пакет → разработчик и сертификаты. */
    val trustedSigners: Map<String, TrustedSigner> = BuiltinSigners.ALL,
) {
    fun weightOf(rule: Rule): Int = weightOverrides[rule.id] ?: rule.weight

    companion object {
        val DEFAULT = RuleParams(
            version = RuleCatalog.VERSION,
            highThreshold = RiskEngine.HIGH_THRESHOLD,
            attentionThreshold = RiskEngine.ATTENTION_THRESHOLD,
            weightOverrides = emptyMap(),
            disabledRules = emptySet(),
            suspiciousTlds = setOf(
                "top", "xyz", "tk", "ml", "ga", "cf", "gq", "pw", "icu", "click", "link", "work", "cc", "su", "onion",
                "buzz", "rest", "cyou", "monster", "lol", "sbs", "cfd", "zip", "mov",
            ),
            dynamicDns = listOf("duckdns.org", "no-ip.", "ddns.net", "ngrok", "serveo.net", "dynu.", "hopto.org", "zapto.org"),
            publicDns = setOf(
                "1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9", "149.112.112.112", "208.67.222.222", "208.67.220.220",
                "223.5.5.5", "223.6.6.6", "114.114.114.114", "119.29.29.29", "180.76.76.76", "94.140.14.14", "94.140.15.15",
                "77.88.8.8", "77.88.8.1", "185.228.168.9", "76.76.2.0", "76.76.10.0",
            ),
            messengerC2 = listOf("api.telegram.org", "discord.com/api/webhooks", "discordapp.com/api/webhooks", "hooks.slack.com"),
        )
    }
}
