package com.apkanalyzer.analyzer.strings

enum class IndicatorType(val labelRu: String) {
    URL("URL"),
    DOMAIN("Домен"),
    IPV4("IP-адрес"),
    SHELL_COMMAND("Shell-команда"),
    SUSPICIOUS_PATH("Системный путь"),
    CONTENT_URI("Content URI"),
}

/** Индикатор, найденный в строках APK, со ссылкой на источник. */
data class StringIndicator(
    val type: IndicatorType,
    val value: String,
    /** Где найден: имя файла внутри APK (classes.dex, assets/config.json, ...). */
    val source: String,
    /** Для IP: частный/локальный адрес (обычно не опасен). */
    val isPrivate: Boolean = false,
)

/**
 * Ищет в строках URL, домены, IP-адреса, shell-команды и чувствительные пути.
 *
 * Принцип — точность важнее полноты: имена Java-пакетов (`com.google.android`)
 * не должны превращаться в «домены», а номера версий — в «IP-адреса».
 * Каждый тип ограничен [maxPerType] значениями, строки обрезаются до [maxValueLength].
 */
class IndicatorExtractor(
    private val maxPerType: Int = 300,
    private val maxValueLength: Int = 256,
) {
    private val found = LinkedHashMap<Pair<IndicatorType, String>, StringIndicator>()
    private val counts = IntArray(IndicatorType.entries.size)

    /** Был ли достигнут лимит хотя бы по одному типу. */
    var truncated: Boolean = false
        private set

    val indicators: List<StringIndicator> get() = found.values.toList()

    fun scan(text: String, source: String) {
        if (text.length < 4) {
            if (text == "su") add(IndicatorType.SHELL_COMMAND, text, source)
            return
        }
        val lower = text.lowercase()

        if (lower.contains("://")) {
            for (m in URL_REGEX.findAll(text)) {
                val url = m.value.trimEnd('.', ',', ')', '"', '\'', ';')
                if (url.startsWith("content://", ignoreCase = true)) {
                    add(IndicatorType.CONTENT_URI, url, source)
                    continue
                }
                if (isNoiseUrl(url)) continue
                add(IndicatorType.URL, url, source)
                hostOf(url)?.let { host ->
                    if (isIpv4(host)) addIp(host, source) else if (isPlausibleDomain(host)) add(IndicatorType.DOMAIN, host, source)
                }
            }
        } else if (BARE_HOST_REGEX.matches(lower) && isPlausibleDomain(lower) && !looksLikePackageName(lower)) {
            add(IndicatorType.DOMAIN, lower, source)
        }

        if (text.any { it == '.' } && text.any(Char::isDigit)) {
            for (m in IPV4_REGEX.findAll(text)) {
                val ip = m.value
                if (isIpv4(ip) && !looksLikeVersion(text, m.range)) addIp(ip, source)
            }
        }

        if (SHELL_HINTS.any { lower.contains(it) } && SHELL_REGEX.containsMatchIn(lower)) {
            add(IndicatorType.SHELL_COMMAND, text, source)
        }
        for (path in SUSPICIOUS_PATHS) {
            if (lower.contains(path)) {
                add(IndicatorType.SUSPICIOUS_PATH, text, source)
                break
            }
        }
    }

    private fun addIp(ip: String, source: String) {
        add(IndicatorType.IPV4, ip, source, isPrivate = isPrivateIp(ip))
    }

    private fun add(type: IndicatorType, raw: String, source: String, isPrivate: Boolean = false) {
        val value = raw.trim().take(maxValueLength)
        if (value.isEmpty()) return
        val key = type to value
        if (key in found) return
        if (counts[type.ordinal] >= maxPerType) {
            truncated = true
            return
        }
        counts[type.ordinal]++
        found[key] = StringIndicator(type, value, source, isPrivate)
    }

    companion object {
        private val URL_REGEX = Regex("""(?i)\b(?:https?|ftp|wss?|content)://[^\s"'<>\\^`{|}]{2,}""")
        private val IPV4_REGEX = Regex("""(?<![\d.])(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?![\d.])""")
        private val BARE_HOST_REGEX = Regex("""^(?=.{4,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}$""")

        /** Домены верхнего уровня, при которых «голая» строка считается адресом, а не идентификатором. */
        private val TLDS = setOf(
            "com", "net", "org", "info", "biz", "io", "co", "me", "xyz", "top", "site", "online", "club", "app",
            "dev", "pro", "live", "shop", "store", "tech", "space", "website", "fun", "icu", "vip", "work", "link",
            "click", "cc", "tk", "ml", "ga", "cf", "gq", "pw", "ws", "su", "ru", "by", "kz", "ua", "uz", "cn", "hk",
            "tw", "jp", "kr", "in", "id", "vn", "th", "ir", "tr", "br", "de", "fr", "uk", "nl", "pl", "es", "it",
            "eu", "us", "ca", "au", "ly", "to", "tv", "gg", "onion",
        )

        /** Первые сегменты типичных имён пакетов/классов — `com.example.app` не является доменом. */
        private val PACKAGE_PREFIXES = setOf(
            "com", "org", "net", "io", "android", "androidx", "java", "javax", "kotlin", "kotlinx", "dalvik",
            "google", "me", "dev", "app",
        )

        private val NOISE_HOSTS = setOf(
            "schemas.android.com", "www.w3.org", "ns.adobe.com", "xml.org", "xmlpull.org", "apache.org",
            "www.apache.org", "purl.org", "json-schema.org",
        )

        private val SHELL_HINTS = listOf(
            "/system/bin/", "/system/xbin/", "chmod ", "chown ", "pm install", "pm uninstall", "pm disable",
            "pm hide", "am start", "am broadcast", "getprop", "setprop", "busybox", "mount -o", "su -c", "/sbin/su",
            "iptables", "reboot", "settings put", "screencap", "input tap", "input keyevent", "logcat",
            "rm -rf", "dd if=", "insmod", "kill -9",
        )
        private val SHELL_REGEX = Regex("""(^|[\s/;&|"'])(su|sh|chmod|chown|pm|am|getprop|setprop|busybox|mount|iptables|reboot|settings|screencap|input|logcat|rm|dd|insmod|kill)(\s|$)""")

        private val SUSPICIOUS_PATHS = listOf(
            "/data/local/tmp", "/system/app/", "/system/priv-app/", "/proc/self/maps", "/proc/net/",
            "/data/data/com.android.providers.telephony", "/dev/socket/", "/system/xbin/su", "/sbin/su",
            "/data/system/packages", "magisk", "/system/framework/xposed",
        )

        fun hostOf(url: String): String? {
            val afterScheme = url.substringAfter("://", "")
            if (afterScheme.isEmpty()) return null
            val authority = afterScheme.substringBefore('/').substringBefore('?').substringBefore('#')
            val host = authority.substringAfterLast('@').let {
                if (it.startsWith("[")) it.substringBefore(']').removePrefix("[") else it.substringBefore(':')
            }.lowercase().trimEnd('.')
            return host.ifEmpty { null }
        }

        fun isIpv4(s: String): Boolean {
            val parts = s.split('.')
            if (parts.size != 4) return false
            return parts.all { p -> p.isNotEmpty() && p.length <= 3 && p.all(Char::isDigit) && p.toInt() <= 255 && !(p.length > 1 && p.startsWith("0")) }
        }

        fun isPrivateIp(ip: String): Boolean {
            val o = ip.split('.').map { it.toInt() }
            return o[0] == 10 || o[0] == 127 || o[0] == 0 ||
                (o[0] == 172 && o[1] in 16..31) ||
                (o[0] == 192 && o[1] == 168) ||
                (o[0] == 169 && o[1] == 254) ||
                (o[0] == 100 && o[1] in 64..127) ||
                o[0] >= 224
        }

        fun isPlausibleDomain(host: String): Boolean {
            if (host in NOISE_HOSTS || host == "localhost") return false
            val labels = host.split('.')
            if (labels.size < 2) return false
            if (labels.any { it.isEmpty() || it.length > 63 }) return false
            return labels.last() in TLDS
        }

        private fun looksLikePackageName(s: String): Boolean {
            val first = s.substringBefore('.')
            return first in PACKAGE_PREFIXES && s.count { it == '.' } >= 2
        }

        private fun isNoiseUrl(url: String): Boolean {
            val host = hostOf(url) ?: return true
            return host in NOISE_HOSTS || host.isEmpty() || host == "localhost"
        }

        /** «1.2.3.4» внутри строк вроде "version 1.2.3.4" или "v1.0.0.1" — скорее версия. */
        private fun looksLikeVersion(text: String, range: IntRange): Boolean {
            val before = text.substring(0, range.first).trimEnd().lowercase()
            return before.endsWith("v") || before.endsWith("version") || before.endsWith("ver") ||
                before.endsWith("build") || text.substring(range).startsWith("0.")
        }
    }
}
