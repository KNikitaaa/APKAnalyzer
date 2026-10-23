package com.apkanalyzer.ai

import com.apkanalyzer.analyzer.report.FeatureEmphasis
import com.apkanalyzer.analyzer.util.Json
import com.apkanalyzer.analyzer.util.JsonValue
import com.apkanalyzer.report.ReportDocument

/** Что пользователь разрешил передавать в AI сверх обязательного минимума. */
data class AiPrivacyOptions(
    /** Передавать домены и URL (иначе они заменяются на «<домен>»). */
    val includeDomains: Boolean = false,
    /** Передавать имя пакета и версию приложения. */
    val includePackageName: Boolean = true,
)

/**
 * Структурированный набор фактов — ровно то, что уходит в AI и что пользователь видит в предпросмотре.
 * Никогда не содержит: байты APK, URI/путь к файлу, имя файла, SHA-256, данные о самом устройстве.
 */
data class AiFacts(val json: JsonValue.Obj) {
    val fragmentCount: Int get() = json.arr("fragments").size
    val triggeredRuleIds: Set<String> get() = json.arr("triggeredRules").mapNotNull { it.str("id") }.toSet()

    fun toJsonString(pretty: Boolean = true): String = Json.write(json, pretty)
}

object AiFactsBuilder {
    const val SCHEMA = "apk-facts/v1"
    const val MAX_FRAGMENTS = 20
    const val MAX_FRAGMENT_CHARS = 200
    private const val MAX_RULES = 40

    fun build(doc: ReportDocument, options: AiPrivacyOptions = AiPrivacyOptions()): AiFacts {
        val clean = { s: String -> FragmentSanitizer.sanitize(s, options.includeDomains) }
        val root = JsonValue.Obj()
            .put("schema", SCHEMA)
            .put("engine", JsonValue.Obj()
                .put("riskLevel", doc.risk.code.name)
                .put("riskLabel", doc.risk.labelRu)
                .put("score", doc.risk.score)
                .put("reason", clean(doc.risk.reasonRu).take(400))
                .put("coverage", doc.risk.coverage.toDouble().let { Math.round(it * 100) / 100.0 })
                .put("rulesVersion", doc.rulesVersion))

        doc.app?.let { a ->
            val app = JsonValue.Obj().put("minSdk", a.minSdk).put("targetSdk", a.targetSdk)
            if (options.includePackageName) app.put("packageName", a.packageName).put("versionName", a.versionName?.take(40))
            root.put("app", app)
        }

        root.put("triggeredRules", JsonValue.Arr(doc.findings.take(MAX_RULES).map { f ->
            JsonValue.Obj().put("id", f.ruleId).put("title", f.titleRu).put("category", f.categoryRu)
                .put("weight", Math.round(f.effectiveWeight)).put("combination", f.combination)
                .apply { if (f.mitigations.isNotEmpty()) put("mitigations", JsonValue.Arr(f.mitigations.map { JsonValue.Str(it) })) }
        }))

        // Разрешения по категориям (из раздела «Разрешения» отчёта).
        val perms = doc.sections.firstOrNull { it.id == "permissions" }?.items.orEmpty()
            .filter { it.value != null }
            .groupBy({ it.value!! }, { it.title })
        root.put("permissionCategories", JsonValue.Arr(perms.map { (cat, list) ->
            JsonValue.Obj().put("category", cat).put("permissions", JsonValue.Arr(list.take(15).map { JsonValue.Str(it) }))
        }))

        // Экспортируемые компоненты — только типы и действия, без имён классов.
        val exported = doc.sections.firstOrNull { it.id == "components" }?.items.orEmpty()
            .mapNotNull { it.value }.filter { "exported" in it }
        val byType = exported.groupBy { it.substringBefore(" ·") }
        root.put("exportedComponents", JsonValue.Arr(byType.map { (type, list) ->
            val actions = list.flatMap { v -> v.split(" · ").filter { p -> p.isNotBlank() && !p.startsWith("exported") && p != type && !p.startsWith("защищён") && !p.startsWith("authorities") } }
                .flatMap { it.split(", ") }.distinct().take(10)
            JsonValue.Obj().put("type", type).put("count", list.size).put("actions", JsonValue.Arr(actions.map { JsonValue.Str(clean(it).take(80)) }))
        }))

        val apis = doc.sections.firstOrNull { it.id == "code" }?.items.orEmpty()
            .filter { it.emphasis != FeatureEmphasis.NORMAL && it.title.contains('.') }
        root.put("sensitiveApis", JsonValue.Arr(apis.take(30).map { JsonValue.Obj().put("api", it.title).put("category", it.value?.substringBefore(':')) }))

        if (options.includeDomains) {
            val domains = doc.sections.firstOrNull { it.id == "network" }?.items.orEmpty()
                .map { it.title }.filter { !it.contains("://") }.distinct().take(20)
            root.put("domains", JsonValue.Arr(domains.map { JsonValue.Str(clean(it).take(100)) }))
        }

        root.put("fragments", JsonValue.Arr(selectFragments(doc, options).map {
            JsonValue.Obj().put("type", it.type).put("reason", it.reason).put("content", it.content)
        }))
        if (doc.limitations.isNotEmpty()) root.put("limitations", JsonValue.Arr(doc.limitations.take(6).map { JsonValue.Str(clean(it).take(200)) }))
        return AiFacts(root)
    }

    /** До [MAX_FRAGMENTS] фрагментов: сначала доказательства самых весомых правил, затем подозрительные строки. */
    fun selectFragments(doc: ReportDocument, options: AiPrivacyOptions): List<SuspiciousFragment> {
        val out = LinkedHashMap<String, SuspiciousFragment>()
        fun add(type: String, reason: String, raw: String) {
            if (out.size >= MAX_FRAGMENTS) return
            val content = FragmentSanitizer.sanitize(raw, options.includeDomains).take(MAX_FRAGMENT_CHARS)
            if (content.isBlank() || content in out) return
            out[content] = SuspiciousFragment(content, reason.take(120), type)
        }
        for (f in doc.findings.sortedByDescending { it.effectiveWeight }) {
            for (e in f.evidence.take(3)) add(typeOf(e.source), f.titleRu, "${e.source}: ${e.detail}")
        }
        doc.sections.firstOrNull { it.id == "strings" }?.items.orEmpty().forEach { add("string", it.value?.substringBefore(" ·") ?: "строка", it.title) }
        return out.values.toList()
    }

    private fun typeOf(source: String): String = when {
        source == "Манифест" -> "manifest"
        source == "Подпись" -> "signature"
        source == "Структура архива" -> "archive"
        source.contains(".dex") || source == "DEX" -> "code"
        source.startsWith("assets/") || source.startsWith("res/") -> "resource"
        source.startsWith("lib/") -> "native"
        else -> "other"
    }
}

/**
 * Очистка строк из APK перед отправкой: убираем управляющие и «невидимые» символы, маскируем похожее на
 * секреты (токены, ключи, email, телефоны), при необходимости скрываем домены и IP. Содержимое строк при этом
 * остаётся данными — от инструкций внутри них защищает системный запрос и проверка ответа.
 */
object FragmentSanitizer {
    private val CONTROL = Regex("[\\p{Cc}\\p{Cf}&&[^\\n\\t]]")
    private val WS = Regex("\\s+")
    private val TELEGRAM_TOKEN = Regex("\\b(bot)?\\d{6,12}:[A-Za-z0-9_-]{30,}")
    private val LONG_SECRET = Regex("[A-Za-z0-9+/_=-]{40,}")
    private val API_KEY_PREFIX = Regex("\\b(sk-[A-Za-z0-9_-]{16,}|AIza[0-9A-Za-z_-]{20,}|ghp_[A-Za-z0-9]{20,})")
    private val EMAIL = Regex("[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}")
    private val PHONE = Regex("(?<![\\d.])\\+?\\d[\\d ()-]{9,}\\d(?![\\d.])")
    private val URL = Regex("(?i)\\b(https?|wss?|ftp)://[^\\s\"'<>]+")
    private val HOST = Regex("(?i)\\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\\.)+(?:com|net|org|info|biz|io|co|me|xyz|top|site|online|club|app|dev|pro|live|shop|store|tech|space|icu|vip|work|link|click|cc|tk|ml|ga|cf|gq|pw|su|ru|by|kz|ua|cn|hk|onion|buzz|lol|sbs|cfd)\\b")
    private val IPV4 = Regex("(?<![\\d.])(?:\\d{1,3}\\.){3}\\d{1,3}(?![\\d.])")

    fun sanitize(input: String, keepDomains: Boolean): String {
        var s = CONTROL.replace(input, "")
        s = WS.replace(s, " ").trim()
        s = TELEGRAM_TOKEN.replace(s) { m -> (m.groupValues[1]) + "<токен скрыт>" }
        s = API_KEY_PREFIX.replace(s, "<ключ скрыт>")
        s = EMAIL.replace(s, "<email>")
        if (!keepDomains) {
            s = URL.replace(s) { m -> m.groupValues[1].lowercase() + "://<домен>" }
            s = HOST.replace(s, "<домен>")
            s = IPV4.replace(s, "<IP>")
        }
        s = LONG_SECRET.replace(s) { m -> "<скрыто ${m.value.length} симв.>" }
        s = PHONE.replace(s, "<телефон>")
        return s
    }
}
