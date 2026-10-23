package com.apkanalyzer.analyzer.util

/**
 * Минимальный JSON без внешних зависимостей: детерминированная запись (порядок ключей сохраняется)
 * и строгий разбор с ограничениями глубины и размера — отчёты читаются из базы и из файлов.
 */
sealed class JsonValue {
    data class Obj(val fields: LinkedHashMap<String, JsonValue> = LinkedHashMap()) : JsonValue() {
        operator fun get(key: String): JsonValue? = fields[key]
        fun put(key: String, value: JsonValue?): Obj = apply { fields[key] = value ?: Null }
        fun put(key: String, value: String?): Obj = put(key, value?.let(::Str))
        fun put(key: String, value: Number?): Obj = put(key, value?.let(::Num))
        fun put(key: String, value: Boolean?): Obj = put(key, value?.let(::Bool))
    }
    data class Arr(val items: List<JsonValue>) : JsonValue()
    data class Str(val value: String) : JsonValue()
    data class Num(val value: Number) : JsonValue()
    data class Bool(val value: Boolean) : JsonValue()
    data object Null : JsonValue()

    // ---- удобный доступ при чтении
    fun obj(key: String): Obj? = (this as? Obj)?.get(key) as? Obj
    fun arr(key: String): List<JsonValue> = ((this as? Obj)?.get(key) as? Arr)?.items.orEmpty()
    fun str(key: String): String? = ((this as? Obj)?.get(key) as? Str)?.value
    fun long(key: String): Long? = ((this as? Obj)?.get(key) as? Num)?.value?.toLong()
    fun int(key: String): Int? = long(key)?.toInt()
    fun double(key: String): Double? = ((this as? Obj)?.get(key) as? Num)?.value?.toDouble()
    fun bool(key: String): Boolean? = ((this as? Obj)?.get(key) as? Bool)?.value
}

class JsonException(message: String) : RuntimeException(message)

object Json {

    fun write(value: JsonValue, pretty: Boolean = true): String = StringBuilder().also { writeTo(it, value, pretty, 0) }.toString()

    private fun writeTo(sb: StringBuilder, v: JsonValue, pretty: Boolean, indent: Int) {
        when (v) {
            is JsonValue.Null -> sb.append("null")
            is JsonValue.Bool -> sb.append(v.value)
            is JsonValue.Num -> sb.append(formatNumber(v.value))
            is JsonValue.Str -> quote(sb, v.value)
            is JsonValue.Arr -> {
                if (v.items.isEmpty()) { sb.append("[]"); return }
                sb.append('[')
                v.items.forEachIndexed { i, item ->
                    if (i > 0) sb.append(',')
                    newline(sb, pretty, indent + 1)
                    writeTo(sb, item, pretty, indent + 1)
                }
                newline(sb, pretty, indent)
                sb.append(']')
            }
            is JsonValue.Obj -> {
                if (v.fields.isEmpty()) { sb.append("{}"); return }
                sb.append('{')
                var first = true
                for ((k, item) in v.fields) {
                    if (!first) sb.append(',')
                    first = false
                    newline(sb, pretty, indent + 1)
                    quote(sb, k)
                    sb.append(if (pretty) ": " else ":")
                    writeTo(sb, item, pretty, indent + 1)
                }
                newline(sb, pretty, indent)
                sb.append('}')
            }
        }
    }

    private fun formatNumber(n: Number): String = when (n) {
        is Int, is Long, is Short, is Byte -> n.toString()
        else -> {
            val d = n.toDouble()
            require(d.isFinite()) { "JSON не поддерживает $d" }
            if (d == Math.rint(d) && kotlin.math.abs(d) < 1e15) d.toLong().toString() else d.toString()
        }
    }

    private fun newline(sb: StringBuilder, pretty: Boolean, indent: Int) {
        if (!pretty) return
        sb.append('\n')
        repeat(indent) { sb.append("  ") }
    }

    private fun quote(sb: StringBuilder, s: String) {
        sb.append('"')
        for (c in s) {
            when (c) {
                '"' -> sb.append("\\\"")
                '\\' -> sb.append("\\\\")
                '\n' -> sb.append("\\n")
                '\r' -> sb.append("\\r")
                '\t' -> sb.append("\\t")
                '\b' -> sb.append("\\b")
                '\u000C' -> sb.append("\\f")
                else -> if (c < ' ' || c == ' ' || c == ' ') sb.append("\\u%04x".format(c.code)) else sb.append(c)
            }
        }
        sb.append('"')
    }

    fun parse(text: String, maxDepth: Int = 64, maxLength: Int = 32 * 1024 * 1024): JsonValue {
        if (text.length > maxLength) throw JsonException("JSON слишком большой")
        val p = Parser(text, maxDepth)
        val v = p.value(0)
        p.skipWs()
        if (!p.atEnd()) throw JsonException("Лишние данные после JSON на позиции ${p.pos}")
        return v
    }

    private class Parser(val s: String, val maxDepth: Int) {
        var pos = 0

        fun atEnd() = pos >= s.length
        fun skipWs() { while (pos < s.length && s[pos].isWhitespace()) pos++ }
        private fun fail(msg: String): Nothing = throw JsonException("$msg (позиция $pos)")

        fun value(depth: Int): JsonValue {
            if (depth > maxDepth) fail("Слишком глубокая вложенность")
            skipWs()
            if (atEnd()) fail("Неожиданный конец JSON")
            return when (val c = s[pos]) {
                '{' -> obj(depth)
                '[' -> arr(depth)
                '"' -> JsonValue.Str(string())
                't' -> literal("true", JsonValue.Bool(true))
                'f' -> literal("false", JsonValue.Bool(false))
                'n' -> literal("null", JsonValue.Null)
                else -> if (c == '-' || c.isDigit()) number() else fail("Неожиданный символ '$c'")
            }
        }

        private fun literal(word: String, v: JsonValue): JsonValue {
            if (!s.startsWith(word, pos)) fail("Ожидалось $word")
            pos += word.length
            return v
        }

        private fun obj(depth: Int): JsonValue {
            pos++
            val o = JsonValue.Obj()
            skipWs()
            if (pos < s.length && s[pos] == '}') { pos++; return o }
            while (true) {
                skipWs()
                if (atEnd() || s[pos] != '"') fail("Ожидался ключ")
                val k = string()
                skipWs()
                if (atEnd() || s[pos] != ':') fail("Ожидалось ':'")
                pos++
                o.fields[k] = value(depth + 1)
                skipWs()
                if (atEnd()) fail("Объект не закрыт")
                when (s[pos++]) {
                    ',' -> continue
                    '}' -> return o
                    else -> fail("Ожидалось ',' или '}'")
                }
            }
        }

        private fun arr(depth: Int): JsonValue {
            pos++
            val items = ArrayList<JsonValue>()
            skipWs()
            if (pos < s.length && s[pos] == ']') { pos++; return JsonValue.Arr(items) }
            while (true) {
                items += value(depth + 1)
                skipWs()
                if (atEnd()) fail("Массив не закрыт")
                when (s[pos++]) {
                    ',' -> continue
                    ']' -> return JsonValue.Arr(items)
                    else -> fail("Ожидалось ',' или ']'")
                }
            }
        }

        private fun string(): String {
            pos++ // "
            val sb = StringBuilder()
            while (true) {
                if (atEnd()) fail("Строка не закрыта")
                val c = s[pos++]
                when {
                    c == '"' -> return sb.toString()
                    c == '\\' -> {
                        if (atEnd()) fail("Обрыв escape-последовательности")
                        when (val e = s[pos++]) {
                            '"' -> sb.append('"'); '\\' -> sb.append('\\'); '/' -> sb.append('/')
                            'b' -> sb.append('\b'); 'f' -> sb.append('\u000C'); 'n' -> sb.append('\n')
                            'r' -> sb.append('\r'); 't' -> sb.append('\t')
                            'u' -> {
                                if (pos + 4 > s.length) fail("Обрыв \\u")
                                val code = s.substring(pos, pos + 4).toIntOrNull(16) ?: fail("Неверный \\u")
                                sb.append(code.toChar()); pos += 4
                            }
                            else -> fail("Неизвестный escape '\\$e'")
                        }
                    }
                    c < ' ' -> fail("Управляющий символ в строке")
                    else -> sb.append(c)
                }
            }
        }

        private fun number(): JsonValue {
            val start = pos
            if (s[pos] == '-') pos++
            while (pos < s.length && (s[pos].isDigit() || s[pos] in ".eE+-")) pos++
            val t = s.substring(start, pos)
            val isInt = t.none { it == '.' || it == 'e' || it == 'E' }
            return JsonValue.Num(
                if (isInt) t.toLongOrNull() ?: fail("Неверное число '$t'") else t.toDoubleOrNull() ?: fail("Неверное число '$t'"),
            )
        }
    }
}
