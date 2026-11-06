package com.apkanalyzer.testing

import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * Минимальный генератор resources.arsc (как у aapt2) для тестов: один пакет 0x7f, тип `string` (id 1).
 * [values]: имя ресурса → (язык или "" для конфигурации по умолчанию → значение).
 * Значение-строка записывается как TYPE_STRING, значение [Ref] — как ссылка на другой ресурс.
 */
object ArscWriter {
    fun write(values: Map<String, Map<String, Any>>, sparse: Boolean = false): ByteArray {
        val keys = values.keys.toList()
        val languages = values.values.flatMap { it.keys }.distinct().sorted()
        val globalStrings = values.values.flatMap { it.values }.filterIsInstance<String>().distinct()

        val pkg = ByteArrayOutputStream()
        val typeStrings = pool(listOf("string"))
        val keyStrings = pool(keys)
        val headerSize = 288
        val typeStringsOff = headerSize
        val keyStringsOff = typeStringsOff + typeStrings.size

        val spec = chunk(0x0202, 16, le { put(1); put(0); putShort(0); putInt(keys.size) } + le { keys.forEach { _ -> putInt(0) } })
        val types = languages.map { lang ->
            val present = keys.withIndex().filter { (_, k) -> values.getValue(k).containsKey(lang) }
            val entries = ByteArrayOutputStream()
            val offsets = IntArray(keys.size) { -1 }
            for ((i, k) in present) {
                offsets[i] = entries.size()
                val v = values.getValue(k).getValue(lang)
                val (type, data) = when (v) {
                    is String -> 0x03 to globalStrings.indexOf(v)
                    is Ref -> 0x01 to v.id
                    else -> error("значение $v")
                }
                entries.write(le { putShort(8); putShort(0); putInt(i); putShort(8); put(0); put(type.toByte()); putInt(data) })
            }
            val config = ByteArray(64).also { c ->
                ByteBuffer.wrap(c).order(ByteOrder.LITTLE_ENDIAN).putInt(0, 64)
                if (lang.isNotEmpty()) { c[8] = lang[0].code.toByte(); c[9] = lang[1].code.toByte() }
            }
            val table = if (sparse) {
                le { present.forEach { (i, _) -> putShort(i.toShort()); putShort((offsets[i] / 4).toShort()) } }
            } else {
                le { offsets.forEach { putInt(it) } }
            }
            val count = if (sparse) present.size else keys.size
            val hdr = 20 + config.size
            val payload = le { put(1); put(if (sparse) 1 else 0); putShort(0); putInt(count); putInt(hdr + table.size) } + config
            chunk(0x0201, hdr, payload + table + entries.toByteArray())
        }
        val body = typeStrings + keyStrings + spec + types.fold(ByteArray(0)) { a, b -> a + b }
        val name = ByteArray(256).also { n -> "com.example.sample".forEachIndexed { i, ch -> n[i * 2] = ch.code.toByte() } }
        val pkgHeaderPayload = le { putInt(0x7f) } + name + le { putInt(typeStringsOff); putInt(1); putInt(keyStringsOff); putInt(keys.size); putInt(0) }
        pkg.write(chunk(0x0200, headerSize, pkgHeaderPayload + body))

        val global = pool(globalStrings)
        return chunk(0x0002, 12, le { putInt(1) } + global + pkg.toByteArray())
    }

    /** Пул строк UTF-8. */
    private fun pool(strings: List<String>): ByteArray {
        val data = ByteArrayOutputStream()
        val offsets = strings.map { s ->
            val off = data.size()
            val bytes = s.toByteArray(Charsets.UTF_8)
            fun len(n: Int) = if (n < 0x80) data.write(n) else { data.write(0x80 or (n shr 8)); data.write(n and 0xFF) }
            len(s.length); len(bytes.size); data.write(bytes); data.write(0)
            off
        }
        while (data.size() % 4 != 0) data.write(0)
        val hdr = 28
        val stringsStart = hdr + strings.size * 4
        val payload = le { putInt(strings.size); putInt(0); putInt(0x100); putInt(stringsStart); putInt(0) } +
            le { offsets.forEach { putInt(it) } } + data.toByteArray()
        return chunk(0x0001, hdr, payload)
    }

    /** Чанк: type u16, headerSize u16, size u32 и содержимое (часть заголовка + данные). */
    private fun chunk(type: Int, headerSize: Int, payload: ByteArray): ByteArray =
        le { putShort(type.toShort()); putShort(headerSize.toShort()); putInt(8 + payload.size) } + payload

    private fun le(block: ByteBuffer.() -> Unit): ByteArray {
        val b = ByteBuffer.allocate(4096).order(ByteOrder.LITTLE_ENDIAN)
        b.block()
        return b.array().copyOf(b.position())
    }
}
