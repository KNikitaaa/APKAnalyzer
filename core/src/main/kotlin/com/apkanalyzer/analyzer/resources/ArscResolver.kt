package com.apkanalyzer.analyzer.resources

import com.apkanalyzer.analyzer.util.LeBytes

/**
 * Разбор таблицы ресурсов resources.arsc — только для строк (название приложения, versionName),
 * на которые манифест ссылается как `@string/...`. Читатель «недоверчивый»: каждая длина и смещение
 * проверяются, при любой порче возвращается null, циклы ссылок обрываются.
 */
class ArscResolver private constructor(
    private val r: LeBytes,
    private val globalPool: StringPool,
    /** id пакета → id типа → чанки этого типа (по одному на конфигурацию). */
    private val types: Map<Int, Map<Int, List<TypeChunk>>>,
) {
    private class TypeChunk(
        val start: Int,
        val headerSize: Int,
        val entryCount: Int,
        val entriesStart: Int,
        val sparse: Boolean,
        val offset16: Boolean,
        /** Язык конфигурации ("" — по умолчанию). */
        val language: String,
        /** В конфигурации задано что-то кроме языка (плотность, размер экрана…) — менее предпочтительна. */
        val qualified: Boolean,
    )

    /**
     * Строка ресурса [resId] для первой подходящей локали из [locales], иначе — из конфигурации по умолчанию.
     */
    fun string(resId: Int, locales: List<String>): String? = try {
        resolve(resId, locales, depth = 0)
    } catch (_: Exception) {
        null
    }

    private fun resolve(resId: Int, locales: List<String>, depth: Int): String? {
        if (depth > MAX_REF_DEPTH) return null
        val chunks = types[resId ushr 24]?.get((resId ushr 16) and 0xFF) ?: return null
        val entry = resId and 0xFFFF
        val ranked = chunks.mapNotNull { c -> entryOffset(c, entry)?.let { c to it } }
            .sortedBy { (c, _) ->
                val localeRank = locales.indexOf(c.language).let { if (it >= 0) it else if (c.language.isEmpty()) locales.size else locales.size + 1 }
                localeRank * 2 + if (c.qualified) 1 else 0
            }
        for ((c, off) in ranked) {
            val pos = c.start + c.entriesStart + off
            if (pos + 8 > r.size) continue
            val flags = r.u16(pos + 2)
            if (flags and FLAG_COMPLEX != 0) continue
            val entrySize = r.u16(pos)
            val valuePos = pos + entrySize
            if (valuePos + 8 > r.size) continue
            val dataType = r.bytes[valuePos + 3].toInt() and 0xFF
            val data = r.s32(valuePos + 4)
            return when (dataType) {
                TYPE_STRING -> globalPool.get(data)
                TYPE_REFERENCE -> if (data == resId) null else resolve(data, locales, depth + 1)
                else -> null
            }
        }
        return null
    }

    private fun entryOffset(c: TypeChunk, entry: Int): Int? {
        val table = c.start + c.headerSize
        if (c.sparse) {
            // Пары (индекс u16, смещение/4 u16), отсортированы по индексу.
            for (i in 0 until c.entryCount) {
                val p = table + i * 4
                if (p + 4 > r.size) return null
                if (r.u16(p) == entry) return r.u16(p + 2) * 4
            }
            return null
        }
        if (entry >= c.entryCount) return null
        return if (c.offset16) {
            val p = table + entry * 2
            if (p + 2 > r.size) return null
            r.u16(p).takeIf { it != 0xFFFF }?.times(4)
        } else {
            val p = table + entry * 4
            if (p + 4 > r.size) return null
            r.s32(p).takeIf { it != -1 && it >= 0 }
        }
    }

    /** Пул строк ресурсов (UTF-8 или UTF-16). */
    private class StringPool(private val r: LeBytes, private val start: Int) {
        private val count = r.s32(start + 8)
        private val flags = r.s32(start + 16)
        private val stringsStart = r.s32(start + 20)
        private val headerSize = r.u16(start + 2)
        private val utf8 = flags and 0x100 != 0

        init {
            if (count < 0 || count > MAX_STRINGS || start + headerSize + count.toLong() * 4 > r.size) throw IllegalStateException("пул строк")
        }

        fun get(index: Int): String? {
            if (index < 0 || index >= count) return null
            var p = start + stringsStart + r.s32(start + headerSize + index * 4)
            if (p < 0 || p >= r.size) return null
            return if (utf8) {
                p += lenBytes(p) // длина в символах
                val byteLen = len8(p)
                p += lenBytes(p)
                if (byteLen < 0 || p + byteLen > r.size || byteLen > MAX_STRING_BYTES) return null
                String(r.bytes, p, byteLen, Charsets.UTF_8)
            } else {
                var n = r.u16(p)
                p += 2
                if (n and 0x8000 != 0) {
                    n = ((n and 0x7FFF) shl 16) or r.u16(p)
                    p += 2
                }
                if (n > MAX_STRING_BYTES || p + n * 2 > r.size) return null
                String(CharArray(n) { i -> r.u16(p + i * 2).toChar() })
            }
        }

        private fun lenBytes(p: Int) = if (r.bytes[p].toInt() and 0x80 != 0) 2 else 1
        private fun len8(p: Int): Int {
            val a = r.bytes[p].toInt() and 0xFF
            return if (a and 0x80 != 0) ((a and 0x7F) shl 8) or (r.bytes[p + 1].toInt() and 0xFF) else a
        }
    }

    companion object {
        private const val RES_TABLE = 0x0002
        private const val RES_STRING_POOL = 0x0001
        private const val RES_PACKAGE = 0x0200
        private const val RES_TYPE = 0x0201
        private const val FLAG_COMPLEX = 0x0001
        private const val TYPE_FLAG_SPARSE = 0x01
        private const val TYPE_FLAG_OFFSET16 = 0x02
        private const val TYPE_REFERENCE = 0x01
        private const val TYPE_STRING = 0x03
        private const val MAX_REF_DEPTH = 4
        private const val MAX_CHUNKS = 200_000
        private const val MAX_STRINGS = 2_000_000
        private const val MAX_STRING_BYTES = 64 * 1024

        /** null — файл не похож на корректную таблицу ресурсов. */
        fun parse(bytes: ByteArray): ArscResolver? = try {
            parseOrThrow(bytes)
        } catch (_: Exception) {
            null
        }

        private fun parseOrThrow(bytes: ByteArray): ArscResolver? {
            val r = LeBytes(bytes)
            if (bytes.size < 12 || r.u16(0) != RES_TABLE) return null
            val tableHeader = r.u16(2)
            val tableSize = minOf(r.s32(4).toLong(), bytes.size.toLong()).toInt()
            var pos = tableHeader
            var global: StringPool? = null
            val types = HashMap<Int, HashMap<Int, MutableList<TypeChunk>>>()
            var chunks = 0
            while (pos + 8 <= tableSize) {
                val type = r.u16(pos)
                val header = r.u16(pos + 2)
                val size = r.s32(pos + 4)
                if (size < 8 || header < 8 || header > size || pos.toLong() + size > tableSize) return null
                if (++chunks > MAX_CHUNKS) return null
                when (type) {
                    RES_STRING_POOL -> if (global == null) global = StringPool(r, pos)
                    RES_PACKAGE -> {
                        val pkgId = r.s32(pos + 8)
                        val byType = types.getOrPut(pkgId) { HashMap() }
                        var p = pos + header
                        val end = pos + size
                        while (p + 8 <= end) {
                            val t = r.u16(p)
                            val h = r.u16(p + 2)
                            val s = r.s32(p + 4)
                            if (s < 8 || h < 8 || h > s || p.toLong() + s > end) return null
                            if (++chunks > MAX_CHUNKS) return null
                            if (t == RES_TYPE && h >= 20 + 12) {
                                val flags = r.bytes[p + 9].toInt() and 0xFF
                                val cfg = p + 20
                                val lang = String(charArrayOf((r.bytes[cfg + 8].toInt() and 0xFF).toChar(), (r.bytes[cfg + 9].toInt() and 0xFF).toChar()))
                                    .trimEnd('\u0000')
                                val cfgSize = r.s32(cfg).coerceIn(0, h - 20)
                                // Всё, кроме imsi (4 байта) и locale (4 байта), — прочие квалификаторы.
                                val qualified = (cfg + 12 until cfg + cfgSize).any { r.bytes[it].toInt() != 0 }
                                byType.getOrPut(r.bytes[p + 8].toInt() and 0xFF) { mutableListOf() }
                                    .add(TypeChunk(p, h, r.s32(p + 12), r.s32(p + 16), flags and TYPE_FLAG_SPARSE != 0, flags and TYPE_FLAG_OFFSET16 != 0, lang, qualified))
                            }
                            p += s
                        }
                    }
                }
                pos += size
            }
            return ArscResolver(r, global ?: return null, types)
        }
    }
}
