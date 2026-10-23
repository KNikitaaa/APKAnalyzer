package com.apkanalyzer.analyzer.dex

import com.apkanalyzer.analyzer.AnalysisLimits
import com.apkanalyzer.analyzer.CancellationCheck
import com.apkanalyzer.analyzer.MalformedApkException
import com.apkanalyzer.analyzer.throwIfCancelled
import com.apkanalyzer.analyzer.util.LeBytes

/** Найденное использование чувствительного API. */
data class ApiUsage(
    val api: ApiSignature,
    /** В каких DEX-файлах встречается ссылка. */
    val dexFiles: Set<String>,
)

/** Результат разбора одного DEX-файла. */
data class DexFileSummary(
    val name: String,
    val version: String,
    val sizeBytes: Int,
    val stringCount: Int,
    val typeCount: Int,
    val methodRefCount: Int,
    val classDefCount: Int,
    /** Разобраны не все строки из-за лимита. */
    val stringsTruncated: Boolean,
)

/**
 * Читает таблицы DEX без исполнения кода: строки, типы, ссылки на методы, определённые классы.
 * Код методов (байткод) не дизассемблируется — для первой версии достаточно таблиц ссылок:
 * если метод вызывается хоть где-то, его ссылка обязательно есть в method_ids.
 */
class DexInspector(
    private val limits: AnalysisLimits = AnalysisLimits(),
    private val cancel: CancellationCheck = CancellationCheck.NEVER,
) {

    class Parsed(
        val summary: DexFileSummary,
        val strings: List<String>,
        /** Дескрипторы всех упомянутых типов. */
        val types: Set<String>,
        /** Дескрипторы классов, определённых в этом DEX. */
        val definedClasses: List<String>,
        /** Пары (класс, метод) — все ссылки на методы. */
        val methodRefs: Set<Pair<String, String>>,
    )

    /**
     * @param stringBudget сколько строк ещё можно прочитать (общий лимит на все DEX).
     */
    fun parse(name: String, data: ByteArray, stringBudget: Int = limits.maxDexStrings): Parsed {
        if (data.size < HEADER_SIZE) throw MalformedApkException("$name: слишком короткий DEX")
        val magic = String(data, 0, 8, Charsets.ISO_8859_1)
        if (!magic.startsWith("dex\n") || magic[7] != '\u0000') throw MalformedApkException("$name: неверная сигнатура DEX")
        val version = magic.substring(4, 7)
        val r = LeBytes(data)
        if (r.u32(40) != ENDIAN_CONSTANT) throw MalformedApkException("$name: нестандартный порядок байт DEX")

        val stringIdsSize = checkedCount(r, 56, 4, data.size, name, "string_ids")
        val stringIdsOff = r.s32(60)
        val typeIdsSize = checkedCount(r, 64, 4, data.size, name, "type_ids")
        val typeIdsOff = r.s32(68)
        val methodIdsSize = checkedCount(r, 88, 8, data.size, name, "method_ids")
        val methodIdsOff = r.s32(92)
        val classDefsSize = checkedCount(r, 96, 32, data.size, name, "class_defs")
        val classDefsOff = r.s32(100)
        checkTable(stringIdsOff, stringIdsSize, 4, data.size, name, "string_ids")
        checkTable(typeIdsOff, typeIdsSize, 4, data.size, name, "type_ids")
        checkTable(methodIdsOff, methodIdsSize, 8, data.size, name, "method_ids")
        checkTable(classDefsOff, classDefsSize, 32, data.size, name, "class_defs")

        // Строки нужны полностью для типов и имён методов (их индексы указывают в общий пул),
        // а для поиска индикаторов — с учётом общего бюджета.
        val strings = ArrayList<String>(minOf(stringIdsSize, stringBudget))
        val decoded = arrayOfNulls<String>(stringIdsSize)
        fun stringAt(idx: Int): String? {
            if (idx < 0 || idx >= stringIdsSize) return null
            decoded[idx]?.let { return it }
            val off = r.s32(stringIdsOff + idx * 4)
            val s = readMutf8(data, off, limits.maxStringBytes)
            decoded[idx] = s
            return s
        }

        val readable = minOf(stringIdsSize, stringBudget.coerceAtLeast(0))
        for (i in 0 until readable) {
            if (i and 0x3FFF == 0) cancel.throwIfCancelled()
            stringAt(i)?.let { strings += it }
        }

        val types = LinkedHashSet<String>(typeIdsSize)
        val typeByIndex = arrayOfNulls<String>(typeIdsSize)
        for (i in 0 until typeIdsSize) {
            val desc = stringAt(r.s32(typeIdsOff + i * 4)) ?: continue
            typeByIndex[i] = desc
            types += desc
        }

        val methodRefs = HashSet<Pair<String, String>>(methodIdsSize)
        for (i in 0 until methodIdsSize) {
            if (i and 0x3FFF == 0) cancel.throwIfCancelled()
            val base = methodIdsOff + i * 8
            val cls = typeByIndex.getOrNull(r.u16(base)) ?: continue
            val method = stringAt(r.s32(base + 4)) ?: continue
            methodRefs += cls to method
        }

        val defined = ArrayList<String>(classDefsSize)
        for (i in 0 until classDefsSize) {
            typeByIndex.getOrNull(r.s32(classDefsOff + i * 32))?.let { defined += it }
        }

        return Parsed(
            summary = DexFileSummary(
                name = name,
                version = version,
                sizeBytes = data.size,
                stringCount = stringIdsSize,
                typeCount = typeIdsSize,
                methodRefCount = methodIdsSize,
                classDefCount = classDefsSize,
                stringsTruncated = readable < stringIdsSize,
            ),
            strings = strings,
            types = types,
            definedClasses = defined,
            methodRefs = methodRefs,
        )
    }

    private fun checkedCount(r: LeBytes, off: Int, itemSize: Int, fileSize: Int, name: String, what: String): Int {
        val count = r.u32(off)
        if (count * itemSize > fileSize) throw MalformedApkException("$name: таблица $what больше файла")
        return count.toInt()
    }

    private fun checkTable(off: Int, count: Int, itemSize: Int, fileSize: Int, name: String, what: String) {
        if (count == 0) return
        if (off < 0 || off.toLong() + count.toLong() * itemSize > fileSize) {
            throw MalformedApkException("$name: таблица $what вне файла")
        }
    }

    companion object {
        private const val HEADER_SIZE = 0x70
        private const val ENDIAN_CONSTANT = 0x12345678L

        /** Сопоставляет ссылки из всех DEX с каталогом чувствительных API. */
        fun matchApis(perDex: List<Pair<String, Parsed>>): List<ApiUsage> {
            val hits = LinkedHashMap<ApiSignature, MutableSet<String>>()
            for ((dexName, parsed) in perDex) {
                for ((cls, sigs) in SensitiveApiCatalog.byClass) {
                    if (cls !in parsed.types) continue
                    for (sig in sigs) {
                        val matched = sig.methodName == null || (cls to sig.methodName) in parsed.methodRefs
                        if (matched) hits.getOrPut(sig) { LinkedHashSet() } += dexName
                    }
                }
            }
            return hits.map { (sig, files) -> ApiUsage(sig, files) }
        }

        /**
         * Декодирует строку DEX (MUTF-8: uleb128-длина в UTF-16 символах, затем байты до 0).
         * Возвращает не более [maxBytes] байт содержимого; при порче — null.
         */
        fun readMutf8(data: ByteArray, offset: Int, maxBytes: Int): String? {
            if (offset < 0 || offset >= data.size) return null
            var p = offset
            // uleb128 (до 5 байт)
            var shift = 0
            while (p < data.size && shift < 35) {
                val b = data[p++].toInt()
                if (b and 0x80 == 0) break
                shift += 7
            }
            val sb = StringBuilder()
            var consumed = 0
            while (p < data.size && consumed < maxBytes) {
                val a = data[p].toInt() and 0xFF
                if (a == 0) break
                when {
                    a < 0x80 -> {
                        sb.append(a.toChar()); p += 1; consumed += 1
                    }
                    a and 0xE0 == 0xC0 && p + 1 < data.size -> {
                        val b = data[p + 1].toInt() and 0x3F
                        sb.append((((a and 0x1F) shl 6) or b).toChar()); p += 2; consumed += 2
                    }
                    a and 0xF0 == 0xE0 && p + 2 < data.size -> {
                        val b = data[p + 1].toInt() and 0x3F
                        val c = data[p + 2].toInt() and 0x3F
                        sb.append((((a and 0x0F) shl 12) or (b shl 6) or c).toChar()); p += 3; consumed += 3
                    }
                    else -> {
                        sb.append('�'); p += 1; consumed += 1
                    }
                }
            }
            return sb.toString()
        }
    }
}
