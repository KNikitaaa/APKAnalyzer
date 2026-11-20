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
    /**
     * Вызывается ли API из кода самого приложения. false — ссылка есть только в коде известных
     * библиотек (androidx, Google Play Services, OkHttp…) и о намерениях приложения не говорит.
     */
    val inAppCode: Boolean = true,
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
 * Читает DEX без исполнения кода: таблицы строк, типов, ссылок на методы и классов, а также
 * байткод методов — чтобы понять, *какой класс* вызывает чувствительный API или использует строку.
 * Ссылки из известных библиотек ([KnownLibraries]) отделяются от кода приложения: иначе почти
 * любое приложение «скрывает иконку» (WorkManager) и «пишет экран» (androidx.core).
 * Если байткод разобрать не удалось, анализ откатывается к таблицам (всё считается кодом приложения).
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
        /** Байткод разобран, и ссылки ниже привязаны к коду приложения. */
        val bytecodeAttributed: Boolean = false,
        /** Методы, которые вызываются из кода приложения. */
        val appMethodRefs: Set<Pair<String, String>> = emptySet(),
        /** Типы, которые использует код приложения (включая классы вызываемых методов). */
        val appTypes: Set<String> = emptySet(),
        /** Строки-константы из кода приложения (const-string) — по ним ищутся индикаторы. */
        val appStrings: List<String> = emptyList(),
        /** Строки-константы, которые использует только код библиотек (не приложения). */
        val libraryStrings: List<String> = emptyList(),
        /**
         * Типы и строки из тех классов приложения, которые вызывают setComponentEnabledSetting:
         * по ним видно, какие компоненты код включает и отключает (например, собственный значок).
         */
        val componentToggleRefs: Set<String> = emptySet(),
    )

    /**
     * @param stringBudget сколько строк ещё можно прочитать (общий лимит на все DEX).
     */
    fun parse(
        name: String,
        data: ByteArray,
        stringBudget: Int = limits.maxDexStrings,
        /** Пакет приложения из манифеста: его классы всегда считаются кодом приложения. */
        appPackage: String? = null,
    ): Parsed {
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

        val toggleMethods = BooleanArray(methodIdsSize)
        for (i in 0 until methodIdsSize) {
            if (stringAt(r.s32(methodIdsOff + i * 8 + 4)) == TOGGLE_METHOD) toggleMethods[i] = true
        }
        val refs = try {
            CodeWalker(data, r, stringIdsSize, typeIdsSize, methodIdsSize, toggleMethods).walk(classDefsOff, classDefsSize, typeByIndex, appPackage)
        } catch (e: com.apkanalyzer.analyzer.AnalysisCancelledException) {
            throw e
        } catch (_: Exception) {
            null // повреждённый байткод — остаёмся на таблицах
        }
        val appMethodRefs = HashSet<Pair<String, String>>()
        val appTypes = HashSet<String>()
        val appStrings = ArrayList<String>()
        if (refs != null) {
            for (i in 0 until methodIdsSize) {
                if (!refs.method[i]) continue
                val base = methodIdsOff + i * 8
                val cls = typeByIndex.getOrNull(r.u16(base)) ?: continue
                appTypes += cls
                stringAt(r.s32(base + 4))?.let { appMethodRefs += cls to it }
            }
            for (i in 0 until typeIdsSize) if (refs.type[i]) typeByIndex[i]?.let { appTypes += it }
            for (i in 0 until stringIdsSize) {
                if (appStrings.size >= readable) break
                if (refs.string[i]) stringAt(i)?.let { appStrings += it }
            }
        }
        val libraryStrings = ArrayList<String>()
        if (refs != null) {
            for (i in 0 until stringIdsSize) {
                if (appStrings.size + libraryStrings.size >= readable) break
                if (refs.libString[i] && !refs.string[i]) stringAt(i)?.let { libraryStrings += it }
            }
        }
        val toggleRefs = HashSet<String>()
        refs?.toggleTypes?.forEach { i -> typeByIndex.getOrNull(i)?.let { toggleRefs += it } }
        refs?.toggleStrings?.forEach { i -> stringAt(i)?.let { toggleRefs += it } }

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
            bytecodeAttributed = refs != null,
            appMethodRefs = appMethodRefs,
            appTypes = appTypes,
            appStrings = appStrings,
            libraryStrings = libraryStrings,
            componentToggleRefs = toggleRefs,
        )
    }

    /** Отметки «используется кодом приложения» по индексам таблиц DEX. */
    private class AppRefs(stringCount: Int, typeCount: Int, methodCount: Int) {
        val string = BooleanArray(stringCount)
        val type = BooleanArray(typeCount)
        val method = BooleanArray(methodCount)
        /** Строки из кода библиотек. */
        val libString = BooleanArray(stringCount)
        /** Индексы типов и строк из классов, вызывающих setComponentEnabledSetting. */
        val toggleTypes = HashSet<Int>()
        val toggleStrings = HashSet<Int>()
    }

    /**
     * Проходит байткод методов классов приложения и отмечает, какие строки, типы и методы они используют.
     * Возвращает null, если в DEX нет ни одного метода с кодом (тогда работаем по таблицам).
     */
    private inner class CodeWalker(
        private val data: ByteArray,
        private val r: LeBytes,
        stringCount: Int,
        typeCount: Int,
        methodCount: Int,
        private val toggleMethods: BooleanArray,
    ) {
        private val refs = AppRefs(stringCount, typeCount, methodCount)
        private var pos = 0

        // Ссылки текущего класса — чтобы связать вызов setComponentEnabledSetting с тем, что именно переключается.
        private val classTypes = HashSet<Int>()
        private val classStrings = HashSet<Int>()
        private var classToggles = false

        fun walk(classDefsOff: Int, classDefsSize: Int, typeByIndex: Array<String?>, appPackage: String?): AppRefs? {
            var methodsWithCode = 0
            for (i in 0 until classDefsSize) {
                if (i and 0xFF == 0) cancel.throwIfCancelled()
                val def = classDefsOff + i * 32
                val classDataOff = r.s32(def + 24)
                if (classDataOff == 0) continue
                if (classDataOff < 0 || classDataOff >= data.size) throw MalformedApkException("class_data вне файла")
                val cls = typeByIndex.getOrNull(r.s32(def)) ?: continue
                val isApp = !KnownLibraries.isLibrary(cls, appPackage)
                pos = classDataOff
                classTypes.clear(); classStrings.clear(); classToggles = false
                val fields = uleb() + uleb()
                val direct = uleb()
                val virtual = uleb()
                if (fields > data.size || direct > data.size || virtual > data.size) throw MalformedApkException("class_data")
                repeat(fields) { uleb(); uleb() }
                repeat(direct + virtual) {
                    uleb(); uleb()
                    val codeOff = uleb()
                    if (codeOff != 0) {
                        methodsWithCode++
                        val saved = pos
                        scanCode(codeOff, isApp)
                        pos = saved
                    }
                }
                if (classToggles && isApp) {
                    refs.toggleTypes += classTypes
                    refs.toggleStrings += classStrings
                }
            }
            return if (methodsWithCode == 0) null else refs
        }

        private fun uleb(): Int {
            var result = 0
            var shift = 0
            while (true) {
                if (pos >= data.size || shift > 28) throw MalformedApkException("uleb128 вне файла")
                val b = data[pos++].toInt() and 0xFF
                result = result or ((b and 0x7F) shl shift)
                if (b and 0x80 == 0) return result
                shift += 7
            }
        }

        private fun scanCode(codeOff: Int, isApp: Boolean) {
            if (codeOff < 0 || codeOff.toLong() + 16 > data.size) throw MalformedApkException("code_item вне файла")
            val units = r.u32(codeOff + 12)
            val base = codeOff + 16
            if (base + units * 2 > data.size) throw MalformedApkException("байткод вне файла")
            val n = units.toInt()
            fun unit(i: Int): Int = if (i < n) r.u16(base + i * 2) else throw MalformedApkException("обрыв инструкции")
            var pc = 0
            while (pc < n) {
                val u = unit(pc)
                val op = u and 0xFF
                if (op == 0 && u != 0) {
                    // Псевдоинструкции с данными: таблицы switch и массивов.
                    val len: Long = when (u) {
                        0x0100 -> unit(pc + 1) * 2L + 4
                        0x0200 -> unit(pc + 1) * 4L + 2
                        0x0300 -> ((unit(pc + 2).toLong() or (unit(pc + 3).toLong() shl 16)) * unit(pc + 1) + 1) / 2 + 4
                        else -> 1
                    }
                    pc = (pc + len.coerceAtLeast(1)).coerceAtMost(n.toLong()).toInt()
                    continue
                }
                if (!isApp) {
                    // В коде библиотек нужны только строки — для адресов C2, которые не прощаются никому.
                    when (op) {
                        0x1a -> mark(refs.libString, unit(pc + 1))
                        0x1b -> mark(refs.libString, unit(pc + 1) or (unit(pc + 2) shl 16))
                    }
                    pc += INSN_UNITS[op]
                    continue
                }
                when (op) {
                    0x1a -> unit(pc + 1).let { mark(refs.string, it); classStrings += it }
                    0x1b -> (unit(pc + 1) or (unit(pc + 2) shl 16)).let { mark(refs.string, it); classStrings += it }
                    0x1c, 0x1f, 0x20, 0x22, 0x23, 0x24, 0x25 -> unit(pc + 1).let { mark(refs.type, it); classTypes += it }
                    in 0x6e..0x72, in 0x74..0x78, 0xfa, 0xfb -> unit(pc + 1).let { idx ->
                        mark(refs.method, idx)
                        if (idx in toggleMethods.indices && toggleMethods[idx]) classToggles = true
                    }
                }
                pc += INSN_UNITS[op]
            }
        }

        private fun mark(arr: BooleanArray, idx: Int) {
            if (idx in arr.indices) arr[idx] = true
        }
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
        private const val TOGGLE_METHOD = "setComponentEnabledSetting"

        /** Длина инструкции Dalvik в 16-битных единицах по коду операции. */
        private val INSN_UNITS: IntArray = IntArray(256) { 1 }.also { t ->
            fun set(range: IntRange, len: Int) = range.forEach { t[it] = len }
            set(0x02..0x02, 2); set(0x03..0x03, 3); set(0x05..0x05, 2); set(0x06..0x06, 3); set(0x08..0x08, 2); set(0x09..0x09, 3)
            set(0x13..0x13, 2); set(0x14..0x14, 3); set(0x15..0x16, 2); set(0x17..0x17, 3); set(0x18..0x18, 5); set(0x19..0x19, 2)
            set(0x1a..0x1a, 2); set(0x1b..0x1b, 3); set(0x1c..0x1c, 2); set(0x1f..0x20, 2); set(0x22..0x23, 2); set(0x24..0x26, 3)
            set(0x29..0x29, 2); set(0x2a..0x2c, 3); set(0x2d..0x3d, 2); set(0x44..0x6d, 2); set(0x6e..0x72, 3); set(0x74..0x78, 3)
            set(0x90..0xaf, 2); set(0xd0..0xe2, 2); set(0xfa..0xfb, 4); set(0xfc..0xfd, 3); set(0xfe..0xff, 2)
        }

        /** Сопоставляет ссылки из всех DEX с каталогом чувствительных API. */
        fun matchApis(perDex: List<Pair<String, Parsed>>): List<ApiUsage> {
            val hits = LinkedHashMap<ApiSignature, MutableSet<String>>()
            val inApp = HashSet<ApiSignature>()
            for ((dexName, parsed) in perDex) {
                for ((cls, sigs) in SensitiveApiCatalog.byClass) {
                    if (cls !in parsed.types) continue
                    for (sig in sigs) {
                        val matched = sig.methodName == null || (cls to sig.methodName) in parsed.methodRefs
                        if (!matched) continue
                        hits.getOrPut(sig) { LinkedHashSet() } += dexName
                        val fromApp = !parsed.bytecodeAttributed ||
                            if (sig.methodName == null) cls in parsed.appTypes else (cls to sig.methodName) in parsed.appMethodRefs
                        if (fromApp) inApp += sig
                    }
                }
            }
            return hits.map { (sig, files) -> ApiUsage(sig, files, inAppCode = sig in inApp) }
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
