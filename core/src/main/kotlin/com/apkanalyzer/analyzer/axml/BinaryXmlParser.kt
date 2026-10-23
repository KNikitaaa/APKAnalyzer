package com.apkanalyzer.analyzer.axml

import com.apkanalyzer.analyzer.AnalysisLimitExceededException
import com.apkanalyzer.analyzer.AnalysisLimits
import com.apkanalyzer.analyzer.MalformedApkException
import com.apkanalyzer.analyzer.util.LeBytes

/** Значение атрибута бинарного XML (Res_value). */
sealed class AttrValue {
    data class Text(val value: String) : AttrValue()
    data class IntValue(val value: Int) : AttrValue()
    data class BoolValue(val value: Boolean) : AttrValue()
    /** Ссылка на ресурс (@string/..., @xml/...) — без таблицы ресурсов раскрыть нельзя. */
    data class Reference(val resourceId: Int) : AttrValue()
    data class Other(val dataType: Int, val data: Int) : AttrValue()

    fun asText(): String? = when (this) {
        is Text -> value
        is IntValue -> value.toString()
        is BoolValue -> value.toString()
        is Reference -> "@0x%08x".format(resourceId)
        is Other -> null
    }

    fun asInt(): Int? = when (this) {
        is IntValue -> value
        is Text -> value.trim().toIntOrNull()
        is BoolValue -> if (value) 1 else 0
        else -> null
    }

    fun asBoolean(): Boolean? = when (this) {
        is BoolValue -> value
        is IntValue -> value != 0
        is Text -> value.trim().lowercase().toBooleanStrictOrNull()
        else -> null
    }
}

data class XmlAttribute(
    val namespace: String?,
    /** Имя после разрешения по resource ID (как это делает Android), иначе — из пула строк. */
    val name: String,
    val resourceId: Int,
    val value: AttrValue,
)

class XmlElement(
    val name: String,
    val attributes: List<XmlAttribute>,
) {
    val children: MutableList<XmlElement> = mutableListOf()

    fun attr(name: String): AttrValue? =
        attributes.firstOrNull { it.name == name && (it.namespace == null || it.namespace == ANDROID_NS) }?.value
            ?: attributes.firstOrNull { it.name == name }?.value

    fun childrenNamed(name: String): List<XmlElement> = children.filter { it.name == name }

    companion object {
        const val ANDROID_NS = "http://schemas.android.com/apk/res/android"
    }
}

data class BinaryXmlDocument(
    val root: XmlElement?,
    /** Сколько атрибутов имели имя в пуле строк, не совпадающее с resource ID (приём обфускации). */
    val renamedAttributeCount: Int,
    /** Документ разобран не до конца (обрыв/порча структуры), но начало удалось прочитать. */
    val truncated: Boolean,
    val warnings: List<String>,
)

/**
 * Парсер бинарного Android XML (AXML), в котором хранится AndroidManifest.xml внутри APK.
 *
 * Разбор снисходительный, как у самого Android: неизвестные чанки пропускаются,
 * а при порче структуры возвращается то, что успели прочитать, с флагом [BinaryXmlDocument.truncated].
 * Все размеры и индексы проверяются, поэтому испорченный файл не может вызвать выход за границы,
 * зацикливание или огромную аллокацию.
 */
class BinaryXmlParser(private val limits: AnalysisLimits = AnalysisLimits()) {

    fun parse(data: ByteArray): BinaryXmlDocument {
        if (data.size < 8) throw MalformedApkException("Бинарный XML слишком короткий")
        val r = LeBytes(data)
        val warnings = mutableListOf<String>()
        val fileType = r.u16(0)
        val fileHeaderSize = r.u16(2)
        if (fileType != RES_XML_TYPE) {
            if (looksLikeTextXml(data)) throw MalformedApkException("Манифест хранится текстом, а не в бинарном формате")
            warnings += "Неожиданный тип файла XML: 0x%04x".format(fileType)
        }
        val declaredSize = r.u32(4)
        if (declaredSize != data.size.toLong()) warnings += "Заявленный размер XML ($declaredSize) ≠ фактическому (${data.size})"

        var strings: StringPool? = null
        var resourceIds = IntArray(0)
        val namespaces = HashMap<Int, String>()
        val stack = ArrayDeque<XmlElement>()
        var root: XmlElement? = null
        var elementCount = 0
        var renamed = 0
        var truncated = false

        var pos = if (fileHeaderSize in 8..data.size) fileHeaderSize else 8
        while (pos + 8 <= data.size) {
            val type = r.u16(pos)
            val headerSize = r.u16(pos + 2)
            val chunkSize = r.u32(pos + 4)
            if (chunkSize < 8 || headerSize < 8 || headerSize > chunkSize || pos + chunkSize > data.size) {
                truncated = true
                warnings += "Повреждён чанк XML по смещению $pos"
                break
            }
            val size = chunkSize.toInt()
            when (type) {
                RES_STRING_POOL_TYPE -> if (strings == null) strings = StringPool.parse(r, pos, headerSize, size, limits)
                RES_XML_RESOURCE_MAP_TYPE -> {
                    val count = (size - headerSize) / 4
                    resourceIds = IntArray(count) { r.s32(pos + headerSize + it * 4) }
                }
                RES_XML_START_NAMESPACE_TYPE -> if (headerSize + 8 <= size) {
                    val uriIdx = r.s32(pos + headerSize + 4)
                    strings?.get(uriIdx)?.let { namespaces[uriIdx] = it }
                }
                RES_XML_START_ELEMENT_TYPE -> {
                    if (++elementCount > limits.maxXmlElements) {
                        throw AnalysisLimitExceededException("Слишком много XML-элементов")
                    }
                    if (stack.size >= limits.maxXmlDepth) {
                        throw AnalysisLimitExceededException("Слишком глубокая вложенность XML")
                    }
                    val pool = strings ?: throw MalformedApkException("XML-элемент встретился до таблицы строк")
                    val ext = pos + headerSize
                    if (ext + 20 > pos + size) {
                        truncated = true
                        break
                    }
                    val nameIdx = r.s32(ext + 4)
                    val attrStart = r.u16(ext + 8)
                    val attrSize = r.u16(ext + 10)
                    val attrCount = r.u16(ext + 12)
                    val elementName = pool[nameIdx] ?: ""
                    val attrs = ArrayList<XmlAttribute>(attrCount)
                    if (attrSize >= 20) {
                        for (i in 0 until attrCount) {
                            val a = ext + attrStart + i * attrSize
                            if (a + 20 > pos + size) {
                                truncated = true
                                break
                            }
                            val nsIdx = r.s32(a)
                            val attrNameIdx = r.s32(a + 4)
                            val rawIdx = r.s32(a + 8)
                            val dataType = r.u8(a + 15)
                            val dataValue = r.s32(a + 16)
                            val resId = if (attrNameIdx in resourceIds.indices) resourceIds[attrNameIdx] else 0
                            val poolName = pool[attrNameIdx] ?: ""
                            val known = AndroidAttributes.nameFor(resId)
                            if (known != null && poolName.isNotEmpty() && poolName != known) renamed++
                            val name = known ?: poolName
                            val ns = if (nsIdx >= 0) pool[nsIdx] ?: namespaces[nsIdx] else null
                            attrs += XmlAttribute(ns, name, resId, decodeValue(pool, dataType, dataValue, rawIdx))
                        }
                    }
                    val element = XmlElement(elementName, attrs)
                    val parent = stack.lastOrNull()
                    if (parent == null) {
                        if (root == null) root = element else warnings += "Лишний корневой элемент '$elementName'"
                    } else {
                        parent.children += element
                    }
                    stack.addLast(element)
                }
                RES_XML_END_ELEMENT_TYPE -> if (stack.isNotEmpty()) stack.removeLast()
                else -> Unit // пространства имён (конец), CDATA и неизвестные чанки пропускаем
            }
            pos += size
        }
        if (stack.isNotEmpty() && !truncated) {
            truncated = true
            warnings += "Не закрыто ${stack.size} XML-элементов"
        }
        return BinaryXmlDocument(root, renamed, truncated, warnings)
    }

    private fun decodeValue(pool: StringPool, dataType: Int, data: Int, rawIdx: Int): AttrValue = when (dataType) {
        TYPE_STRING -> AttrValue.Text(pool[data] ?: "")
        TYPE_INT_DEC, TYPE_INT_HEX -> AttrValue.IntValue(data)
        TYPE_INT_BOOLEAN -> AttrValue.BoolValue(data != 0)
        TYPE_REFERENCE, TYPE_ATTRIBUTE -> AttrValue.Reference(data)
        TYPE_NULL -> pool[rawIdx]?.let { AttrValue.Text(it) } ?: AttrValue.Other(dataType, data)
        else -> pool[rawIdx]?.let { AttrValue.Text(it) } ?: AttrValue.Other(dataType, data)
    }

    private fun looksLikeTextXml(data: ByteArray): Boolean {
        val head = String(data, 0, minOf(64, data.size), Charsets.ISO_8859_1).trimStart('﻿', ' ', '\n', '\r', '\t')
        return head.startsWith("<?xml") || head.startsWith("<manifest")
    }

    companion object {
        const val RES_STRING_POOL_TYPE = 0x0001
        const val RES_XML_TYPE = 0x0003
        const val RES_XML_START_NAMESPACE_TYPE = 0x0100
        const val RES_XML_END_NAMESPACE_TYPE = 0x0101
        const val RES_XML_START_ELEMENT_TYPE = 0x0102
        const val RES_XML_END_ELEMENT_TYPE = 0x0103
        const val RES_XML_CDATA_TYPE = 0x0104
        const val RES_XML_RESOURCE_MAP_TYPE = 0x0180

        const val TYPE_NULL = 0x00
        const val TYPE_REFERENCE = 0x01
        const val TYPE_ATTRIBUTE = 0x02
        const val TYPE_STRING = 0x03
        const val TYPE_INT_DEC = 0x10
        const val TYPE_INT_HEX = 0x11
        const val TYPE_INT_BOOLEAN = 0x12
    }
}

/** Пул строк ResStringPool. Строки декодируются лениво и с ограничением длины. */
internal class StringPool private constructor(
    private val r: LeBytes,
    private val offsets: IntArray,
    private val stringsStart: Int,
    private val end: Int,
    private val utf8: Boolean,
    private val maxChars: Int,
) {
    private val cache = HashMap<Int, String?>()

    val size: Int get() = offsets.size

    operator fun get(index: Int): String? {
        if (index < 0 || index >= offsets.size) return null
        return cache.getOrPut(index) { decode(index) }
    }

    private fun decode(index: Int): String? {
        val start = stringsStart + offsets[index]
        if (offsets[index] < 0 || start >= end) return null
        return try {
            if (utf8) decodeUtf8(start) else decodeUtf16(start)
        } catch (_: IndexOutOfBoundsException) {
            null
        }
    }

    private fun decodeUtf8(start: Int): String? {
        var p = start
        // Длина в символах UTF-16 (1–2 байта), затем длина в байтах (1–2 байта).
        p += if (r.u8(p) and 0x80 != 0) 2 else 1
        var byteLen = r.u8(p)
        if (byteLen and 0x80 != 0) {
            byteLen = ((byteLen and 0x7F) shl 8) or r.u8(p + 1)
            p += 2
        } else {
            p += 1
        }
        if (p + byteLen > end) return null
        val n = minOf(byteLen, maxChars * 3)
        return String(r.bytes, p, n, Charsets.UTF_8).take(maxChars)
    }

    private fun decodeUtf16(start: Int): String? {
        var p = start
        var len = r.u16(p)
        if (len and 0x8000 != 0) {
            len = ((len and 0x7FFF) shl 16) or r.u16(p + 2)
            p += 4
        } else {
            p += 2
        }
        if (len < 0 || p + len.toLong() * 2 > end) return null
        val n = minOf(len, maxChars)
        val chars = CharArray(n) { r.u16(p + it * 2).toChar() }
        return String(chars)
    }

    companion object {
        private const val UTF8_FLAG = 1 shl 8

        fun parse(r: LeBytes, pos: Int, headerSize: Int, size: Int, limits: AnalysisLimits): StringPool {
            if (headerSize < 28) throw MalformedApkException("Повреждён заголовок таблицы строк")
            val count = r.u32(pos + 8)
            val flags = r.s32(pos + 16)
            val stringsStart = r.u32(pos + 20)
            val chunkEnd = pos + size
            val maxCount = (size - headerSize) / 4
            if (count > maxCount) throw MalformedApkException("Таблица строк заявляет больше строк, чем помещается")
            val offsets = IntArray(count.toInt()) { r.s32(pos + headerSize + it * 4) }
            val start = pos + stringsStart.toInt()
            if (stringsStart > size) throw MalformedApkException("Смещение строк вне таблицы строк")
            return StringPool(r, offsets, start, chunkEnd, flags and UTF8_FLAG != 0, limits.maxStringBytes)
        }
    }
}
