package com.apkanalyzer.analyzer.archive

import com.apkanalyzer.analyzer.AnalysisLimitExceededException
import com.apkanalyzer.analyzer.AnalysisLimits
import com.apkanalyzer.analyzer.CancellationCheck
import com.apkanalyzer.analyzer.MalformedApkException
import com.apkanalyzer.analyzer.throwIfCancelled
import com.apkanalyzer.analyzer.util.LeBytes
import java.io.ByteArrayOutputStream
import java.io.Closeable
import java.io.File
import java.io.RandomAccessFile
import java.util.zip.CRC32
import java.util.zip.DataFormatException
import java.util.zip.Inflater

/** Запись центрального каталога ZIP. */
data class ZipEntryInfo(
    val name: String,
    val method: Int,
    val flags: Int,
    val crc32: Long,
    val compressedSize: Long,
    val uncompressedSize: Long,
    val localHeaderOffset: Long,
) {
    val isDirectory: Boolean get() = name.endsWith("/")
}

enum class ArchiveAnomalyType {
    /** Выставлен флаг шифрования, который Android игнорирует — приём против анализаторов. */
    FAKE_ENCRYPTION_FLAG,
    /** Нестандартный метод сжатия (Android всё равно попытается распаковать как Deflate). */
    UNSUPPORTED_COMPRESSION_METHOD,
    /** Размеры в локальном заголовке/каталоге противоречат друг другу. */
    INCONSISTENT_SIZES,
    /** Несколько записей с одинаковым именем. */
    DUPLICATE_ENTRY,
    /** Имя записи с выходом за пределы каталога (`../`, абсолютный путь). */
    PATH_TRAVERSAL,
    /** Признаки ZIP64 — формат, который обычный APK не использует. */
    ZIP64,
    /** Лишние данные внутри архива / несоответствие смещений. */
    STRUCTURE_MISMATCH,
}

data class ArchiveAnomaly(val type: ArchiveAnomalyType, val detail: String)

/**
 * Минимальный и намеренно «недоверчивый» читатель ZIP/APK.
 *
 * Почему не java.util.zip.ZipFile: поведение ZipFile на JVM и на разных версиях Android
 * отличается на испорченных архивах, а вредоносные APK как раз используют такие трюки
 * (фальшивое шифрование, неверные размеры в локальных заголовках, дубликаты имён).
 * Здесь мы читаем центральный каталог сами, повторяя логику установщика Android,
 * фиксируем каждую аномалию и ограничиваем объём распаковки.
 */
class SafeApkArchive private constructor(
    private val raf: RandomAccessFile,
    val fileSize: Long,
    val entries: List<ZipEntryInfo>,
    val anomalies: List<ArchiveAnomaly>,
    /** Смещение начала центрального каталога (нужно для поиска APK Signing Block). */
    val centralDirectoryOffset: Long,
    val eocdOffset: Long,
    private val limits: AnalysisLimits,
    private val cancel: CancellationCheck,
) : Closeable {

    private val byName: Map<String, ZipEntryInfo> = buildMap {
        // Как и установщик, используем первую запись с данным именем.
        for (e in this@SafeApkArchive.entries) if (!containsKey(e.name)) put(e.name, e)
    }

    /** Сколько байт уже распаковано за время жизни архива (защита от zip-bomb суммарно). */
    var totalInflatedBytes: Long = 0
        private set

    fun find(name: String): ZipEntryInfo? = byName[name]

    /**
     * Читает содержимое записи. Распаковка прерывается, если результат превышает [maxBytes]
     * (при [truncate] = true возвращается начало данных, иначе — исключение лимита).
     */
    fun read(entry: ZipEntryInfo, maxBytes: Int, truncate: Boolean = false): ByteArray {
        require(maxBytes >= 0)
        val dataStart = dataOffset(entry)
        val data = if (entry.method == METHOD_STORED) {
            readStored(entry, dataStart, maxBytes, truncate)
        } else {
            inflate(entry, dataStart, maxBytes, truncate)
        }
        // Как и Android, проверяем CRC32 полностью прочитанной записи: порча данных не должна
        // незаметно превращаться в «нормальные» байты для анализа.
        val complete = data.size.toLong() == entry.uncompressedSize || !truncate
        if (complete) {
            val crc = CRC32().apply { update(data) }.value
            if (crc != entry.crc32) throw MalformedApkException("Контрольная сумма '${entry.name}' не совпадает")
        }
        return data
    }

    /** Чтение «сырого» диапазона файла (для APK Signing Block). */
    fun readRange(offset: Long, length: Int): ByteArray {
        if (offset < 0 || length < 0 || offset + length > fileSize) {
            throw MalformedApkException("Диапазон $offset+$length вне файла")
        }
        val buf = ByteArray(length)
        synchronized(raf) {
            raf.seek(offset)
            raf.readFully(buf)
        }
        return buf
    }

    private fun dataOffset(entry: ZipEntryInfo): Long {
        val header = try {
            readRange(entry.localHeaderOffset, LOCAL_HEADER_SIZE)
        } catch (e: MalformedApkException) {
            throw MalformedApkException("Локальный заголовок '${entry.name}' вне файла", e)
        }
        val le = LeBytes(header)
        if (le.u32(0) != LOCAL_HEADER_SIG) {
            throw MalformedApkException("Повреждён локальный заголовок '${entry.name}'")
        }
        val nameLen = le.u16(26)
        val extraLen = le.u16(28)
        val start = entry.localHeaderOffset + LOCAL_HEADER_SIZE + nameLen + extraLen
        if (start > fileSize) throw MalformedApkException("Данные '${entry.name}' вне файла")
        return start
    }

    private fun readStored(entry: ZipEntryInfo, start: Long, maxBytes: Int, truncate: Boolean): ByteArray {
        // Установщик Android для STORED использует несжатый размер из центрального каталога.
        val declared = entry.uncompressedSize
        val available = fileSize - start
        if (declared > available) throw MalformedApkException("Запись '${entry.name}' обрезана")
        if (declared > maxBytes && !truncate) {
            throw AnalysisLimitExceededException("Запись '${entry.name}' больше лимита $maxBytes байт")
        }
        val len = minOf(declared, maxBytes.toLong()).toInt()
        account(len.toLong())
        return readRange(start, len)
    }

    private fun inflate(entry: ZipEntryInfo, start: Long, maxBytes: Int, truncate: Boolean): ByteArray {
        // Сжатый размер берём из каталога, но не выходим за пределы файла.
        // Если размер в каталоге нулевой/подделан, читаем не дальше начала центрального каталога.
        val dataLimit = centralDirectoryOffset
        val compressedEnd = if (entry.compressedSize > 0) {
            minOf(start + entry.compressedSize, dataLimit)
        } else {
            dataLimit
        }.let { if (it <= start) dataLimit else it }
        val inflater = Inflater(true)
        val out = ByteArrayOutputStream(minOf(maxBytes, 64 * 1024).coerceAtLeast(16))
        val inBuf = ByteArray(IO_CHUNK)
        val outBuf = ByteArray(IO_CHUNK)
        var position = start
        var consumed = 0L
        var produced = 0L
        try {
            while (!inflater.finished()) {
                cancel.throwIfCancelled()
                if (inflater.needsInput()) {
                    val toRead = minOf(IO_CHUNK.toLong(), compressedEnd - position).toInt()
                    if (toRead <= 0) {
                        // Deflate-поток оборвался раньше конца — для Android это ошибка распаковки.
                        throw MalformedApkException("Сжатые данные '${entry.name}' обрываются")
                    }
                    synchronized(raf) {
                        raf.seek(position)
                        raf.readFully(inBuf, 0, toRead)
                    }
                    position += toRead
                    consumed += toRead
                    inflater.setInput(inBuf, 0, toRead)
                }
                val n = inflater.inflate(outBuf)
                if (n == 0 && inflater.needsDictionary()) {
                    throw MalformedApkException("Запись '${entry.name}' требует словарь Deflate")
                }
                if (n > 0) {
                    produced += n
                    account(n.toLong())
                    if (produced > limits.compressionRatioMinBytes &&
                        consumed > 0 && produced / consumed > limits.maxCompressionRatio
                    ) {
                        throw AnalysisLimitExceededException(
                            "Подозрение на zip-bomb: '${entry.name}' сжат в ${produced / consumed}+ раз"
                        )
                    }
                    val room = maxBytes - out.size()
                    if (n > room) {
                        if (truncate) {
                            out.write(outBuf, 0, room)
                            return out.toByteArray()
                        }
                        throw AnalysisLimitExceededException("Запись '${entry.name}' больше лимита $maxBytes байт")
                    }
                    out.write(outBuf, 0, n)
                }
            }
        } catch (e: DataFormatException) {
            throw MalformedApkException("Повреждены сжатые данные '${entry.name}'", e)
        } finally {
            inflater.end()
        }
        return out.toByteArray()
    }

    private fun account(bytes: Long) {
        totalInflatedBytes += bytes
        if (totalInflatedBytes > limits.maxTotalInflatedBytes) {
            throw AnalysisLimitExceededException(
                "Превышен общий лимит распаковки ${limits.maxTotalInflatedBytes} байт"
            )
        }
    }

    override fun close() = raf.close()

    companion object {
        const val METHOD_STORED = 0
        const val METHOD_DEFLATED = 8

        private const val EOCD_SIG = 0x06054b50L
        private const val ZIP64_LOCATOR_SIG = 0x07064b50L
        private const val CD_SIG = 0x02014b50L
        private const val LOCAL_HEADER_SIG = 0x04034b50L
        private const val EOCD_MIN = 22
        private const val CD_HEADER_SIZE = 46
        private const val LOCAL_HEADER_SIZE = 30
        private const val MAX_COMMENT = 0xFFFF
        private const val IO_CHUNK = 64 * 1024

        fun open(
            file: File,
            limits: AnalysisLimits = AnalysisLimits(),
            cancel: CancellationCheck = CancellationCheck.NEVER,
        ): SafeApkArchive {
            if (!file.isFile) throw MalformedApkException("Файл не найден")
            val size = file.length()
            if (size > limits.maxApkBytes) {
                throw AnalysisLimitExceededException("Файл больше допустимых ${limits.maxApkBytes} байт")
            }
            if (size < EOCD_MIN + LOCAL_HEADER_SIZE) throw MalformedApkException("Файл слишком мал для APK")
            val raf = RandomAccessFile(file, "r")
            try {
                return parse(raf, size, limits, cancel)
            } catch (t: Throwable) {
                raf.close()
                throw t
            }
        }

        private fun parse(
            raf: RandomAccessFile,
            size: Long,
            limits: AnalysisLimits,
            cancel: CancellationCheck,
        ): SafeApkArchive {
            val head = ByteArray(4)
            raf.seek(0)
            raf.readFully(head)
            if (LeBytes(head).u32(0) != LOCAL_HEADER_SIG) {
                throw MalformedApkException("Это не ZIP/APK: неверная сигнатура в начале файла")
            }

            // Ищем EOCD с конца: комментарий архива может быть до 65535 байт.
            val tailLen = minOf(size, (EOCD_MIN + MAX_COMMENT).toLong()).toInt()
            val tail = ByteArray(tailLen)
            raf.seek(size - tailLen)
            raf.readFully(tail)
            val tailLe = LeBytes(tail)
            var eocdInTail = -1
            var i = tailLen - EOCD_MIN
            while (i >= 0) {
                if (tailLe.u32(i) == EOCD_SIG) {
                    val commentLen = tailLe.u16(i + 20)
                    if (i + EOCD_MIN + commentLen == tailLen) {
                        eocdInTail = i
                        break
                    }
                }
                i--
            }
            if (eocdInTail < 0) throw MalformedApkException("Не найден конец центрального каталога ZIP")
            val eocdOffset = size - tailLen + eocdInTail

            val anomalies = mutableListOf<ArchiveAnomaly>()
            if (eocdInTail >= 20 && tailLe.u32(eocdInTail - 20) == ZIP64_LOCATOR_SIG) {
                anomalies += ArchiveAnomaly(ArchiveAnomalyType.ZIP64, "Найден ZIP64-локатор")
            }

            val totalEntries = tailLe.u16(eocdInTail + 10)
            val cdSize = tailLe.u32(eocdInTail + 12)
            val cdOffset = tailLe.u32(eocdInTail + 16)
            if (totalEntries == 0xFFFF || cdSize == 0xFFFFFFFFL || cdOffset == 0xFFFFFFFFL) {
                throw MalformedApkException("ZIP64-архивы не поддерживаются")
            }
            if (totalEntries > limits.maxZipEntries) {
                throw AnalysisLimitExceededException("Слишком много записей в архиве: $totalEntries")
            }
            if (cdOffset + cdSize > eocdOffset) {
                throw MalformedApkException("Центральный каталог выходит за пределы архива")
            }
            if (cdOffset + cdSize != eocdOffset) {
                anomalies += ArchiveAnomaly(
                    ArchiveAnomalyType.STRUCTURE_MISMATCH,
                    "Между центральным каталогом и его концом ${eocdOffset - cdOffset - cdSize} лишних байт",
                )
            }
            if (cdSize > Int.MAX_VALUE / 2) throw AnalysisLimitExceededException("Центральный каталог слишком велик")

            val cd = ByteArray(cdSize.toInt())
            raf.seek(cdOffset)
            raf.readFully(cd)
            val le = LeBytes(cd)

            val entries = ArrayList<ZipEntryInfo>(totalEntries)
            val seen = HashSet<String>()
            var p = 0
            var fakeEncryptionCount = 0
            var oddMethodCount = 0
            while (p + CD_HEADER_SIZE <= cd.size) {
                if (entries.size and 0xFF == 0) cancel.throwIfCancelled()
                if (le.u32(p) != CD_SIG) break
                val flags = le.u16(p + 8)
                val method = le.u16(p + 10)
                val crc = le.u32(p + 16)
                val compSize = le.u32(p + 20)
                val uncompSize = le.u32(p + 24)
                val nameLen = le.u16(p + 28)
                val extraLen = le.u16(p + 30)
                val commentLen = le.u16(p + 32)
                val localOffset = le.u32(p + 42)
                val nameEnd = p + CD_HEADER_SIZE + nameLen
                if (nameEnd > cd.size) throw MalformedApkException("Повреждён центральный каталог (имя записи)")
                val name = String(cd, p + CD_HEADER_SIZE, nameLen, Charsets.UTF_8)
                p = nameEnd + extraLen + commentLen

                if (entries.size >= limits.maxZipEntries) {
                    throw AnalysisLimitExceededException("Слишком много записей в архиве")
                }
                if (localOffset >= cdOffset) {
                    throw MalformedApkException("Запись '$name' указывает за пределы данных архива")
                }
                if (flags and 1 != 0) fakeEncryptionCount++
                val effectiveMethod = when (method) {
                    METHOD_STORED -> METHOD_STORED
                    METHOD_DEFLATED -> METHOD_DEFLATED
                    else -> {
                        oddMethodCount++
                        METHOD_DEFLATED
                    }
                }
                if (effectiveMethod == METHOD_STORED && compSize != uncompSize) {
                    anomalies += ArchiveAnomaly(
                        ArchiveAnomalyType.INCONSISTENT_SIZES,
                        "'$name': для несжатой записи размеры отличаются ($compSize ≠ $uncompSize)",
                    )
                }
                if (!seen.add(name)) {
                    anomalies += ArchiveAnomaly(ArchiveAnomalyType.DUPLICATE_ENTRY, "Повтор имени '$name'")
                }
                if (isTraversal(name)) {
                    anomalies += ArchiveAnomaly(ArchiveAnomalyType.PATH_TRAVERSAL, "Опасное имя '$name'")
                }
                entries += ZipEntryInfo(name, effectiveMethod, flags, crc, compSize, uncompSize, localOffset)
            }
            if (entries.isEmpty()) throw MalformedApkException("Архив не содержит записей")
            if (entries.size != totalEntries) {
                anomalies += ArchiveAnomaly(
                    ArchiveAnomalyType.STRUCTURE_MISMATCH,
                    "В каталоге ${entries.size} записей, а заявлено $totalEntries",
                )
            }
            if (fakeEncryptionCount > 0) {
                anomalies += ArchiveAnomaly(
                    ArchiveAnomalyType.FAKE_ENCRYPTION_FLAG,
                    "Флаг шифрования у $fakeEncryptionCount записей (Android его игнорирует)",
                )
            }
            if (oddMethodCount > 0) {
                anomalies += ArchiveAnomaly(
                    ArchiveAnomalyType.UNSUPPORTED_COMPRESSION_METHOD,
                    "Нестандартный метод сжатия у $oddMethodCount записей",
                )
            }
            return SafeApkArchive(raf, size, entries, anomalies.distinct(), cdOffset, eocdOffset, limits, cancel)
        }

        private fun isTraversal(name: String): Boolean {
            val n = name.replace('\\', '/')
            return n.startsWith("/") || n.split('/').any { it == ".." } || n.contains('\u0000')
        }
    }
}
