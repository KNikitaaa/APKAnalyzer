package com.apkanalyzer.analyzer.container

import com.apkanalyzer.analyzer.AnalysisLimits
import com.apkanalyzer.analyzer.CancellationCheck
import com.apkanalyzer.analyzer.MalformedApkException
import com.apkanalyzer.analyzer.throwIfCancelled
import com.apkanalyzer.analyzer.archive.SafeApkArchive
import com.apkanalyzer.analyzer.archive.ZipEntryInfo
import java.io.Closeable
import java.io.File

/** Формат контейнера split APK. */
enum class ContainerFormat(val label: String, val descriptionRu: String) {
    APKS("APKS", "набор split APK (SAI, bundletool)"),
    XAPK("XAPK", "контейнер APKPure"),
    APKM("APKM", "контейнер APKMirror"),
}

/**
 * Контейнеры split APK — ZIP-архивы с несколькими APK внутри: основным (base) и частями
 * (языки, плотность экрана, архитектура процессора, модули функций).
 *
 * Вложенные APK распаковываются потоком во временную папку под служебными именами `part-N.apk`
 * (имена из архива на диск не попадают — `../` не выйдет за пределы папки). Действуют лимиты
 * [AnalysisLimits]: размер каждого APK, общий объём распаковки, защита от zip-bomb.
 */
object SplitContainer {

    /** Сколько частей максимум извлекаем (в реальных приложениях — до пары десятков). */
    private const val MAX_PARTS = 64

    class Part(val name: String, val file: File)

    class Extracted(
        val format: ContainerFormat,
        val base: Part,
        val splits: List<Part>,
        private val dir: File,
    ) : Closeable {
        override fun close() {
            dir.deleteRecursively()
        }
    }

    /** Формат контейнера или null, если это не контейнер (нет вложенных APK или есть свой манифест). */
    fun detect(archive: SafeApkArchive): ContainerFormat? {
        if (archive.find("AndroidManifest.xml") != null) return null
        if (apkEntries(archive).isEmpty()) return null
        return when {
            archive.find("manifest.json") != null -> ContainerFormat.XAPK
            archive.find("info.json") != null -> ContainerFormat.APKM
            else -> ContainerFormat.APKS
        }
    }

    fun extract(
        archive: SafeApkArchive,
        format: ContainerFormat,
        tempDir: File,
        limits: AnalysisLimits,
        cancel: CancellationCheck,
    ): Extracted {
        val entries = apkEntries(archive)
        val base = chooseBase(archive, format, entries) ?: throw MalformedApkException("В контейнере не найден основной APK")
        val ordered = listOf(base) + entries.filter { it !== base }
        if (ordered.size > MAX_PARTS) throw MalformedApkException("Слишком много частей в контейнере: ${ordered.size}")

        val dir = File(tempDir, "container-" + System.nanoTime()).apply { mkdirs() }
        try {
            val parts = ordered.mapIndexed { i, e ->
                cancel.throwIfCancelled()
                val file = File(dir, "part-$i.apk")
                file.outputStream().buffered().use { out -> archive.copyTo(e, out, limits.maxApkBytes) }
                Part(e.name, file)
            }
            return Extracted(format, parts.first(), parts.drop(1), dir)
        } catch (t: Throwable) {
            dir.deleteRecursively()
            throw t
        }
    }

    private fun apkEntries(archive: SafeApkArchive): List<ZipEntryInfo> =
        archive.entries.filter { !it.isDirectory && it.name.endsWith(".apk", ignoreCase = true) && !it.name.startsWith("Android/obb/") }
            .distinctBy { it.name }

    private fun chooseBase(archive: SafeApkArchive, format: ContainerFormat, apks: List<ZipEntryInfo>): ZipEntryInfo? {
        fun named(vararg names: String) = apks.firstOrNull { e -> names.any { e.name == it || e.name.endsWith("/$it") } }
        named("base.apk", "base-master.apk")?.let { return it }
        if (format == ContainerFormat.XAPK) {
            xapkPackage(archive)?.let { pkg -> named("$pkg.apk")?.let { return it } }
        }
        // Части конфигураций называются config.* / split_config.* / base-<abi> — основной среди остальных самый большой.
        val nonConfig = apks.filterNot { val n = it.name.substringAfterLast('/'); n.startsWith("config.") || n.startsWith("split_") }
        return (nonConfig.ifEmpty { apks }).maxByOrNull { it.uncompressedSize }
    }

    /** Имя пакета из manifest.json контейнера XAPK (без полноценного JSON-парсера — нужна одна строка). */
    private fun xapkPackage(archive: SafeApkArchive): String? {
        val entry = archive.find("manifest.json") ?: return null
        val text = try {
            String(archive.read(entry, 256 * 1024, truncate = true), Charsets.UTF_8)
        } catch (_: Exception) {
            return null
        }
        return Regex(""""package_name"\s*:\s*"([A-Za-z0-9_.]+)"""").find(text)?.groupValues?.get(1)
    }
}
