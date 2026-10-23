package com.apkanalyzer.analyzer.contents

import com.apkanalyzer.analyzer.archive.SafeApkArchive
import com.apkanalyzer.analyzer.archive.ZipEntryInfo

data class NativeLibrary(
    val path: String,
    val abi: String,
    val fileName: String,
    val sizeBytes: Long,
    /** Начинается ли файл с сигнатуры ELF (иначе — подмена/зашифрованный payload). */
    val isElf: Boolean?,
)

/** Упаковщик/протектор, найденный по характерным файлам. */
data class PackerMatch(
    val name: String,
    val evidence: String,
)

/** Исполняемое содержимое, спрятанное вне стандартных мест (assets/, res/raw/ и т.п.). */
data class HiddenPayload(
    val path: String,
    val kind: PayloadKind,
    val sizeBytes: Long,
)

enum class PayloadKind(val labelRu: String) {
    DEX("DEX-код"),
    APK_OR_JAR("Вложенный APK/JAR/ZIP"),
    ELF("Нативный исполняемый файл"),
    MISNAMED("Файл с подменённым расширением"),
}

data class ContentsSummary(
    val totalEntries: Int,
    val dexFiles: List<String>,
    val nativeLibraries: List<NativeLibrary>,
    val abis: Set<String>,
    val packers: List<PackerMatch>,
    val hiddenPayloads: List<HiddenPayload>,
    val hasResourcesArsc: Boolean,
)

/**
 * Обзор содержимого архива: DEX, нативные библиотеки, известные упаковщики,
 * исполняемые файлы в assets. Читает только первые байты файлов (сигнатуры).
 */
object ContentsInspector {

    private val CLASSES_DEX = Regex("""^classes(\d*)\.dex$""")
    private val NATIVE_LIB = Regex("""^lib/([^/]+)/([^/]+\.so)$""")

    /** Характерные файлы известных коммерческих упаковщиков/протекторов. */
    private val PACKER_FILES: List<Pair<Regex, String>> = listOf(
        Regex("""(^|/)libjiagu(_a64|_x86|_x64)?\.so$""") to "Qihoo 360 Jiagu",
        Regex("""(^|/)libprotectClass\.so$""") to "Qihoo 360 (старый)",
        Regex("""(^|/)libsecexe(\.x86)?\.so$""") to "Bangcle",
        Regex("""(^|/)libsecmain(\.x86)?\.so$""") to "Bangcle",
        Regex("""(^|/)libSecShell(-x86)?\.so$""") to "Bangcle (SecShell)",
        Regex("""(^|/)libDexHelper(-x86)?\.so$""") to "SecNeo / Bangcle (DexHelper)",
        Regex("""(^|/)libexec(main)?\.so$""") to "Ijiami",
        Regex("""^assets/ijiami\.(dat|ajm)$""") to "Ijiami",
        Regex("""(^|/)libshell[ax]-.*\.so$""") to "Tencent Legu",
        Regex("""(^|/)libtup\.so$""") to "Tencent Legu",
        Regex("""^assets/(0OO00l111l1l|t86|tosversion)$""") to "Tencent Legu",
        Regex("""(^|/)libbaiduprotect(_x86)?\.so$""") to "Baidu Protect",
        Regex("""(^|/)libmobisec\.so$""") to "Alibaba Mobisec",
        Regex("""(^|/)libAPKProtect\.so$""") to "APKProtect",
        Regex("""(^|/)libchaosvmp\.so$""") to "Naga (ChaosVMP)",
        Regex("""(^|/)libddog\.so$""") to "Naga",
        Regex("""(^|/)libnqshield\.so$""") to "NQ Shield",
        Regex("""(^|/)libkwscmm\.so$""") to "Kiwisec",
        Regex("""(^|/)libitsec\.so$""") to "Itsec",
        Regex("""(^|/)libdexprotector[^/]*\.so$""") to "DexProtector",
        Regex("""^assets/dp\.arm(-v7|-v8)?\.so\.dat$""") to "DexProtector",
        Regex("""(^|/)libjgdtc\.so$""") to "Jiagu (dtc)",
        Regex("""^assets/classes\.jar$""") to "Неизвестный упаковщик (classes.jar в assets)",
    )

    private val EXECUTABLE_EXT = setOf("dex", "jar", "apk", "zip", "so", "odex", "vdex", "oat", "bin")
    private val MEDIA_OR_DATA_EXT = setOf(
        "png", "jpg", "jpeg", "gif", "webp", "mp3", "ogg", "wav", "mp4", "ttf", "otf", "txt", "json", "xml",
        "html", "htm", "css", "js", "dat", "db", "properties", "cfg", "conf", "csv", "svg", "ico", "webm", "glsl",
    )

    fun dexEntries(archive: SafeApkArchive): List<ZipEntryInfo> =
        archive.entries
            .filter { CLASSES_DEX.matches(it.name) }
            .distinctBy { it.name }
            .sortedBy { CLASSES_DEX.find(it.name)!!.groupValues[1].ifEmpty { "1" }.toIntOrNull() ?: Int.MAX_VALUE }

    fun inspect(archive: SafeApkArchive, readMagic: (ZipEntryInfo) -> ByteArray?): ContentsSummary {
        val dex = dexEntries(archive).map { it.name }

        val libs = mutableListOf<NativeLibrary>()
        for (e in archive.entries) {
            val m = NATIVE_LIB.find(e.name) ?: continue
            val head = readMagic(e)
            libs += NativeLibrary(
                path = e.name,
                abi = m.groupValues[1],
                fileName = m.groupValues[2],
                sizeBytes = e.uncompressedSize,
                isElf = head?.let { isElf(it) },
            )
        }

        val packers = LinkedHashMap<String, PackerMatch>()
        for (e in archive.entries) {
            for ((re, name) in PACKER_FILES) {
                if (re.containsMatchIn(e.name) && name !in packers) packers[name] = PackerMatch(name, e.name)
            }
        }

        val payloads = mutableListOf<HiddenPayload>()
        for (e in archive.entries) {
            if (e.isDirectory || e.uncompressedSize < 4) continue
            val n = e.name
            val inStandardPlace = CLASSES_DEX.matches(n) || NATIVE_LIB.matches(n) ||
                n.startsWith("META-INF/") || n == "AndroidManifest.xml" || n == "resources.arsc" ||
                n.startsWith("kotlin/") || n.startsWith("okhttp3/") || n.startsWith("res/") && n.endsWith(".xml")
            if (inStandardPlace) continue
            val ext = n.substringAfterLast('/').substringAfterLast('.', "").lowercase()
            val candidate = n.startsWith("assets/") || n.startsWith("res/raw/") || ext in EXECUTABLE_EXT || !n.contains('/')
            if (!candidate) continue
            val head = readMagic(e) ?: continue
            val kind = when {
                isDex(head) -> PayloadKind.DEX
                isZip(head) -> PayloadKind.APK_OR_JAR
                isElf(head) -> PayloadKind.ELF
                else -> null
            } ?: continue
            // Исполняемое содержимое под видом картинки/данных — отдельный, более сильный признак.
            val finalKind = if (ext in MEDIA_OR_DATA_EXT) PayloadKind.MISNAMED else kind
            payloads += HiddenPayload(n, finalKind, e.uncompressedSize)
        }

        return ContentsSummary(
            totalEntries = archive.entries.size,
            dexFiles = dex,
            nativeLibraries = libs,
            abis = libs.mapTo(sortedSetOf()) { it.abi },
            packers = packers.values.toList(),
            hiddenPayloads = payloads,
            hasResourcesArsc = archive.find("resources.arsc") != null,
        )
    }

    fun isDex(h: ByteArray) = h.size >= 4 && h[0] == 'd'.code.toByte() && h[1] == 'e'.code.toByte() && h[2] == 'x'.code.toByte() && h[3] == '\n'.code.toByte()
    fun isZip(h: ByteArray) = h.size >= 4 && h[0] == 'P'.code.toByte() && h[1] == 'K'.code.toByte() && h[2] == 3.toByte() && h[3] == 4.toByte()
    fun isElf(h: ByteArray) = h.size >= 4 && h[0] == 0x7F.toByte() && h[1] == 'E'.code.toByte() && h[2] == 'L'.code.toByte() && h[3] == 'F'.code.toByte()
}
