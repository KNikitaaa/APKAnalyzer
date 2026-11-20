package com.apkanalyzer.analyzer

import com.apkanalyzer.analyzer.archive.ArchiveAnomaly
import com.apkanalyzer.analyzer.archive.SafeApkArchive
import com.apkanalyzer.analyzer.container.SplitContainer
import com.apkanalyzer.analyzer.contents.ContentsInspector
import com.apkanalyzer.analyzer.contents.ContentsSummary
import com.apkanalyzer.analyzer.dex.DexInspector
import com.apkanalyzer.analyzer.manifest.ApkManifest
import com.apkanalyzer.analyzer.manifest.ManifestParser
import com.apkanalyzer.analyzer.resources.ArscResolver
import com.apkanalyzer.analyzer.signature.SignatureInfo
import com.apkanalyzer.analyzer.signature.SignatureInspector
import com.apkanalyzer.analyzer.strings.IndicatorExtractor
import java.io.File
import java.security.MessageDigest

/**
 * Полностью локальный статический анализ APK: файл не устанавливается и не запускается,
 * никакие данные никуда не отправляются.
 *
 * Каждый этап изолирован: ошибка одного этапа (например, испорченный DEX) не прерывает
 * остальные, а отражается в [ApkAnalysisReport.stages] и снижает полноту анализа.
 * Отмена — через [CancellationCheck], при отмене выбрасывается [AnalysisCancelledException].
 */
class ApkAnalyzer(
    private val limits: AnalysisLimits = AnalysisLimits(),
    private val clock: () -> Long = System::currentTimeMillis,
    /** Куда временно распаковывать вложенные APK из контейнеров .apks/.xapk/.apkm (удаляются после анализа). */
    private val tempDir: File = File(System.getProperty("java.io.tmpdir")),
    /** Языки, на которых показывать название приложения из resources.arsc (по порядку предпочтения). */
    private val preferredLocales: List<String> = listOf("ru", "en"),
) {

    fun analyze(
        file: File,
        displayName: String = file.name,
        cancel: CancellationCheck = CancellationCheck.NEVER,
        progress: AnalysisProgressListener = AnalysisProgressListener.NONE,
        /**
         * Дополнительные части split APK (у установленных приложений и в контейнерах .apks/.xapk).
         * Манифест и подпись берутся из основного файла, а код, нативные библиотеки и строки — из всех частей.
         */
        splits: List<File> = emptyList(),
    ): AnalysisOutcome {
        val started = clock()
        val stages = mutableListOf<StageResult>()
        val totalWeight = AnalysisStage.entries.size.toFloat()
        fun step(stage: AnalysisStage) {
            cancel.throwIfCancelled()
            progress.onProgress(stage, stage.ordinal / totalWeight)
        }

        // 1. Проверка файла
        step(AnalysisStage.VALIDATION)
        if (!file.isFile) return AnalysisOutcome.Rejected(RejectionKind.NOT_FOUND, "Файл не найден или недоступен")
        val size = file.length()
        if (size > limits.maxApkBytes) {
            return AnalysisOutcome.Rejected(
                RejectionKind.TOO_LARGE,
                "Файл слишком большой: ${size / (1024 * 1024)} МБ (максимум ${limits.maxApkBytes / (1024 * 1024)} МБ)",
            )
        }
        stages += StageResult(AnalysisStage.VALIDATION, StageStatus.OK)

        // 2. SHA-256 (по всему файлу, с возможностью отмены)
        step(AnalysisStage.HASH)
        val sha256 = sha256(file, cancel)
        stages += StageResult(AnalysisStage.HASH, StageStatus.OK)

        // 3. Структура архива
        step(AnalysisStage.ARCHIVE)
        val archive = try {
            SafeApkArchive.open(file, limits, cancel)
        } catch (e: AnalysisCancelledException) {
            throw e
        } catch (e: AnalysisLimitExceededException) {
            return AnalysisOutcome.Rejected(RejectionKind.ZIP_BOMB, e.message ?: "Сработал защитный лимит")
        } catch (e: MalformedApkException) {
            val kind = if (e.message?.startsWith("Это не ZIP") == true) RejectionKind.NOT_AN_APK else RejectionKind.CORRUPTED
            return AnalysisOutcome.Rejected(kind, e.message ?: "Повреждённый архив")
        } catch (e: java.io.IOException) {
            return AnalysisOutcome.Rejected(RejectionKind.CORRUPTED, "Ошибка чтения файла: ${e.message}")
        }

        val splitInfos = mutableListOf<SplitFileInfo>()
        val splitArchives = mutableListOf<Source>()
        // Контейнер split APK (.apks/.xapk/.apkm): анализируем основной APK из него, остальные — как части.
        var primary = archive
        var container: SplitContainer.Extracted? = null
        val containerAnomalies = mutableListOf<ArchiveAnomaly>()
        if (archive.find("AndroidManifest.xml") == null) {
            val format = SplitContainer.detect(archive)
            if (format == null) {
                archive.close()
                return AnalysisOutcome.Rejected(RejectionKind.NOT_AN_APK, "Это ZIP-архив, но в нём нет AndroidManifest.xml — это не APK")
            }
            val extracted = try {
                SplitContainer.extract(archive, format, tempDir, limits, cancel)
            } catch (e: AnalysisCancelledException) {
                archive.close(); throw e
            } catch (e: AnalysisLimitExceededException) {
                archive.close()
                return AnalysisOutcome.Rejected(RejectionKind.ZIP_BOMB, e.message ?: "Сработал защитный лимит")
            } catch (e: Exception) {
                archive.close()
                return AnalysisOutcome.Rejected(RejectionKind.CORRUPTED, "Не удалось распаковать контейнер ${format.label}: ${e.message}")
            }
            containerAnomalies += archive.anomalies.map { it.copy(detail = "контейнер: ${it.detail}") }
            archive.close()
            container = extracted
            val unreadable = "Основной APK «${extracted.base.name}» внутри контейнера ${format.label} не читается — " +
                "возможно, он зашифрован (так защищены новые .apkm) или повреждён"
            primary = try {
                SafeApkArchive.open(extracted.base.file, limits, cancel)
            } catch (e: AnalysisCancelledException) {
                extracted.close(); throw e
            } catch (e: Exception) {
                extracted.close()
                return AnalysisOutcome.Rejected(RejectionKind.CORRUPTED, unreadable)
            }
            if (primary.find("AndroidManifest.xml") == null) {
                primary.close(); extracted.close()
                return AnalysisOutcome.Rejected(RejectionKind.CORRUPTED, unreadable)
            }
            splitInfos += SplitFileInfo(extracted.base.name, extracted.base.file.length(), sha256(extracted.base.file, cancel), null)
        }
        val allSplits = container?.splits.orEmpty().map { it.file to it.name } + splits.map { it to it.name }
        try {
        primary.use { zip ->
            if (zip.find("AndroidManifest.xml") == null) {
                return AnalysisOutcome.Rejected(RejectionKind.NOT_AN_APK, "Это ZIP-архив, но в нём нет AndroidManifest.xml — это не APK")
            }
            for ((split, name) in allSplits) {
                cancel.throwIfCancelled()
                val opened = openSplit(split, name, cancel)
                splitInfos += opened.first
                opened.second?.let { splitArchives += Source("$name!", it) }
            }
            val sources = listOf(Source("", zip)) + splitArchives
            val anomalies = containerAnomalies + sources.flatMap { src ->
                if (src.prefix.isEmpty()) src.zip.anomalies
                else src.zip.anomalies.map { it.copy(detail = "${src.prefix.dropLast(1)}: ${it.detail}") }
            }
            val archiveProblems = buildList {
                if (anomalies.isNotEmpty()) add("аномалий структуры: ${anomalies.size}")
                splitInfos.forEach { s -> s.error?.let { add("${s.name}: $it") } }
            }
            stages += StageResult(
                AnalysisStage.ARCHIVE,
                if (archiveProblems.isEmpty()) StageStatus.OK else StageStatus.PARTIAL,
                archiveProblems.takeIf { it.isNotEmpty() }?.joinToString("; "),
            )

            // 4. Манифест
            step(AnalysisStage.MANIFEST)
            val manifest: ApkManifest? = runStage(stages, AnalysisStage.MANIFEST) {
                val entry = zip.find("AndroidManifest.xml")!!
                val m = ManifestParser(limits).parse(zip.read(entry, limits.maxManifestBytes))
                resolveResourceRefs(zip, m) to if (m.truncated) "манифест прочитан не полностью" else null
            }

            // 5. Подпись
            step(AnalysisStage.SIGNATURE)
            val signature: SignatureInfo? = runStage(stages, AnalysisStage.SIGNATURE) {
                val s = SignatureInspector(limits).inspect(zip)
                s to s.warnings.firstOrNull()
            }

            // 6. Содержимое архива
            step(AnalysisStage.CONTENTS)
            val contents: ContentsSummary? = runStage(stages, AnalysisStage.CONTENTS) {
                sources.map { src ->
                    val summary = ContentsInspector.inspect(src.zip) { e ->
                        try {
                            src.zip.read(e, MAGIC_BYTES, truncate = true)
                        } catch (ce: AnalysisCancelledException) {
                            throw ce
                        } catch (_: Exception) {
                            null
                        }
                    }
                    if (src.prefix.isEmpty()) summary else summary.prefixed(src.prefix)
                }.reduce(ContentsSummary::plus) to null
            }

            // 7. Код DEX + строки
            step(AnalysisStage.CODE)
            val indicators = IndicatorExtractor(limits.maxIndicatorsPerType)
            val code = runStage(stages, AnalysisStage.CODE) { analyzeDex(sources, indicators, cancel, manifest) }

            // 8. Текстовые ресурсы (assets, res/raw)
            step(AnalysisStage.ASSETS)
            runStage(stages, AnalysisStage.ASSETS) { scanTextAssets(sources, indicators, cancel) }

            progress.onProgress(AnalysisStage.ASSETS, 1f)
            return AnalysisOutcome.Completed(
                ApkAnalysisReport(
                    analyzerVersion = ANALYZER_VERSION,
                    analyzedAtMs = started,
                    durationMs = clock() - started,
                    file = FileInfo(displayName, size, sha256),
                    manifest = manifest,
                    signature = signature,
                    contents = contents,
                    code = code,
                    indicators = indicators.indicators,
                    indicatorsTruncated = indicators.truncated,
                    archiveAnomalies = anomalies,
                    stages = stages,
                    splits = splitInfos,
                    containerFormat = container?.format?.label,
                ),
            )
        }
        } finally {
            splitArchives.forEach { runCatching { it.zip.close() } }
            container?.close()
        }
    }

    private class Source(val prefix: String, val zip: SafeApkArchive)

    /**
     * Название приложения и versionName часто заданы ссылкой `@string/...` — подставляем текст из
     * resources.arsc. Не получилось (нет таблицы, она повреждена или слишком велика) — остаётся ссылка.
     */
    private fun resolveResourceRefs(zip: SafeApkArchive, m: ApkManifest): ApkManifest {
        fun refId(v: String?): Int? = v?.takeIf { it.startsWith("@0x") }?.removePrefix("@0x")?.toLongOrNull(16)?.toInt()
        val labelRef = refId(m.application.label)
        val versionRef = refId(m.versionName)
        if (labelRef == null && versionRef == null) return m
        val resolver = try {
            zip.find("resources.arsc")?.let { ArscResolver.parse(zip.read(it, limits.maxResourcesBytes)) }
        } catch (e: AnalysisCancelledException) {
            throw e
        } catch (_: Exception) {
            null
        } ?: return m
        fun clean(s: String?) = s?.filter { !it.isISOControl() }?.trim()?.take(120)?.ifEmpty { null }
        return m.copy(
            versionName = versionRef?.let { clean(resolver.string(it, preferredLocales)) } ?: m.versionName,
            application = m.application.copy(label = labelRef?.let { clean(resolver.string(it, preferredLocales)) } ?: m.application.label),
        )
    }

    /** Открывает часть split APK. Ошибка не прерывает анализ основного файла, а попадает в отчёт. */
    private fun openSplit(file: File, name: String, cancel: CancellationCheck): Pair<SplitFileInfo, SafeApkArchive?> {
        if (!file.isFile) return SplitFileInfo(name, 0, "", "файл недоступен") to null
        val size = file.length()
        if (size > limits.maxApkBytes) return SplitFileInfo(name, size, "", "файл слишком большой") to null
        val hash = sha256(file, cancel)
        return try {
            SplitFileInfo(name, size, hash, null) to SafeApkArchive.open(file, limits, cancel)
        } catch (e: AnalysisCancelledException) {
            throw e
        } catch (e: Exception) {
            SplitFileInfo(name, size, hash, e.message ?: e.javaClass.simpleName) to null
        }
    }

    /** Выполняет этап, превращая ошибки в статус этапа. Блок возвращает (результат, сообщение-о-частичности). */
    private inline fun <T> runStage(
        stages: MutableList<StageResult>,
        stage: AnalysisStage,
        block: () -> Pair<T, String?>,
    ): T? = try {
        val (value, partial) = block()
        stages += StageResult(stage, if (partial == null) StageStatus.OK else StageStatus.PARTIAL, partial)
        value
    } catch (e: AnalysisCancelledException) {
        throw e
    } catch (e: AnalysisLimitExceededException) {
        stages += StageResult(stage, StageStatus.FAILED, e.message)
        null
    } catch (e: MalformedApkException) {
        stages += StageResult(stage, StageStatus.FAILED, e.message)
        null
    } catch (e: OutOfMemoryError) {
        stages += StageResult(stage, StageStatus.FAILED, "недостаточно памяти")
        null
    } catch (e: Exception) {
        stages += StageResult(stage, StageStatus.FAILED, e.message ?: e.javaClass.simpleName)
        null
    }

    private fun analyzeDex(
        sources: List<Source>,
        indicators: IndicatorExtractor,
        cancel: CancellationCheck,
        manifest: ApkManifest?,
    ): Pair<CodeSummary, String?> {
        val appPackage = manifest?.packageName
        val entries = sources.flatMap { src -> ContentsInspector.dexEntries(src.zip).map { src to it } }
        if (entries.isEmpty()) throw MalformedApkException("В APK нет classes.dex")
        val inspector = DexInspector(limits, cancel)
        val parsed = mutableListOf<Pair<String, DexInspector.Parsed>>()
        val problems = mutableListOf<String>()
        var budget = limits.maxDexStrings
        var scanned = 0
        var definedTotal = 0
        var shortNames = 0
        for ((src, entry) in entries.take(limits.maxDexFiles)) {
            cancel.throwIfCancelled()
            val zip = src.zip
            val name = src.prefix + entry.name
            try {
                val bytes = zip.read(entry, limits.maxDexBytes)
                val p = inspector.parse(name, bytes, budget, appPackage)
                parsed += name to p
                budget -= p.strings.size
                // Индикаторы ищем только в строках кода приложения; без байткода — во всех строках.
                val candidates = if (p.bytecodeAttributed) p.appStrings else p.strings
                scanned += candidates.size + p.libraryStrings.size
                for (s in candidates) indicators.scan(s, name)
                for (s in p.libraryStrings) indicators.scan(s, "$name · код библиотеки", fromLibrary = true)
                for (c in p.definedClasses) {
                    definedTotal++
                    val simple = c.removeSuffix(";").substringAfterLast('/').substringAfterLast('$')
                    if (simple.length <= 2) shortNames++
                }
                if (p.summary.stringsTruncated) problems += "$name: строки прочитаны не все (лимит)"
            } catch (e: AnalysisCancelledException) {
                throw e
            } catch (e: AnalysisLimitExceededException) {
                // Общий лимит распаковки — дальнейшее чтение тоже бессмысленно.
                if (zip.totalInflatedBytes > limits.maxTotalInflatedBytes) throw e
                problems += "$name: ${e.message}"
            } catch (e: MalformedApkException) {
                problems += "$name: ${e.message}"
            }
        }
        if (entries.size > limits.maxDexFiles) problems += "DEX-файлов ${entries.size}, разобрано ${limits.maxDexFiles}"
        if (parsed.isEmpty()) throw MalformedApkException(problems.joinToString("; ").ifEmpty { "DEX не прочитан" })
        val summary = CodeSummary(
            dexFiles = parsed.map { it.second.summary },
            apiUsages = DexInspector.matchApis(parsed),
            obfuscation = ObfuscationInfo(
                definedClasses = definedTotal,
                shortNameRatio = if (definedTotal == 0) 0f else shortNames.toFloat() / definedTotal,
            ),
            stringsScanned = scanned,
            bytecodeAttributed = parsed.isNotEmpty() && parsed.all { it.second.bytecodeAttributed },
            componentsToggledByApp = run {
                val refs = parsed.flatMapTo(HashSet()) { it.second.componentToggleRefs }
                manifest?.components.orEmpty().mapNotNullTo(LinkedHashSet()) { c ->
                    c.name.takeIf { "L" + it.replace('.', '/') + ";" in refs || it in refs }
                }
            },
        )
        return summary to problems.takeIf { it.isNotEmpty() }?.joinToString("; ")
    }

    private fun scanTextAssets(
        sources: List<Source>,
        indicators: IndicatorExtractor,
        cancel: CancellationCheck,
    ): Pair<Unit, String?> {
        val candidates = sources.flatMap { src ->
            src.zip.entries.filter { e ->
                !e.isDirectory && (e.name.startsWith("assets/") || e.name.startsWith("res/raw/")) &&
                    e.name.substringAfterLast('.', "").lowercase() in TEXT_EXT
            }.map { src to it }
        }
        var skipped = 0
        for ((i, pair) in candidates.withIndex()) {
            val (src, e) = pair
            cancel.throwIfCancelled()
            if (i >= limits.maxTextAssets) {
                skipped += candidates.size - i
                break
            }
            if (e.uncompressedSize > limits.maxTextAssetBytes) {
                skipped++
                continue
            }
            val text = try {
                String(src.zip.read(e, limits.maxTextAssetBytes), Charsets.UTF_8)
            } catch (ce: AnalysisCancelledException) {
                throw ce
            } catch (_: MalformedApkException) {
                skipped++
                continue
            }
            text.lineSequence().forEach { line ->
                if (line.isNotBlank()) indicators.scan(line.take(limits.maxStringBytes), src.prefix + e.name)
            }
        }
        return Unit to if (skipped > 0) "пропущено текстовых файлов: $skipped" else null
    }

    private fun sha256(file: File, cancel: CancellationCheck): String {
        val md = MessageDigest.getInstance("SHA-256")
        val buf = ByteArray(256 * 1024)
        file.inputStream().use { input ->
            while (true) {
                cancel.throwIfCancelled()
                val n = input.read(buf)
                if (n < 0) break
                md.update(buf, 0, n)
            }
        }
        return md.digest().joinToString("") { "%02x".format(it) }
    }

    companion object {
        /** Версия анализатора: записывается в отчёт, чтобы результат был воспроизводимым. */
        const val ANALYZER_VERSION = "0.2.0"
        private const val MAGIC_BYTES = 16
        private val TEXT_EXT = setOf("json", "txt", "xml", "html", "htm", "js", "properties", "cfg", "conf", "ini", "yml", "yaml")
    }
}
