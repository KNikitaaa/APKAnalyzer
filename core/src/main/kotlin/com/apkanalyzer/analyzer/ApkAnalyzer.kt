package com.apkanalyzer.analyzer

import com.apkanalyzer.analyzer.archive.SafeApkArchive
import com.apkanalyzer.analyzer.contents.ContentsInspector
import com.apkanalyzer.analyzer.contents.ContentsSummary
import com.apkanalyzer.analyzer.dex.DexInspector
import com.apkanalyzer.analyzer.manifest.ApkManifest
import com.apkanalyzer.analyzer.manifest.ManifestParser
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
) {

    fun analyze(
        file: File,
        displayName: String = file.name,
        cancel: CancellationCheck = CancellationCheck.NEVER,
        progress: AnalysisProgressListener = AnalysisProgressListener.NONE,
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

        archive.use { zip ->
            if (zip.find("AndroidManifest.xml") == null) {
                return AnalysisOutcome.Rejected(RejectionKind.NOT_AN_APK, "Это ZIP-архив, но в нём нет AndroidManifest.xml — это не APK")
            }
            stages += StageResult(
                AnalysisStage.ARCHIVE,
                if (zip.anomalies.isEmpty()) StageStatus.OK else StageStatus.PARTIAL,
                zip.anomalies.takeIf { it.isNotEmpty() }?.let { "аномалий структуры: ${it.size}" },
            )

            // 4. Манифест
            step(AnalysisStage.MANIFEST)
            val manifest: ApkManifest? = runStage(stages, AnalysisStage.MANIFEST) {
                val entry = zip.find("AndroidManifest.xml")!!
                val m = ManifestParser(limits).parse(zip.read(entry, limits.maxManifestBytes))
                m to if (m.truncated) "манифест прочитан не полностью" else null
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
                ContentsInspector.inspect(zip) { e ->
                    try {
                        zip.read(e, MAGIC_BYTES, truncate = true)
                    } catch (ce: AnalysisCancelledException) {
                        throw ce
                    } catch (_: Exception) {
                        null
                    }
                } to null
            }

            // 7. Код DEX + строки
            step(AnalysisStage.CODE)
            val indicators = IndicatorExtractor(limits.maxIndicatorsPerType)
            val code = runStage(stages, AnalysisStage.CODE) { analyzeDex(zip, indicators, cancel) }

            // 8. Текстовые ресурсы (assets, res/raw)
            step(AnalysisStage.ASSETS)
            runStage(stages, AnalysisStage.ASSETS) { scanTextAssets(zip, indicators, cancel) }

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
                    archiveAnomalies = zip.anomalies,
                    stages = stages,
                ),
            )
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
        zip: SafeApkArchive,
        indicators: IndicatorExtractor,
        cancel: CancellationCheck,
    ): Pair<CodeSummary, String?> {
        val entries = ContentsInspector.dexEntries(zip)
        if (entries.isEmpty()) throw MalformedApkException("В APK нет classes.dex")
        val inspector = DexInspector(limits, cancel)
        val parsed = mutableListOf<Pair<String, DexInspector.Parsed>>()
        val problems = mutableListOf<String>()
        var budget = limits.maxDexStrings
        var scanned = 0
        var definedTotal = 0
        var shortNames = 0
        for (entry in entries.take(limits.maxDexFiles)) {
            cancel.throwIfCancelled()
            try {
                val bytes = zip.read(entry, limits.maxDexBytes)
                val p = inspector.parse(entry.name, bytes, budget)
                parsed += entry.name to p
                budget -= p.strings.size
                scanned += p.strings.size
                for (s in p.strings) indicators.scan(s, entry.name)
                for (c in p.definedClasses) {
                    definedTotal++
                    val simple = c.removeSuffix(";").substringAfterLast('/').substringAfterLast('$')
                    if (simple.length <= 2) shortNames++
                }
                if (p.summary.stringsTruncated) problems += "${entry.name}: строки прочитаны не все (лимит)"
            } catch (e: AnalysisCancelledException) {
                throw e
            } catch (e: AnalysisLimitExceededException) {
                // Общий лимит распаковки — дальнейшее чтение тоже бессмысленно.
                if (zip.totalInflatedBytes > limits.maxTotalInflatedBytes) throw e
                problems += "${entry.name}: ${e.message}"
            } catch (e: MalformedApkException) {
                problems += "${entry.name}: ${e.message}"
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
        )
        return summary to problems.takeIf { it.isNotEmpty() }?.joinToString("; ")
    }

    private fun scanTextAssets(
        zip: SafeApkArchive,
        indicators: IndicatorExtractor,
        cancel: CancellationCheck,
    ): Pair<Unit, String?> {
        val candidates = zip.entries.filter { e ->
            !e.isDirectory && (e.name.startsWith("assets/") || e.name.startsWith("res/raw/")) &&
                e.name.substringAfterLast('.', "").lowercase() in TEXT_EXT
        }
        var skipped = 0
        for ((i, e) in candidates.withIndex()) {
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
                String(zip.read(e, limits.maxTextAssetBytes), Charsets.UTF_8)
            } catch (ce: AnalysisCancelledException) {
                throw ce
            } catch (_: MalformedApkException) {
                skipped++
                continue
            }
            text.lineSequence().forEach { line ->
                if (line.isNotBlank()) indicators.scan(line.take(limits.maxStringBytes), e.name)
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
        const val ANALYZER_VERSION = "0.1.0"
        private const val MAGIC_BYTES = 16
        private val TEXT_EXT = setOf("json", "txt", "xml", "html", "htm", "js", "properties", "cfg", "conf", "ini", "yml", "yaml")
    }
}
