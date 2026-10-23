package com.apkanalyzer.data.export

import android.graphics.Canvas
import android.graphics.Color
import android.graphics.Paint
import android.graphics.Typeface
import android.graphics.pdf.PdfDocument
import android.text.Layout
import android.text.StaticLayout
import android.text.TextPaint
import com.apkanalyzer.analyzer.report.FeatureEmphasis
import com.apkanalyzer.analyzer.report.RawFeatureFormatter
import com.apkanalyzer.domain.model.RiskLevel
import com.apkanalyzer.report.ReportDocument
import java.io.OutputStream
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * Рисует отчёт в PDF (A4) средствами Android: без сторонних библиотек и без сети.
 * Длинные блоки переносятся между страницами построчно.
 */
class PdfReportRenderer {

    private val pageWidth = 595
    private val pageHeight = 842
    private val margin = 44f
    private val contentWidth = (pageWidth - 2 * margin).toInt()
    private val footerTop = pageHeight - 36f

    private val title = paint(20f, bold = true)
    private val h2 = paint(14f, bold = true)
    private val body = paint(10.5f)
    private val small = paint(8.5f, color = 0xFF5F6B7A.toInt())
    private val mono = paint(8.5f, color = 0xFF37474F.toInt(), typeface = Typeface.MONOSPACE)

    private lateinit var doc: PdfDocument
    private var page: PdfDocument.Page? = null
    private var canvas: Canvas? = null
    private var y = 0f
    private var pageNumber = 0
    private var footerText = ""

    fun render(report: ReportDocument, out: OutputStream) {
        doc = PdfDocument()
        footerText = "APK AI Analyzer ${report.appVersion} · правила ${report.rulesVersion} · SHA-256 ${report.file.sha256.take(16)}…"
        try {
            newPage()
            text("Отчёт о проверке APK", title)
            text(report.title, h2)
            text("Файл: ${report.file.name} · ${RawFeatureFormatter.humanBytes(report.file.sizeBytes)}", body)
            text("Дата: ${SimpleDateFormat("dd.MM.yyyy HH:mm", Locale.forLanguageTag("ru")).format(Date(report.generatedAtMs))}", body)
            text("SHA-256: ${report.file.sha256}", mono)
            space(10f)

            riskBlock(report)

            if (report.recommendations.isNotEmpty()) {
                heading("Что делать")
                report.recommendations.forEachIndexed { i, r -> text("${i + 1}. $r", body, indent = 6f) }
            }

            heading("Причины и доказательства (${report.findings.size})")
            if (report.findings.isEmpty()) text("Ни одно правило не сработало.", body)
            for (f in report.findings) {
                val kind = if (f.combination) " · связка признаков" else ""
                text("+${"%.0f".format(f.effectiveWeight)}  ${f.titleRu}", paint(11f, bold = true))
                text("${f.categoryRu}$kind · ${f.ruleId}", small)
                text(f.descriptionRu, body)
                f.mitigations.forEach { text("Смягчено: $it", paint(9.5f, color = 0xFF2E7D32.toInt())) }
                f.evidence.forEach { text("${it.source}: ${it.detail}", mono, indent = 8f) }
                space(6f)
            }

            if (report.limitations.isNotEmpty()) {
                heading("Ограничения анализа")
                report.limitations.forEach { text("• $it", body) }
            }

            report.aiExplanation?.let { ai ->
                heading("Объяснение AI (${ai.provider}, ${ai.model})")
                text("Текст сгенерирован языковой моделью по фактам локального анализа и не влияет на оценку риска.", small)
                ai.summary?.let { text(it, body) }
                if (ai.scenarios.isNotEmpty()) {
                    text("Предполагаемое поведение", paint(11f, bold = true))
                    ai.scenarios.forEach { s -> text("• ${s.title} (${s.confidence}): ${s.description}", body, indent = 6f) }
                    ai.uncertainty?.let { text("Неопределённость: $it", small) }
                }
                if (ai.actions.isNotEmpty()) {
                    text("Рекомендации модели", paint(11f, bold = true))
                    ai.actions.forEachIndexed { i, a -> text("${i + 1}. ${a.action}" + (if (a.why.isNotBlank()) " — ${a.why}" else ""), body, indent = 6f) }
                }
                ai.reportSummary?.let {
                    text(ai.reportTitle ?: "Краткий вывод", paint(11f, bold = true))
                    text(it, body)
                    ai.reportSections.forEach { sec -> text(sec.heading, paint(10.5f, bold = true)); text(sec.text, body) }
                }
                if (ai.findingNotes.isNotEmpty()) {
                    text("Пояснения к находкам", paint(11f, bold = true))
                    val titles = report.findings.associate { it.ruleId to it.titleRu }
                    ai.findingNotes.forEach { n -> text("${titles[n.ruleId] ?: n.ruleId}: ${n.text}", body, indent = 6f) }
                }
            }

            heading("Все найденные признаки")
            for (s in report.sections) {
                text(s.title, paint(11f, bold = true))
                for (item in s.items) {
                    val p = when (item.emphasis) {
                        FeatureEmphasis.WARNING -> paint(9.5f, color = 0xFFC62828.toInt())
                        FeatureEmphasis.NOTICE -> paint(9.5f, color = 0xFFB26A00.toInt())
                        FeatureEmphasis.NORMAL -> paint(9.5f)
                    }
                    text(item.title + (item.value?.let { " — $it" } ?: ""), p, indent = 8f)
                }
                space(4f)
            }

            space(8f)
            text(
                "Анализ выполнен локально, без установки и запуска APK. Отчёт сформирован приложением из локальных " +
                    "доказательств; статический анализ не гарантирует безопасность.",
                small,
            )
            finishPage()
            doc.writeTo(out)
        } finally {
            doc.close()
        }
    }

    private fun riskBlock(report: ReportDocument) {
        val color = when (report.risk.level) {
            RiskLevel.Low -> 0xFF2E7D32.toInt()
            RiskLevel.Attention -> 0xFFB26A00.toInt()
            RiskLevel.High -> 0xFFC62828.toInt()
            RiskLevel.Insufficient -> 0xFF616161.toInt()
        }
        val label = paint(18f, bold = true, color = color)
        val scoreText = if (report.risk.level == RiskLevel.Insufficient) "" else " · балл ${report.risk.score}/100"
        val l1 = layout("${report.risk.labelRu}$scoreText", label, contentWidth - 16)
        val l2 = layout(report.risk.reasonRu, body, contentWidth - 16)
        val l3 = layout("Полнота анализа ${(report.risk.coverage * 100).toInt()}% · версия правил ${report.rulesVersion}", small, contentWidth - 16)
        val h = l1.height + l2.height + l3.height + 24f
        ensure(h)
        val c = canvas!!
        val bg = Paint().apply { this.color = color; alpha = 28 }
        c.drawRect(margin, y, margin + contentWidth, y + h, bg)
        c.drawRect(margin, y, margin + 4f, y + h, Paint().apply { this.color = color })
        var yy = y + 8f
        for (l in listOf(l1, l2, l3)) {
            c.save(); c.translate(margin + 12f, yy); l.draw(c); c.restore()
            yy += l.height + 4f
        }
        y += h + 10f
    }

    private fun heading(t: String) {
        space(10f)
        ensure(40f)
        text(t, h2)
        canvas!!.drawLine(margin, y, margin + contentWidth, y, Paint().apply { color = 0xFFCFD8DC.toInt(); strokeWidth = 0.8f })
        space(6f)
    }

    /** Абзац с построчным переносом на следующую страницу. */
    private fun text(t: String, p: TextPaint, indent: Float = 0f) {
        val l = layout(t, p, (contentWidth - indent).toInt())
        for (i in 0 until l.lineCount) {
            val top = l.getLineTop(i).toFloat()
            val bottom = l.getLineBottom(i).toFloat()
            val lineH = bottom - top
            ensure(lineH)
            val c = canvas!!
            c.save()
            c.translate(margin + indent, y - top)
            c.clipRect(0f, top, contentWidth.toFloat(), bottom)
            l.draw(c)
            c.restore()
            y += lineH
        }
        y += 2f
    }

    private fun space(h: Float) { y += h }

    private fun ensure(h: Float) {
        if (y + h > footerTop - 8f) {
            finishPage()
            newPage()
        }
    }

    private fun newPage() {
        pageNumber++
        val info = PdfDocument.PageInfo.Builder(pageWidth, pageHeight, pageNumber).create()
        page = doc.startPage(info)
        canvas = page!!.canvas
        y = margin
    }

    private fun finishPage() {
        val c = canvas ?: return
        c.drawText(footerText, margin, footerTop + 14f, small)
        val num = "стр. $pageNumber"
        c.drawText(num, pageWidth - margin - small.measureText(num), footerTop + 14f, small)
        doc.finishPage(page!!)
        page = null
        canvas = null
    }

    private fun layout(t: String, p: TextPaint, width: Int): StaticLayout =
        StaticLayout.Builder.obtain(t, 0, t.length, p, width.coerceAtLeast(10))
            .setAlignment(Layout.Alignment.ALIGN_NORMAL)
            .setLineSpacing(1.5f, 1f)
            .setIncludePad(false)
            .build()

    private fun paint(size: Float, bold: Boolean = false, color: Int = Color.BLACK, typeface: Typeface = Typeface.DEFAULT) =
        TextPaint(Paint.ANTI_ALIAS_FLAG).apply {
            textSize = size
            this.color = color
            this.typeface = if (bold) Typeface.create(typeface, Typeface.BOLD) else typeface
        }
}
