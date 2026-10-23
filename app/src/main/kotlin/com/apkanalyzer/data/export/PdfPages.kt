package com.apkanalyzer.data.export

import android.graphics.Bitmap
import android.graphics.Color
import android.graphics.pdf.PdfRenderer
import android.os.ParcelFileDescriptor
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import java.io.Closeable
import java.io.File

/** Постраничный рендер PDF в Bitmap. PdfRenderer не потокобезопасен — доступ через мьютекс. */
class PdfPages(file: File) : Closeable {
    private val fd = ParcelFileDescriptor.open(file, ParcelFileDescriptor.MODE_READ_ONLY)
    private val renderer = PdfRenderer(fd)
    private val mutex = Mutex()
    private var closed = false

    val pageCount: Int = renderer.pageCount

    /** Соотношение высоты к ширине страницы (для резервирования места до рендера). */
    suspend fun aspect(index: Int): Float = mutex.withLock {
        withContext(Dispatchers.IO) {
            renderer.openPage(index).use { it.height.toFloat() / it.width }
        }
    }

    suspend fun render(index: Int, widthPx: Int): Bitmap? = mutex.withLock {
        if (closed) return@withLock null
        withContext(Dispatchers.IO) {
            renderer.openPage(index).use { page ->
                val w = widthPx.coerceIn(200, MAX_WIDTH)
                val h = (w.toFloat() * page.height / page.width).toInt()
                Bitmap.createBitmap(w, h, Bitmap.Config.ARGB_8888).also { bmp ->
                    bmp.eraseColor(Color.WHITE)
                    page.render(bmp, null, null, PdfRenderer.Page.RENDER_MODE_FOR_DISPLAY)
                }
            }
        }
    }

    override fun close() {
        if (closed) return
        closed = true
        renderer.close()
        fd.close()
    }

    companion object {
        /** Ограничение ширины рендера, чтобы не съесть память на больших экранах и масштабе. */
        const val MAX_WIDTH = 2400
    }
}
