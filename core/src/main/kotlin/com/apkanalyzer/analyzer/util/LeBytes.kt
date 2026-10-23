package com.apkanalyzer.analyzer.util

/** Чтение little-endian значений из массива байт. Выход за границы — IndexOutOfBoundsException. */
class LeBytes(val bytes: ByteArray) {
    val size: Int get() = bytes.size
    fun u8(o: Int): Int = bytes[o].toInt() and 0xFF
    fun u16(o: Int): Int = (bytes[o].toInt() and 0xFF) or ((bytes[o + 1].toInt() and 0xFF) shl 8)
    fun s32(o: Int): Int = u16(o) or (u16(o + 2) shl 16)
    fun u32(o: Int): Long = s32(o).toLong() and 0xFFFFFFFFL
    fun u64(o: Int): Long = u32(o) or (u32(o + 4) shl 32)
}
