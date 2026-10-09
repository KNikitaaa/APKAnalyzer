package com.apkanalyzer.analyzer

import java.io.File
import java.io.InputStream
import java.security.MessageDigest

object HashCalculator {

    private const val BUFFER_SIZE = 8 * 1024
    private const val ALGORITHM_SHA256 = "SHA-256"
    private const val ALGORITHM_MD5 = "MD5"
    private const val MAX_FILE_BYTES_DEFAULT = 200L * 1024 * 1024

    fun sha256(file: File, maxBytes: Long = MAX_FILE_BYTES_DEFAULT): String {
        require(file.exists()) { "File does not exist: ${file.path}" }
        require(file.isFile) { "Path is not a regular file: ${file.path}" }
        if (file.length() > maxBytes) {
            throw SecurityException("File size ${file.length()} exceeds limit $maxBytes bytes")
        }
        return file.inputStream().use { digest(it, ALGORITHM_SHA256) }
    }

    fun sha256(stream: InputStream): String = digest(stream, ALGORITHM_SHA256)

    fun sha256(text: String): String {
        val md = MessageDigest.getInstance(ALGORITHM_SHA256)
        return md.digest(text.toByteArray(Charsets.UTF_8)).toHex()
    }

    fun md5(file: File): String {
        require(file.exists()) { "File does not exist: ${file.path}" }
        return file.inputStream().use { digest(it, ALGORITHM_MD5) }
    }

    private fun digest(stream: InputStream, algorithm: String): String {
        val md = MessageDigest.getInstance(algorithm)
        val buffer = ByteArray(BUFFER_SIZE)
        var bytesRead: Int
        while (stream.read(buffer).also { bytesRead = it } != -1) {
            md.update(buffer, 0, bytesRead)
        }
        return md.digest().toHex()
    }

    private fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }
}

fun File.sha256(maxBytes: Long = 200L * 1024 * 1024): String =
    HashCalculator.sha256(this, maxBytes)
