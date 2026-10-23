package com.apkanalyzer.testing

import java.io.File

/**
 * Генерирует безопасные синтетические APK для ручной проверки приложения на эмуляторе.
 * Это не рабочие приложения (их нельзя установить) — только структуры для анализатора.
 *
 * Запуск: main(arrayOf("samples/synthetic")).
 */
object SampleApkGenerator {
    @JvmStatic
    fun main(args: Array<String>) {
        val dir = File(args.firstOrNull() ?: "samples/synthetic").apply { mkdirs() }
        fun out(name: String, bytes: ByteArray) {
            File(dir, name).writeBytes(bytes)
            println("${File(dir, name).path}  ${bytes.size} bytes")
        }

        out("01-suspicious-sms-autostart.apk", Fixtures.suspiciousApk())
        out("02-clean-launcher.apk", Fixtures.cleanApk())

        val apk = Fixtures.suspiciousApk()
        out("03-truncated.apk", apk.copyOf(apk.size / 2))

        val broken = Fixtures.suspiciousApk()
        val dexPos = String(broken, Charsets.ISO_8859_1).indexOf("classes.dex") + 40
        for (i in dexPos until minOf(dexPos + 64, broken.size)) broken[i] = (broken[i].toInt() xor 0x55).toByte()
        out("04-corrupted-data.apk", broken)

        out(
            "05-zip-bomb.apk",
            ApkBuilder.zip(
                listOf(
                    "AndroidManifest.xml" to AxmlWriter.write(Fixtures.launcherManifest()),
                    "classes.dex" to ByteArray(200 * 1024 * 1024),
                ),
            ),
        )
        out("06-not-an-apk.apk", "Это текстовый файл с расширением .apk".toByteArray())
        out("07-zip-without-manifest.apk", ApkBuilder.zip(listOf("readme.txt" to "hello".toByteArray())))
    }
}
