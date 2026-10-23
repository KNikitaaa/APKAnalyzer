package com.apkanalyzer.testing

import com.apkanalyzer.analyzer.axml.AndroidAttributes
import com.apkanalyzer.analyzer.axml.XmlElement
import java.io.ByteArrayOutputStream
import java.io.File
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.zip.CRC32
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

/** Ссылка на ресурс как значение атрибута. */
data class Ref(val id: Int)

/** Атрибут для генератора AXML. [poolName] позволяет записать в пул строк «чужое» имя (обфускация). */
data class A(
    val name: String,
    val value: Any,
    val ns: String? = XmlElement.ANDROID_NS,
    val resId: Int? = if (ns == XmlElement.ANDROID_NS) AndroidAttributes.idFor(name) else null,
    val poolName: String = name,
)

data class El(val name: String, val attrs: List<A> = emptyList(), val children: List<El> = emptyList())

fun el(name: String, vararg attrs: A, children: List<El> = emptyList()) = El(name, attrs.toList(), children)
fun a(name: String, value: Any) = A(name, value)
fun plain(name: String, value: Any) = A(name, value, ns = null)

/** Генератор бинарного Android XML — то же, что делает aapt2 при сборке APK. */
object AxmlWriter {
    fun write(root: El, utf8: Boolean = false): ByteArray {
        // Строки атрибутов с resource ID должны идти первыми — их индексы совпадают с resource map.
        val withId = LinkedHashMap<String, Int>()
        val others = LinkedHashSet<String>()
        fun collect(e: El) {
            others += e.name
            for (at in e.attrs) {
                if (at.resId != null) withId.putIfAbsent(at.poolName, at.resId) else others += at.poolName
                at.ns?.let { others += it }
                if (at.value is String) others += at.value
            }
            e.children.forEach(::collect)
        }
        collect(root)
        others += "android"
        others += XmlElement.ANDROID_NS
        val pool = withId.keys.toMutableList().apply { addAll(others.filter { it !in withId.keys }) }
        val idx = pool.withIndex().associate { (i, s) -> s to i }

        val body = ByteArrayOutputStream()
        body.write(stringPool(pool, utf8))
        body.write(chunk(0x0180, 8, le { withId.values.forEach(::putInt) }))
        val nsChunk = le { putInt(1); putInt(-1); putInt(idx.getValue("android")); putInt(idx.getValue(XmlElement.ANDROID_NS)) }
        body.write(chunk(0x0100, 16, nsChunk))
        fun emit(e: El) {
            val start = le {
                putInt(1); putInt(-1)
                putInt(-1); putInt(idx.getValue(e.name))
                putShort(20); putShort(20); putShort(e.attrs.size.toShort())
                putShort(0); putShort(0); putShort(0)
                for (at in e.attrs) {
                    putInt(at.ns?.let { idx.getValue(it) } ?: -1)
                    putInt(idx.getValue(at.poolName))
                    val (type, data, raw) = when (val v = at.value) {
                        is String -> Triple(0x03, idx.getValue(v), idx.getValue(v))
                        is Boolean -> Triple(0x12, if (v) -1 else 0, -1)
                        is Int -> Triple(0x10, v, -1)
                        is Ref -> Triple(0x01, v.id, -1)
                        else -> error("unsupported $v")
                    }
                    putInt(raw)
                    putShort(8); put(0); put(type.toByte()); putInt(data)
                }
            }
            body.write(chunk(0x0102, 16, start))
            e.children.forEach(::emit)
            body.write(chunk(0x0103, 16, le { putInt(1); putInt(-1); putInt(-1); putInt(idx.getValue(e.name)) }))
        }
        emit(root)
        body.write(chunk(0x0101, 16, nsChunk))
        val content = body.toByteArray()
        return le { putShort(0x0003); putShort(8); putInt(8 + content.size) } + content
    }

    private fun stringPool(strings: List<String>, utf8: Boolean): ByteArray {
        val data = ByteArrayOutputStream()
        val offsets = mutableListOf<Int>()
        for (s in strings) {
            offsets += data.size()
            if (utf8) {
                val b = s.toByteArray(Charsets.UTF_8)
                require(s.length < 128 && b.size < 128)
                data.write(s.length); data.write(b.size); data.write(b); data.write(0)
            } else {
                data.write(le { putShort(s.length.toShort()); s.forEach { putChar(it) }; putShort(0) })
            }
        }
        while (data.size() % 4 != 0) data.write(0)
        val headerSize = 28
        val stringsStart = headerSize + strings.size * 4
        val payload = le {
            putInt(strings.size); putInt(0); putInt(if (utf8) 0x100 else 0); putInt(stringsStart); putInt(0)
            offsets.forEach(::putInt)
        } + data.toByteArray()
        return le { putShort(0x0001); putShort(headerSize.toShort()); putInt(8 + payload.size) } + payload
    }

    private fun chunk(type: Int, headerSize: Int, payload: ByteArray): ByteArray =
        le { putShort(type.toShort()); putShort(headerSize.toShort()); putInt(8 + payload.size) } + payload
}

/** Генератор минимального DEX: строки, типы, ссылки на методы и определённые классы. */
object DexWriter {
    fun write(
        strings: List<String> = emptyList(),
        methodRefs: List<Pair<String, String>> = emptyList(),
        definedClasses: List<String> = listOf("Lcom/example/app/MainActivity;"),
    ): ByteArray {
        val all = LinkedHashSet<String>()
        all += strings
        methodRefs.forEach { (c, m) -> all += c; all += m }
        all += definedClasses
        val pool = all.toList()
        val sIdx = pool.withIndex().associate { (i, s) -> s to i }
        val types = (methodRefs.map { it.first } + definedClasses).distinct()
        val tIdx = types.withIndex().associate { (i, s) -> s to i }

        val stringIdsOff = 0x70
        val typeIdsOff = stringIdsOff + pool.size * 4
        val methodIdsOff = typeIdsOff + types.size * 4
        val classDefsOff = methodIdsOff + methodRefs.size * 8
        var dataOff = classDefsOff + definedClasses.size * 32
        val stringData = ByteArrayOutputStream()
        val stringOffsets = pool.map { s ->
            val off = dataOff + stringData.size()
            val bytes = s.toByteArray(Charsets.UTF_8) // для ASCII совпадает с MUTF-8
            var len = s.length
            do {
                var b = len and 0x7F
                len = len ushr 7
                if (len != 0) b = b or 0x80
                stringData.write(b)
            } while (len != 0)
            stringData.write(bytes); stringData.write(0)
            off
        }
        val fileSize = dataOff + stringData.size()
        val buf = ByteBuffer.allocate(fileSize).order(ByteOrder.LITTLE_ENDIAN)
        buf.put("dex\n035\u0000".toByteArray(Charsets.ISO_8859_1))
        buf.putInt(32, fileSize); buf.putInt(36, 0x70); buf.putInt(40, 0x12345678)
        buf.putInt(56, pool.size); buf.putInt(60, stringIdsOff)
        buf.putInt(64, types.size); buf.putInt(68, typeIdsOff)
        buf.putInt(88, methodRefs.size); buf.putInt(92, methodIdsOff)
        buf.putInt(96, definedClasses.size); buf.putInt(100, classDefsOff)
        stringOffsets.forEachIndexed { i, off -> buf.putInt(stringIdsOff + i * 4, off) }
        types.forEachIndexed { i, t -> buf.putInt(typeIdsOff + i * 4, sIdx.getValue(t)) }
        methodRefs.forEachIndexed { i, (c, m) ->
            buf.putShort(methodIdsOff + i * 8, tIdx.getValue(c).toShort())
            buf.putShort(methodIdsOff + i * 8 + 2, 0)
            buf.putInt(methodIdsOff + i * 8 + 4, sIdx.getValue(m))
        }
        definedClasses.forEachIndexed { i, c -> buf.putInt(classDefsOff + i * 32, tIdx.getValue(c)) }
        buf.position(dataOff); buf.put(stringData.toByteArray())
        return buf.array()
    }
}

/** Сборщик ZIP/APK для тестов, включая добавление APK Signing Block. */
object ApkBuilder {
    fun zip(entries: List<Pair<String, ByteArray>>, stored: Set<String> = emptySet()): ByteArray {
        val out = ByteArrayOutputStream()
        ZipOutputStream(out).use { z ->
            for ((name, data) in entries) {
                val e = ZipEntry(name)
                if (name in stored) {
                    e.method = ZipEntry.STORED
                    e.size = data.size.toLong(); e.compressedSize = data.size.toLong()
                    e.crc = CRC32().apply { update(data) }.value
                }
                z.putNextEntry(e); z.write(data); z.closeEntry()
            }
        }
        return out.toByteArray()
    }

    /** Вставляет APK Signing Block перед центральным каталогом и исправляет смещение в EOCD. */
    fun withSigningBlock(zip: ByteArray, pairs: List<Pair<Int, ByteArray>>): ByteArray {
        val eocd = zip.size - 22
        val bb = ByteBuffer.wrap(zip).order(ByteOrder.LITTLE_ENDIAN)
        require(bb.getInt(eocd) == 0x06054b50)
        val cdOffset = bb.getInt(eocd + 16)
        val pairBytes = ByteArrayOutputStream()
        for ((id, value) in pairs) pairBytes.write(le { putLong(value.size + 4L); putInt(id) } + value)
        val sizeField = pairBytes.size() + 8 + 16L
        val block = le { putLong(sizeField) } + pairBytes.toByteArray() +
            le { putLong(sizeField) } + "APK Sig Block 42".toByteArray(Charsets.US_ASCII)
        val result = zip.copyOfRange(0, cdOffset) + block + zip.copyOfRange(cdOffset, zip.size)
        ByteBuffer.wrap(result).order(ByteOrder.LITTLE_ENDIAN).putInt(result.size - 22 + 16, cdOffset + block.size)
        return result
    }

    /** Значение блока v2/v3 с одним подписантом и заданными сертификатами (подпись не настоящая). */
    fun v2SignerValue(certsDer: List<ByteArray>): ByteArray {
        val certs = lp(certsDer.fold(ByteArray(0)) { acc, c -> acc + lp(c) })
        val signedData = lp(ByteArray(0)) + certs + lp(ByteArray(0))
        val signer = lp(signedData) + lp(ByteArray(0)) + lp(ByteArray(16))
        return lp(lp(signer))
    }

    fun lp(b: ByteArray): ByteArray = le { putInt(b.size) } + b
}

fun le(block: ByteBuffer.() -> Unit): ByteArray {
    val buf = ByteBuffer.allocate(1 shl 16).order(ByteOrder.LITTLE_ENDIAN)
    buf.block()
    return buf.array().copyOf(buf.position())
}

fun resource(name: String): ByteArray =
    requireNotNull(Fixtures::class.java.getResourceAsStream("/fixtures/$name")) { "нет ресурса $name" }.readBytes()

fun tempApk(bytes: ByteArray): File = File.createTempFile("test", ".apk").apply {
    deleteOnExit()
    writeBytes(bytes)
}

object Fixtures {
    const val PKG = "com.example.sample"

    /** Манифест «подозрительного» приложения: SMS + автозапуск + без иконки. */
    fun suspiciousManifest(targetSdk: Int = 30) = el(
        "manifest", plain("package", PKG), a("versionCode", 42), a("versionName", "1.2.3"),
        children = listOf(
            el("uses-sdk", a("minSdkVersion", 21), a("targetSdkVersion", targetSdk)),
            el("uses-permission", a("name", "android.permission.READ_SMS")),
            el("uses-permission", a("name", "android.permission.RECEIVE_BOOT_COMPLETED")),
            el("uses-permission", a("name", "android.permission.INTERNET")),
            el(
                "application", a("name", ".App"), a("debuggable", true), a("allowBackup", false),
                children = listOf(
                    el("activity", a("name", ".SettingsActivity")),
                    el(
                        "receiver", a("name", ".BootReceiver"),
                        children = listOf(el("intent-filter", children = listOf(el("action", a("name", "android.intent.action.BOOT_COMPLETED"))))),
                    ),
                    el("service", a("name", "com.example.sample.sync.SyncService"), a("exported", false)),
                    el("provider", a("name", ".DataProvider"), a("authorities", "com.example.sample.data;com.example.sample.files")),
                ),
            ),
        ),
    )

    fun launcherManifest() = el(
        "manifest", plain("package", PKG), a("versionCode", 1), a("versionName", "1.0"),
        children = listOf(
            el("uses-sdk", a("minSdkVersion", 26), a("targetSdkVersion", 36)),
            el("uses-permission", a("name", "android.permission.INTERNET")),
            el(
                "application",
                children = listOf(
                    el(
                        "activity", a("name", ".MainActivity"), a("exported", true),
                        children = listOf(el("intent-filter", children = listOf(
                            el("action", a("name", "android.intent.action.MAIN")),
                            el("category", a("name", "android.intent.category.LAUNCHER")),
                        ))),
                    ),
                ),
            ),
        ),
    )

    fun suspiciousDex() = DexWriter.write(
        strings = listOf(
            "https://evil-panel.xyz/api/upload?id=1",
            "185.234.10.77",
            "version 1.2.3.4",
            "com.google.android.gms",
            "su",
            "/system/bin/sh -c chmod 777 /data/local/tmp/payload",
            "content://sms/inbox",
            "Hello world",
        ),
        methodRefs = listOf(
            "Landroid/telephony/SmsManager;" to "sendTextMessage",
            "Ldalvik/system/DexClassLoader;" to "<init>",
            "Landroid/content/pm/PackageManager;" to "setComponentEnabledSetting",
            "Ljava/lang/String;" to "length",
        ),
        definedClasses = listOf("Lcom/example/sample/App;", "La/a;", "La/b;", "Lb/c;"),
    )

    fun suspiciousApk(signed: Boolean = true): ByteArray {
        val zip = ApkBuilder.zip(
            listOf(
                "AndroidManifest.xml" to AxmlWriter.write(suspiciousManifest()),
                "classes.dex" to suspiciousDex(),
                "classes2.dex" to DexWriter.write(strings = listOf("http://192.168.1.10:8080/debug")),
                "resources.arsc" to ByteArray(64),
                "lib/arm64-v8a/libjiagu_a64.so" to byteArrayOf(0x7F, 'E'.code.toByte(), 'L'.code.toByte(), 'F'.code.toByte()) + ByteArray(100),
                "assets/config.json" to """{"server":"https://c2.badhost.top/gate.php","backup":"91.215.85.3"}""".toByteArray(),
                "assets/logo.png" to DexWriter.write(strings = listOf("hidden")),
            ),
        )
        return if (signed) ApkBuilder.withSigningBlock(zip, listOf(0x7109871a to ApkBuilder.v2SignerValue(listOf(resource("debug-cert.der"))))) else zip
    }

    fun cleanApk(): ByteArray = ApkBuilder.withSigningBlock(
        ApkBuilder.zip(
            listOf(
                "AndroidManifest.xml" to AxmlWriter.write(launcherManifest(), utf8 = true),
                "classes.dex" to DexWriter.write(strings = listOf("Hello"), methodRefs = listOf("Ljava/lang/String;" to "length")),
                "META-INF/DEV.RSA" to resource("v1-dev.rsa"),
            ),
        ),
        listOf(0x7109871a to ApkBuilder.v2SignerValue(listOf(resource("dev-cert.der")))),
    )
}
