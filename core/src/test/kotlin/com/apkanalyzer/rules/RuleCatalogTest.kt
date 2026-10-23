package com.apkanalyzer.rules

import com.apkanalyzer.testing.A
import com.apkanalyzer.testing.ApkSpec
import com.apkanalyzer.testing.DexWriter
import com.apkanalyzer.testing.a
import com.apkanalyzer.testing.component
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Для каждого правила — минимальный APK, на котором оно должно сработать.
 * Мета-тест в конце проверяет, что ни одно правило каталога не осталось без такого случая.
 */
class RuleCatalogTest {

    private val elf = byteArrayOf(0x7F, 'E'.code.toByte(), 'L'.code.toByte(), 'F'.code.toByte()) + ByteArray(64)
    private val hiddenDex = DexWriter.write(strings = listOf("payload"))

    private val positive: Map<String, ApkSpec> = mapOf(
        "SMS_READ" to ApkSpec(permissions = listOf("READ_SMS")),
        "SMS_SEND" to ApkSpec(permissions = listOf("SEND_SMS")),
        "CALLS_ACCESS" to ApkSpec(permissions = listOf("READ_CALL_LOG")),
        "MIC_RECORD" to ApkSpec(permissions = listOf("RECORD_AUDIO")),
        "CAMERA_ACCESS" to ApkSpec(permissions = listOf("CAMERA")),
        "LOCATION_ANY" to ApkSpec(permissions = listOf("ACCESS_FINE_LOCATION")),
        "LOCATION_BACKGROUND" to ApkSpec(permissions = listOf("ACCESS_BACKGROUND_LOCATION")),
        "SCREEN_CAPTURE" to ApkSpec(apis = listOf("Landroid/media/projection/MediaProjection;" to "createVirtualDisplay")),
        "NOTIFICATION_LISTENER" to ApkSpec(components = listOf(component("service", ".Notif", "BIND_NOTIFICATION_LISTENER_SERVICE", listOf("android.service.notification.NotificationListenerService")))),
        "CONTACTS_ACCOUNTS" to ApkSpec(permissions = listOf("READ_CONTACTS")),
        "DEVICE_IDS" to ApkSpec(apis = listOf("Landroid/telephony/TelephonyManager;" to "getSubscriberId")),
        "CLIPBOARD_READ" to ApkSpec(apis = listOf("Landroid/content/ClipboardManager;" to "getPrimaryClip")),
        "BOOT_AUTOSTART" to ApkSpec(permissions = listOf("RECEIVE_BOOT_COMPLETED"), components = listOf(component("receiver", ".Boot", actions = listOf("android.intent.action.BOOT_COMPLETED")))),
        "NO_LAUNCHER_ICON" to ApkSpec(launcher = false),
        "HIDE_ICON_API" to ApkSpec(apis = listOf("Landroid/content/pm/PackageManager;" to "setComponentEnabledSetting")),
        "DYNAMIC_CODE" to ApkSpec(apis = listOf("Ldalvik/system/DexClassLoader;" to "<init>")),
        "INSTALL_PACKAGES" to ApkSpec(permissions = listOf("REQUEST_INSTALL_PACKAGES")),
        "HIDDEN_PAYLOAD" to ApkSpec(extraEntries = listOf("assets/update.bin" to hiddenDex)),
        "HIDDEN_PAYLOAD_DISGUISED" to ApkSpec(extraEntries = listOf("assets/banner.png" to hiddenDex)),
        "ACCESSIBILITY_SERVICE" to ApkSpec(components = listOf(component("service", ".Acc", "BIND_ACCESSIBILITY_SERVICE", listOf("android.accessibilityservice.AccessibilityService")))),
        "DEVICE_ADMIN" to ApkSpec(components = listOf(component("receiver", ".Admin", "BIND_DEVICE_ADMIN", listOf("android.app.action.DEVICE_ADMIN_ENABLED")))),
        "DEVICE_ADMIN_DESTRUCTIVE_API" to ApkSpec(apis = listOf("Landroid/app/admin/DevicePolicyManager;" to "lockNow")),
        "OVERLAY_WINDOWS" to ApkSpec(permissions = listOf("SYSTEM_ALERT_WINDOW")),
        "PACKER" to ApkSpec(extraEntries = listOf("lib/arm64-v8a/libjiagu_a64.so" to elf)),
        "ARCHIVE_TRICKS" to ApkSpec(appAttrs = listOf(A("allowBackup", false, poolName = "zz"))),
        "HEAVY_OBFUSCATION" to ApkSpec(definedClasses = listOf("La/a;", "La/b;", "Lb/c;", "Lc/d;")),
        "ROOT_COMMANDS" to ApkSpec(dexStrings = listOf("su")),
        "SHELL_EXEC" to ApkSpec(apis = listOf("Ljava/lang/Runtime;" to "exec")),
        "SYSTEM_SHARED_UID" to ApkSpec(manifestAttrs = listOf(a("sharedUserId", "android.uid.system"))),
        "HARDCODED_PUBLIC_IP" to ApkSpec(dexStrings = listOf("185.10.10.10")),
        "SUSPICIOUS_DOMAINS" to ApkSpec(dexStrings = listOf("https://pay-check.top/x")),
        "C2_MESSENGER_API" to ApkSpec(dexStrings = listOf("https://api.telegram.org/bot123:abc/sendMessage")),
        "DEBUGGABLE" to ApkSpec(appAttrs = listOf(a("debuggable", true))),
        "DEBUG_CERTIFICATE" to ApkSpec(cert = "debug-cert.der"),
        "AOSP_TEST_KEY" to ApkSpec(cert = "aosp-like-cert.der"),
        "UNSIGNED" to ApkSpec(cert = null),
        "LOW_TARGET_SDK" to ApkSpec(targetSdk = 22),
        "CLEARTEXT_HTTP" to ApkSpec(appAttrs = listOf(a("usesCleartextTraffic", true))),
        "EXPORTED_UNPROTECTED_PROVIDER" to ApkSpec(components = listOf(component("provider", ".Data", exported = true))),

        "COMBO_SMS_STEALER" to ApkSpec(permissions = listOf("INTERNET", "READ_SMS"), launcher = false),
        "COMBO_SMS_FRAUD" to ApkSpec(permissions = listOf("SEND_SMS"), launcher = false),
        "COMBO_BANKER_ACCESSIBILITY" to ApkSpec(
            permissions = listOf("INTERNET", "SYSTEM_ALERT_WINDOW"),
            components = listOf(component("service", ".Acc", "BIND_ACCESSIBILITY_SERVICE")),
        ),
        "COMBO_SPYWARE" to ApkSpec(permissions = listOf("INTERNET", "RECORD_AUDIO"), launcher = false),
        "COMBO_DROPPER" to ApkSpec(apis = listOf("Ldalvik/system/DexClassLoader;" to "<init>"), extraEntries = listOf("assets/update.bin" to hiddenDex)),
        "COMBO_LOCKER" to ApkSpec(
            components = listOf(component("receiver", ".Admin", "BIND_DEVICE_ADMIN")),
            apis = listOf("Landroid/app/admin/DevicePolicyManager;" to "resetPassword"),
        ),
        "COMBO_STEALTH_PERSISTENCE" to ApkSpec(launcher = false, components = listOf(component("receiver", ".Boot", actions = listOf("android.intent.action.BOOT_COMPLETED")))),
        "COMBO_OTP_INTERCEPT" to ApkSpec(
            permissions = listOf("INTERNET", "RECEIVE_SMS"),
            components = listOf(component("service", ".Notif", "BIND_NOTIFICATION_LISTENER_SERVICE")),
        ),
        "COMBO_ROOT_TOOLKIT" to ApkSpec(dexStrings = listOf("su"), apis = listOf("Ljava/lang/Runtime;" to "exec")),
        "COMBO_DATA_EXFIL" to ApkSpec(permissions = listOf("READ_CONTACTS"), dexStrings = listOf("https://grab-data.xyz/upload")),
    )

    @Test
    fun baselineAppTriggersNothing() {
        val r = ApkSpec().assess()
        assertTrue("сработало: ${r.triggeredRuleIds}", r.matches.isEmpty())
        assertEquals(com.apkanalyzer.domain.model.RiskLevel.Low, r.level)
        assertEquals(0, r.score)
    }

    @Test
    fun everyRuleFiresOnItsCase() {
        val failures = positive.mapNotNull { (id, spec) ->
            val r = spec.assess()
            val m = r.matches.firstOrNull { it.ruleId == id }
            when {
                m == null -> "$id не сработало (сработали: ${r.triggeredRuleIds})"
                m.evidence.isEmpty() -> "$id сработало без доказательств"
                else -> null
            }
        }
        assertTrue(failures.joinToString("\n"), failures.isEmpty())
    }

    @Test
    fun everyCatalogRuleHasATestCase() {
        val testable = RuleCatalog.all.filter { !it.informational }.map { it.id }.toSet()
        assertEquals(emptySet<String>(), testable - positive.keys)
    }

    @Test
    fun catalogIsConsistent() {
        RuleCatalog.all.forEach {
            assertTrue("${it.id}: пустое название/описание", it.titleRu.isNotBlank() && it.descriptionRu.isNotBlank())
        }
        assertTrue(RuleCatalog.combinations.all { it.weight > 20 })
    }
}
