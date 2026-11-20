package com.apkanalyzer.rules

import com.apkanalyzer.domain.model.RiskLevel
import com.apkanalyzer.testing.ApkSpec
import com.apkanalyzer.testing.Insn
import com.apkanalyzer.testing.component
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** Типичные библиотеки не должны превращать обычное приложение в «опасное» (замер на реальных APK). */
class LibraryCodeRulesTest {

    private val hideIcon = Insn.Invoke("Landroid/content/pm/PackageManager;", "setComponentEnabledSetting")
    private val main = "Lcom/example/sample/MainActivity;"
    private val boot = "android.intent.action.BOOT_COMPLETED"

    /** Так выглядит любое приложение с WorkManager: своя перезагрузка задач и включение компонентов. */
    private fun workManagerApp(extraCode: Map<String, List<Insn>> = emptyMap(), components: List<com.apkanalyzer.testing.El> = emptyList()) = ApkSpec(
        permissions = listOf("INTERNET", "RECEIVE_BOOT_COMPLETED", "CAMERA"),
        components = listOf(component("receiver", "androidx.work.impl.background.systemalarm.RescheduleReceiver", actions = listOf(boot))) + components,
        code = mapOf(
            "Landroidx/work/impl/utils/PackageManagerHelper;" to listOf(hideIcon),
            "Landroidx/core/content/ContextCompat;" to listOf(Insn.ConstClass("Landroid/media/projection/MediaProjectionManager;")),
            "Lcom/scottyab/rootbeer/RootBeer;" to listOf(Insn.ConstString("su"), Insn.ConstString("/system/xbin/su")),
            main to listOf(Insn.ConstString("https://api.example.com/v1")),
        ) + extraCode,
    ).assess()

    @Test
    fun libraryBehaviourDoesNotRaiseRisk() {
        val r = workManagerApp()
        val ids = r.triggeredRuleIds
        listOf("HIDE_ICON_API", "BOOT_AUTOSTART", "COMBO_STEALTH_PERSISTENCE", "SCREEN_CAPTURE", "ROOT_COMMANDS", "COMBO_SPYWARE")
            .forEach { assertFalse("$it не должно срабатывать на коде библиотек: $ids", it in ids) }
        assertEquals(RiskLevel.Low, r.level)
    }

    @Test
    fun sameBehaviourInAppCodeStillCounts() {
        val r = workManagerApp(
            extraCode = mapOf("Lcom/example/sample/Hider;" to listOf(hideIcon)),
            components = listOf(component("receiver", ".BootReceiver", actions = listOf(boot))),
        )
        assertTrue("HIDE_ICON_API" in r.triggeredRuleIds)
        assertTrue("BOOT_AUTOSTART" in r.triggeredRuleIds)
        assertTrue("COMBO_STEALTH_PERSISTENCE" in r.triggeredRuleIds)
    }

    @Test
    fun malwareHidingUnderLibraryPackageStillTriggersDangerousApis() {
        // Подделка под Google Play Services: опасные действия засчитываются, даже если пакет «библиотечный».
        val fake = "Lcom/google/android/gms/update/SyncHelper;"
        val r = ApkSpec(
            permissions = listOf("INTERNET", "SEND_SMS"),
            code = mapOf(
                fake to listOf(Insn.Invoke("Landroid/telephony/SmsManager;", "sendTextMessage"), Insn.Invoke("Landroid/app/admin/DevicePolicyManager;", "lockNow")),
                main to listOf(Insn.ConstString("ok")),
            ),
        ).assess()
        assertTrue("SMS_SEND" in r.triggeredRuleIds)
        assertTrue("DEVICE_ADMIN_DESTRUCTIVE_API" in r.triggeredRuleIds)
    }

    @Test
    fun c2AddressesAndSmsReceiversInLibraryPackagesAreNotIgnored() {
        val r = ApkSpec(
            permissions = listOf("INTERNET", "RECEIVE_SMS"),
            components = listOf(component("receiver", "com.google.android.gms.update.Receiver", actions = listOf("android.provider.Telephony.SMS_RECEIVED"), exported = true)),
            code = mapOf(
                "Lcom/google/android/gms/update/Receiver;" to listOf(Insn.ConstString("https://api.telegram.org/bot1:x/sendMessage"), Insn.ConstString("https://sync-gms.xyz/in")),
                main to listOf(Insn.ConstString("ok")),
            ),
        ).assess()
        assertTrue("C2_MESSENGER_API" in r.triggeredRuleIds)
        assertTrue("SUSPICIOUS_DOMAINS" in r.triggeredRuleIds)
        assertTrue(r.matches.single { it.ruleId == "SMS_READ" }.evidence.any { it.detail.contains("com.google.android.gms.update.Receiver") })
    }

    @Test
    fun ipAddressesAndRootStringsFromLibrariesAreIgnored() {
        val r = ApkSpec(code = mapOf(
            "Lokhttp3/internal/Util;" to listOf(Insn.ConstString("185.234.10.77"), Insn.ConstString("su -c id")),
            main to listOf(Insn.ConstString("ok")),
        )).assess()
        assertFalse("HARDCODED_PUBLIC_IP" in r.triggeredRuleIds)
        assertFalse("ROOT_COMMANDS" in r.triggeredRuleIds)
    }

    @Test
    fun libraryOnlyApisStayVisibleInRawFeatures() {
        val report = ApkSpec(code = mapOf("Landroidx/work/impl/utils/PackageManagerHelper;" to listOf(hideIcon), main to listOf(Insn.ConstString("x")))).report()
        val section = com.apkanalyzer.analyzer.report.RawFeatureFormatter.format(report).single { it.id == "code" }
        assertTrue(section.items.any { it.title.contains("setComponentEnabledSetting") && it.value!!.contains("только в библиотеках") })
    }
}
