package com.apkanalyzer.rules

import com.apkanalyzer.analyzer.strings.IndicatorExtractor
import com.apkanalyzer.analyzer.strings.IndicatorType
import com.apkanalyzer.testing.ApkSpec
import com.apkanalyzer.testing.Insn
import com.apkanalyzer.testing.a
import com.apkanalyzer.testing.component
import com.apkanalyzer.testing.el
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** Случаи из замера на реальных приложениях (NewPipe, Bitwarden, Aegis, AdAway и др.), которые давали ложные срабатывания. */
class CalibrationTest {

    private fun domains(vararg strings: String): List<String> {
        val x = IndicatorExtractor()
        strings.forEach { x.scan(it, "classes.dex") }
        return x.indicators.filter { it.type == IndicatorType.DOMAIN }.map { it.value }
    }

    private fun ips(vararg strings: String) = IndicatorExtractor().apply { strings.forEach { scan(it, "classes.dex") } }
        .indicators.filter { it.type == IndicatorType.IPV4 }

    @Test
    fun codeIdentifiersAreNotDomains() {
        assertEquals(emptyList<String>(), domains("this.link", "current.work", "gcm.n.link", "libcore.icu.icu", "lineHeightStyle.Alignment.Top", "systemsoundtype.click"))
    }

    @Test
    fun realHostsAreStillDomains() {
        assertEquals(
            listOf("evil-panel.xyz", "c2host1.top", "www.update.link", "this.link", "badhost.ru"),
            domains("evil-panel.xyz", "c2host1.top", "www.update.link", "https://this.link/gate", "badhost.ru"),
        )
    }

    @Test
    fun reservedAndNetworkAddressesAreNotPublic() {
        val found = ips("192.0.2.10", "198.51.100.7", "203.0.113.5", "198.18.0.1", "131.0.0.0", "185.234.10.77")
        assertEquals(listOf("185.234.10.77"), found.filterNot { it.isPrivate }.map { it.value })
    }

    @Test
    fun publicDnsResolversAreNotHardcodedServers() {
        assertFalse("HARDCODED_PUBLIC_IP" in ApkSpec(dexStrings = listOf("1.1.1.1", "8.8.8.8", "223.5.5.5")).assess().triggeredRuleIds)
        assertTrue("HARDCODED_PUBLIC_IP" in ApkSpec(dexStrings = listOf("185.234.10.77")).assess().triggeredRuleIds)
    }

    @Test
    fun rootDetectionIsWeakerThanRootCommand() {
        val detect = ApkSpec(dexStrings = listOf("su", "/system/xbin/su", "/system/app/Superuser.apk")).assess()
        assertEquals(0.3f, detect.matches.single { it.ruleId == "ROOT_COMMANDS" }.confidence, 0.001f)

        val command = ApkSpec(dexStrings = listOf("su -c pm install /data/local/tmp/x.apk")).assess()
        assertEquals(1f, command.matches.single { it.ruleId == "ROOT_COMMANDS" }.confidence, 0.001f)
    }

    @Test
    fun rootToolkitNeedsDroppedExecutableNotJustShell() {
        val r = ApkSpec(
            dexStrings = listOf("su -c id"),
            apis = listOf("Ljava/lang/Runtime;" to "exec"),
        ).assess()
        assertTrue("ROOT_COMMANDS" in r.triggeredRuleIds)
        assertTrue("SHELL_EXEC" in r.triggeredRuleIds)
        assertFalse("COMBO_ROOT_TOOLKIT" in r.triggeredRuleIds)
    }

    private val hideIcon = Insn.Invoke("Landroid/content/pm/PackageManager;", "setComponentEnabledSetting")

    @Test
    fun hidingOwnLauncherIsStrongOtherComponentsAreWeak() {
        val other = ApkSpec(code = mapOf("Lcom/example/sample/Settings;" to listOf(hideIcon, Insn.ConstClass("Lcom/example/sample/ShareTarget;")))).assess()
        assertEquals(0.4f, other.matches.single { it.ruleId == "HIDE_ICON_API" }.confidence, 0.001f)

        val own = ApkSpec(code = mapOf("Lcom/example/sample/Hider;" to listOf(hideIcon, Insn.ConstClass("Lcom/example/sample/MainActivity;")))).assess()
        val match = own.matches.single { it.ruleId == "HIDE_ICON_API" }
        assertEquals(1f, match.confidence, 0.001f)
        assertTrue(match.evidence.any { it.detail.contains("com.example.sample.MainActivity") })
    }

    @Test
    fun launcherReferenceInAnotherClassIsNotHiding() {
        // Почти любое приложение открывает MainActivity из уведомлений — это не связано с отключением компонентов.
        val r = ApkSpec(code = mapOf(
            "Lcom/example/sample/Toggler;" to listOf(hideIcon, Insn.ConstClass("Lcom/example/sample/ShareTarget;")),
            "Lcom/example/sample/Notifications;" to listOf(Insn.ConstClass("Lcom/example/sample/MainActivity;")),
        )).assess()
        assertEquals(0.4f, r.matches.single { it.ruleId == "HIDE_ICON_API" }.confidence, 0.001f)
    }

    @Test
    fun iconSwitcherAliasesMitigateHideIcon() {
        val launcherFilter = listOf(el("intent-filter", children = listOf(
            el("action", a("name", "android.intent.action.MAIN")),
            el("category", a("name", "android.intent.category.LAUNCHER")),
        )))
        val aliases = listOf("Dark", "Light").map { name ->
            el("activity-alias", a("name", ".Icon$name"), a("targetActivity", ".MainActivity"), a("exported", true), children = launcherFilter)
        }
        val r = ApkSpec(
            components = aliases,
            code = mapOf("Lcom/example/sample/IconPicker;" to listOf(hideIcon, Insn.ConstString("com.example.sample.IconDark"))),
        ).assess()
        val match = r.matches.single { it.ruleId == "HIDE_ICON_API" }
        assertTrue(match.mitigations.any { it.id == "MIT_ICON_SWITCHER" })
        assertTrue(match.effectiveWeight < 3f)
    }

    @Test
    fun appWithoutLauncherAccessIsUnaffected() {
        // Компонент-приёмник в манифесте, но код ссылается только на него — не на иконку.
        val r = ApkSpec(
            components = listOf(component("receiver", ".Boot", actions = listOf("android.intent.action.BOOT_COMPLETED"))),
            permissions = listOf("INTERNET", "RECEIVE_BOOT_COMPLETED"),
            code = mapOf("Lcom/example/sample/Toggle;" to listOf(hideIcon, Insn.ConstClass("Lcom/example/sample/Boot;"))),
        ).assess()
        assertEquals(0.4f, r.matches.single { it.ruleId == "COMBO_STEALTH_PERSISTENCE" }.confidence, 0.001f)
    }
}
