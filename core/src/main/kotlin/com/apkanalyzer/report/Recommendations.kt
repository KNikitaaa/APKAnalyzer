package com.apkanalyzer.report

import com.apkanalyzer.domain.model.RiskLevel
import com.apkanalyzer.rules.BehaviorCategory
import com.apkanalyzer.rules.RiskAssessment

/** Рекомендуемые безопасные действия по результату оценки (от самых важных). */
object Recommendations {

    fun forAssessment(risk: RiskAssessment): List<String> {
        val ids = risk.triggeredRuleIds.toSet()
        val cats = risk.categoryScores.keys
        val out = mutableListOf<String>()
        when (risk.level) {
            RiskLevel.High -> {
                out += "Не устанавливайте этот APK."
                out += "Если приложение уже установлено — удалите его (кнопка «Удалить установленное приложение»)."
                if ("DEVICE_ADMIN" in ids || "COMBO_LOCKER" in ids) {
                    out += "Перед удалением отключите права администратора: Настройки → Безопасность → Администраторы устройства."
                }
                if ("ACCESSIBILITY_SERVICE" in ids) {
                    out += "Отключите службу приложения в Настройки → Специальные возможности."
                }
                if (BehaviorCategory.SMS_CALLS in cats || "COMBO_OTP_INTERCEPT" in ids || "COMBO_BANKER_ACCESSIBILITY" in ids) {
                    out += "Если приложение было установлено, позвоните в банк по номеру с карты, заблокируйте подозрительные операции и смените пароли."
                }
                out += "Смените пароли от почты и аккаунтов, которые вводились на устройстве после установки."
            }
            RiskLevel.Attention -> {
                out += "Устанавливайте, только если доверяете источнику; надёжнее скачать приложение из официального магазина."
                out += "Проверьте причины выше: нужны ли приложению такие возможности для его заявленной функции?"
                if ("NO_LAUNCHER_ICON" in ids || "HIDE_ICON_API" in ids) {
                    out += "Будьте осторожны с приложениями, которые прячут свою иконку: их трудно найти и удалить."
                }
                if ("ACCESSIBILITY_SERVICE" in ids) {
                    out += "Не включайте приложению «Специальные возможности», если не понимаете, зачем это нужно."
                }
            }
            RiskLevel.Insufficient -> {
                out += "Файл не удалось проверить полностью — не устанавливайте его, если источник неизвестен."
                out += "Проверьте SHA-256 файла в независимых сервисах репутации."
            }
            RiskLevel.Low -> {
                out += "Явных угроз не найдено. Статический анализ не гарантирует безопасность — скачивайте приложения из проверенных источников."
            }
        }
        if (risk.level != RiskLevel.High && "UNSIGNED" in ids) out += "APK без подписи Android не установит — вероятно, файл повреждён или это не готовое приложение."
        return out.distinct()
    }
}
