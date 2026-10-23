package com.apkanalyzer.rules

enum class PermissionCategory(val labelRu: String, val baseWeight: Int) {
    SMS_CALLS("SMS и звонки", 8),
    LOCATION_TRACKING("Геолокация", 7),
    DATA_EXFILTRATION("Утечка данных", 9),
    DEVICE_ADMIN("Администрирование устройства", 10),
    CODE_LOADING("Динамическая загрузка кода", 9),
    CONTACTS_CALENDAR("Контакты и календарь", 5),
    CAMERA_MICROPHONE("Камера и микрофон", 6),
    BOOT_AUTOSTART("Автозапуск при загрузке", 5),
    STORAGE("Файловое хранилище", 4),
    NETWORK("Сетевой доступ", 2),
    NOTIFICATIONS("Уведомления", 1),
    VIBRATION_WAKE("Вибрация и пробуждение", 1),
    OTHER("Прочее", 0),
}

val PERMISSION_CATEGORY_MAP: Map<String, PermissionCategory> = mapOf(
    "READ_SMS" to PermissionCategory.SMS_CALLS,
    "RECEIVE_SMS" to PermissionCategory.SMS_CALLS,
    "SEND_SMS" to PermissionCategory.SMS_CALLS,
    "READ_CALL_LOG" to PermissionCategory.SMS_CALLS,
    "WRITE_CALL_LOG" to PermissionCategory.SMS_CALLS,
    "PROCESS_OUTGOING_CALLS" to PermissionCategory.SMS_CALLS,
    "CALL_PHONE" to PermissionCategory.SMS_CALLS,
    "ANSWER_PHONE_CALLS" to PermissionCategory.SMS_CALLS,
    "RECEIVE_MMS" to PermissionCategory.SMS_CALLS,
    "ACCESS_FINE_LOCATION" to PermissionCategory.LOCATION_TRACKING,
    "ACCESS_COARSE_LOCATION" to PermissionCategory.LOCATION_TRACKING,
    "ACCESS_BACKGROUND_LOCATION" to PermissionCategory.LOCATION_TRACKING,
    "READ_CONTACTS" to PermissionCategory.DATA_EXFILTRATION,
    "GET_ACCOUNTS" to PermissionCategory.DATA_EXFILTRATION,
    "READ_PHONE_STATE" to PermissionCategory.DATA_EXFILTRATION,
    "READ_PHONE_NUMBERS" to PermissionCategory.DATA_EXFILTRATION,
    "BIND_DEVICE_ADMIN" to PermissionCategory.DEVICE_ADMIN,
    "MANAGE_DEVICE_POLICY" to PermissionCategory.DEVICE_ADMIN,
    "REQUEST_INSTALL_PACKAGES" to PermissionCategory.CODE_LOADING,
    "INSTALL_PACKAGES" to PermissionCategory.CODE_LOADING,
    "WRITE_CONTACTS" to PermissionCategory.CONTACTS_CALENDAR,
    "READ_CALENDAR" to PermissionCategory.CONTACTS_CALENDAR,
    "WRITE_CALENDAR" to PermissionCategory.CONTACTS_CALENDAR,
    "CAMERA" to PermissionCategory.CAMERA_MICROPHONE,
    "RECORD_AUDIO" to PermissionCategory.CAMERA_MICROPHONE,
    "RECEIVE_BOOT_COMPLETED" to PermissionCategory.BOOT_AUTOSTART,
    "READ_EXTERNAL_STORAGE" to PermissionCategory.STORAGE,
    "WRITE_EXTERNAL_STORAGE" to PermissionCategory.STORAGE,
    "MANAGE_EXTERNAL_STORAGE" to PermissionCategory.STORAGE,
    "INTERNET" to PermissionCategory.NETWORK,
    "ACCESS_NETWORK_STATE" to PermissionCategory.NETWORK,
    "ACCESS_WIFI_STATE" to PermissionCategory.NETWORK,
    "CHANGE_NETWORK_STATE" to PermissionCategory.NETWORK,
    "POST_NOTIFICATIONS" to PermissionCategory.NOTIFICATIONS,
    "VIBRATE" to PermissionCategory.VIBRATION_WAKE,
    "WAKE_LOCK" to PermissionCategory.VIBRATION_WAKE,
)

fun categorizePermission(permission: String): PermissionCategory {
    val short = permission.removePrefix("android.permission.")
    return PERMISSION_CATEGORY_MAP[short] ?: PermissionCategory.OTHER
}
