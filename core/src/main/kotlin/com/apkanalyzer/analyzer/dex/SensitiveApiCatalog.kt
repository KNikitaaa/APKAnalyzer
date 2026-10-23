package com.apkanalyzer.analyzer.dex

/** Поведенческая категория чувствительного Android API. */
enum class ApiCategory(val labelRu: String) {
    SMS("Отправка/чтение SMS"),
    TELEPHONY_ID("Идентификаторы телефона и SIM"),
    SHELL_EXEC("Выполнение shell-команд"),
    DYNAMIC_CODE("Динамическая загрузка кода"),
    REFLECTION("Рефлексия и скрытые вызовы"),
    CAMERA("Камера"),
    AUDIO_RECORD("Запись звука"),
    LOCATION("Геолокация"),
    DEVICE_ADMIN("Администрирование устройства"),
    ACCESSIBILITY("Службы специальных возможностей"),
    HIDE_ICON("Скрытие/отключение компонентов"),
    PACKAGE_INSTALL("Установка/удаление приложений"),
    SCREEN_CAPTURE("Захват экрана"),
    OVERLAY("Окна поверх других приложений"),
    CLIPBOARD("Буфер обмена"),
    ACCOUNTS_CONTACTS("Аккаунты и контакты"),
    CRYPTO("Шифрование данных"),
    NATIVE_CODE("Загрузка нативных библиотек"),
    NETWORK_RAW("Прямые сетевые соединения"),
    NOTIFICATIONS_READ("Чтение уведомлений"),
}

/**
 * Сигнатура API в формате DEX: дескриптор класса (`Landroid/telephony/SmsManager;`)
 * и, опционально, имя метода. Без имени метода совпадением считается любая ссылка на класс.
 */
data class ApiSignature(
    val classDescriptor: String,
    val methodName: String?,
    val category: ApiCategory,
    val descriptionRu: String,
) {
    val displayName: String
        get() {
            val cls = classDescriptor.removePrefix("L").removeSuffix(";").replace('/', '.')
            return if (methodName != null) "$cls.$methodName()" else cls
        }
}

object SensitiveApiCatalog {
    private fun api(cls: String, method: String?, cat: ApiCategory, desc: String) = ApiSignature(cls, method, cat, desc)

    val all: List<ApiSignature> = listOf(
        api("Landroid/telephony/SmsManager;", "sendTextMessage", ApiCategory.SMS, "Отправка SMS"),
        api("Landroid/telephony/SmsManager;", "sendMultipartTextMessage", ApiCategory.SMS, "Отправка длинных SMS"),
        api("Landroid/telephony/SmsManager;", "sendDataMessage", ApiCategory.SMS, "Отправка бинарных SMS"),
        api("Landroid/telephony/SmsMessage;", "createFromPdu", ApiCategory.SMS, "Разбор входящих SMS"),
        api("Landroid/provider/Telephony\$Sms;", null, ApiCategory.SMS, "Доступ к базе SMS"),

        api("Landroid/telephony/TelephonyManager;", "getDeviceId", ApiCategory.TELEPHONY_ID, "Получение IMEI/MEID"),
        api("Landroid/telephony/TelephonyManager;", "getImei", ApiCategory.TELEPHONY_ID, "Получение IMEI"),
        api("Landroid/telephony/TelephonyManager;", "getSubscriberId", ApiCategory.TELEPHONY_ID, "Получение IMSI"),
        api("Landroid/telephony/TelephonyManager;", "getLine1Number", ApiCategory.TELEPHONY_ID, "Получение номера телефона"),
        api("Landroid/telephony/TelephonyManager;", "getSimSerialNumber", ApiCategory.TELEPHONY_ID, "Серийный номер SIM"),

        api("Ljava/lang/Runtime;", "exec", ApiCategory.SHELL_EXEC, "Запуск процессов/команд"),
        api("Ljava/lang/ProcessBuilder;", "start", ApiCategory.SHELL_EXEC, "Запуск процессов"),

        api("Ldalvik/system/DexClassLoader;", null, ApiCategory.DYNAMIC_CODE, "Загрузка DEX из файла"),
        api("Ldalvik/system/InMemoryDexClassLoader;", null, ApiCategory.DYNAMIC_CODE, "Загрузка DEX из памяти"),
        api("Ldalvik/system/PathClassLoader;", null, ApiCategory.DYNAMIC_CODE, "Загрузка кода по пути"),
        api("Ldalvik/system/DexFile;", "loadDex", ApiCategory.DYNAMIC_CODE, "Загрузка DEX-файла"),

        api("Ljava/lang/reflect/Method;", "invoke", ApiCategory.REFLECTION, "Вызов метода через рефлексию"),
        api("Ljava/lang/Class;", "getDeclaredMethod", ApiCategory.REFLECTION, "Поиск скрытых методов"),

        api("Landroid/hardware/Camera;", "open", ApiCategory.CAMERA, "Доступ к камере (старый API)"),
        api("Landroid/hardware/camera2/CameraManager;", "openCamera", ApiCategory.CAMERA, "Доступ к камере"),

        api("Landroid/media/AudioRecord;", "startRecording", ApiCategory.AUDIO_RECORD, "Запись с микрофона"),
        api("Landroid/media/MediaRecorder;", "setAudioSource", ApiCategory.AUDIO_RECORD, "Запись аудио"),

        api("Landroid/location/LocationManager;", "requestLocationUpdates", ApiCategory.LOCATION, "Слежение за местоположением"),
        api("Landroid/location/LocationManager;", "getLastKnownLocation", ApiCategory.LOCATION, "Последнее местоположение"),
        api("Lcom/google/android/gms/location/FusedLocationProviderClient;", null, ApiCategory.LOCATION, "Геолокация Google Play Services"),

        api("Landroid/app/admin/DevicePolicyManager;", "lockNow", ApiCategory.DEVICE_ADMIN, "Блокировка экрана"),
        api("Landroid/app/admin/DevicePolicyManager;", "resetPassword", ApiCategory.DEVICE_ADMIN, "Сброс пароля блокировки"),
        api("Landroid/app/admin/DevicePolicyManager;", "wipeData", ApiCategory.DEVICE_ADMIN, "Стирание данных устройства"),

        api("Landroid/accessibilityservice/AccessibilityService;", "performGlobalAction", ApiCategory.ACCESSIBILITY, "Глобальные действия от имени пользователя"),
        api("Landroid/accessibilityservice/AccessibilityService;", "dispatchGesture", ApiCategory.ACCESSIBILITY, "Имитация жестов"),
        api("Landroid/view/accessibility/AccessibilityNodeInfo;", "performAction", ApiCategory.ACCESSIBILITY, "Нажатия в чужих окнах"),

        api("Landroid/content/pm/PackageManager;", "setComponentEnabledSetting", ApiCategory.HIDE_ICON, "Включение/отключение компонентов (часто — скрытие иконки)"),

        api("Landroid/content/pm/PackageInstaller;", null, ApiCategory.PACKAGE_INSTALL, "Установка приложений"),

        api("Landroid/media/projection/MediaProjection;", "createVirtualDisplay", ApiCategory.SCREEN_CAPTURE, "Захват содержимого экрана"),
        api("Landroid/media/projection/MediaProjectionManager;", null, ApiCategory.SCREEN_CAPTURE, "Запрос записи экрана"),

        api("Landroid/view/WindowManager;", "addView", ApiCategory.OVERLAY, "Добавление окон (возможен оверлей)"),

        api("Landroid/content/ClipboardManager;", "getPrimaryClip", ApiCategory.CLIPBOARD, "Чтение буфера обмена"),

        api("Landroid/accounts/AccountManager;", "getAccounts", ApiCategory.ACCOUNTS_CONTACTS, "Список аккаунтов"),
        api("Landroid/provider/ContactsContract;", null, ApiCategory.ACCOUNTS_CONTACTS, "Доступ к контактам"),
        api("Landroid/provider/CallLog\$Calls;", null, ApiCategory.ACCOUNTS_CONTACTS, "Журнал звонков"),

        api("Ljavax/crypto/Cipher;", "getInstance", ApiCategory.CRYPTO, "Шифрование/расшифровка"),

        api("Ljava/lang/System;", "loadLibrary", ApiCategory.NATIVE_CODE, "Загрузка нативной библиотеки"),
        api("Ljava/lang/System;", "load", ApiCategory.NATIVE_CODE, "Загрузка нативной библиотеки по пути"),

        api("Ljava/net/Socket;", null, ApiCategory.NETWORK_RAW, "TCP-сокеты"),

        api("Landroid/service/notification/NotificationListenerService;", null, ApiCategory.NOTIFICATIONS_READ, "Чтение уведомлений"),
    )

    /** Индекс: дескриптор класса → сигнатуры этого класса. */
    val byClass: Map<String, List<ApiSignature>> = all.groupBy { it.classDescriptor }
}
