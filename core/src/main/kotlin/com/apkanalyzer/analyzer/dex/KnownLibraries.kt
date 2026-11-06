package com.apkanalyzer.analyzer.dex

/**
 * Пакеты распространённых библиотек и SDK. Вызовы чувствительных API из них не говорят
 * о намерениях самого приложения: WorkManager включает свои компоненты через
 * setComponentEnabledSetting, androidx.core ссылается на все системные сервисы, библиотеки
 * проверки root содержат строку «su».
 *
 * Классы внутри пакета приложения (из манифеста) всегда считаются его кодом — так вредонос
 * не спрячется за именем вида `com.google.*`, если сам называется так же.
 * Обфусцированные библиотеки (a/b/c) попадают в «код приложения» — это осознанный
 * консервативный выбор: лучше лишнее предупреждение, чем пропуск.
 */
object KnownLibraries {

    private val PREFIXES: List<String> = listOf(
        // Платформа и Jetpack
        "Landroid/", "Landroidx/", "Lcom/android/", "Ldalvik/", "Ljava/", "Ljavax/", "Lj$/", "Lsun/", "Llibcore/",
        "Lcom/google/android/material/", "Lcom/google/android/gms/", "Lcom/google/firebase/", "Lcom/google/android/play/",
        "Lcom/google/android/datatransport/", "Lcom/google/android/exoplayer2/", "Lcom/google/android/flexbox/",
        "Lcom/google/common/", "Lcom/google/gson/", "Lcom/google/protobuf/", "Lcom/google/zxing/", "Lcom/google/crypto/",
        "Lcom/google/errorprone/", "Lcom/google/thirdparty/", "Lcom/google/mlkit/", "Lcom/google/accompanist/",
        "Lcom/google/auto/", "Lcom/google/re2j/",
        // Kotlin
        "Lkotlin/", "Lkotlinx/", "Lorg/jetbrains/", "Lorg/intellij/",
        // Сеть и сериализация
        "Lokhttp3/", "Lokio/", "Lretrofit2/", "Lcom/squareup/", "Lio/ktor/", "Lcom/fasterxml/", "Lorg/json/",
        "Lcom/android/volley/", "Lorg/apache/", "Lcom/jakewharton/", "Lcom/neovisionaries/", "Lorg/conscrypt/",
        "Lorg/bouncycastle/", "Lorg/spongycastle/", "Lnet/i2p/crypto/", "Lorg/minidns/", "Lcom/thoughtworks/",
        "Lorg/xmlpull/", "Lorg/kxml2/", "Lorg/simpleframework/", "Lorg/yaml/", "Lcom/esotericsoftware/",
        // Реактивность, DI, логирование
        "Lio/reactivex/", "Lrx/", "Ldagger/", "Lhilt_aggregated_deps/", "Lcom/google/dagger/", "Lorg/koin/",
        "Ltimber/", "Lorg/slf4j/", "Lch/qos/", "Lorg/greenrobot/", "Lorg/reactivestreams/",
        // UI, медиа, изображения
        "Lcom/bumptech/", "Lcoil/", "Lio/coil/", "Lcom/facebook/", "Lcom/airbnb/", "Lde/hdodenhof/",
        "Lcom/journeyapps/", "Lme/zhanghai/", "Lio/noties/", "Lorg/commonmark/", "Lcom/caverock/", "Lorg/videolan/",
        "Lcom/mikepenz/", "Lcom/afollestad/", "Lcom/nostra13/", "Lcom/davemorrissey/", "Lcom/yalantis/",
        "Lcom/theartofdev/", "Lcom/h6ah4i/", "Lnet/sqlcipher/", "Lio/realm/", "Lorg/sqlite/", "Lio/requery/",
        "Lorg/mozilla/", "Lorg/chromium/", "Lorg/webrtc/", "Lorg/jsoup/", "Lorg/ccil/", "Lorg/apache/commons/",
        // Аналитика, отчёты об ошибках, SDK
        "Lorg/acra/", "Lio/sentry/", "Lcom/microsoft/", "Lcom/amazonaws/", "Lcom/crashlytics/", "Lio/fabric/",
        "Lcom/appsflyer/", "Lcom/adjust/", "Lcom/onesignal/", "Lcom/yandex/", "Lcom/vk/", "Lcom/huawei/",
        "Lcom/samsung/", "Lcom/transistorsoft/", "Lio/flutter/", "Lcom/facebook/react/", "Lorg/unimodules/",
        "Lexpo/modules/", "Lcom/swmansion/", "Lcom/th3rdwave/", "Lcom/reactnative",
        // Только обнаружение root; библиотеки, которые сами запускают su (libsuperuser, RootTools), сюда не входят.
        "Lcom/scottyab/rootbeer/",
        // Прочие популярные
        "Lnet/lingala/zip4j/", "Lorg/tukaani/", "Lcom/sun/", "Lorg/w3c/", "Lorg/xml/", "Lorg/hamcrest/",
        "Lorg/junit/", "Lorg/checkerframework/", "Ledu/umd/", "Lorg/joda/", "Lorg/threeten/",
    )

    fun isLibrary(classDescriptor: String, appPackage: String?): Boolean {
        if (appPackage != null && appPackage.isNotEmpty()) {
            val own = "L" + appPackage.replace('.', '/') + "/"
            if (classDescriptor.startsWith(own)) return false
        }
        return PREFIXES.any { classDescriptor.startsWith(it) }
    }
}
