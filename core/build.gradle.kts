import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    alias(libs.plugins.kotlin.jvm)
}

java {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
}

kotlin {
    compilerOptions {
        jvmTarget.set(JvmTarget.JVM_17)
    }
}

dependencies {
    // Ядро намеренно не зависит ни от Android, ни от сторонних библиотек:
    // так анализатор можно гонять обычными JVM-тестами и переиспользовать вне приложения.
    testImplementation(libs.junit4)
}

// Замер качества на размеченном наборе: ./gradlew :core:evaluate -Psamples=<папка с malicious/ и benign/>
tasks.register<JavaExec>("evaluate") {
    group = "verification"
    description = "Считает FPR/FNR и долю неполных анализов на размеченном наборе APK"
    classpath = sourceSets["main"].runtimeClasspath
    mainClass.set("com.apkanalyzer.eval.EvaluationKt")
    workingDir = rootProject.projectDir
    args(
        (findProperty("samples") as String?) ?: rootProject.file("samples/eval").path,
        layout.buildDirectory.dir("evaluation").get().asFile.path,
    )
}

// Синтетические «вредоносные» образцы для замера: ./gradlew :core:generateSyntheticSamples -Psamples=samples/eval
tasks.register<JavaExec>("generateSyntheticSamples") {
    group = "verification"
    description = "Записывает синтетические образцы, повторяющие устройство известных семейств вредоносов, в <samples>/malicious"
    classpath = sourceSets["test"].runtimeClasspath
    mainClass.set("com.apkanalyzer.testing.MalwareLikeSamples")
    workingDir = rootProject.projectDir
    args((findProperty("samples") as String?) ?: rootProject.file("samples/eval").path)
}

// Пакеты правил: ./gradlew :core:rulePackKeygen -Pkey=<файл вне репозитория>
tasks.register<JavaExec>("rulePackKeygen") {
    group = "rules"
    description = "Создаёт пару ключей для подписи пакетов правил"
    classpath = sourceSets["main"].runtimeClasspath
    mainClass.set("com.apkanalyzer.rules.pack.RulePackTool")
    workingDir = rootProject.projectDir
    args("keygen", (findProperty("key") as String?) ?: "../APKAnalyzer-keys/rulepack-signing.key")
}

// ./gradlew :core:signRulePack -Ppack=docs/rules/rulepack-example.json -Pkey=../APKAnalyzer-keys/rulepack-signing.key -Pout=build/example.rulepack
tasks.register<JavaExec>("signRulePack") {
    group = "rules"
    description = "Проверяет и подписывает пакет правил"
    classpath = sourceSets["main"].runtimeClasspath
    mainClass.set("com.apkanalyzer.rules.pack.RulePackTool")
    workingDir = rootProject.projectDir
    args(
        "sign",
        (findProperty("pack") as String?) ?: "docs/rules/rulepack-example.json",
        (findProperty("key") as String?) ?: "../APKAnalyzer-keys/rulepack-signing.key",
        (findProperty("out") as String?) ?: "docs/rules/rulepack-example.rulepack",
    )
}
