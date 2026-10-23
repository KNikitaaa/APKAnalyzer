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
