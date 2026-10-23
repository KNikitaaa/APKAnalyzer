pluginManagement {
    repositories {
        google {
            content {
                includeGroupByRegex("com\\.android.*")
                includeGroupByRegex("com\\.google.*")
                includeGroupByRegex("androidx.*")
            }
        }
        mavenCentral()
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
    }
}

rootProject.name = "APKAnalyzer"

// core — чистый Kotlin/JVM: анализатор APK, правила, модели. Без зависимостей от Android.
include(":core")
// app — Android-приложение: UI (Compose), импорт файлов, хранение, интеграции.
include(":app")
