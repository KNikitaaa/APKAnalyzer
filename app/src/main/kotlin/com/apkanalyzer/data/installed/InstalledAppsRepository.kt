package com.apkanalyzer.data.installed

import android.Manifest
import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.graphics.Bitmap
import android.os.Build
import android.util.LruCache
import androidx.core.content.pm.PackageInfoCompat
import androidx.core.graphics.drawable.toBitmap
import com.apkanalyzer.installed.InstalledAppSummary
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File

/** Файлы установленного приложения: основной APK и части split APK. */
data class InstalledApkFiles(
    val label: String,
    val base: File,
    val splits: List<File>,
)

/** Что известно об установленном пакете с таким именем. */
data class InstalledPackageState(
    val installed: Boolean,
    val isSystem: Boolean = false,
    val versionCode: Long? = null,
    val versionName: String? = null,
)

/**
 * Доступ к установленным приложениям только на чтение: список пакетов, их APK и иконки.
 *
 * Package visibility (Android 11+): приложение видит все пакеты только с разрешением
 * QUERY_ALL_PACKAGES. Если его нет (например, в сборке для Google Play без одобренной декларации),
 * видны только приложения с иконкой в лаунчере — это объявлено в `<queries>` манифеста,
 * и экран честно сообщает об ограничении.
 */
class InstalledAppsRepository(private val context: Context) {

    private val pm: PackageManager get() = context.packageManager
    private val icons = LruCache<String, Bitmap>(ICON_CACHE_SIZE)

    /** true — видны все установленные пакеты; false — только те, что разрешает package visibility. */
    val seesAllPackages: Boolean
        get() = Build.VERSION.SDK_INT < Build.VERSION_CODES.R ||
            context.checkSelfPermission(Manifest.permission.QUERY_ALL_PACKAGES) == PackageManager.PERMISSION_GRANTED

    suspend fun list(): List<InstalledAppSummary> = withContext(Dispatchers.IO) {
        installedPackages().mapNotNull { info ->
            val app = info.applicationInfo ?: return@mapNotNull null
            if (info.packageName == context.packageName) return@mapNotNull null
            val splits = app.splitSourceDirs.orEmpty()
            InstalledAppSummary(
                packageName = info.packageName,
                label = runCatching { app.loadLabel(pm).toString() }.getOrDefault(info.packageName),
                versionName = info.versionName,
                versionCode = PackageInfoCompat.getLongVersionCode(info),
                isSystem = app.isSystem,
                installerPackage = installerOf(info.packageName),
                lastUpdateMs = info.lastUpdateTime,
                totalApkBytes = (listOfNotNull(app.sourceDir) + splits).sumOf { File(it).length() },
                splitCount = splits.size,
            )
        }
    }

    suspend fun state(packageName: String): InstalledPackageState = withContext(Dispatchers.IO) {
        val info = packageInfo(packageName) ?: return@withContext InstalledPackageState(installed = false)
        InstalledPackageState(
            installed = true,
            isSystem = info.applicationInfo?.isSystem == true,
            versionCode = PackageInfoCompat.getLongVersionCode(info),
            versionName = info.versionName,
        )
    }

    /** APK-файлы приложения. Они доступны на чтение любому приложению — копировать их не нужно. */
    suspend fun apkFiles(packageName: String): InstalledApkFiles? = withContext(Dispatchers.IO) {
        val app = packageInfo(packageName)?.applicationInfo ?: return@withContext null
        val base = app.sourceDir?.let(::File)?.takeIf { it.canRead() } ?: return@withContext null
        InstalledApkFiles(
            label = runCatching { app.loadLabel(pm).toString() }.getOrDefault(packageName),
            base = base,
            splits = app.splitSourceDirs.orEmpty().map(::File),
        )
    }

    suspend fun icon(packageName: String, sizePx: Int): Bitmap? {
        icons.get(packageName)?.let { return it }
        return withContext(Dispatchers.IO) {
            runCatching { pm.getApplicationIcon(packageName).toBitmap(sizePx, sizePx) }.getOrNull()
                ?.also { icons.put(packageName, it) }
        }
    }

    private fun installedPackages(): List<PackageInfo> =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            pm.getInstalledPackages(PackageManager.PackageInfoFlags.of(0))
        } else {
            @Suppress("DEPRECATION")
            pm.getInstalledPackages(0)
        }

    private fun packageInfo(packageName: String): PackageInfo? = try {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            pm.getPackageInfo(packageName, PackageManager.PackageInfoFlags.of(0))
        } else {
            @Suppress("DEPRECATION")
            pm.getPackageInfo(packageName, 0)
        }
    } catch (_: PackageManager.NameNotFoundException) {
        null
    }

    private fun installerOf(packageName: String): String? = try {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            pm.getInstallSourceInfo(packageName).installingPackageName
        } else {
            @Suppress("DEPRECATION")
            pm.getInstallerPackageName(packageName)
        }
    } catch (_: Exception) {
        null
    }

    private val ApplicationInfo.isSystem: Boolean
        get() = (flags and ApplicationInfo.FLAG_SYSTEM) != 0

    private companion object {
        const val ICON_CACHE_SIZE = 200
    }
}
