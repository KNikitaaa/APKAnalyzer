package com.apkanalyzer.ui.navigation

import android.net.Uri
import androidx.compose.runtime.Composable
import androidx.navigation.NavType
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.rememberNavController
import androidx.navigation.navArgument
import com.apkanalyzer.ui.analysis.AnalysisRoute
import com.apkanalyzer.ui.analysis.AnalysisViewModel
import com.apkanalyzer.ui.history.HistoryRoute
import com.apkanalyzer.ui.history.SavedReportRoute
import com.apkanalyzer.ui.history.SavedReportViewModel
import com.apkanalyzer.ui.home.HomeScreen
import com.apkanalyzer.ui.installed.InstalledAppsRoute
import com.apkanalyzer.ui.settings.SettingsRoute

object Routes {
    const val HOME = "home"
    const val HISTORY = "history"
    const val SETTINGS = "settings"
    const val INSTALLED = "installed?vt={vt}&ai={ai}"
    const val ANALYSIS = "analysis?${AnalysisViewModel.ARG_URI}={${AnalysisViewModel.ARG_URI}}&${AnalysisViewModel.ARG_PKG}={${AnalysisViewModel.ARG_PKG}}&vt={vt}&ai={ai}"
    const val REPORT = "report/{${SavedReportViewModel.ARG_ID}}"

    fun analysis(uri: Uri, vt: Boolean, ai: Boolean) = "analysis?${AnalysisViewModel.ARG_URI}=${Uri.encode(uri.toString())}&vt=$vt&ai=$ai"
    fun analysisInstalled(packageName: String, vt: Boolean, ai: Boolean) = "analysis?${AnalysisViewModel.ARG_PKG}=${Uri.encode(packageName)}&vt=$vt&ai=$ai"
    fun installed(vt: Boolean, ai: Boolean) = "installed?vt=$vt&ai=$ai"
    fun report(id: Long) = "report/$id"
}

@Composable
fun AppNavHost() {
    val nav = rememberNavController()
    NavHost(navController = nav, startDestination = Routes.HOME) {
        composable(Routes.HOME) {
            HomeScreen(
                onApkPicked = { uri, vt, ai -> nav.navigate(Routes.analysis(uri, vt, ai)) },
                onOpenInstalled = { vt, ai -> nav.navigate(Routes.installed(vt, ai)) },
                onOpenHistory = { nav.navigate(Routes.HISTORY) },
                onOpenSettings = { nav.navigate(Routes.SETTINGS) },
                onOpenReport = { id -> nav.navigate(Routes.report(id)) },
            )
        }
        composable(
            route = Routes.ANALYSIS,
            arguments = listOf(
                navArgument(AnalysisViewModel.ARG_URI) { type = NavType.StringType; nullable = true; defaultValue = null },
                navArgument(AnalysisViewModel.ARG_PKG) { type = NavType.StringType; nullable = true; defaultValue = null },
                navArgument("vt") { type = NavType.BoolType; defaultValue = false },
                navArgument("ai") { type = NavType.BoolType; defaultValue = false },
            ),
        ) {
            AnalysisRoute(onBack = { nav.popBackStack() }, onOpenSettings = { nav.navigate(Routes.SETTINGS) })
        }
        composable(Routes.INSTALLED, arguments = listOf(
            navArgument("vt") { type = NavType.BoolType; defaultValue = false },
            navArgument("ai") { type = NavType.BoolType; defaultValue = false },
        )) { entry ->
            val vt = entry.arguments?.getBoolean("vt") ?: false
            val ai = entry.arguments?.getBoolean("ai") ?: false
            InstalledAppsRoute(onBack = { nav.popBackStack() }, onAnalyze = { pkg -> nav.navigate(Routes.analysisInstalled(pkg, vt, ai)) })
        }
        composable(Routes.HISTORY) {
            HistoryRoute(onBack = { nav.popBackStack() }, onOpen = { id -> nav.navigate(Routes.report(id)) })
        }
        composable(
            route = Routes.REPORT,
            arguments = listOf(navArgument(SavedReportViewModel.ARG_ID) { type = NavType.LongType }),
        ) {
            SavedReportRoute(onBack = { nav.popBackStack() }, onOpenSettings = { nav.navigate(Routes.SETTINGS) })
        }
        composable(Routes.SETTINGS) {
            SettingsRoute(onBack = { nav.popBackStack() })
        }
    }
}
