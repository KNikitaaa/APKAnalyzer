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
import com.apkanalyzer.ui.settings.SettingsRoute

object Routes {
    const val HOME = "home"
    const val HISTORY = "history"
    const val SETTINGS = "settings"
    const val ANALYSIS = "analysis?${AnalysisViewModel.ARG_URI}={${AnalysisViewModel.ARG_URI}}"
    const val REPORT = "report/{${SavedReportViewModel.ARG_ID}}"

    fun analysis(uri: Uri) = "analysis?${AnalysisViewModel.ARG_URI}=${Uri.encode(uri.toString())}"
    fun report(id: Long) = "report/$id"
}

@Composable
fun AppNavHost() {
    val nav = rememberNavController()
    NavHost(navController = nav, startDestination = Routes.HOME) {
        composable(Routes.HOME) {
            HomeScreen(
                onApkPicked = { uri -> nav.navigate(Routes.analysis(uri)) },
                onOpenHistory = { nav.navigate(Routes.HISTORY) },
                onOpenSettings = { nav.navigate(Routes.SETTINGS) },
            )
        }
        composable(
            route = Routes.ANALYSIS,
            arguments = listOf(navArgument(AnalysisViewModel.ARG_URI) { type = NavType.StringType }),
        ) {
            AnalysisRoute(onBack = { nav.popBackStack() }, onOpenSettings = { nav.navigate(Routes.SETTINGS) })
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
