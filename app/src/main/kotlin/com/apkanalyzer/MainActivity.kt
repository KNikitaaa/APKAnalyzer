package com.apkanalyzer

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import com.apkanalyzer.ui.navigation.AppNavHost
import com.apkanalyzer.ui.theme.ApkAnalyzerTheme

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContent {
            ApkAnalyzerTheme {
                AppNavHost()
            }
        }
    }
}
