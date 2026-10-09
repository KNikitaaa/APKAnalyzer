package com.apkanalyzer.ai

enum class AiProviderType(val displayName: String, val defaultBaseUrl: String) {
    DEEPSEEK("DeepSeek", "https://api.deepseek.com/v1"),
    OPENAI("OpenAI", "https://api.openai.com/v1"),
    GEMINI("Google Gemini", "https://generativelanguage.googleapis.com/v1beta/openai"),
    CUSTOM("Custom (OpenAI-compatible)", ""),
}

data class AiProfileConfig(
    val id: String,
    val displayName: String,
    val providerType: AiProviderType,
    val baseUrl: String,
    val modelId: String?,
    val keyAlias: String,
    val isActive: Boolean = false,
) {
    val resolvedBaseUrl: String
        get() = baseUrl.ifBlank { providerType.defaultBaseUrl }

    companion object {
        fun defaultKeyAlias(profileId: String) = "ai_key_$profileId"
    }
}

enum class AiRequestType(val promptVersion: String) {
    EXPLAIN_FINDINGS("v1"),
    INFER_BEHAVIOR("v1"),
    RECOMMENDATIONS("v1"),
    REPORT_SUMMARY("v1"),
}

data class AiRequestPayload(
    val requestType: AiRequestType,
    val triggeredRuleIds: List<String>,
    val permissionCategories: List<String>,
    val exportedComponentTypes: List<String>,
    val engineScore: Int,
    val riskLevelName: String,
    val analysisCoverage: Float,
    val suspiciousFragments: List<SuspiciousFragment> = emptyList(),
    val externalDomains: List<String> = emptyList(),
)

data class SuspiciousFragment(
    val content: String,
    val reason: String,
    val type: String,
)
