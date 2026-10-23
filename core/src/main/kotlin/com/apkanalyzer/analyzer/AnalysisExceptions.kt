package com.apkanalyzer.analyzer

/** Анализ отменён пользователем. */
class AnalysisCancelledException : RuntimeException("Анализ отменён")

/** Структура файла некорректна или намеренно испорчена. */
open class MalformedApkException(message: String, cause: Throwable? = null) :
    RuntimeException(message, cause)

/** Сработал защитный лимит (размер, zip-bomb, слишком много записей и т.п.). */
class AnalysisLimitExceededException(message: String) : MalformedApkException(message)

/**
 * Источник отмены, не зависящий от корутин/Android.
 * Приложение передаёт сюда, например, `{ !coroutineContext.isActive }`.
 */
fun interface CancellationCheck {
    fun isCancelled(): Boolean

    companion object {
        val NEVER = CancellationCheck { false }
    }
}

fun CancellationCheck.throwIfCancelled() {
    if (isCancelled()) throw AnalysisCancelledException()
}
