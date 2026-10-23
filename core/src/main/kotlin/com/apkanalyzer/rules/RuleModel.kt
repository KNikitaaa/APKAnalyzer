package com.apkanalyzer.rules

/** Поведенческая группа правил (раздел плана «Правильная логика оценки риска»). */
enum class BehaviorCategory(val labelRu: String) {
    SMS_CALLS("SMS и звонки"),
    SURVEILLANCE("Слежка"),
    DATA_COLLECTION("Сбор данных"),
    PERSISTENCE("Скрытый автозапуск"),
    CODE_LOADING("Загрузка кода"),
    DEVICE_CONTROL("Контроль устройства"),
    PHISHING_OVERLAY("Фишинг и оверлеи"),
    EVASION("Сокрытие и обфускация"),
    PRIVILEGE("Root и системные права"),
    NETWORK("Сеть"),
    HYGIENE("Качество сборки"),
}

enum class RuleKind {
    /** Одиночный признак. */
    SIGNAL,
    /** Связка признаков — весит больше, чем сумма составляющих. */
    COMBINATION,
}

/** Доказательство: что найдено и где. */
data class Evidence(
    /** Источник факта: «Манифест», «Подпись», «classes.dex», «assets/config.json», «Структура архива»… */
    val source: String,
    val detail: String,
)

/** Результат срабатывания проверки до применения смягчений. */
data class Hit(
    val evidence: List<Evidence>,
    /** Уверенность 0..1: насколько признак однозначен (например, упаковщики используют и легальные приложения). */
    val confidence: Float = 1f,
)

/**
 * Правило. [weight] — вклад в риск в «очках» 0..100 при уверенности 1 и без смягчений.
 * Вклады объединяются как независимые вероятности: 1 − Π(1 − wᵢ/100), поэтому много слабых
 * признаков не дают «высокого риска» сами по себе, а одна сильная связка — даёт.
 */
class Rule(
    val id: String,
    val titleRu: String,
    val descriptionRu: String,
    val category: BehaviorCategory,
    val weight: Int,
    val kind: RuleKind = RuleKind.SIGNAL,
    /** Служебный признак: используется в связках, но сам в причины не выводится (вес 0). */
    val informational: Boolean = false,
    /** Для связок: группы ID правил; связка срабатывает, если из КАЖДОЙ группы сработало хотя бы одно. */
    val requires: List<Set<String>> = emptyList(),
    private val check: (ApkFacts) -> Hit? = { null },
) {
    init {
        require(weight in 0..100) { "вес правила $id вне 0..100" }
        require(kind == RuleKind.SIGNAL || requires.isNotEmpty()) { "связка $id без условий" }
    }

    internal fun evaluateSignal(facts: ApkFacts): Hit? = check(facts)
}

/** Легитимный контекст, который снижает вес части правил, но не удаляет доказательства. */
class Mitigation(
    val id: String,
    val titleRu: String,
    /** Множитель веса 0..1. */
    val factor: Float,
    /** К каким правилам применяется. */
    val appliesTo: (Rule) -> Boolean,
    private val check: (ApkFacts) -> Evidence?,
) {
    internal fun evaluate(facts: ApkFacts): Evidence? = check(facts)
}

/** Сработавшее правило с итоговым вкладом. */
data class RuleMatch(
    val ruleId: String,
    val titleRu: String,
    val descriptionRu: String,
    val category: BehaviorCategory,
    val kind: RuleKind,
    val baseWeight: Int,
    val confidence: Float,
    /** Применённые смягчения (id → описание + доказательство). */
    val mitigations: List<AppliedMitigation>,
    /** Итоговый вклад в очках 0..100 после уверенности и смягчений. */
    val effectiveWeight: Float,
    val evidence: List<Evidence>,
)

data class AppliedMitigation(val id: String, val titleRu: String, val factor: Float, val evidence: Evidence)
