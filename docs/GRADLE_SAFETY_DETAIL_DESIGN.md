# Gradle Safety Job — Detailed Design (OpenClaw Runner)

## 0. Цель и контекст

### Цель
Сделать отдельный **job “Gradle Safety”**, который автоматически проверяет любые изменения Gradle-конфигурации Android-проекта на:
- supply-chain подлянки (репозитории/плагины/подмены),
- выполнение произвольных команд / скачивания на этапе сборки,
- изменения подписи релиза,
- уязвимые зависимости,
- небезопасные и невоспроизводимые настройки.

Job выдаёт **вердикт**:
- ✅ **ALLOW** — низкий риск, можно продолжать сборку/PR
- ⚠️ **ALLOW_WITH_CONDITIONS** — допустимо, но нужно применить условия/фиксы
- ❌ **BLOCK** — запрещено, требует ручного вмешательства/переработки

### Контекст архитектуры
- OpenClaw Gateway живёт в песочнице (Ubuntu VM), запуск действий — через Runner (allowlist jobs).
- Gradle Safety должен работать **детерминированно**, без “магии”.
- Основной принцип: **агент не “решает по ощущениям”, а доказывает по правилам + инструментам**.

---

## 1. Угрозы и модель безопасности

### Что защищаем
- исходники проекта и секреты (keystore, токены, env),
- хост/VM от выполнения произвольного кода через Gradle,
- цепочку поставки (plugins/dependencies),
- долгосрочную воспроизводимость сборок.

### Основные угрозы
1) **Malicious repository**
   - добавление `jitpack.io` / кастомных Maven URL / http репозиториев
   - подмена артефактов
2) **Malicious plugin**
   - новый Gradle plugin с кодом, который выполняется при конфигурации/сборке
3) **Arbitrary command execution**
   - `Exec` таски, `project.exec`, `Runtime.exec`, `ProcessBuilder`, shell
4) **Exfiltration**
   - скачивание/отправка данных по сети из build scripts
5) **Signing compromise**
   - изменение signingConfig / путей keystore / паролей / CI переменных
6) **Wrapper hijack**
   - подмена gradle-wrapper.jar, distributionUrl на сомнительный источник
7) **Dependency vulnerabilities**
   - критические CVE/OSV в зависимостях

### Фундаментальный факт
Gradle build scripts — это **исполняемый код**. Поэтому любые изменения Gradle — высокорисковая поверхность.

---

## 2. Границы ответственности Job

### Job делает
- статический анализ diff’ов (Gradle/Wrapper)
- анализ файлов проекта (Gradle-related only)
- вывод списка зависимостей (без запуска сборки кода)
- запуск vulnerability scanner (OSV)
- проверку политик allowlist/denylist
- генерацию отчёта и вердикта

### Job НЕ делает
- полноценную сборку APK/AAB
- запуск тестов/линта (это отдельный job)
- автоматическое “доверие” новым репозиториям/плагинам без правил
- доступ к секретам проекта

---

## 3. Входы/Выходы

### Inputs (обязательные)
- `WORKSPACE_PATH` — путь к репозиторию (read-only mount)
- `BASE_REF` / `HEAD_REF` или patch/diff (варианты ниже)
- `POLICY_PATH` — путь к policy YAML (read-only)
- `MODE` — `pr` | `branch` | `local` (как получаем diff)
- `ALLOW_NETWORK` — default `false` (см. раздел 6)

### Outputs
- `verdict.json` (машиночитаемо)
- `report.md` (человекочитаемо)
- `risk_score` (0..100)
- `findings[]` с категориями и доказательствами (пути/строки/patch hunks)

### Exit codes
- `0` = ALLOW
- `10` = ALLOW_WITH_CONDITIONS
- `20` = BLOCK
- `30` = ERROR (job failure, не принимать изменения)

---

## 4. Объект проверки: что считается “Gradle surface”

Job следит за изменениями в файлах:
- `build.gradle`, `build.gradle.kts` (root и modules)
- `settings.gradle`, `settings.gradle.kts`
- `gradle.properties`
- `gradle/` (в т.ч. `gradle-wrapper.properties`, `gradle-wrapper.jar`)
- `gradlew`, `gradlew.bat`
- `libs.versions.toml`
- `versions.gradle` (если используется)
- `*.gradle` / `*.gradle.kts` в `buildSrc/` (если есть)
- `buildSrc/**` (особенно опасно: это полноценный код для Gradle)

Любые изменения **вне этого списка** job игнорирует (это работа других jobs).

---

## 5. Политики (Policy Pack)

Policy хранится как YAML (пример ниже). Разделяется на:
- **HARD_BLOCK** (всегда BLOCK)
- **SOFT_RULES** (даёт очки риска, иногда conditions)
- **ALLOWLIST** (доверенные плагины/репозитории/домены)

### 5.1 HARD_BLOCK правила (без исключений)
1) **Новые репозитории**, кроме:
   - `google()`
   - `mavenCentral()`
   - (опционально) `gradlePluginPortal()`
2) Любой `maven { url "http://..." }` (http)
3) Любой репозиторий по домену из denylist
4) Любой новый plugin id **не в allowlist**
5) Любые изменения в `signingConfig`, `keystore`, `storeFile`, `storePassword`, `keyAlias`, `keyPassword`
6) Любая кастомная таска/скрипт с признаками execution/network:
   - `Exec`, `project.exec`, `JavaExec`
   - `Runtime.getRuntime().exec`
   - `ProcessBuilder`
   - `curl`, `wget`, `Invoke-WebRequest`
   - `HttpURLConnection`, `OkHttp`, `java.net.URL`
7) Изменения `gradle-wrapper.jar` (любой diff) → BLOCK
8) `gradle-wrapper.properties`:
   - `distributionUrl` не https
   - домен не в allowlist (services.gradle.org или корпоративный mirror)
9) Любые изменения в `buildSrc/` → BLOCK (если не разрешено отдельно политикой)

### 5.2 SOFT_RULES (скоринг)
- bump версий плагинов/AGP/Gradle → риск +5..+15 (в зависимости от скачка)
- добавление новой зависимости:
  - если group/artifact новый → риск +5
  - если версия alpha/beta/rc/SNAPSHOT → риск +15
- включение/выключение R8/minify → риск +5 (может менять артефакт)
- изменение `repositoriesMode` / dependency resolution strategy → риск +10

### 5.3 Conditions (ALLOW_WITH_CONDITIONS)
- Wrapper обновлён на новую версию Gradle, но url корректный:
  - condition: “прикрепить release notes / использовать только services.gradle.org”
- Новая зависимость добавлена:
  - condition: “закрепить версию (no dynamic versions)”
- Обнаружены уязвимости OSV:
  - condition: “обновить до фиксированной версии или объяснить ложное срабатывание”

---

## 6. Сеть и воспроизводимость

### Принцип
По умолчанию job должен работать **без сети**, кроме сценариев где нужна проверка уязвимостей.

### Режимы
- `ALLOW_NETWORK=false` (default):
  - только статический анализ diff и локальные проверки
  - OSV scan пропускается или работает по локальной базе (если имеется)
- `ALLOW_NETWORK=true` (только для work gateway или по явному разрешению):
  - разрешаем выход только на:
    - `osv.dev` (или github advisory mirror)
    - `services.gradle.org` (если нужно проверить wrapper URL — но лучше без)
  - сетевые egress правила на уровне контейнера/Runner (желательно)

**Важно:** Gradle Safety job **не должен запускать полноценный Gradle build**, чтобы не тянуть зависимости по сети в ходе проверки. Разрешено:
- `./gradlew -q dependencies` только если:
  - включён offline cache, и
  - нет сети, и
  - это контролируемо (иначе это не “safety job”, а “download job”).

Рекомендуемый вариант: использовать **lockfiles** (`gradle.lockfile`, version catalogs) и анализировать их.

---

## 7. Точность: откуда берём diff

### Вариант A (лучший): git diff внутри workspace
- Runner монтирует репозиторий с `.git`
- Job делает:
  - `git diff --name-only BASE..HEAD`
  - `git diff BASE..HEAD -- <gradle-surface-files>`

### Вариант B: patch файл
- Runner даёт `PATCH_PATH`
- Job анализирует patch напрямую

### Вариант C: PR API (не рекомендуется)
- требует токены и сеть — увеличивает риск
- лучше пусть gateway/runner сам скачивает и кладёт локально

---

## 8. Пайплайн проверки (Step-by-step)

### Step 0 — Prepare
- определить base/head
- построить список изменённых файлов
- если нет изменений в Gradle surface → ALLOW (risk_score=0)

### Step 1 — Static rules: repos/plugins/wrapper/signing
- парсить patch и/или файлы целиком
- обнаружить:
  - repos additions
  - plugin additions
  - wrapper changes
  - signing changes
  - buildSrc changes
- при попадании в HARD_BLOCK → BLOCK немедленно

### Step 2 — Dangerous constructs scan (semgrep/regex)
- прогнать набор правил по изменённым Gradle-файлам:
  - Exec / project.exec / JavaExec
  - Runtime.exec / ProcessBuilder
  - download patterns
  - network classes
  - base64 decode + write file patterns (индикатор payload)
- если найдено → BLOCK (или ALLOW_WITH_CONDITIONS по политике, но по умолчанию BLOCK)

### Step 3 — Dependency deltas
- извлечь список зависимостей:
  - из `libs.versions.toml`
  - из `dependencies {}` блоков (best-effort)
- построить “что добавили/обновили”
- начислить риск баллы

### Step 4 — Vulnerability scan (если разрешена сеть/есть локальная БД)
- собрать перечень координат dependencies (group:artifact:version)
- прогнать `osv-scanner` или запросы OSV
- для CRITICAL/HIGH:
  - если есть фикс версия → ALLOW_WITH_CONDITIONS или BLOCK (по политике)
  - если нет → ALLOW_WITH_CONDITIONS с пометкой

### Step 5 — Final scoring + verdict
- `risk_score` = clamp(0..100)
- правила вердикта (дефолт):
  - score < 20 → ALLOW
  - 20..49 → ALLOW_WITH_CONDITIONS
  - >= 50 → BLOCK
- но HARD_BLOCK всегда BLOCK

### Step 6 — Generate artifacts
- `report.md`: кратко + таблица finding’ов + что изменилось + какие условия
- `verdict.json`: для автоматизации gating

---

## 9. Risk Scoring (пример модели)

### Базовые веса
- Новый репозиторий (даже “почти норм”) → HARD_BLOCK (по умолчанию)
- Новый plugin id → HARD_BLOCK
- Wrapper URL домен не allowlist → HARD_BLOCK
- buildSrc изменения → HARD_BLOCK
- Signing изменения → HARD_BLOCK
- Новый dependency:
  - +5 если новый group:artifact
  - +10 если из “редкой” группы (не android/jetbrains/google)
  - +15 если alpha/beta/rc/SNAPSHOT
- Mass upgrade (>= 10 зависимостей) → +15
- Major bump AGP (например 8.0→8.3) → +10
- CVE HIGH → +20, CRITICAL → +40

---

## 10. Реализация Job (Container)

### Образ
`openclaw-runner-gradle-safety:<version>`

Состав:
- bash + coreutils
- git
- python3 (или node) для парсинга + генерации JSON/MD
- semgrep (опционально, но желательно)
- osv-scanner (желательно)
- jq

### Запуск
Runner запускает контейнер:
- read-only rootfs (желательно)
- workspace mount: read-only
- tmp dir: rw
- no docker.sock
- no privileged
- pids-limit небольшой (например 256)
- network по умолчанию отключён

### Поведение
Entry script:
- читает env
- запускает pipeline
- пишет artifacts в `/out` (mount rw), например:
  - `/out/report.md`
  - `/out/verdict.json`

---

## 11. Интеграция в OpenClaw Workflow

### Триггеры
Gradle Safety запускается автоматически при:
- изменениях файлов Gradle surface в PR/ветке
- перед запуском build job

### Gate
- build job **не запускается**, если verdict = BLOCK
- если ALLOW_WITH_CONDITIONS:
  - либо автоматом применить “safe fixes” (если разрешено отдельным policy)
  - либо остановиться и попросить подтверждение/доработку (в зависимости от gateway)

### Авто-фиксы (опционально)
Разрешать только безопасные механические правки:
- запрет dynamic versions (`+`, `latest.release`) — заменить на pinned
- включить/обновить dependency verification metadata
- убрать http → https в wrapper URL
**Но:** любые изменения Gradle через job должны быть отдельно флагом `ALLOW_AUTOFIX=true` и только для work gateway.

---

## 12. Policy YAML (пример)

```yaml
version: 1

repositories:
  allowed_shortcuts:
    - google
    - mavenCentral
    - gradlePluginPortal
  allowed_domains:
    - services.gradle.org
    - plugins.gradle.org
  deny_domains:
    - jitpack.io

plugins:
  allowlist:
    - com.android.application
    - com.android.library
    - org.jetbrains.kotlin.android
    - org.jetbrains.kotlin.jvm
    - com.google.dagger.hilt.android
  denylist: []

hard_block:
  block_buildsrc_changes: true
  block_signing_changes: true
  block_new_repositories: true
  block_new_plugins_not_allowlisted: true
  block_exec_network_patterns: true
  block_wrapper_jar_changes: true
  block_wrapper_distribution_non_https: true
  block_wrapper_distribution_domain_not_allowlisted: true

risk_scoring:
  thresholds:
    allow_max: 19
    allow_with_conditions_max: 49
  weights:
    new_dependency: 5
    pre_release_version: 15
    mass_dependency_change: 15
    agp_major_bump: 10
    osv_high: 20
    osv_critical: 40

network:
  allow_network_default: false
  allowed_egress_domains:
    - osv.dev
```

---

## 13. Отчётность

### report.md (структура)
- Summary (verdict, score)
- Changed files (Gradle surface only)
- Findings table:
  - Severity (BLOCKER/HIGH/MED/LOW)
  - Category (repo/plugin/wrapper/signing/exec/vuln/other)
  - Evidence (file:line, patch hunk)
  - Recommendation
- Conditions (если есть)
- Suggested safe fixes (если применимо)

### verdict.json (структура)
```json
{
  "verdict": "ALLOW_WITH_CONDITIONS",
  "risk_score": 32,
  "changed_files": ["app/build.gradle.kts", "gradle/wrapper/gradle-wrapper.properties"],
  "findings": [
    {
      "severity": "HIGH",
      "category": "DEPENDENCY",
      "message": "New dependency added: com.some:lib:1.2.3",
      "evidence": "app/build.gradle.kts:123",
      "recommendation": "Pin version and ensure dependency is from mavenCentral/google."
    }
  ],
  "conditions": [
    "Pin all dependency versions; no dynamic versions.",
    "Run OSV scan with network allowed (osv.dev) or provide SBOM."
  ]
}
```

---

## 14. Тест-план

### Unit-like tests (fixtures)
Создать набор фикстур репозиториев/patches:
- adding jitpack → BLOCK
- adding new plugin not allowlisted → BLOCK
- wrapper url to http → BLOCK
- buildSrc change → BLOCK
- new dependency stable → ALLOW_WITH_CONDITIONS (если score выше порога)
- osv critical found → ALLOW_WITH_CONDITIONS/BLOCK (по policy)

### Regression tests
- проверка, что “нет gradle changes” → ALLOW
- проверка, что job не запускает gradle build и не скачивает ничего (по логам)

---

## 15. Рекомендованные “долгосрочные усилители”
1) **Gradle Dependency Verification** (hash-based): повышает гарантию, что артефакты не подменены.
2) Dependency locking (lockfiles) — воспроизводимость.
3) Запрет новых репозиториев вообще (жёстко) — почти всегда разумно.
4) Разделить policy на home/work gateway (work может быть чуть более гибким, home — максимально строгий).

---

## 16. Решения по умолчанию (наш baseline)
- Postgres/pgvector — долговременная память отдельно от Gradle Safety.
- Gradle Safety по умолчанию:
  - сеть выключена
  - любые новые репозитории/плагины — BLOCK
  - любые signing/buildSrc/wrapper.jar изменения — BLOCK
  - зависимость добавлять можно, но только если:
    - pinned versions
    - из trusted repositories
    - без критических уязвимостей

---

## 17. Следующий шаг (implementation checklist)
- [ ] Утвердить policy YAML baseline
- [ ] Собрать docker image `openclaw-runner-gradle-safety`
- [ ] Реализовать entry script + parser + report generator
- [ ] Интегрировать в Runner allowlist как job `android_gradle_safety`
- [ ] Включить gating: build job зависит от safety verdict
- [ ] Набор fixture tests
- [ ] Документация “как добавить новый разрешённый plugin/dependency”
