# Dashboard read-model contract v1

Crate: `crates/vor-dashboard`. Artefactos versionados: `docs/contracts/`.

## Propósito

El panel web (M6) debe distinguir siempre entre datos **reales**, **desconocidos** y **simulados**. El prototipo de referencia usa un único objeto `snapshot` con `mode: "demo"` y valores sintéticos sin procedencia por campo. Este contrato fija esa distinción en tipos antes de conectar ningún backend.

El contrato es sólo datos: no concede autoridad, no hace I/O y **no está expuesto en ninguna ruta HTTP**. La exposición (por ejemplo `GET /v1/dashboard/snapshot` con scope `gateway.read`) es un hito posterior y separado.

## Alcance de la garantía de procedencia

La garantía cubre los **valores observables**: estado, métricas e información derivada. Cada uno es un `Observed<T>` serializado con `provenance`:

- `{"provenance":"live","value":…,"observed_at_unix_ms":…}`: observado por el backend en ese instante.
- `{"provenance":"unknown","reason":"not_reported"|"not_implemented"|"unavailable"}`: el backend no lo sabe. Nunca se rellena con un valor inventado.
- `{"provenance":"simulated","value":…}`: dato sintético de vista previa.

Los **identificadores** no son observaciones sino claves estructurales, y no llevan procedencia por campo: `organization.organization_id`, `devices[].device_id`, `devices[].workspace_ids[]`, y dentro de `usage` los campos `workspace_id` y `usage_key`. Su procedencia es la del `mode` del snapshot (o, para los de `usage`, la del valor `usage` que los contiene). El contrato genérico **no inspecciona el contenido** de los identificadores: `validate()` comprueba que no estén vacíos y que no se repitan, pero no puede determinar si un string corresponde a una organización, dispositivo o workspace reales. Por tanto, que un snapshot `simulated` use identificadores sintéticos es responsabilidad de su productor, no una garantía de validación. El productor incluido (`simulated_preview_snapshot`, versionado en `docs/contracts/dashboard-snapshot.v1.simulated.example.json`) usa nombres de ejemplo reservados que contienen `example`; un test lo comprueba sobre ese fixture, y otro test documenta que `validate()` acepta un snapshot simulado cuyos identificadores no siguen esa convención.

## Reglas de validación (`DashboardSnapshot::validate`)

Procedencia:

1. `mode: "live"` no puede contener valores `simulated`; `mode: "simulated"` no puede contener valores `live`.
2. Un valor `live` no puede tener `observed_at_unix_ms` posterior a `generated_at_unix_ms`.
3. `schema_version` distinto de `1` se rechaza.

Identificadores (vacío incluye sólo espacios):

4. `organization_id` vacío.
5. `device_id` vacío o duplicado.
6. `workspace_id` vacío en `devices[].workspace_ids` o en `usage`; `workspace_id` duplicado dentro de un dispositivo.
7. `usage_key` vacío o `plan` de suscripción vacío, cuando el valor que los contiene es conocido.

Conteos de `summary`. En v1 los conteos **se derivan de `devices` del mismo snapshot**; no existe otra fuente. Un conteo `unknown` nunca se compara.

8. `total_devices` conocido debe ser igual a `devices.length`.
9. `connected_devices` / `revoked_devices` conocidos: si todos los `status` son conocidos, deben ser iguales al número de dispositivos con ese estado. Si algún `status` es `unknown`, el conteo debe estar entre los dispositivos conocidos con ese estado y esa cifra más los desconocidos.
10. Ningún conteo puede superar `devices.length`, y `connected_devices + revoked_devices` no puede superarlo (los estados son excluyentes).

Si una versión futura trae conteos desde otra fuente (por ejemplo, agregados del servidor con paginación de `devices`), debe declararlo en el contrato con un campo nuevo y `schema_version` nuevo; v1 no relaja estas reglas.

## Campos no declarados

Todas las estructuras deserializables y las variantes de `Observed` usan `deny_unknown_fields`, y el JSON Schema publica `additionalProperties: false` en cada objeto. `DashboardSnapshot::from_json` rechaza cualquier campo no declarado, en la raíz o anidado (hay pruebas que inyectan un campo `token` en la raíz y en niveles anidados representativos: `organization`, `summary`, un conteo de `summary`, un dispositivo, dos valores `Observed` de dispositivo, `subscription` y su valor, `usage` y una entrada de `usage`).

Alcance de esta garantía: el contrato **rechaza campos no declarados** y ninguno de sus campos declarados tiene nombre de credencial (lo comprueba un test sobre el esquema). No detecta secretos en general: no inspecciona el contenido de los strings declarados. Evitar que el backend coloque datos sensibles en un campo declarado sigue siendo responsabilidad del productor.

## Proyección real (`project_live_snapshot`)

Entrada: registros de `vor-auth` de **una** organización autenticada (`OrganizationRecord`, `TenantDeviceRecord`, `SubscriptionRecord`, `UsageRecord`) más el conjunto de dispositivos con enlace de transporte activo.

- La conectividad se identifica con la clave compuesta `DeviceKey { organization_id, device_id }`, igual que el modelo persistente. Un `device_id` conectado en `org-b` no marca como conectado un dispositivo con el mismo `device_id` en `org-a`.
- Quien llama resuelve cada enlace a su organización a través del registro de dispositivos de confianza. La proyección no infiere la organización a partir de un `device_id`. Hoy el hub de transporte indexa por `device_id` global; esa resolución es trabajo del hito que exponga el endpoint.
- Un registro persistente de otra organización hace fallar la proyección (`CrossTenantRecord`). Nada se filtra en silencio.
- `revoked` tiene prioridad sobre la conexión: un dispositivo revocado que aún mantiene un enlace se muestra `revoked` y no cuenta como conectado.
- Campos que el backend aún no rastrea (`display_name`, `os`, `agent_version`, `capabilities`, `last_seen_unix_ms`) salen como `unknown`. `DeviceHello` ya transporta versión y capacidades, pero el hub no las persiste todavía.
- `usage` es `unknown/not_implemented` salvo que el llamador aporte registros: hoy `TenantStore::record_usage` no se invoca desde el camino de peticiones (M5).
- `subscription` es sólo visualización; nunca es entrada de autorización (SAAS_TENANCY invariante 4).
- La proyección valida su propio resultado; registros con identificadores vacíos también fallan.

## Cobertura de secciones del panel

| Sección | Contrato v1 | Fuente real disponible hoy |
|---|---|---|
| Overview | `summary`, `organization` | Tenant store + hub de transporte |
| Devices | `devices[]` | Tenant store + hub; OS/versión/last-seen `unknown` |
| Usage | `usage` | `unknown` hasta M5 |
| Plan & billing | `subscription` | `SubscriptionRecord` (sandbox; cobros apagados) |
| GitHub | fuera de v1 | No existe integración GitHub en el backend |
| Install MCP | fuera de v1 | Contenido estático/documentación, no estado |
| Settings | fuera de v1 | Pendiente de modelo de cuenta (M4) |

## Regenerar artefactos

```sh
VOR_UPDATE_CONTRACTS=1 cargo test -p vor-dashboard
```

Sin la variable, los tests comparan `docs/contracts/dashboard-snapshot.v1.schema.json` y `docs/contracts/dashboard-snapshot.v1.simulated.example.json` con el código y fallan si divergen. Un cambio incompatible del contrato requiere `schema_version` nuevo y una nota de migración.
