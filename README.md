# Aura Mobile Defens

**Versión de la aplicación:** `1.0.0+1` · **Versión del modelo:** `3.0.0` · **Estado:** En desarrollo

Aura Mobile Defens es una aplicación Android de ciberdefensa local construida con Flutter/Dart y componentes nativos Kotlin, JNI y C. Su núcleo combina un `VpnService` autorizado por la persona usuaria, un túnel TUN basado en `hev-socks5-tunnel`, inspección DNS/SNI, una allowlist y un clasificador local de dominios. No requiere root. No es una solución certificada ni garantiza cobertura integral: el alcance depende del dispositivo, permisos, conectividad y protocolos observables.

![Build de release signing](https://img.shields.io/github/actions/workflow/status/yovanymoreno001-glitch/Aura-V1.0/release-signing-integrity.yml?branch=main&label=release%20signing)
![Cobertura](https://img.shields.io/badge/cobertura-no%20medida-lightgrey)
![Modelo](https://img.shields.io/badge/modelo-3.0.0-blue)

El estado se marca **En desarrollo**: el repositorio tiene workflows de validación y artefactos del modelo publicados en GitHub Pages, pero este README no afirma que exista una release Android distribuida. La insignia de cobertura indica que no hay un porcentaje de cobertura medido y versionado.

## 1. Arquitectura

```text
┌──────────────────────────────────── Android ────────────────────────────────────┐
│ Persona usuaria → consola autenticada → control Escudo VPN                       │
│                                           │ MainActivity solicita consentimiento │
│                                           ▼                                       │
│                           AuraVpnService (Kotlin, VpnService) → TUN               │
│                                           ▼                                       │
│                              motor hev-socks5-tunnel (C)                          │
│                         ┌─────────────┴──────────────┐                            │
│                         │ DNS / SNI / firewall C     │                            │
│                         └─────────────┬──────────────┘                            │
│                                       │ JNI / MethodChannel / EventChannel         │
└───────────────────────────────────────┼──────────────────────────────────────────┘
                                        ▼
┌──────────────────────────────── Flutter / Dart ─────────────────────────────────┐
│ AuraAIInference ← AuraAIBrain / AuraTools ← AgentController / AuraIntentParser   │
│        │                         │                                                │
│        ├─ Isolate.run           ├─ valida RSA-2048 y SHA-256 del modelo remoto   │
│        └─ bosque JSON local     └─ cifra e instala tras validar                   │
└─────────────────────────────────────────────────────────────────────────────────┘
```

Flujo de análisis: tras autenticar la consola, `AuraNetworkAuditor` escucha el EventChannel nativo. Los eventos `BLOCKED` y `DGA_ALERT` inician `DNS → hev-mapped-dns/motor C → JNI/eventos → Dart → AuraAIBrain → AuraAIInference en isolate → bosque serializado`; si el modelo confirma una amenaza, Aura solicita una regla DNS y registra si el motor la confirmó. La allowlist se consulta antes del bosque. El clasificador da votos binarios por mayoría; esos votos no son probabilidades calibradas.

| Componente | Responsabilidad observada |
|---|---|
| `MainActivity` | Expone el control Escudo VPN, solicita el consentimiento del sistema y comunica el resultado del servicio a Flutter. |
| `AuraVpnService` | Mantiene la interfaz VPN foreground y coordina el túnel mientras está activo. |
| `hev-socks5-tunnel` | Procesa tráfico encaminado por TUN; incluye la ruta DNS mapeada y código C/JNI. |
| Firewall C / SNI | Reglas nativas de red y reporte de hosts/eventos al lado Flutter. |
| `AuraNetworkAuditor` | Escucha eventos DNS tras autenticar la consola, mantiene una bitácora acotada y solicita inferencia para eventos bloqueados o DGA. |
| `AuraAIInference` | Extrae hosts, calcula las seis características y evalúa el bosque en `Isolate.run`. |
| `AuraAIBrain` | Carga/valida el modelo local y coordina inferencia, cachés y reglas seguras. |
| `AgentController` | Coordina órdenes, eventos y herramientas disponibles para la consola. |
| `AuraTools` | Acciones como actualizar defensas, bloquear un dominio o solicitar aislamiento nativo. |

### Contrato de características

El orden del vector está fijado por el modelo y Dart; no debe cambiarse sin una nueva compatibilidad de esquema:

| Índice | Campo JSON | Cálculo |
|---:|---|---|
| 0 | `length` | Longitud del host normalizado. |
| 1 | `shannon_entropy` | Entropía de Shannon de los caracteres del host. |
| 2 | `digit_ratio` | Dígitos ASCII divididos por la longitud. |
| 3 | `vowel_ratio` | Vocales ASCII (`a,e,i,o,u`) divididas por letras. |
| 4 | `consonant_sequence_ratio` | Caracteres de rachas consonánticas de longitud ≥3, divididos por letras. |
| 5 | `suspicious_tld` | `1.0` si el TLD pertenece al conjunto sospechoso del entrenador; si no, `0.0`. |

## 2. Incisiones integradas

La numeración de incisiones no está representada por tags Git. La tabla relaciona las etiquetas solicitadas con grupos de commits y merges que sí aparecen en el historial de `main`; para #4/#4b, la asignación se basa en la secuencia de commits, no en refs Git llamadas así.

| Incisión | Objetivo y archivos principales | Commits verificables | Estado |
|---|---|---|---|
| #1 | Integridad del firmado Android: `android/app/build.gradle`, `tool/compile_aura.sh`, `.github/workflows/release-signing-integrity.yml`, `codemagic.yaml`, README. | `0b329180c6ac3d75ea5826bb2e132f38537fd20c` (credenciales), `0a7c74a37cb1dab6f47004b982e65682e423de95` (guard end-to-end), merge `1a6a5749adbbccc88342558285c685baa24c7e59`. | Mergeada en `main` (`5b33743`). |
| #2 | Pipeline reproducible de datos/modelo: `tool/dataset/*`, `tool/train_max_aura_brain.py`, benchmark, tests, dependencias, `.github/workflows/model-training.yml`, `.gitignore`, README. | `67df3b39b177ef0a8c7a3a4408679ea2d0404784`, merge `83f102359978f13fb30742550a3c2876fafb94de`. | Mergeada en `main` (`5b33743`). |
| #4 | Robustez Codemagic y formatos de artefacto: `codemagic.yaml`, `tool/compile_aura.sh`, README. | `da8c138d3dbea6b3431a2a12acb7d25239928b8c`, merge `b9ab2d33384329acd8999b913c2b4d648bdeb2c4`. | Mergeada en `main` (`5b33743`). |
| #4b | Compatibilidad Base64 macOS/BSD de Codemagic: `tool/compile_aura.sh`. | `70780d03493ecfa481b9f406130cd35be63653ad`. | Mergeada en `main` (`5b33743`). |
| #5 | Brain v2, preset móvil firmado y benchmark: trainer, benchmark, tests, asset/sidecar/firma y README. | `23613194b33d963bdbcad669f6e82f1b063a0635`, `bb1b99b316291f9d25f74a55d7819cf31bced9e6`, merge `a82ff9f22c708b69033b375436529f92be6f6425`. | Mergeada en `main`. |

Merges posteriores también están en `main`: arreglo de `hashFiles()` inválido, `532b4be2e4351e8bebb12acb26abb9bcd95e72da`; URL del modelo y clave pública, `60d1f501cf905ff9965599c51c8faddf22632208`; merge final, `ba9ccacf5770e75a327298b3730fc9b0796398cb`. Historial: `git log --oneline --all --graph`.

## 3. Brain v2

Asset publicado: [`assets/model/aura_brain_model.json`](assets/model/aura_brain_model.json). Esquema: `random_forest`, clases `safe`/`threat` y seis características documentadas arriba.

| Propiedad | Valor real |
|---|---:|
| Versión JSON | `3.0.0` |
| Tamaño | 3,004,068 bytes (≈2.86 MiB; ≈3 MB decimal) |
| Árboles | 500 |
| Profundidad máxima | 10 |
| `min_samples_leaf` | 2048 |
| Muestras de entrenamiento | 339,279 |
| Cuantización de umbrales | 4 decimales |
| SHA-256 del JSON | `d190dddf5ca0d55093a215463dfd98d81395d9282f3a93fb425a058853928ba2` |

Métricas del preset móvil sobre test holdout; precision, recall, F1 y FPR son para `threat`. La matriz usa filas reales y columnas predichas `[safe, threat]`.

| Accuracy | Precision | Recall | F1 | FPR |
|---:|---:|---:|---:|---:|
| 0.786501 | 0.964630 | 0.758888 | 0.849479 | 0.107160 |

Matriz de confusión: `[[13381, 1606], [13916, 43800]]`.

### Benchmark de runner

Runner Linux `x86_64`, kernel `6.8.0-1064-azure`, glibc 2.39, 2 CPUs lógicas. No representa rendimiento en teléfono.

| Modo | Muestras | p50 | p95 | p99 | Throughput |
|---|---:|---:|---:|---:|---:|
| Warm, modelo residente | 10,000 | 1.980 ms | 4.085 ms | 7.300 ms | 434.22 dominios/s |
| Cold, incluye recarga JSON | 500 | 56.011 ms | 97.569 ms | 136.403 ms | 16.08 dominios/s |

La orden `actualizar` descarga el JSON, el sidecar `.sha256` y la firma `.sig` desde <https://yovanymoreno001-glitch.github.io/Aura-V1.0/model/>. La firma se verificó localmente con RSA-2048, PKCS#1 v1.5 y SHA-256. El cliente valida firma y digest antes de cifrar/instalar; un fallo activa reglas conservadoras sin bloqueo automático.

## Configuración de Codemagic para Producción

### Variables del grupo `production_keys`

Configura estas variables en Codemagic → Environment groups → `production_keys`:

| Variable | Tipo | Descripción |
|---|---|---|
| `AURA_PUBLIC_KEY_ENV` | Secure | Clave pública RSA Base64 DER (ver abajo) |
| `AURA_KEYSTORE_FILE` | File | Archivo `.jks` de tu keystore de producción |
| `AURA_STORE_PASSWORD` | Secure | Contraseña del keystore |
| `AURA_KEY_ALIAS` | Secure | Alias de la clave (ej: `aura-release`) |
| `AURA_KEY_PASSWORD` | Secure | Contraseña de la clave |
| `AURA_BUILD_FORMAT` | Secure | `apk` (predeterminado) o `aab` |

### Clave pública RSA Base64 DER

Copia este valor exacto para `AURA_PUBLIC_KEY_ENV` en una sola línea, sin comillas, espacios ni saltos de línea:

```text
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuG7nFF0UbTjT6Y8Ju0p31nVPiqx3aq6yg7+g/JtRJ+Y9WDAY504WdCnACplCVwju/5tnJhkvD3kWbsmfX45t9ZqMyCBo4stXbvRdbpe2WwMmxR/9ZHGGQQ1vjKyE4klsQ03aC836GW8l5y1IV/jknU4C03GRRMjfhkwTKpMjqq3kZAgQ62Yo2Prw0fB2c7b/2RjN5yiUZLtjh8FEQBhe8aW+4lrxEVkRJZxPrkbYdQoqBQKm2hQq1AUHurXx+HwHqDplb6mTcNttbnFtrkS0IDqXrhDSAHjaMLY8k6zyCutL7kTPBrAb44KaYvTRhMRBeUyOXHIb9YfxgAA0cCNs5wIDAQAB
```

La clave pública no es secreta y debe corresponder a la clave privada que firma el modelo. Protege como secretos `AURA_STORE_PASSWORD`, `AURA_KEY_PASSWORD` y cualquier keystore privado. En el `codemagic.yaml` actual, `AURA_BUILD_FORMAT` tiene un valor de entorno predeterminado `apk`; configura el override de formato según la política del proyecto.

## 4. Pipeline de datos

- Amenazas: [Phishing.Database](https://github.com/mitchellkrogza/Phishing.Database), MIT.
- Dominios seguros: [Majestic Million](https://majestic.com/reports/majestic-million), CC BY 3.0; [licencia](https://creativecommons.org/licenses/by/3.0/).
- Manifiesto: 484,685 dominios, 384,775 `threat` y 99,910 `safe`.
- Splits deterministas (semilla 42): train 339,279; val 72,703; test 72,703.
- Normalización: minúsculas, punto final eliminado, A-label IDNA2003; rechaza IPs y hosts inválidos, deduplica y excluye conflictos.
- La allowlist estática excluye coincidencias de threat. El manifiesto registra URLs/licencias, hashes de entradas crudas, conteos y timestamp.
- Majestic es el baseline seguro obligatorio. URLhaus requiere opt-in/licencia; Tranco está deshabilitado.
- Constructor: `tool/dataset/build_dataset.py`; splits y crudos son artefactos regenerables ignorados por Git.

Reproducción: `python -m pip install -r tool/requirements-train.txt`, `python tool/dataset/build_dataset.py --sources phishing_database`, `python tool/train_max_aura_brain.py`, `python tool/train_max_aura_brain.py --preset mobile`, `python tool/bench_aura_brain.py`, `python -m pytest tool/test_aura_brain.py -q`. CI no firma candidatos automáticamente.

## 5. Firma y seguridad Android

- La configuración Android usa `compileSdk 36`, `targetSdk 36` y NDK `25.2.13676358`.
- Gradle firma `release` solo cuando están presentes las cuatro variables `AURA_KEYSTORE_PATH`, `AURA_STORE_PASSWORD`, `AURA_KEY_ALIAS` y `AURA_KEY_PASSWORD`, y el keystore existe. Si no se configura ninguna, permite un artefacto release sin firmar y emite una advertencia; nunca sustituye la firma de producción por la clave debug. La configuración parcial o un keystore ausente con credenciales configuradas genera un error explícito.
- El modo release sin firma es solo para diagnóstico local: el artefacto no es instalable como actualización firmada. `tool/compile_aura.sh` y los flujos de producción siguen exigiendo y verificando el keystore.
- `tool/compile_aura.sh` falla rápido si faltan valores, valida con `keytool`, registra fingerprint SHA-256 y rechaza certificado/sujeto `Android Debug`.
- Para APK, usa `apksigner` si está disponible; su fallback `keytool` verifica el certificado configurado, no los bytes del APK. Para AAB verifica el certificado configurado.
- `AURA_ALLOWED_CERT_SHA256` se genera con el certificado activo. No se incluyen contraseñas, keystores ni claves privadas en el repo.
- El modelo remoto usa clave pública RSA-2048. Codemagic inyecta `AURA_PUBLIC_KEY_ENV` desde `production_keys`, que prevalece sobre el fallback local.

Clave pública Base64 DER `SubjectPublicKeyInfo` completa, de una línea, asociada a la firma del asset:

```text
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuG7nFF0UbTjT6Y8Ju0p31nVPiqx3aq6yg7+g/JtRJ+Y9WDAY504WdCnACplCVwju/5tnJhkvD3kWbsmfX45t9ZqMyCBo4stXbvRdbpe2WwMmxR/9ZHGGQQ1vjKyE4klsQ03aC836GW8l5y1IV/jknU4C03GRRMjfhkwTKpMjqq3kZAgQ62Yo2Prw0fB2c7b/2RjN5yiUZLtjh8FEQBhe8aW+4lrxEVkRJZxPrkbYdQoqBQKm2hQq1AUHurXx+HwHqDplb6mTcNttbnFtrkS0IDqXrhDSAHjaMLY8k6zyCutL7kTPBrAb44KaYvTRhMRBeUyOXHIb9YfxgAA0cCNs5wIDAQAB
```

## 6. GitHub Actions

| Workflow | Propósito | Triggers |
|---|---|---|
| `release-signing-integrity.yml` | Verifica credenciales requeridas, ausencia de firma debug y ruta positiva con keystore efímero. | PR/push a `main` cuando cambia Gradle, `tool/compile_aura.sh` o el workflow; `workflow_dispatch`. |
| `model-training.yml` | Instala Python, construye dataset, entrena, benchmark, pytest y publica reportes de CI. | PR y push a `main` para cambios `tool/**`, `data/**` o workflow; `workflow_dispatch`. |
| `deploy-model-pages.yml` | Publica JSON, SHA-256 y firma en Pages. | Push a `main` al cambiar workflow o los tres assets; `workflow_dispatch`. |

## 7. Codemagic

`codemagic.yaml` define `android-build`, grupo protegido `production_keys`, Flutter stable y Java 17. Trigger push a `main` o `principal`; APK predeterminado. `AURA_BUILD_FORMAT` admite `apk`, `aab` o `appbundle`. Keystore mediante `AURA_KEYSTORE_PATH`, `AURA_KEYSTORE_BASE64` temporal o file variable `AURA_KEYSTORE_FILE`, que se resuelve a path vía `CM_ENV`.

Variables protegidas: `AURA_STORE_PASSWORD`, `AURA_KEY_ALIAS`, `AURA_KEY_PASSWORD` y una modalidad de keystore. `AURA_PUBLIC_KEY_ENV` contiene la clave pública DER Base64. El preflight falla antes del build si falta configuración.

En Codemagic, configura `AURA_PUBLIC_KEY_ENV` en el grupo `production_keys` con este valor completo, sin comillas, prefijo ni saltos de línea. La variable del grupo prevalece sobre el fallback local de `tool/compile_aura.sh`:

```text
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuG7nFF0UbTjT6Y8Ju0p31nVPiqx3aq6yg7+g/JtRJ+Y9WDAY504WdCnACplCVwju/5tnJhkvD3kWbsmfX45t9ZqMyCBo4stXbvRdbpe2WwMmxR/9ZHGGQQ1vjKyE4klsQ03aC836GW8l5y1IV/jknU4C03GRRMjfhkwTKpMjqq3kZAgQ62Yo2Prw0fB2c7b/2RjN5yiUZLtjh8FEQBhe8aW+4lrxEVkRJZxPrkbYdQoqBQKm2hQq1AUHurXx+HwHqDplb6mTcNttbnFtrkS0IDqXrhDSAHjaMLY8k6zyCutL7kTPBrAb44KaYvTRhMRBeUyOXHIb9YfxgAA0cCNs5wIDAQAB
```

## 8. Estructura del repositorio

```text
assets/model/          modelo JSON, SHA-256 y firma
lib/                   Flutter/Dart: agent, crypto, inference, providers, screens, services, theme
android/app/           Gradle, manifest, Kotlin/Java, JNI y C
  src/main/cpp/        aura_crypto_secure, aura_sni_firewall, hev-socks5-tunnel
 tool/                 dataset, entrenamiento, benchmark, firma, build y pruebas
  dataset/             fuentes licenciadas, parser y fixture offline
  reports/             métricas locales ignoradas por Git
.github/workflows/     release-signing-integrity, model-training, deploy-model-pages
 data/                 fuentes crudas, CSV, manifiesto y splits regenerables
 test/                 pruebas Flutter/Dart
```

Archivos Dart versionados:

```text
lib/agent/agent_controller.dart
lib/agent/agent_event.dart
lib/agent/aura_crypto_layer.dart
lib/agent/aura_intent_parser.dart
lib/agent/aura_tools.dart
lib/agent/aura_whitelist.dart
lib/ai_brain.dart
lib/crypto/aura_crypto_layer.dart
lib/inference/aura_ai_inference.dart
lib/infrastructure/agent/aura_intent_parser.dart
lib/infrastructure/security/aura_dynamic_whitelist.dart
lib/main.dart
lib/models/aura_ai_brain.dart
lib/network_auditor.dart
lib/providers/aura_state_provider.dart
lib/radar_waves.dart
lib/screens/aura_core_screen.dart
lib/screens/splash_screen.dart
lib/secure_memory.dart
lib/secure_vault.dart
lib/security/shannon_entropy.dart
lib/security_engine.dart
lib/services/ai_brain.dart
lib/services/aura_core.dart
lib/theme/aura_tokens.dart
lib/voice_engine.dart
```

Fuentes nativos propios y artefactos versionados:

```text
android/app/src/main/AndroidManifest.xml
android/app/src/main/java/hev/htproxy/TProxyService.java
android/app/src/main/kotlin/com/aura/cyberdefense/AuraCryptoSecure.kt
android/app/src/main/kotlin/com/aura/cyberdefense/AuraNotificationService.kt
android/app/src/main/kotlin/com/ciberdefensa/aura/AuraAppGenomeScanner.kt
android/app/src/main/kotlin/com/ciberdefensa/aura/AuraHostileEnvironment.kt
android/app/src/main/kotlin/com/ciberdefensa/aura/AuraNetworkStream.kt
android/app/src/main/kotlin/com/ciberdefensa/aura/AuraUpdateWorker.kt
android/app/src/main/kotlin/com/ciberdefensa/aura/AuraVpnService.kt
android/app/src/main/kotlin/com/ciberdefensa/aura/MainActivity.kt
android/app/src/main/cpp/aura_crypto_secure.c
android/app/src/main/cpp/aura_sni_firewall.c
android/app/src/main/cpp/aura_sni_firewall.h
assets/images/aura_emblem.svg
assets/model/aura_brain_model.json
assets/model/aura_brain_model.json.sha256
assets/model/aura_brain_model.json.sig
```

Herramientas versionadas:

```text
tool/bench_aura_brain.py
tool/compile_aura.sh
tool/dataset/build_dataset.py
tool/dataset/fixtures/sample.csv
tool/dataset/sources.py
tool/install_flutter_env.sh
tool/requirements-train.txt
tool/setup_env_fix.sh
tool/sign_model.py
tool/test_aura_brain.py
tool/train_max_aura_brain.py
```

`hev-socks5-tunnel` es código C/JNI de terceros dentro de `android/app/src/main/cpp/hev-socks5-tunnel/`; se omite su inventario exhaustivo en este mapa. Componentes Dart centrales: `AuraTools`, `AgentController`, `AuraAIInference`, `AuraAIBrain`, `AuraCryptoLayer`, `AuraCoreScreen` y `AuraDynamicWhitelist`.

## 9. Build y validación

Para un build local se requiere Flutter stable, JDK 17, Android SDK Platform 36, Build Tools 36.0.0, NDK 25.2.13676358 y CMake 3.22.1. El build debug no necesita credenciales de release. Instala los componentes Android con `sdkmanager` y ejecuta:

```sh
sdkmanager "platform-tools" "platforms;android-36" "build-tools;36.0.0" "ndk;25.2.13676358" "cmake;3.22.1"
flutter pub get
flutter analyze
flutter test
flutter build apk --debug
```

El build debug se verificó con las cuatro ABI configuradas (`armeabi-v7a`, `arm64-v8a`, `x86`, `x86_64`). El proyecto usa AndroidX con Jetifier desactivado.

Un build release directo de Gradle sin variables de firmado produce un artefacto sin firma, solo apto para diagnóstico local:

```sh
flutter build apk --release
```

Para producir y verificar una release distribuible, configura el keystore y las cuatro variables `AURA_KEYSTORE_PATH`, `AURA_STORE_PASSWORD`, `AURA_KEY_ALIAS` y `AURA_KEY_PASSWORD`, y usa el preflight:

```sh
bash tool/compile_aura.sh --check-signing
bash tool/compile_aura.sh
bash tool/compile_aura.sh --verify-artifact
```

AAB: `AURA_BUILD_FORMAT=aab bash tool/compile_aura.sh`. Comprueba `CERT_SHA256`, compara con el fingerprint de release esperado y verifica que el sujeto no sea `Android Debug`. Codemagic configura `production_keys`, inicia `android-build` y revisa el preflight/fingerprint. Pruebas del modelo: `python -m pytest tool/test_aura_brain.py -q`. Cobertura porcentual: no medida/publicada.

## 10. Licencias y atribución

- Código Aura: licencia propietaria en [`LICENSE`](LICENSE). Permite visualización/revisión/auditoría bajo sus términos; modificación y distribución requieren autorización escrita del titular.
- Phishing.Database: MIT; [repositorio y licencia](https://github.com/mitchellkrogza/Phishing.Database).
- Majestic Million: CC BY 3.0; atribución bajo [Creative Commons Attribution 3.0](https://creativecommons.org/licenses/by/3.0/).
- URLhaus: opt-in y sujeto a [términos de abuse.ch](https://abuse.ch/terms-of-use/); confirma entitlement comercial antes de usarlo.
- Tranco está deshabilitado por condiciones mixtas de proveedores.

## 11. Roadmap

Pendientes propuestos, no funciones completadas:

- Incisión #6: Aura Agéntica (registro de herramientas y clasificador de intenciones).
- Incisión #7: Suite 3D / núcleo neuronal holográfico.
- Revisar permisos y manifiesto para Android 14+ y APIs 34/36; el build actual declara `compileSdk 36` y `targetSdk 36`.
- Evaluar cobertura DoH, DoQ e IPv6; la inspección actual no cubre universalmente esos transportes/resolvers.
- Refactor de nombres de `AuraAIInference` y clases relacionadas manteniendo contrato/tests.
- Añadir cobertura de tests reproducible y benchmark en dispositivos reales.

## 12. Código crítico auditado

Los bloques siguientes se insertan literalmente desde los archivos versionados. Actualízalos al cambiar el código.

### `android/app/build.gradle` (completo)
```groovy
import java.security.KeyStore
import java.security.MessageDigest

plugins {
    id "com.android.application"
    id "kotlin-android"
    id "dev.flutter.flutter-gradle-plugin"
}

def releaseSigningVariables = [
    "AURA_KEYSTORE_PATH",
    "AURA_STORE_PASSWORD",
    "AURA_KEY_ALIAS",
    "AURA_KEY_PASSWORD",
]
def releaseSigningValues = releaseSigningVariables.collectEntries {
    [(it): System.getenv(it)]
}
def releaseSigningConfigured = releaseSigningValues.values().any {
    it != null && !it.trim().isEmpty()
}
def releaseSigningComplete = releaseSigningValues.values().every {
    it != null && !it.trim().isEmpty()
}
def releaseKeystorePath = releaseSigningValues["AURA_KEYSTORE_PATH"]
def releaseKeystoreFile = releaseKeystorePath
    ? project.file(releaseKeystorePath).absoluteFile
    : null

android {
    namespace "com.ciberdefensa.aura"
    compileSdk 36
    ndkVersion = "25.2.13676358"

    buildFeatures {
        buildConfig true
    }

    compileOptions {
        sourceCompatibility JavaVersion.VERSION_17
        targetCompatibility JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = '17'
    }

    defaultConfig {
        applicationId "com.ciberdefensa.aura"
        minSdk 24
        targetSdk 36
        versionCode 1
        versionName "1.0.0"

        ndk {
            abiFilters "armeabi-v7a", "arm64-v8a", "x86", "x86_64"
        }
    }

    signingConfigs {
        release {
            def keystorePath = System.getenv("AURA_KEYSTORE_PATH")
            storeFile = keystorePath ? project.file(keystorePath).absoluteFile : null
            storePassword = System.getenv("AURA_STORE_PASSWORD")
            keyAlias = System.getenv("AURA_KEY_ALIAS")
            keyPassword = System.getenv("AURA_KEY_PASSWORD")
        }
    }

    buildTypes {
        release {
            if (releaseSigningComplete && releaseKeystoreFile.isFile()) {
                signingConfig signingConfigs.release
            }
            minifyEnabled true
            shrinkResources true
            proguardFiles getDefaultProguardFile('proguard-android-optimize.txt'), 'proguard-rules.pro'
        }
    }

}

dependencies {
    implementation "androidx.biometric:biometric:1.1.0"
    implementation "androidx.work:work-runtime-ktx:2.10.1"
    implementation "androidx.core:core-ktx:1.16.0"
}

def signingCertificateSha256 = { signingConfig ->
    def keystoreFile = signingConfig.storeFile
    def storePassword = signingConfig.storePassword
    def keyAlias = signingConfig.keyAlias
    if (keystoreFile == null || !keystoreFile.isFile() ||
        storePassword == null || storePassword.trim().isEmpty() ||
        keyAlias == null || keyAlias.trim().isEmpty()) {
        return null
    }

    def keyStore = null
    Exception lastLoadError = null
    [signingConfig.storeType, "JKS", "PKCS12"].findAll { it != null }.unique().each { type ->
        if (keyStore == null) {
            try {
                def candidate = KeyStore.getInstance(type)
                keystoreFile.withInputStream { stream ->
                    candidate.load(stream, storePassword.toCharArray())
                }
                keyStore = candidate
            } catch (Exception exception) {
                lastLoadError = exception
            }
        }
    }

    if (keyStore == null) {
        throw new GradleException("Could not read signing keystore '${keystoreFile}'.", lastLoadError)
    }

    def certificate = keyStore.getCertificate(keyAlias)
    if (certificate == null) {
        throw new GradleException("Alias '${keyAlias}' has no signing certificate in '${keystoreFile}'.")
    }

    MessageDigest.getInstance("SHA-256").digest(certificate.encoded)
        .collect { String.format("%02X", it & 0xff) }
        .join()
}

android.buildTypes.each { buildType ->
    def activeSigningConfig = buildType.signingConfig
    def activeCertificateSha256 = activeSigningConfig == null
        ? null
        : signingCertificateSha256(activeSigningConfig)
    buildType.buildConfigField(
        "String",
        "AURA_ALLOWED_CERT_SHA256",
        "\"${activeCertificateSha256 ?: ''}\"",
    )
}

gradle.taskGraph.whenReady { taskGraph ->
    def releaseSigningRequested = taskGraph.allTasks.any { task ->
        task.project == project &&
            (task.name == "printReleaseSigning" || task.name.toLowerCase().contains("release"))
    }
    if (releaseSigningRequested) {
        if (releaseSigningConfigured && !releaseSigningComplete) {
            def missingVariables = releaseSigningVariables.findAll {
                def value = releaseSigningValues[it]
                value == null || value.trim().isEmpty()
            }
            throw new GradleException(
                "Missing required release signing environment variable(s): ${missingVariables.join(', ')}"
            )
        }
        if (releaseSigningComplete &&
            (releaseKeystoreFile == null || !releaseKeystoreFile.isFile())) {
            throw new GradleException(
                "AURA_KEYSTORE_PATH must point to an existing keystore file. Release signing credentials were supplied, but the keystore is unavailable."
            )
        }
        if (!releaseSigningConfigured) {
            logger.warn(
                "No release signing credentials were supplied; the release artifact will be unsigned."
            )
        }
    }
}

tasks.register("printReleaseSigning") {
    group = "verification"
    description = "Prints the configured release signing identity without exposing credentials."
    doLast {
        def releaseSigningConfig = android.buildTypes.getByName("release").signingConfig
        println "STORE_FILE=${releaseSigningConfig?.storeFile?.absolutePath ?: ''}"
        println "KEY_ALIAS=${releaseSigningConfig?.keyAlias ?: ''}"
        println "IS_DEBUG_SIGNING=${releaseSigningConfig == android.signingConfigs.debug}"
    }
}

flutter {
    source '../..'
}

def hevSourceDir = file("src/main/cpp/hev-socks5-tunnel")
def hevBuildDir = layout.buildDirectory.dir("generated/hev-tun2socks")
def hevJniLibsDir = hevBuildDir.map { it.dir("jniLibs") }

android.sourceSets.main.jniLibs.srcDir(hevJniLibsDir)

tasks.register("buildHevSocks5Tunnel", Exec) {
    inputs.dir(hevSourceDir)
    inputs.files(
        file("src/main/cpp/aura_crypto_secure.c"),
        file("src/main/cpp/aura_sni_firewall.c"),
        file("src/main/cpp/aura_sni_firewall.h"),
    )
    outputs.dir(hevJniLibsDir)

    doFirst {
        hevBuildDir.get().asFile.mkdirs()
        hevJniLibsDir.get().asFile.mkdirs()
    }

    commandLine(
        file("${android.sdkDirectory}/ndk/${android.ndkVersion}/ndk-build").absolutePath,
        "NDK_PROJECT_PATH=null",
        "APP_BUILD_SCRIPT=${new File(hevSourceDir, 'Android.mk').absolutePath}",
        "NDK_APPLICATION_MK=${new File(hevSourceDir, 'Application.mk').absolutePath}",
        "NDK_OUT=${hevBuildDir.get().dir('obj').asFile.absolutePath}",
        "NDK_LIBS_OUT=${hevJniLibsDir.get().asFile.absolutePath}",
    )
}

tasks.named("preBuild").configure {
    dependsOn("buildHevSocks5Tunnel")
}
```

### `codemagic.yaml` (completo)
```yaml
workflows:
  android-build:
    name: Aura Android Release Pipeline
    max_build_duration: 60
    instance_type: mac_mini_m1
    environment:
      groups:
        - production_keys
      vars:
        PACKAGE_NAME: "com.aura.cyberdefense"
        AURA_BUILD_FORMAT: "apk"
      # AURA_PUBLIC_KEY_ENV is injected by production_keys; store only the Base64 DER body there.
      flutter: stable
      java: 17
    triggering:
      events:
        - push
      branch_patterns:
        - pattern: 'main'
        - pattern: 'principal'
    scripts:
      - name: Resolve Codemagic keystore file variable
        script: |
          set -euo pipefail
          if [[ -n "${AURA_KEYSTORE_FILE:-}" && -z "${AURA_KEYSTORE_PATH:-}" ]]; then
            [[ -f "$AURA_KEYSTORE_FILE" ]] || {
              printf '%s\n' '[AURA-PREFLIGHT][ERROR] AURA_KEYSTORE_FILE does not reference an existing file.' >&2
              exit 1
            }
            [[ -n "${CM_ENV:-}" ]] || {
              printf '%s\n' '[AURA-PREFLIGHT][ERROR] CM_ENV is unavailable for persisting AURA_KEYSTORE_PATH.' >&2
              exit 1
            }
            printf 'AURA_KEYSTORE_PATH=%s\n' "$AURA_KEYSTORE_FILE" >> "$CM_ENV"
          fi
      - name: Preflight release signing variables
        script: |
          set -euo pipefail
          missing=()
          for variable in AURA_STORE_PASSWORD AURA_KEY_ALIAS AURA_KEY_PASSWORD; do
            [[ -n "${!variable:-}" ]] || missing+=("$variable")
          done
          if [[ -z "${AURA_KEYSTORE_PATH:-}" && -z "${AURA_KEYSTORE_BASE64:-}" ]]; then
            missing+=("AURA_KEYSTORE_PATH or AURA_KEYSTORE_BASE64")
          fi
          if ((${#missing[@]} > 0)); then
            printf '[AURA-PREFLIGHT][ERROR] Configure required production_keys variables: %s\n' "${missing[*]}" >&2
            exit 1
          fi
      - name: Build Android Release artifact
        script: |
          set -euo pipefail
          cd "${CM_BUILD_DIR:?CM_BUILD_DIR is required}"
          bash tool/compile_aura.sh
      - name: Verify Android Release artifact signer
        script: |
          set -euo pipefail
          cd "${CM_BUILD_DIR:?CM_BUILD_DIR is required}"
          bash tool/compile_aura.sh --verify-artifact
    artifacts:
      - build/app/outputs/flutter-apk/*.apk
      - build/app/outputs/bundle/release/*.aab

```

### `tool/compile_aura.sh` (completo)
```bash
#!/usr/bin/env bash
# Release builds default to APK; set AURA_BUILD_FORMAT=appbundle for an AAB.
set -euo pipefail

log() {
    printf '[AURA-BUILD] %s\n' "$*"
}

fail() {
    printf '[AURA-BUILD][ERROR] %s\n' "$*" >&2
    exit 1
}

mode="build"
case "${1:-}" in
    --check-signing)
        mode="check-signing"
        shift
        ;;
    --verify-artifact)
        mode="verify-artifact"
        shift
        ;;
    --help|-h)
        printf '%s\n' \
            'Usage: compile_aura.sh [--check-signing|--verify-artifact]' \
            '  --check-signing    Resolve and validate the keystore; print its SHA-256 certificate fingerprint.' \
            '  --verify-artifact  Verify the configured release artifact without rebuilding.'
        exit 0
        ;;
esac
[[ "$#" -eq 0 ]] || fail "Unsupported argument. Use --check-signing or --verify-artifact."

temporary_files=()
cleanup_temporary_files() {
    local temporary_file
    for temporary_file in "${temporary_files[@]}"; do
        rm -f -- "$temporary_file"
    done
}
trap cleanup_temporary_files EXIT

resolve_keystore() {
    if [[ -n "${AURA_KEYSTORE_PATH:-}" ]]; then
        if [[ -f "$AURA_KEYSTORE_PATH" && -r "$AURA_KEYSTORE_PATH" ]]; then
            export AURA_KEYSTORE_PATH
            return
        fi
        [[ -n "${AURA_KEYSTORE_BASE64:-}" ]] ||
            fail "AURA_KEYSTORE_PATH must reference an existing readable file, or set AURA_KEYSTORE_BASE64."
    fi

    [[ -n "${AURA_KEYSTORE_BASE64:-}" ]] ||
        fail "Missing release keystore: set AURA_KEYSTORE_PATH or AURA_KEYSTORE_BASE64."

    local keystore_file
    keystore_file="$(mktemp "${TMPDIR:-/tmp}/aura-release-keystore.XXXXXX")"
    temporary_files+=("$keystore_file")
    chmod 0600 "$keystore_file" 2>/dev/null ||
        fail "Could not secure the temporary Base64 keystore."
    if [[ "$(uname -s)" == "Darwin" ]]; then
        if ! printf '%s' "$AURA_KEYSTORE_BASE64" | base64 -D > "$keystore_file" 2>/dev/null; then
            fail "AURA_KEYSTORE_BASE64 is not valid Base64 keystore data."
        fi
    elif ! printf '%s' "$AURA_KEYSTORE_BASE64" | base64 --decode > "$keystore_file" 2>/dev/null; then
        fail "AURA_KEYSTORE_BASE64 is not valid Base64 keystore data."
    fi
    [[ -s "$keystore_file" ]] || fail "AURA_KEYSTORE_BASE64 decoded to an empty keystore."
    export AURA_KEYSTORE_PATH="$keystore_file"
}

require_release_signing_environment() {
    local required_variables=(AURA_STORE_PASSWORD AURA_KEY_ALIAS AURA_KEY_PASSWORD)
    local missing_variables=()
    local variable
    for variable in "${required_variables[@]}"; do
        [[ -n "${!variable:-}" ]] || missing_variables+=("$variable")
    done
    if [[ -z "${AURA_KEYSTORE_PATH:-}" && -z "${AURA_KEYSTORE_BASE64:-}" ]]; then
        missing_variables+=("AURA_KEYSTORE_PATH or AURA_KEYSTORE_BASE64")
    fi
    ((${#missing_variables[@]} == 0)) ||
        fail "Missing required release signing environment variable(s): ${missing_variables[*]}"
}

validate_signing_credentials() {
    local missing_variables=()
    local variable
    for variable in AURA_STORE_PASSWORD AURA_KEY_ALIAS AURA_KEY_PASSWORD; do
        [[ -n "${!variable:-}" ]] || missing_variables+=("$variable")
    done
    ((${#missing_variables[@]} == 0)) ||
        fail "Missing release signing variable(s): ${missing_variables[*]}"
    command -v keytool >/dev/null 2>&1 || fail "keytool is required to validate release signing."
}

keytool_certificate_info() {
    local keytool_output
    if ! keytool_output="$(keytool -list -v \
        -keystore "$AURA_KEYSTORE_PATH" \
        -alias "$AURA_KEY_ALIAS" \
        -storepass:env AURA_STORE_PASSWORD \
        -keypass:env AURA_KEY_PASSWORD 2>/dev/null)"; then
        fail "keytool could not validate the release keystore; check AURA_KEYSTORE_PATH, AURA_STORE_PASSWORD, AURA_KEY_ALIAS and AURA_KEY_PASSWORD."
    fi

    local fingerprint
    fingerprint="$(printf '%s\n' "$keytool_output" | awk '
        /SHA-?256:/ { sub(/^.*SHA-?256:[[:space:]]*/, ""); print; exit }
        /SHA256:/ { sub(/^.*SHA256:[[:space:]]*/, ""); print; exit }
    ' | tr -d ':[:space:]' | tr '[:lower:]' '[:upper:]')"
    [[ "$fingerprint" =~ ^[[:xdigit:]]{64}$ ]] ||
        fail "keytool did not return a valid SHA-256 certificate fingerprint."

    local subject
    subject="$(printf '%s\n' "$keytool_output" | awk -F': ' '/^[[:space:]]*Owner:/ {print $2; exit}')"
    if grep -Fqi 'Android Debug' <<< "$subject"; then
        fail "Release signing certificate is the public Android Debug certificate."
    fi
    printf '%s\n' "$fingerprint"
}

verify_release_signer() {
    local artifact="$1"
    local extension="${artifact##*.}"
    local certificate_output=""
    local certificate_subject=""
    local certificate_fingerprint=""
    local apksigner_binary="$(command -v apksigner || true)"
    local android_sdk="${ANDROID_SDK_ROOT:-${ANDROID_HOME:-}}"
    local candidate

    if [[ -z "$apksigner_binary" && -n "$android_sdk" ]]; then
        for candidate in "$android_sdk"/build-tools/*/apksigner; do
            [[ -x "$candidate" ]] && apksigner_binary="$candidate"
        done
    fi

    if [[ "$extension" == "apk" && -n "$apksigner_binary" ]]; then
        if ! certificate_output="$("$apksigner_binary" verify --print-certs "$artifact" 2>/dev/null)"; then
            fail "apksigner rejected the release APK."
        fi
        certificate_fingerprint="$(printf '%s\n' "$certificate_output" | awk -F': ' 'tolower($0) ~ /certificate sha-256 digest:/ {print $2; exit}' | tr -d ':[:space:]' | tr '[:lower:]' '[:upper:]')"
        certificate_subject="$(printf '%s\n' "$certificate_output" | awk -F': ' 'tolower($0) ~ /certificate dn:/ {print $2; exit}')"
        [[ "$certificate_fingerprint" =~ ^[[:xdigit:]]{64}$ ]] ||
            fail "apksigner did not return a valid SHA-256 certificate fingerprint."
        log "APK signer verification used apksigner."
    else
        if [[ "$extension" == "apk" ]]; then
            log "apksigner unavailable; using keytool keystore-certificate fallback (does not inspect APK bytes)."
        else
            log "AAB signer verification uses the configured keytool certificate."
        fi
        certificate_fingerprint="$(keytool_certificate_info)"
        certificate_subject="$(keytool -list -v \
            -keystore "$AURA_KEYSTORE_PATH" \
            -alias "$AURA_KEY_ALIAS" \
            -storepass:env AURA_STORE_PASSWORD \
            -keypass:env AURA_KEY_PASSWORD 2>/dev/null |
            awk -F': ' '/^[[:space:]]*Owner:/ {print $2; exit}')"
    fi

    if grep -Fqi 'Android Debug' <<< "$certificate_subject"; then
        fail "Release artifact is signed with the public Android Debug certificate."
    fi
    printf 'CERT_SHA256=%s\n' "$certificate_fingerprint"
}

project_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
android_dir="$project_root/android"
local_properties="$android_dir/local.properties"

require_release_signing_environment
resolve_keystore
validate_signing_credentials
build_format="${AURA_BUILD_FORMAT:-apk}"
case "$build_format" in
    apk) ;;
    aab) build_format="appbundle" ;;
    appbundle) ;;
    *) fail "AURA_BUILD_FORMAT must be 'apk', 'aab' or 'appbundle'." ;;
esac
signing_fingerprint="$(keytool_certificate_info)"

if [[ "$mode" == "check-signing" ]]; then
    printf 'CERT_SHA256=%s\n' "$signing_fingerprint"
    exit 0
fi

if [[ "$mode" == "verify-artifact" ]]; then
    if [[ "$build_format" == "apk" ]]; then
        release_artifact="$project_root/build/app/outputs/flutter-apk/app-release.apk"
    else
        release_artifact="$project_root/build/app/outputs/bundle/release/app-release.aab"
    fi
    [[ -f "$release_artifact" ]] || fail "Configured release artifact is missing."
    verify_release_signer "$release_artifact"
    exit 0
fi

property_value() {
    local key="$1"
    local file="$2"
    if [[ -f "$file" ]]; then
        awk -F= -v key="$key" '$1 == key {sub(/^[^=]*=/, ""); value = $0} END {print value}' "$file"
    fi
}

flutter_root="${FLUTTER_ROOT:-}"
if [[ -z "$flutter_root" || ! -x "$flutter_root/bin/flutter" ]]; then
    flutter_root="$(property_value flutter.sdk "$local_properties")"
fi
if [[ -z "$flutter_root" || ! -x "$flutter_root/bin/flutter" ]]; then
    flutter_binary="$(command -v flutter || true)"
    if [[ -n "$flutter_binary" ]]; then
        flutter_root="$(cd "$(dirname "$flutter_binary")/.." && pwd -P)"
    fi
fi
if [[ -z "$flutter_root" || ! -x "$flutter_root/bin/flutter" ]]; then
    for candidate in \
        "$HOME/development/flutter" \
        "$HOME/.flutter_sdk/flutter" \
        /opt/flutter \
        /usr/local/flutter
    do
        if [[ -x "$candidate/bin/flutter" ]]; then
            flutter_root="$candidate"
            break
        fi
    done
fi
[[ -n "$flutter_root" && -x "$flutter_root/bin/flutter" ]] ||
    fail "Flutter SDK not found. Set FLUTTER_ROOT to an installed stable Flutter SDK."
export FLUTTER_ROOT="$(cd "$flutter_root" && pwd -P)"
export PATH="$FLUTTER_ROOT/bin:$PATH"

if [[ -z "${AURA_PUBLIC_KEY_ENV:-}" ]]; then
    AURA_PUBLIC_KEY_ENV='MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuG7nFF0UbTjT6Y8Ju0p31nVPiqx3aq6yg7+g/JtRJ+Y9WDAY504WdCnACplCVwju/5tnJhkvD3kWbsmfX45t9ZqMyCBo4stXbvRdbpe2WwMmxR/9ZHGGQQ1vjKyE4klsQ03aC836GW8l5y1IV/jknU4C03GRRMjfhkwTKpMjqq3kZAgQ62Yo2Prw0fB2c7b/2RjN5yiUZLtjh8FEQBhe8aW+4lrxEVkRJZxPrkbYdQoqBQKm2hQq1AUHurXx+HwHqDplb6mTcNttbnFtrkS0IDqXrhDSAHjaMLY8k6zyCutL7kTPBrAb44KaYvTRhMRBeUyOXHIb9YfxgAA0cCNs5wIDAQAB'
    public_key_source="build-only fallback"
    log "WARNING: AURA_PUBLIC_KEY_ENV is empty; using the build-only fallback key. Signed model updates will fail closed. Configure production_keys for a production release."
else
    public_key_source="production"
fi
[[ "$AURA_PUBLIC_KEY_ENV" =~ ^[A-Za-z0-9+/]+={0,2}$ ]] ||
    fail "AURA_PUBLIC_KEY_ENV must be the Base64 DER body without PEM delimiters or whitespace."

key_file="$(mktemp "${TMPDIR:-/tmp}/aura-public-key.XXXXXX")"
temporary_files+=("$key_file")
python3 - "$AURA_PUBLIC_KEY_ENV" "$key_file" <<'PY'
import base64
import sys

try:
    der = base64.b64decode(sys.argv[1], validate=True)
except (ValueError, base64.binascii.Error) as error:
    raise SystemExit(f"AURA_PUBLIC_KEY_ENV is not valid Base64: {error}")
if not der:
    raise SystemExit("AURA_PUBLIC_KEY_ENV decoded to an empty public key.")
with open(sys.argv[2], "wb") as key_file:
    key_file.write(der)
PY
openssl pkey -pubin -inform DER -in "$key_file" -noout
rm -f "$key_file"

log "Selecting JDK 17 and mapping the installed Android SDK/NDK."
source "$project_root/tool/setup_env_fix.sh"
trap cleanup_temporary_files EXIT
[[ -x "$JAVA_HOME/bin/java" ]] ||
    fail "The JDK 17 setup did not provide JAVA_HOME/bin/java."

java_version="$("$JAVA_HOME/bin/java" -version 2>&1 | awk -F '"' '/version/ {print $2; exit}')"
[[ "$java_version" == 17.* ]] ||
    fail "Expected Java 17 at JAVA_HOME, found '${java_version:-unknown}'."
export PATH="$JAVA_HOME/bin:$PATH"
export GRADLE_OPTS="${GRADLE_OPTS:+$GRADLE_OPTS }-Dorg.gradle.java.home=$JAVA_HOME"
log "Gradle Java: $("$JAVA_HOME/bin/java" -version 2>&1 | head -n 1)"

gradle_version_output="$(
    cd "$android_dir"
    ./gradlew --version
)"
gradle_java_major="$(
    printf '%s\n' "$gradle_version_output" |
        awk '/^(Launcher )?JVM:/ {version = $NF; sub(/\..*/, "", version); print version; exit}'
)"
[[ "$gradle_java_major" == "17" ]] ||
    fail "Gradle reports Java ${gradle_java_major:-unknown}; Java 17 is required."

properties_tmp="$(mktemp "$local_properties.XXXXXX")"
temporary_files+=("$properties_tmp")
if [[ -f "$local_properties" ]]; then
    awk -F= '$1 != "flutter.sdk" {print}' "$local_properties" > "$properties_tmp"
fi
printf 'flutter.sdk=%s\n' "$FLUTTER_ROOT" >> "$properties_tmp"
mv "$properties_tmp" "$local_properties"

if [[ -n "${CM_ENV:-}" ]]; then
    printf 'FLUTTER_ROOT=%s\n' "$FLUTTER_ROOT" >> "$CM_ENV"
fi

cd "$project_root"
if [[ "$build_format" == "apk" ]]; then
    log "Building the release APK with the ${public_key_source} RSA public key."
    "$FLUTTER_ROOT/bin/flutter" build apk --release \
        --dart-define="AURA_PUBLIC_KEY=$AURA_PUBLIC_KEY_ENV"
    release_artifact="$project_root/build/app/outputs/flutter-apk/app-release.apk"
else
    log "Building the release app bundle with the ${public_key_source} RSA public key."
    "$FLUTTER_ROOT/bin/flutter" build appbundle --release \
        --dart-define="AURA_PUBLIC_KEY=$AURA_PUBLIC_KEY_ENV"
    release_artifact="$project_root/build/app/outputs/bundle/release/app-release.aab"
fi
[[ -f "$release_artifact" ]] || fail "Release artifact was not created."
verify_release_signer "$release_artifact"
log "Release artifact signature verified."
```

### `.github/workflows/deploy-model-pages.yml` (completo)
```yaml
name: Deploy model to GitHub Pages

on:
  push:
    branches:
      - main
    paths:
      - '.github/workflows/deploy-model-pages.yml'
      - 'assets/model/aura_brain_model.json'
      - 'assets/model/aura_brain_model.json.sha256'
      - 'assets/model/aura_brain_model.json.sig'
  workflow_dispatch:

permissions:
  contents: read
  pages: write
  id-token: write

concurrency:
  group: github-pages
  cancel-in-progress: true

jobs:
  deploy:
    environment:
      name: github-pages
      url: ${{ steps.deployment.outputs.page_url }}
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/configure-pages@v5
      - name: Prepare model-only site
        run: |
          mkdir -p _site/model
          cp assets/model/aura_brain_model.json _site/model/
          cp assets/model/aura_brain_model.json.sha256 _site/model/
          cp assets/model/aura_brain_model.json.sig _site/model/
      - uses: actions/upload-pages-artifact@v3
        with:
          path: _site
      - name: Deploy to GitHub Pages
        id: deployment
        uses: actions/deploy-pages@v4
```

### `tool/train_max_aura_brain.py` (primeras 150 líneas)
```python
import argparse
import csv
import hashlib
import json
import math
import os
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
from sklearn.metrics import accuracy_score, confusion_matrix, f1_score, precision_score, recall_score
from sklearn.ensemble import RandomForestClassifier
from sklearn.tree import _tree

ROOT = Path(__file__).resolve().parents[1]
FEATURE_ORDER = [
    "length",
    "shannon_entropy",
    "digit_ratio",
    "vowel_ratio",
    "consonant_sequence_ratio",
    "suspicious_tld",
]
SUSPICIOUS_TLDS = {
    "cam", "click", "country", "date", "download", "fit", "gq", "loan",
    "mov", "party", "review", "rest", "stream", "support", "tk", "top",
    "wang", "work", "xyz", "zip",
}
DATASET_DIR = ROOT / "data"
REPORTS_DIR = ROOT / "tool/reports"
MODEL_OUTPUT = REPORTS_DIR / "aura_brain_model.json"
METRICS_JSON = REPORTS_DIR / "metrics.json"
METRICS_MARKDOWN = REPORTS_DIR / "metrics.md"
MOBILE_MODEL_OUTPUT = REPORTS_DIR / "aura_brain_model_mobile.json"
MOBILE_METRICS_JSON = REPORTS_DIR / "metrics_mobile.json"
MOBILE_METRICS_MARKDOWN = REPORTS_DIR / "metrics_mobile.md"
MOBILE_SIZE_TRIALS = REPORTS_DIR / "mobile_size_trials.json"
MAX_MOBILE_MODEL_BYTES = 4 * 1024 * 1024
EXPECTED_CLASSES = {0, 1}
MIN_TEST_ROWS_PER_CLASS = 500


def normalize_domain(value):
    return value.strip().lower().rstrip(".")
SEED_DATASET = [
    ("google.com", 0), ("github.com", 0), ("whatsapp.com", 0),
    ("amazon.com", 0), ("bancodevenezuela.com", 0), ("codemagic.io", 0),
    ("flutter.dev", 0), ("wikipedia.org", 0), ("microsoft.com", 0),
    ("netflix.com", 0), ("binance.com", 0), ("youtube.com", 0),
    ("stackoverflow.com", 0), ("apple.com", 0), ("linkedin.com", 0),
    ("zoom.us", 0), ("cloudflare.com", 0), ("android.com", 0),
    ("x7z9q1wplmnb.xyz", 1), ("aqwzsxedcrfv12.top", 1),
    ("free-crypto-rewards.click", 1), ("update-system-android.live", 1),
    ("cxj9812kmzsloq.cc", 1), ("malicious-payload-server.info", 1),
    ("shw28190axmzq.xyz", 1), ("get-root-bypass.top", 1),
    ("91kazmslqo1029az.biz", 1), ("free-cleaner-android.gq", 1),
    ("p0wz9172mlxozq.tk", 1), ("get-unlocked-premium.fit", 1),
]


def calculate_shannon_entropy(domain_string):
    if not domain_string:
        return 0.0
    frequencies = {}
    for character in domain_string.lower():
        frequencies[character] = frequencies.get(character, 0) + 1
    length = len(domain_string)
    return -sum(
        (count / length) * math.log2(count / length)
        for count in frequencies.values()
    )


def extract_maximum_features(domain):
    host = normalize_domain(domain)
    length = len(host)
    if length == 0:
        return [0.0, 0.0, 0.0, 0.0, 0.0, 0.0]

    letters = [character for character in host if character.isascii() and character.isalpha()]
    digits = sum(character.isascii() and character.isdigit() for character in host)
    vowels = sum(character in "aeiou" for character in letters)
    letter_count = len(letters)
    run_length = 0
    consonant_sequence_characters = 0
    for character in host:
        if character.isascii() and character.isalpha() and character not in "aeiou":
            run_length += 1
        else:
            if run_length >= 3:
                consonant_sequence_characters += run_length
            run_length = 0
    if run_length >= 3:
        consonant_sequence_characters += run_length

    tld = host.rsplit(".", 1)[-1]
    return [
        float(length),
        calculate_shannon_entropy(host),
        digits / length,
        vowels / letter_count if letter_count else 0.0,
        consonant_sequence_characters / letter_count if letter_count else 0.0,
        float(tld in SUSPICIOUS_TLDS),
    ]


def read_split(path):
    if not path.is_file():
        raise FileNotFoundError(f"Dataset split is missing: {path}")
    rows = []
    with path.open("r", encoding="utf-8", newline="") as stream:
        reader = csv.DictReader(stream)
        expected_header = ["domain", "label", "source", "license", "retrieved_at"]
        if reader.fieldnames != expected_header:
            raise ValueError(f"Unexpected dataset CSV schema in {path}: {reader.fieldnames}")
        for row in reader:
            domain = row["domain"].strip().lower()
            if not domain or "." not in domain or row["label"] not in {"0", "1"}:
                raise ValueError(f"Invalid dataset row in {path}: {row}")
            rows.append((domain, int(row["label"])))
    return rows


def evaluate_metrics(labels, predictions):
    matrix = confusion_matrix(labels, predictions, labels=[0, 1])
    true_negative, false_positive, false_negative, true_positive = matrix.ravel()
    specificity_denominator = true_negative + false_positive
    return {
        "accuracy": float(accuracy_score(labels, predictions)),
        "precision": float(precision_score(labels, predictions, zero_division=0)),
        "recall": float(recall_score(labels, predictions, zero_division=0)),
        "f1": float(f1_score(labels, predictions, zero_division=0)),
        "false_positive_rate": (
            float(false_positive / specificity_denominator)
            if specificity_denominator
            else 0.0
        ),
        "confusion_matrix": {
            "labels": ["safe", "threat"],
            "rows_actual_columns_predicted": matrix.tolist(),
            "true_negative": int(true_negative),
            "false_positive": int(false_positive),
            "false_negative": int(false_negative),
            "true_positive": int(true_positive),
        },
    }


```

El resto valida al menos 500 filas por clase en cada split. El modo `full` ajusta 500 árboles y escribe candidato/métricas en `tool/reports/`. `--preset mobile` conserva 500 árboles, busca poda/profundidad bajo 4 MiB, cuantiza umbrales a cuatro decimales y mide el JSON serializado contra test/val; no reemplaza automáticamente el asset.

### `tool/dataset/build_dataset.py` (primeras 150 líneas)
```python
#!/usr/bin/env python3
"""Download licensed domain sources and build deterministic Aura CSV splits."""

from __future__ import annotations

import argparse
import csv
import hashlib
import ipaddress
import json
import os
import re
import sys
import tempfile
import urllib.error
import urllib.request
import zipfile
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

from sklearn.model_selection import train_test_split

from sources import DEFAULT_SAFE_SOURCE, SOURCES, SourceDefinition, iter_source_domains

ROOT = Path(__file__).resolve().parents[2]
DATA_DIR = ROOT / "data"
RAW_DIR = DATA_DIR / "raw"
OUTPUT_CSV = DATA_DIR / "aura_dataset.csv"
SPLIT_DIR = DATA_DIR / "splits"
MANIFEST_PATH = DATA_DIR / "dataset_manifest.json"
SPLIT_SEED = 42
NORMALIZATION_VERSION = "aura-domain-idna2003-v1"
CSV_FIELDS = ["domain", "label", "source", "license", "retrieved_at"]
STATIC_ALLOWLIST = {
    "google.com", "apple.com", "microsoft.com", "amazonaws.com",
    "cloudflare.com", "akamaiedge.net", "android.com", "github.com",
    "whatsapp.net", "googleapis.com", "gstatic.com", "googleusercontent.com",
    "apple-dns.net", "icloud.com", "microsoftonline.com", "windows.net",
    "amazon.com", "awsstatic.com", "akamaized.net", "fastly.net",
}
HOST_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


class DatasetBuildError(RuntimeError):
    pass


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def normalize_domain(value: str) -> str | None:
    candidate = value.strip()
    if not candidate or any(ord(char) < 0x20 for char in candidate):
        return None
    try:
        if "://" in candidate:
            parsed = urlsplit(candidate)
            if parsed.scheme.lower() not in {"http", "https"} or parsed.username or parsed.password:
                return None
            candidate = parsed.hostname or ""
        else:
            parsed = urlsplit("//" + candidate.lstrip("/"))
            if parsed.username or parsed.password:
                return None
            candidate = parsed.hostname or ""
    except ValueError:
        return None

    candidate = candidate.rstrip(".").lower()
    if not candidate:
        return None
    try:
        candidate = candidate.encode("idna").decode("ascii").lower()
        ipaddress.ip_address(candidate)
        return None
    except ValueError:
        pass
    except UnicodeError:
        return None

    if len(candidate) > 253 or "." not in candidate:
        return None
    labels = candidate.split(".")
    if any(len(label) > 63 or not HOST_LABEL.fullmatch(label) for label in labels):
        return None
    return candidate


def is_allowlisted(domain: str) -> bool:
    return any(domain == suffix or domain.endswith("." + suffix) for suffix in STATIC_ALLOWLIST)


def parse_acceptance(raw_value: str) -> tuple[str, str]:
    source_name, separator, license_id = raw_value.partition(":")
    if not separator or not source_name or not license_id:
        raise argparse.ArgumentTypeError(
            "license acceptance must be formatted as <source>:<SPDX-id>"
        )
    return source_name, license_id


def download_source(source: SourceDefinition, raw_dir: Path) -> tuple[Path, str, int, str]:
    raw_dir.mkdir(parents=True, exist_ok=True)
    suffix = {
        "threat-urls-zip": ".zip",
        "threat-domain-lines": ".txt",
        "safe-domains-gzip-csv": ".csv.gz",
        "safe-domains-zip-csv": ".zip",
    }[source.kind]
    destination = raw_dir / f"{source.name}{suffix}"
    digest = hashlib.sha256()
    byte_count = 0
    retrieved_at = utc_now()
    request = urllib.request.Request(
        source.url,
        headers={"User-Agent": "Aura-Dataset-Pipeline/1.0 (+https://github.com/)"},
    )
    try:
        with urllib.request.urlopen(request, timeout=90) as response, tempfile.NamedTemporaryFile(
            mode="wb", dir=raw_dir, prefix=f".{source.name}.", suffix=".download", delete=False
        ) as temporary:
            temporary_path = Path(temporary.name)
            while chunk := response.read(1024 * 1024):
                temporary.write(chunk)
                digest.update(chunk)
                byte_count += len(chunk)
            temporary.flush()
            os.fsync(temporary.fileno())
        os.replace(temporary_path, destination)
    except (OSError, urllib.error.URLError) as error:
        try:
            temporary_path.unlink(missing_ok=True)
        except (UnboundLocalError, OSError):
            pass
        raise DatasetBuildError(f"Download failed for {source.name} ({source.url}): {error}") from error
    return destination, digest.hexdigest(), byte_count, retrieved_at


def write_csv(path: Path, rows: list[dict[str, object]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=CSV_FIELDS, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def class_counts(rows: list[dict[str, object]]) -> dict[str, int]:
```

El resto descarga las fuentes seleccionadas, registra licencia/hash/timestamp, normaliza y valida dominios, elimina duplicados/conflictos, crea splits estratificados con semilla fija y escribe CSV/manifiesto. Majestic es el baseline seguro obligatorio. No uses `--allow-seed-only` para afirmar evaluación holdout.
