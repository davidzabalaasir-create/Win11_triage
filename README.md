# win11-triage

[![CI](https://github.com/davidzabalaasir-create/Win11_triage/actions/workflows/ci.yml/badge.svg)](https://github.com/davidzabalaasir-create/Win11_triage/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![Plataforma](https://img.shields.io/badge/plataforma-Windows%2011-0078D6)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-red)
[![Licencia: MIT](https://img.shields.io/badge/licencia-MIT-green)](LICENSE)

Herramienta de **triaje defensivo y respuesta a incidentes** para Windows 11. Examina el equipo en vivo:

- persistencia;
- procesos y conexiones de red;
- eventos de Windows;
- contenido de los ejecutables (análisis PE y YARA);
- reputación en VirusTotal.

Con todo ello, **puntúa cada elemento de 0 a 100 explicando por qué** y lo relaciona con técnicas de **MITRE ATT&CK**.

Se usa con **interfaz gráfica** o desde la **línea de comandos**. Es **solo lectura**: nunca borra, termina procesos ni sube ficheros.

![Panel de win11-triage](docs/gui.png)

## Qué analiza

| Módulo | Fuente | Qué busca |
|---|---|---|
| `--autoruns` | `autorunsc` | Persistencia no firmada por Microsoft **y** abusos de binarios de Microsoft (LOLBins con argumentos peligrosos, WMI, IFEO) |
| `--scan-user` | `sigcheck` | Ejecutables y DLL sin firma válida en `%LOCALAPPDATA%\Temp` y `%APPDATA%` |
| `--processes` | `psutil` | Procesos en rutas de usuario, nombres de sistema suplantados, Office lanzando consolas, padres inesperados, binarios borrados |
| `--events [DÍAS]` | `wevtutil` | Servicios instalados (7045), tareas creadas (4698) y detecciones de Defender (1116/1117) |
| `--network` | `psutil` (`tcpvcon` de respaldo) | Conexiones externas, correlacionadas **por PID y ruta exacta** |
| `--static` | `pefile` + YARA | Empaquetadores, entropía alta, imports de inyección, timestamps imposibles y reglas YARA |
| `--vt` | API v3 de VirusTotal | Reputación de cada SHA-256, con caché y límite de tasa |

### Puntuación y veredicto

Cada regla que se dispara aporta una **señal** con su peso, su técnica ATT&CK y la evidencia concreta. Ejemplo: «PowerShell con comando codificado en Base64, +45, T1059.001, `powershell -nop -w hidden -enc SQBF…`». La puntuación es la suma de los pesos, de 0 a 100.

| | Estado | Criterio |
|---|---|---|
| 🔴 | **DETECTADO** | VirusTotal ≥ 1 motor **o** puntuación ≥ 70 |
| 🟡 | **SOSPECHOSO / SIN FIRMA** | Puntuación 30–69, o sin firma válida |
| 🟢 | **LIMPIO** | Puntuación < 30 y firma válida o VirusTotal limpio |

Una sola señal débil (sin firma, carpeta de usuario) nunca basta para el rojo. Una firma válida resta puntos, salvo que el binario firmado se esté usando de forma maliciosa (por ejemplo, `mshta.exe` lanzando una URL desde la clave Run).

> [!IMPORTANT]
> Es una herramienta de **triaje**, no un antivirus. Sirve para **priorizar** qué revisar primero.

## Instalación

### Opción A: instalador (sin Python)

En [Releases](https://github.com/davidzabalaasir-create/Win11_triage/releases) hay tres formatos, todos firmados digitalmente por **David**:

| Archivo | Para qué |
|---|---|
| `win11-triage-setup-<versión>.exe` | Instalador con asistente. Instala solo para tu usuario, sin pedir administrador, y puede instalar las herramientas de Sysinternals |
| `win11-triage-<versión>.msi` | Instalador MSI para todo el equipo. Sirve para despliegues con GPO, Intune o SCCM: `msiexec /i win11-triage-<versión>.msi /qn` |
| `win11-triage-portable-<versión>.zip` | Sin instalar: descomprimir y ejecutar |

La configuración y los informes se guardan en `%LOCALAPPDATA%\win11-triage`; en la versión portable, en su propia carpeta.

> [!NOTE]
> La firma es de un certificado propio (autofirmado). Windows puede seguir mostrando SmartScreen o bloquearla con el **Control de aplicaciones inteligente** hasta que esté disponible la firma de SignPath Foundation (ver [Firma de código](#firma-de-código)).

### Opción B: desde el código

```powershell
git clone https://github.com/davidzabalaasir-create/Win11_triage.git
cd Win11_triage
python -m pip install ".[yara]"     # sin YARA: python -m pip install .
```

### Herramientas de Sysinternals (en ambos casos)

```powershell
winget install --id Microsoft.Sysinternals.Autoruns -e
winget install --id Microsoft.Sysinternals.Sigcheck -e
winget install --id Microsoft.Sysinternals.TCPView -e   # opcional: respaldo de --network
```

### Clave de VirusTotal (opcional)

Desde la interfaz, en **«Clave de VirusTotal…»**. A mano: `copy .env.example .env` y escribe `VT_API_KEY=tu_clave`. El `.env` está en `.gitignore`: la clave nunca se sube a GitHub.

## Interfaz gráfica

```powershell
win11-triage-gui          # o: win11-triage --gui · o doble clic en win11-triage-gui.pyw
```

![Hallazgos con el porqué de cada uno](docs/gui_hallazgos.png)

- **Panel**:
  - distribución de veredictos y puntuación máxima;
  - elementos sospechosos por origen;
  - técnicas ATT&CK observadas;
  - **«Prioriza esto primero»** (doble clic para saltar al elemento).
- **Hallazgos**:
  - filtros, búsqueda (por nombre, ruta, hash o técnica, como `T1059.001`) y orden por columnas;
  - interruptor **«Solo nuevos»**;
  - panel **«Por qué»** con cada señal, su peso, su técnica y la evidencia;
  - acciones: VirusTotal, ATT&CK, copiar hash, ruta o línea de comandos, Explorador e ignorar ruta o hash (también con clic derecho).
- **Conexiones**: conexiones externas de los procesos señalados. Permite buscar la IP en VirusTotal o copiarla.
- **Historial**: análisis anteriores. Puedes recargar cualquiera y la tarjeta **«Nuevos»** marca lo que ha aparecido desde el análisis anterior.
- **Exportar**: CSV de la vista actual (se abre en Excel), HTML, Markdown o JSON.
- **Perfiles**: **Rápido** o **Completo**. La interfaz recuerda tus preferencias.
- **Atajos**: `Ctrl+R` analizar · `Esc` cancelar · `Ctrl+F` buscar · `Ctrl+E` exportar CSV · `Ctrl+O` abrir informe · `Ctrl+1…5` pestañas · `F5` volver a comprobar las herramientas.

El análisis corre en segundo plano y se puede **cancelar** en cualquier momento.

## Línea de comandos

![Demo de la CLI](docs/demo.svg)

```powershell
win11-triage                          # solo comprueba el entorno
win11-triage --all                    # todos los módulos
win11-triage --autoruns --processes --network   # triaje rápido sin red externa
win11-triage --events 30              # servicios, tareas y Defender de los últimos 30 días
win11-triage --all --format all --vt-limit 20
win11-triage --dry-run                # demostración con datos de ejemplo
```

| Opción | Descripción |
|---|---|
| `--all` | Activa todos los módulos |
| `--vt-limit N` | Máximo de consultas **nuevas** a VirusTotal (las de caché no cuentan) |
| `--format md\|html\|json\|both\|all` | Formato del informe (`both` = md + json, `all` = los tres) |
| `--output-dir DIR` / `--config-dir DIR` | Carpeta de informes / de `.env`, `whitelist.json`, `vt_cache.json` y `yara/` |
| `--no-report` · `--no-color` · `-v` · `--gui` | Sin informe · sin colores · detallado · abrir la interfaz |

**Códigos de salida:**
- `0`: nada detectado.
- `1`: entorno incompleto.
- `2`: hay elementos detectados.
- `130`: interrumpido.

Sirven para tareas programadas o pipelines.

## Informes

En `reportes/triage_<equipo>_<fecha>.{html,md,json}`. Incluyen:

- resumen;
- **«Prioriza esto primero»** (los 5 elementos de mayor puntuación);
- tabla de **técnicas ATT&CK** con enlaces a attack.mitre.org;
- una tabla por módulo con su puntuación y el «por qué»;
- detalle de cada elemento con sus señales (peso, técnica y evidencia), sus conexiones y VirusTotal.

El **HTML** es un único archivo que se puede imprimir a PDF. El **JSON** (`schema_version: 2`) está pensado para SIEM y automatización:

```json
{ "schema_version": 2, "max_score": 100,
  "attack": [{"id": "T1059.001", "name": "PowerShell", "count": 3}],
  "findings": [{ "source": "autoruns", "name": "UpdChk", "status": "DETECTADO", "score": 100,
                 "signals": [{"id": "CMD_PS_ENCODED", "weight": 45, "attack": "T1059.001", "evidence": "powershell … -enc …"}],
                 "attack": ["T1059.001", "T1071", "T1218", "T1546.003", "T1564.003"] }] }
```

## Configuración

| Archivo | Para qué |
|---|---|
| `.env` | `VT_API_KEY` y, opcionalmente, `SYSINTERNALS_DIR` |
| `whitelist.json` | `paths` (admite `*`, `%VAR%` y carpetas terminadas en `\`), `hashes` y `publishers` (solo se aplica a elementos con firma válida) |
| `yara/*.yar` | Tus reglas YARA. Se suman a las incluidas; usa `meta: description`, `mitre` y `weight` |
| `vt_cache.json` | Caché de VirusTotal. Los «no encontrado» caducan a los 7 días |

## Falsos positivos conocidos

| Señal | Puede saltar con | Qué hacer |
|---|---|---|
| Carpeta de usuario | Teams, Zoom, Discord, Spotify (viven en AppData) | Si están firmados quedan en 🟢. Si no, `publishers` o `paths` en la lista blanca |
| Sin firma | Scripts internos, herramientas portables | Por sí sola solo da 🟡 |
| Empaquetador / entropía | Instaladores (NSIS, Inno), protectores anti-trampas | Peso bajo: necesita otras señales para llegar al rojo |
| Imports de inyección | Depuradores, antivirus, overlays (Discord, NVIDIA) | Lista blanca por editor firmado |
| PowerShell oculto | Intune/SCCM, scripts de inicio corporativos | Lista blanca por hash o ruta |
| Evento 4698 | Requiere la auditoría «Otros eventos de objetos» | Se informa como «no disponible», nunca como «sin tareas» |

**Limitaciones:**
- Sin acceso a kernel ni a memoria, un rootkit puede esconderse.
- Sin privilegios de administrador se ve menos.
- La herramienta no ejecuta muestras.

## Desarrollo

```bash
pip install -e ".[dev,yara]"
pytest                          # 100+ tests; no necesitan Windows ni red
ruff check . && ruff format --check .
python scripts/make_demo.py     # regenera docs/demo.svg
python scripts/make_icon.py     # regenera el logo
```

Ejecutables (en Windows): `powershell -ExecutionPolicy Bypass -File scripts\build_exe.ps1`. La CI los compila en cada cambio y los adjunta a la release al publicar un tag `v*`.

```
win11_triage/
├── engine.py              # orquesta: colectores → reglas → red → contenido → VT → veredicto
├── collectors.py          # autorunsc / sigcheck / tcpvcon
├── collectors_live.py     # procesos y conexiones (psutil)
├── collectors_events.py   # eventos 7045 / 4698 / Defender (wevtutil)
├── enrich/                # análisis PE (pefile) y YARA
├── rules/                 # heurísticas, ATT&CK y reglas YARA incluidas
├── virustotal.py          # cliente VT v3 con caché y límite de tasa
├── report.py              # Rich, Markdown, HTML y JSON v2
├── gui/                   # interfaz (CustomTkinter): app, gráficos, historial
└── samples/               # datos de ejemplo para --dry-run y tests
```

## Firma de código

Los binarios (`.exe`, `.dll`, `.pyd`, el instalador y el `.msi`) se firman con un certificado **«David»** con sello de tiempo. En sus propiedades (clic derecho → Propiedades → Firmas digitales) aparece «David».

- **Certificado propio (gratis).** El autor lo crea una vez en su PC con `scripts\new_signing_cert.ps1 -Trust` y lo guarda como secretos de GitHub (`WIN11_TRIAGE_PFX` y `WIN11_TRIAGE_PFX_PASSWORD`). Desde entonces la CI firma con él cada compilación. Si el secreto no existe, la CI firma con un certificado «David» temporal.
  - Al ser autofirmado, **solo es de confianza en los equipos donde se importe** `win11-triage-david.cer`.
  - **No evita** SmartScreen ni el Control de aplicaciones inteligente en otros equipos.
- **SignPath Foundation (solicitado, gratis).** Certificado de confianza pública para proyectos de código abierto: [SignPath.io](https://about.signpath.io/), certificado de [SignPath Foundation](https://signpath.org/). Ver la [política de firma](CODE_SIGNING_POLICY.md).
- **Certum (opcional, de pago).** `scripts\sign_release.ps1` firma la versión portable con un certificado de Certum y reconstruye el instalador.

### Publicar una versión

Con un tag `v*`, o desde **Actions → CI → Run workflow** indicando `release_tag` (p. ej. `v2.0.0`): la CI compila, prueba el instalador y publica la release con el instalador y la versión portable.

## Licencia

© 2026 David. Publicado bajo licencia [MIT](LICENSE).
