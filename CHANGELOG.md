# Changelog

Formato basado en [Keep a Changelog](https://keepachangelog.com/es-ES/1.1.0/) y [SemVer](https://semver.org/lang/es/).

## [2.0.0] — 2026-11-22

### Añadido
- **Puntuación 0–100 explicable**: cada regla aporta una señal con peso, técnica MITRE ATT&CK y evidencia. Veredicto: 🔴 VT ≥ 1 o score ≥ 70 · 🟡 30–69 o sin firma · 🟢 resto.
- **Heurísticas**:
  - LOLBins: PowerShell codificado, oculto o descargando; mshta, regsvr32, rundll32, certutil, bitsadmin y WSH;
  - rutas escribibles por el usuario;
  - suplantación de binarios de sistema, typosquatting y dobles extensiones;
  - categorías de persistencia con peso ATT&CK;
  - puerta trasera de accesibilidad vía IFEO;
  - LOLBins firmados en autoarranque.
- `--processes`: procesos sospechosos con psutil (Office → consola, padres inesperados, binarios borrados).
- `--network` correlaciona por **PID y ruta exacta** (tcpvcon queda como respaldo).
- `--static`: análisis PE con pefile y **YARA** opcional (7 reglas incluidas y reglas propias en `<config-dir>/yara/`).
- `--events [DÍAS]`: servicios 7045, tareas 4698 y detecciones de Defender 1116/1117.
- **Informes**:
  - «Prioriza esto primero» y resumen de técnicas ATT&CK;
  - tabla de señales por elemento;
  - nuevo formato **HTML** (`--format html|all`);
  - JSON `schema_version: 2`.
- **GUI renovada**:
  - logo nuevo;
  - panel con gráficos (distribución, puntuación, origen, ATT&CK) y prioridades;
  - historial con recarga y marca de **novedades**;
  - exportación CSV, HTML, MD y JSON;
  - menús contextuales, perfiles Rápido y Completo, atajos de teclado y preferencias persistentes.
- Lista blanca por **editor firmado** (`publishers`).

### Cambiado
- Las entradas firmadas por Microsoft ya no se descartan si se usan de forma sospechosa (LOLBin, WMI, IFEO).
- Dependencias nuevas: `psutil`, `pefile`, `pillow`. Extra opcional `[yara]`.

## [1.2.0] — 2026-11-22

### Añadido
- **Interfaz gráfica** (`win11-triage-gui` / `--gui`):
  - tarjetas de resumen;
  - tabla filtrable, ordenable y con búsqueda;
  - detalle de cada elemento con acciones (VirusTotal, copiar hash, Explorador, lista blanca);
  - pestañas de conexiones y registro;
  - gestión de la API key, ayuda para instalar Sysinternals y reinicio como administrador;
  - análisis en segundo plano con barra de progreso y cancelación.
- Motor de triaje (`engine.py`) compartido por CLI y GUI.
- Ejecutables `.exe` generados con PyInstaller en la CI y publicados en las releases.
- Tests del motor y prueba de humo de la GUI.

### Corregido
- La plantilla de `whitelist.json` se modificaba en memoria al añadir entradas.

## [1.1.0] — 2026-11-22

### Añadido
- Módulo `--network`: correlaciona hallazgos con conexiones activas de `tcpvcon`.
- Informe JSON (`--format json|both`) para integrarlo con SIEM u otras herramientas.
- `--vt-limit N` para acotar consultas nuevas y estimación del tiempo de espera.
- `--config-dir` / `WIN11_TRIAGE_HOME`, `--no-color` y `-v/--verbose`.
- Aviso si no se ejecuta como administrador.
- Cálculo local del SHA-256 cuando Sysinternals no lo devuelve.
- Paquete instalable (`pip install .`) con comando `win11-triage`.
- CI en GitHub Actions (Windows y Linux, Python 3.10 y 3.13), ruff y 40+ tests con pytest.

### Cambiado
- Expansión de variables `%VAR%` independiente de la plataforma y sin distinguir mayúsculas.
- Caché de VirusTotal con escritura atómica; sesión HTTP reutilizada.
- Informe Markdown con avisos, detalle plegable y escape de valores no confiables.
- Los datos de ejemplo viajan dentro del paquete; el dry-run no toca la caché ni la lista blanca reales.

### Corregido
- Conexiones duplicadas cuando dos hallazgos compartían ejecutable.
- `whitelist.json` corrupto ahora da un error claro en lugar de una traza.

## [1.0.0] — 2026-11-22

- Versión inicial: `--autoruns`, `--scan-user`, `--vt` con caché, rate-limit y lista blanca, tablas Rich e informe Markdown.
