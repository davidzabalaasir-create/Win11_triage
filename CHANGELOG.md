# Changelog

Formato basado en [Keep a Changelog](https://keepachangelog.com/es-ES/1.1.0/) y [SemVer](https://semver.org/lang/es/).

## [3.1.0] — 2026-11-23

### Rendimiento
- **Colectores en paralelo**: autorunsc, sigcheck, eventos, Sigma, navegadores y procesos se ejecutan a la vez (hasta 4). El análisis dura lo que el módulo más lento, no la suma de todos.
- **wevtutil en paralelo**: los registros de eventos (Sistema, Seguridad, Defender, Sysmon, PowerShell) se consultan a la vez.
- **Caché persistente de hashes** (`hash_cache.json`): si un fichero no ha cambiado (ruta, tamaño y fecha), no se vuelve a leer. Los nuevos se calculan en paralelo (≈3,5× más rápido; con caché, casi instantáneo).
- **Motor Sigma compilado**: cada regla se compila una vez y cada evento se prepara una sola vez; las reglas se indexan por tipo de evento (≈4× más rápido: 20 000 eventos en 0,19 s frente a 0,76 s).
- **Análisis de contenido (PE/YARA) en paralelo**.
- **Reputación (AbuseIPDB/MalwareBazaar)**: varias consultas a la vez; la primera de cada servicio va sola para no insistir si la clave es mala.
- **Historial en caché**: refrescar la lista con 150 informes pasa de ≈140 ms a ≈1 ms.

## [3.0.0] — 2026-11-23

### Añadido
- **Árbol de procesos**: página «Procesos» con las ramas sospechosas desplegadas y cadenas padre → hijo en los informes.
- **Reglas Sigma** (`--sigma`): motor propio compatible con el formato estándar sobre Sysmon (1, 3, 11, 12–14, 22), Security 4688, PowerShell 4104 y System 7045. 11 reglas incluidas y reglas propias en `sigma/*.yml`.
- **Extensiones de navegador** (`--browsers`): Chrome, Edge, Brave y Firefox; fuera de la tienda, sin empaquetar, sin firma y permisos peligrosos.
- **Reputación** (`--intel`): AbuseIPDB para IPs remotas y MalwareBazaar para hashes, con caché.
- **Alertas**: notificación de Windows (`--notify`), webhooks para Slack, Teams, Splunk HEC o JSON genérico (`--webhook`), JSON Lines para Wazuh/Filebeat (`--jsonl`) y `--alert-new` para avisar solo de lo nuevo o lo que empeora. También en Ajustes.
- **Análisis programado** (`--schedule daily|weekly`) con el Programador de tareas; en la GUI, en Ajustes.
- **«¿Qué hago con esto?»**: pasos recomendados para cada hallazgo en la GUI, los informes y la CLI (`--explain`).
- **Resumen ejecutivo en PDF** de una página (`--format pdf` y Exportar).
- **Triaje remoto por WinRM** (`--remote`), sin instalar nada en el equipo analizado; también en «Nuevo análisis».
- **Inglés**: interfaz, informes, PDF y recomendaciones (`--lang en` o Ajustes → Idioma).
- **Paquete MSIX** para Microsoft Store (`scripts/build_msix.ps1`) y guía de publicación en `docs/MICROSOFT_STORE.md`.
- **Página web** del proyecto en GitHub Pages (`site/`).
- **Asistente de IA**: página «Asistente» y `--ask "pregunta"` (también sobre informes guardados con `--report`).
  - Usa Groq (gratuito) u Ollama (local).
  - Consulta los datos del análisis con herramientas de solo lectura.
  - Anonimiza el usuario y el nombre del equipo.

### Corregido
- Los avisos flotantes ocupaban 200 px de alto.

## [2.1.0] — 2026-11-23

### Añadido
- **Revisión del analista**:
  - estados Pendiente, En revisión, Falso positivo y Confirmado, con notas;
  - atajos `P` `R` `F` `C`, filtro y progreso «Revisados X/Y»;
  - persistente entre sesiones (`review.json`) e incluida en los informes, el JSON y el CSV.
- **Comparar análisis** desde el Historial: nuevos, resueltos, empeoran y mejoran.
- **Paquete de evidencias** `.zip`: informes, CSV, revisiones, IoC SHA-256, LEEME y SHA256SUMS. Desde la GUI o con `--evidence`.
- **Cronología** en los informes HTML y Markdown.
- CLI: `--min-score`, `--fail-on-score` y `--check-update`.
- **Buscar actualizaciones** en Ajustes (consulta manual a GitHub Releases).

### Cambiado
- **Rediseño completo de la interfaz**:
  - sistema de diseño con tokens de color (claro y oscuro), escala tipográfica (Segoe UI Variable, Cascadia Mono para rutas y hashes), rejilla de 4 px e iconos Segoe Fluent con alternativa Unicode;
  - barra lateral de navegación (Inicio, Hallazgos, Red, Historial, Ajustes) en lugar de la barra lateral saturada;
  - diálogo **Nuevo análisis** con perfiles y módulos agrupados;
  - **panel de detalle lateral** con el porqué de cada señal;
  - tabla con punto de estado (sin colorear filas enteras), chips de filtro con contador y rutas abreviadas por el centro;
  - KPIs con tendencia, estado vacío con acceso a la demostración, barra de estado con el entorno y registro plegable;
  - **tema claro, oscuro o del sistema**.
- **Microinteracciones**: «Deshacer» al ignorar elementos, confirmación en el botón al copiar, avisos con acción y el botón Analizar que se convierte en Cancelar.

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
- **Aplicación de Windows**:
  - instalador `.exe` (Inno Setup), instalador **`.msi`** (WiX) y versión portable `.zip`;
  - **firma digital «David»** en todos los binarios;
  - copyright © 2026 David en el ejecutable, los instaladores, la interfaz y los informes;
  - registro de errores, autodiagnóstico (`--selftest`) e instalación de Sysinternals con winget desde la app.

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
