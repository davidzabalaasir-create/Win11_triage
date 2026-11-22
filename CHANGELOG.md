# Changelog

Formato basado en [Keep a Changelog](https://keepachangelog.com/es-ES/1.1.0/) y [SemVer](https://semver.org/lang/es/).

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
