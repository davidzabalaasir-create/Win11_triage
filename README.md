# win11-triage

CLI defensiva para Windows 11: busca persistencia no-Microsoft y binarios sin firma con Sysinternals y consulta sus hashes en VirusTotal.

## Instalación

```powershell
python -m pip install -r requirements.txt
winget install --id Microsoft.Sysinternals.Autoruns -e
winget install --id Microsoft.Sysinternals.Sigcheck -e
winget install --id Microsoft.Sysinternals.TCPView -e
copy .env.example .env   # y pon tu VT_API_KEY
```

Ejecuta en una consola **como administrador** para que autoruns vea todas las ubicaciones.

## Uso

| Comando | Qué hace |
|---|---|
| `python win11-triage.py` | Solo comprueba el entorno (PATH, WinGet, `SYSINTERNALS_DIR`) |
| `--autoruns` | `autorunsc -a * -c -h -s` → entradas no firmadas por Microsoft o `(Not verified)` |
| `--scan-user` | `sigcheck -u -e -c -h -s` sobre `%LOCALAPPDATA%\Temp` y `%APPDATA%` |
| `--vt` | Consulta los SHA-256 en VirusTotal (activa los dos anteriores si no se indican) |
| `--all` | Todo lo anterior |
| `--dry-run` | Usa los datos de `samples/`; no ejecuta herramientas ni usa la red |
| `--output-dir DIR`, `--no-report` | Control del informe Markdown (por defecto `reportes/`) |

Código de salida: `0` sin detecciones, `1` falta de entorno, `2` hay detecciones en VT.

## Colores

- 🔴 **DETECTADO**: ≥1 motor de VT lo marca como malicioso.
- 🟡 **DESCONOCIDO**: sin firma / no verificado y sin veredicto VT limpio (no encontrado, sin consultar o con sospechosos).
- 🟢 **LIMPIO**: 0 detecciones en VT, o firma válida de un tercero si no se consultó VT.

## VirusTotal

- URL: `https://www.virustotal.com/api/v3/files/{sha256}` con cabecera `x-apikey`.
- `vt_cache.json`: cada hash se consulta una sola vez (los "no encontrado" se reconsultan tras 7 días; los errores no se cachean).
- 15 s entre peticiones nuevas (límite gratuito 4/min). Un 429 espera 60 s y reintenta una vez.

## Lista blanca (`whitelist.json`)

```json
{
  "paths": ["C:\\Program Files\\MiApp\\*", "%APPDATA%\\Zoom\\bin\\Zoom.exe"],
  "hashes": ["<sha256>"]
}
```

Sin distinción de mayúsculas; admite `*` y variables `%VAR%`.

## Pruebas

```bash
python -m unittest discover tests
python win11-triage.py --dry-run
```
