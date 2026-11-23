# Publicar win11-triage en Microsoft Store

La Store firma el paquete con un certificado de Microsoft. Es la vía **gratuita** para que Windows
(SmartScreen y el Control inteligente de aplicaciones) confíe en la aplicación.

## 1. Cuenta de desarrollador (gratis para particulares)

1. Entra en <https://developer.microsoft.com/store/register> y pulsa **Get started for free**.
2. Elige **Individual developer (free)** e inicia sesión con tu cuenta Microsoft personal.
3. Verifica tu identidad (documento y selfie) cuando lo pida.

> Si en algún paso te pide pagar, has entrado por el flujo antiguo: vuelve a empezar desde el enlace anterior.

## 2. Reservar el nombre y copiar la identidad

En **Partner Center → Apps y juegos → Nueva aplicación**, reserva el nombre (por ejemplo `win11-triage`).
Después, en **Administración de productos → Identidad del producto**, copia:

| Campo de Partner Center | Parámetro de `build_msix.ps1` |
|---|---|
| `Package/Identity/Name` | `-IdentityName` |
| `Package/Identity/Publisher` (`CN=…`) | `-Publisher` |
| `Package/Properties/PublisherDisplayName` | `-PublisherDisplay` |

## 3. Generar el paquete

En un PC con Windows, Python y el Windows SDK:

```powershell
.\scripts\build_exe.ps1
.\scripts\build_msix.ps1 -IdentityName "<Name>" -Publisher "<CN=...>" -PublisherDisplay "<nombre>"
```

Resultado: `dist\win11-triage-<versión>.msix`, **sin firmar** (la Store lo firma).

## 4. Enviar a certificación

En el envío de la aplicación:

- **Paquetes:** sube el `.msix`.
- **Capacidades restringidas:** `runFullTrust` es necesaria porque es una aplicación de escritorio que lee
  procesos, eventos y el registro. Justificación sugerida: *«Herramienta de seguridad de solo lectura que
  analiza persistencia, procesos y eventos del sistema para detectar malware.»*
- **Clasificación por edades:** cuestionario IARC (herramienta, sin contenido sensible).
- **Política de privacidad:** enlaza la página del proyecto; la app no envía datos salvo a los servicios que
  el usuario configura (VirusTotal, AbuseIPDB, MalwareBazaar, webhooks).

La certificación suele tardar de unas horas a unos días.

## Notas

- En CI se genera un `.msix` de prueba firmado con el certificado «David» (identidad `David.win11-triage`),
  solo para comprobar que el paquete es válido. **No es el que se sube a la Store.**
- Dentro del paquete, la configuración se guarda en `%LOCALAPPDATA%\Packages\<paquete>\LocalCache`.
- El análisis programado usa el alias `win11-triage.exe`, porque los ejecutables de `WindowsApps` no se
  pueden lanzar por su ruta.
