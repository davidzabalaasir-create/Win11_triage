"""Traducciones al inglés (clave: texto original en español)."""

from __future__ import annotations

from .i18n import compile_patterns

EN: dict[str, str] = {
    # ---------------------------------------------------------------- estados y orígenes
    "Detectado": "Detected",
    "Sospechoso": "Suspicious",
    "Limpio": "Clean",
    "DETECTADO": "DETECTED",
    "DESCONOCIDO": "UNKNOWN",
    "LIMPIO": "CLEAN",
    "Todos": "All",
    "Detectados": "Detected",
    "Sospechosos": "Suspicious",
    "Limpios": "Clean",
    "Persistencia": "Persistence",
    "Carpeta usuario": "User folder",
    "Proceso": "Process",
    "Evento": "Event",
    "Sigma": "Sigma",
    "Navegador": "Browser",
    "Pendiente": "Pending",
    "En revisión": "In review",
    "Falso positivo": "False positive",
    "Confirmado": "Confirmed",
    "Cualquier revisión": "Any review",
    # ---------------------------------------------------------------- navegación y páginas
    "Inicio": "Home",
    "Hallazgos": "Findings",
    "Red": "Network",
    "Procesos": "Processes",
    "Historial": "History",
    "Ajustes": "Settings",
    "Resumen del último análisis": "Summary of the latest scan",
    "Todo lo encontrado, con el porqué de cada elemento": "Everything found, with the reason for each item",
    "Conexiones externas de los procesos señalados": "External connections of flagged processes",
    "Árbol padre → hijo; las ramas con procesos señalados aparecen desplegadas": (
        "Parent → child tree; branches with flagged processes are expanded"
    ),
    "Análisis anteriores guardados en la carpeta de informes": "Previous scans saved in the reports folder",
    "Claves, listas blancas, herramientas y apariencia": "Keys, allowlists, tools and appearance",
    "Analizar": "Scan",
    "  Analizar": "  Scan",
    "Exportar": "Export",
    "Nuevo análisis (Ctrl+N) · Repetir el último: Ctrl+R": "New scan (Ctrl+N) · Repeat the last one: Ctrl+R",
    "Abrir informe (Ctrl+O)": "Open report (Ctrl+O)",
    "Buscar nombre, ruta, hash o técnica   (Ctrl+F)": "Search name, path, hash or technique   (Ctrl+F)",
    "Listo.": "Ready.",
    "  Registro": "  Log",
    "Registro": "Log",
    "Acerca de": "About",
    "Cerrar (Ctrl+L)": "Close (Ctrl+L)",
    "Copiar registro": "Copy log",
    # ---------------------------------------------------------------- inicio
    "Prioriza esto primero": "Prioritise this first",
    "Puntuación máxima": "Highest score",
    "Técnicas MITRE ATT&CK": "MITRE ATT&CK techniques",
    "Distribución": "Distribution",
    "Sin técnicas observadas": "No techniques observed",
    "VirusTotal o score ≥ 70": "VirusTotal or score ≥ 70",
    "Revisar manualmente": "Review manually",
    "Firma válida o VT limpio": "Valid signature or clean VT",
    "Nuevos": "New",
    "Desde el análisis anterior": "Since the previous scan",
    "Primer análisis de este tipo": "First scan of this kind",
    "Aún no hay ningún análisis": "No scans yet",
    "Revisa la persistencia, los procesos y la red de este equipo en unos minutos.": (
        "Check this computer's persistence, processes and network in a few minutes."
    ),
    "Nuevo análisis": "New scan",
    "Probar con datos de ejemplo": "Try with sample data",
    "Aún no hay resultados.\nPulsa «Analizar» o prueba con datos de ejemplo.": (
        "No results yet.\nPress “Scan” or try with sample data."
    ),
    "riesgo alto": "high risk",
    "riesgo medio": "medium risk",
    "riesgo bajo": "low risk",
    "sin análisis": "no scan",
    "elementos": "items",
    "Revisados": "Reviewed",
    "teclas": "keys",
    "Ver": "View",
    "Asistente de IA": "AI assistant",
    "Asistente": "Assistant",
    "Pensando…": "Thinking…",
    "Consultando": "Looking up",
    "Pregunta en lenguaje natural sobre el análisis": "Ask questions about the scan in plain language",
    "Nueva conversación": "New conversation",
    "Conversación nueva.": "New conversation.",
    "Configurar…": "Configure…",
    "Enviar": "Send",
    "Escribe tu pregunta y pulsa Intro": "Type your question and press Enter",
    "Se envía un resumen del análisis sin tu usuario ni el nombre del equipo. El asistente solo consulta datos: "
    "no cambia nada.": (
        "A summary of the scan is sent without your user name or computer name. The assistant only reads data: "
        "it changes nothing."
    ),
    "Hola. Haz un análisis (o carga uno del historial) y pregúntame lo que quieras sobre él.": (
        "Hi. Run a scan (or load one from the history) and ask me anything about it."
    ),
    "Sin clave de Groq": "No Groq key",
    "Primero haz o carga un análisis.": "Run or load a scan first.",
    "Groq es gratuito (console.groq.com). Ollama funciona sin Internet en tu PC.": (
        "Groq is free (console.groq.com). Ollama runs offline on your PC."
    ),
    "¿Qué debería revisar primero?": "What should I check first?",
    "¿Mi equipo está infectado?": "Is my computer infected?",
    "Explícame el hallazgo más grave en palabras sencillas": "Explain the most serious finding in simple words",
    "¿Qué técnicas de ataque se ven y qué significan?": "Which attack techniques show up and what do they mean?",
    "no encontrado": "not found",
    "= igual": "= same",
    " · cargado del historial": " · loaded from history",
    "cargado del historial": "loaded from history",
    "Proceso en ejecución": "Running process",
    # ---------------------------------------------------------------- hallazgos y detalle
    "Score": "Score",
    "Origen": "Source",
    "Nombre": "Name",
    "Ruta": "Path",
    "Por qué": "Why",
    "Revisión": "Review",
    "Estado": "Status",
    "Solo nuevos": "New only",
    "Selecciona un elemento para ver por qué es sospechoso.": "Select an item to see why it is suspicious.",
    "Ningún elemento coincide con el filtro o la búsqueda.": "No item matches the filter or search.",
    "Nada sospechoso con los módulos elegidos.": "Nothing suspicious with the selected modules.",
    "Revisión del analista": "Analyst review",
    "Guardar nota": "Save note",
    "  Guardada": "  Saved",
    "Archivo": "File",
    "Editor · firma": "Publisher · signature",
    "Resultado": "Result",
    "Ejecución": "Execution",
    "Línea de comandos": "Command line",
    "Ubicación": "Location",
    "¿Qué hago con esto?": "What should I do?",
    "no disponible": "not available",
    "Ver en VirusTotal": "View on VirusTotal",
    "Copiar SHA-256": "Copy SHA-256",
    "Más acciones": "More actions",
    "Ver técnica ATT&CK": "View ATT&CK technique",
    "Copiar ruta": "Copy path",
    "Copiar línea de comandos": "Copy command line",
    "Mostrar en el Explorador": "Show in Explorer",
    "Ignorar esta ruta": "Ignore this path",
    "Ignorar este hash": "Ignore this hash",
    "Deshacer": "Undo",
    "Abrir": "Open",
    "Ruta copiada.": "Path copied.",
    "Comando copiado.": "Command copied.",
    # ---------------------------------------------------------------- red y procesos
    "Proto": "Proto",
    "Local": "Local",
    "Remoto": "Remote",
    "Copiar IP": "Copy IP",
    "Buscar IP en VirusTotal": "Look up IP on VirusTotal",
    "Copiar IP remota": "Copy remote IP",
    "Selecciona una conexión.": "Select a connection.",
    "Solo ramas con procesos señalados": "Only branches with flagged processes",
    "Activa «Procesos en ejecución» en el análisis para ver el árbol.": (
        "Enable “Running processes” in the scan to see the tree."
    ),
    "Este proceso no tiene hallazgos: solo forma parte de la cadena.": (
        "This process has no findings: it is only part of the chain."
    ),
    # ---------------------------------------------------------------- historial
    "Cargar análisis": "Load scan",
    "Comparar con el actual": "Compare with current",
    "Abrir informe": "Open report",
    "Actualizar lista": "Refresh list",
    "Fecha": "Date",
    "Equipo": "Computer",
    "Modo": "Mode",
    "Total": "Total",
    "Score máx.": "Max score",
    "demostración": "demo",
    "real": "real",
    "Selecciona un análisis del historial.": "Select a scan from the history.",
    # ---------------------------------------------------------------- ajustes
    "VirusTotal": "VirusTotal",
    "La clave se guarda solo en el archivo .env de tu carpeta de configuración.": (
        "The key is stored only in the .env file of your configuration folder."
    ),
    "Se guarda solo en el archivo .env de tu carpeta de configuración.": (
        "Stored only in the .env file of your configuration folder."
    ),
    "Configurar clave…": "Set key…",
    "Clave configurada": "Key set",
    "Sin clave": "No key",
    "Sin clave VT": "No VT key",
    "Apariencia": "Appearance",
    "Sigue el tema de Windows o fuerza claro u oscuro.": "Follow the Windows theme or force light or dark.",
    "Sistema": "System",
    "Claro": "Light",
    "Oscuro": "Dark",
    "Idioma": "Language",
    "Herramientas y componentes": "Tools and components",
    "Sysinternals se instala con winget; YARA es opcional.": "Sysinternals is installed with winget; YARA is optional.",
    "Datos y reglas": "Data and rules",
    "Lista blanca, reglas YARA propias e informes.": "Allowlist, custom YARA rules and reports.",
    "Editar lista blanca": "Edit allowlist",
    "Reglas YARA propias": "Custom YARA rules",
    "Carpeta de informes": "Reports folder",
    "Carpeta de configuración": "Configuration folder",
    "Actualizaciones": "Updates",
    "Buscar actualizaciones": "Check for updates",
    "Privilegios": "Privileges",
    "Sin administrador, autoruns y los eventos de seguridad ven menos.": (
        "Without administrator rights, autoruns and security events see less."
    ),
    "Reiniciar como administrador": "Restart as administrator",
    "Administrador": "Administrator",
    "Sin administrador": "Not administrator",
    "Reputación (opcional)": "Reputation (optional)",
    "AbuseIPDB para IPs remotas y MalwareBazaar para hashes.": "AbuseIPDB for remote IPs and MalwareBazaar for hashes.",
    "Alertas e integraciones": "Alerts and integrations",
    "Notificación de Windows y webhook (Slack, Teams, Splunk HEC o JSON).": (
        "Windows notification and webhook (Slack, Teams, Splunk HEC or JSON)."
    ),
    "Notificar al terminar si la ventana está en segundo plano": "Notify when finished if the window is in the background",
    "Enviar solo lo nuevo o lo que empeora": "Send only what is new or worse",
    "Guardar": "Save",
    "Enviar prueba": "Send test",
    "Análisis programado": "Scheduled scan",
    "Se ejecuta con el Programador de tareas y solo avisa si hay novedades.": (
        "Runs with Task Scheduler and only alerts when something changes."
    ),
    "Desactivado": "Off",
    "Diario": "Daily",
    "Semanal": "Weekly",
    "Hora": "Time",
    "Aplicar": "Apply",
    "Webhook guardado.": "Webhook saved.",
    "Webhook desactivado.": "Webhook disabled.",
    "Escribe primero la URL del webhook.": "Enter the webhook URL first.",
    "La URL del webhook debe empezar por https://": "The webhook URL must start with https://",
    "Análisis programado desactivado.": "Scheduled scan disabled.",
    "Reinicia la aplicación para cambiar el idioma.": "Restart the application to change the language.",
    "YARA no instalado": "YARA not installed",
    "psutil (procesos y red)": "psutil (processes and network)",
    "pefile (análisis PE)": "pefile (PE analysis)",
    "YARA (opcional)": "YARA (optional)",
    "Instalar herramientas": "Install tools",
    "Instalar": "Install",
    "Herramientas listas.": "Tools ready.",
    # ---------------------------------------------------------------- diálogos
    "Rápido": "Quick",
    "Completo": "Full",
    "Personalizado": "Custom",
    "Recolección": "Collection",
    "RECOLECCIÓN": "COLLECTION",
    "Enriquecimiento": "Enrichment",
    "ENRIQUECIMIENTO": "ENRICHMENT",
    "Elige un perfil o personaliza los módulos. Se recordará para la próxima vez.": (
        "Pick a profile or customise the modules. It will be remembered next time."
    ),
    "Programas que arrancan solos (autorunsc)": "Programs that start automatically (autorunsc)",
    "Carpetas de usuario": "User folders",
    "Ejecutables sin firma en Temp y AppData": "Unsigned executables in Temp and AppData",
    "Procesos en ejecución": "Running processes",
    "Rutas raras, suplantación, Office → consola": "Odd paths, impersonation, Office → console",
    "Eventos de Windows": "Windows events",
    "Servicios y tareas nuevos, detecciones de Defender": "New services and tasks, Defender detections",
    "Extensiones de navegador": "Browser extensions",
    "Chrome, Edge, Brave y Firefox: permisos y origen": "Chrome, Edge, Brave and Firefox: permissions and origin",
    "Reglas Sigma": "Sigma rules",
    "Sysmon, PowerShell y procesos (4688)": "Sysmon, PowerShell and processes (4688)",
    "Conexiones de red": "Network connections",
    "Qué proceso sospechoso habla con el exterior": "Which suspicious process talks to the outside",
    "Análisis de contenido": "Content analysis",
    "Empaquetadores, imports de inyección, YARA": "Packers, injection imports, YARA",
    "Reputación de cada hash (15 s por consulta nueva)": "Reputation of each hash (15 s per new lookup)",
    "AbuseIPDB y MalwareBazaar": "AbuseIPDB and MalwareBazaar",
    "Reputación de IPs remotas y hashes conocidos": "Reputation of remote IPs and known hashes",
    "Eventos de los últimos": "Events from the last",
    "días": "days",
    "Límite de consultas a VirusTotal": "VirusTotal lookup limit",
    "Vacío = sin límite. Las consultas en caché no cuentan.": "Empty = no limit. Cached lookups do not count.",
    "Guardar informe como": "Save report as",
    "Se guarda en la carpeta de informes": "Saved in the reports folder",
    "Equipo remoto (WinRM)": "Remote computer (WinRM)",
    "Vacío = este equipo": "Empty = this computer",
    "Analiza otro PC con tu cuenta de dominio: persistencia, procesos y red. Requiere WinRM.": (
        "Scan another PC with your domain account: persistence, processes and network. Requires WinRM."
    ),
    "Modo demostración (datos de ejemplo, sin red)": "Demo mode (sample data, no network)",
    "Iniciar análisis": "Start scan",
    "Cancelar": "Cancel",
    "  Cancelar": "  Cancel",
    "Cerrar": "Close",
    "Comparar análisis": "Compare scans",
    "No hay elementos nuevos.": "No new items.",
    "Nada ha desaparecido.": "Nothing has disappeared.",
    "Ninguna puntuación ha subido 10 puntos o más.": "No score went up by 10 points or more.",
    "Ninguna puntuación ha bajado 10 puntos o más.": "No score went down by 10 points or more.",
    "Pega aquí tu clave": "Paste your key here",
    "Obtener clave gratis ↗": "Get a free key ↗",
    "Mostrar u ocultar": "Show or hide",
    "Repositorio": "Repository",
    "Acerca de win11-triage": "About win11-triage",
    "Valor no válido": "Invalid value",
    "El límite de VirusTotal debe ser un número entero.": "The VirusTotal limit must be a whole number.",
    "Equipo no válido": "Invalid computer",
    "Nada que analizar": "Nothing to scan",
    "Activa al menos un módulo de recolección.": "Enable at least one collection module.",
    "Sistema no compatible": "Unsupported system",
    "Fuera de Windows solo funciona el modo demostración.": "Outside Windows only demo mode works.",
    "Este sistema no es Windows: solo está disponible el modo demostración.": (
        "This system is not Windows: only demo mode is available."
    ),
    "Faltan herramientas": "Missing tools",
    "Falta la clave de VirusTotal": "VirusTotal key missing",
    "No hay API key configurada. ¿Añadirla ahora?\n\nSi no, el análisis seguirá sin VirusTotal.": (
        "No API key configured. Add it now?\n\nOtherwise the scan will continue without VirusTotal."
    ),
    "Análisis iniciado": "Scan started",
    "Cancelando… (las herramientas externas terminan su paso actual)": (
        "Cancelling… (external tools finish their current step)"
    ),
    "Análisis terminado": "Scan finished",
    "Análisis terminado: nada detectado.": "Scan finished: nothing detected.",
    "Análisis cancelado.": "Scan cancelled.",
    "Análisis cancelado por el usuario.": "Scan cancelled by the user.",
    "Aún no hay resultados que exportar.": "No results to export yet.",
    "Buscando actualizaciones…": "Checking for updates…",
    "Error": "Error",
    "Error inesperado": "Unexpected error",
    "No se pudo cargar": "Could not load",
    "No se pudo guardar": "Could not save",
    "Abrir carpeta": "Open folder",
    "Descargar": "Download",
    "Informe HTML…": "HTML report…",
    "Resumen ejecutivo (PDF)…": "Executive summary (PDF)…",
    "Informe Markdown…": "Markdown report…",
    "JSON (esquema v2)…": "JSON (schema v2)…",
    "Paquete de evidencias (.zip)…": "Evidence package (.zip)…",
    "CSV de la vista actual…        Ctrl+E": "CSV of the current view…        Ctrl+E",
    "Carga o ejecuta un análisis y selecciona otro del historial para compararlos.": (
        "Load or run a scan and select another one from the history to compare them."
    ),
    # ---------------------------------------------------------------- informes
    "Informe win11-triage": "win11-triage report",
    "Resumen": "Summary",
    "Entorno": "Environment",
    "Comprobación de entorno": "Environment check",
    "Herramienta": "Tool",
    "Técnica": "Technique",
    "Elementos": "Items",
    "Veredicto": "Verdict",
    "Campo": "Field",
    "Valor": "Value",
    "Equipo / usuario": "Computer / user",
    "Privilegios de administrador": "Administrator privileges",
    "Módulos": "Modules",
    "Ignorados por lista blanca": "Ignored by allowlist",
    "Versión": "Version",
    "Duración": "Duration",
    "Reputación": "Reputation",
    "Técnicas MITRE ATT&CK observadas": "Observed MITRE ATT&CK techniques",
    "Conexiones activas de procesos señalados": "Active connections of flagged processes",
    "Cadenas de procesos sospechosos": "Suspicious process chains",
    "Cronología": "Timeline",
    "Errores durante la ejecución": "Errors during execution",
    "Detalle de cada elemento": "Details of each item",
    "Señal": "Signal",
    "Peso": "Weight",
    "Evidencia": "Evidence",
    "Categoría": "Category",
    "Editor": "Publisher",
    "Firma": "Signature",
    "Conexión": "Connection",
    "Informe VT": "VT report",
    "Sin hallazgos.": "No findings.",
    "sí": "yes",
    "no": "no",
    "ninguno": "none",
    "Herramienta de triaje: no sustituye a un antivirus.": "Triage tool: it does not replace an antivirus.",
    "DRY-RUN: datos de ejemplo; no se ejecutaron herramientas ni se usó la red.": (
        "DRY-RUN: sample data; no tools were run and the network was not used."
    ),
    "Leyenda: 🔴 VirusTotal ≥ 1 motor o score ≥ 70 · 🟡 score 30–69 o sin firma · 🟢 score < 30 con firma válida o "
    "VirusTotal limpio.": (
        "Legend: 🔴 VirusTotal ≥ 1 engine or score ≥ 70 · 🟡 score 30–69 or unsigned · 🟢 score < 30 with valid "
        "signature or clean VirusTotal."
    ),
    # ---------------------------------------------------------------- PDF ejecutivo
    "Informe ejecutivo de seguridad": "Executive security report",
    "Riesgo alto": "High risk",
    "Hay elementos con indicios claros de actividad maliciosa. Actúa hoy.": (
        "Some items show clear signs of malicious activity. Act today."
    ),
    "Revisar": "Review",
    "No hay detecciones claras, pero sí elementos que conviene comprobar.": (
        "No clear detections, but some items are worth checking."
    ),
    "Sin indicios": "No indicators",
    "No se han encontrado elementos sospechosos en los módulos ejecutados.": (
        "No suspicious items were found in the modules that ran."
    ),
    "detectados": "detected",
    "a revisar": "to review",
    "limpios": "clean",
    "puntuación máxima (0-100)": "highest score (0-100)",
    "revisados por el analista": "reviewed by the analyst",
    "Lo más importante": "Most important",
    "Motivo principal del primer elemento": "Main reason for the first item",
    "Elemento": "Item",
    "Qué es y qué hacer": "What it is and what to do",
    "Técnicas de ataque observadas (MITRE ATT&CK)": "Observed attack techniques (MITRE ATT&CK)",
    "Alcance": "Scope",
    "Informe técnico completo: HTML/Markdown/JSON": "Full technical report: HTML/Markdown/JSON",
    # ---------------------------------------------------------------- «¿Qué hago con esto?»
    "Varios antivirus de VirusTotal identifican este archivo como malicioso.": (
        "Several VirusTotal antivirus engines identify this file as malicious."
    ),
    "El hash aparece en MalwareBazaar, una base de datos de muestras de malware confirmadas.": (
        "The hash appears in MalwareBazaar, a database of confirmed malware samples."
    ),
    "Pocos motores lo marcan: puede ser un falso positivo o algo muy nuevo.": (
        "Few engines flag it: it may be a false positive or something very new."
    ),
    "Microsoft Defender ya detectó una amenaza en este equipo.": (
        "Microsoft Defender has already detected a threat on this computer."
    ),
    "Una regla de detección (Sigma) coincide con la actividad registrada en los eventos de Windows.": (
        "A detection rule (Sigma) matches activity recorded in the Windows events."
    ),
    "El programa se conecta a una dirección IP denunciada por actividad maliciosa.": (
        "The program connects to an IP address reported for malicious activity."
    ),
    "Un documento de Office lanzó una consola: es la forma típica en que actúan las macros maliciosas.": (
        "An Office document launched a console: this is how malicious macros typically work."
    ),
    "Una herramienta de accesibilidad (sethc, utilman…) se sustituyó: permite abrir una consola sin contraseña.": (
        "An accessibility tool (sethc, utilman…) was replaced: it allows opening a console without a password."
    ),
    "PowerShell se lanza con un comando codificado: se usa para esconder lo que hace.": (
        "PowerShell is launched with an encoded command: used to hide what it does."
    ),
    "Se usa un programa del propio Windows para descargar o ejecutar código (técnica «Living off the Land»).": (
        "A built-in Windows program is used to download or run code (“Living off the Land” technique)."
    ),
    "Este elemento hace que algo se ejecute solo al iniciar Windows o con un desencadenante.": (
        "This item makes something run automatically at Windows startup or on a trigger."
    ),
    "Se instaló un servicio nuevo. Los atacantes los usan para persistir o moverse por la red.": (
        "A new service was installed. Attackers use them to persist or move across the network."
    ),
    "Se creó una tarea programada.": "A scheduled task was created.",
    "Una extensión del navegador tiene permisos amplios o no viene de la tienda oficial.": (
        "A browser extension has broad permissions or does not come from the official store."
    ),
    "El nombre imita a un archivo de Windows o a un programa conocido, pero está en otro sitio.": (
        "The name imitates a Windows file or a well-known program, but it is somewhere else."
    ),
    "El contenido del ejecutable tiene rasgos típicos de malware (empaquetado, imports de inyección…).": (
        "The executable's content has typical malware traits (packing, injection imports…)."
    ),
    "Una regla YARA reconoce patrones de malware dentro del archivo.": (
        "A YARA rule recognises malware patterns inside the file."
    ),
    "Se ejecuta desde una carpeta en la que cualquier programa puede escribir (Temp, AppData, Descargas).": (
        "It runs from a folder any program can write to (Temp, AppData, Downloads)."
    ),
    "El archivo no tiene firma digital válida, así que no se puede saber quién lo creó.": (
        "The file has no valid digital signature, so its author cannot be verified."
    ),
    "Prioridad alta: revisa este elemento hoy.": "High priority: review this item today.",
    "No es necesariamente malo, pero tiene rasgos que conviene comprobar.": (
        "It is not necessarily bad, but it has traits worth checking."
    ),
    "No hay indicios de riesgo.": "No signs of risk.",
    "Desconecta el equipo de la red (Wi-Fi o cable) si el archivo se está ejecutando.": (
        "Disconnect the computer from the network (Wi-Fi or cable) if the file is running."
    ),
    "Ejecuta un análisis completo con Microsoft Defender (Seguridad de Windows → Protección contra virus).": (
        "Run a full scan with Microsoft Defender (Windows Security → Virus & threat protection)."
    ),
    "Abre el enlace de VirusTotal para ver el nombre de la amenaza y busca guías de limpieza específicas.": (
        "Open the VirusTotal link to see the threat name and look for specific removal guides."
    ),
    "Cambia desde OTRO dispositivo las contraseñas que hayas usado en este equipo (correo y banco primero).": (
        "From ANOTHER device, change the passwords you used on this computer (email and bank first)."
    ),
    "Trátalo como malware confirmado: aísla el equipo de la red.": (
        "Treat it as confirmed malware: isolate the computer from the network."
    ),
    "Anota la ruta y el nombre de la familia; elimina el archivo con Defender (no a mano si se está ejecutando).": (
        "Write down the path and family name; remove the file with Defender (not by hand if it is running)."
    ),
    "Revisa la persistencia (página Hallazgos, origen Persistencia) por si vuelve a instalarse al reiniciar.": (
        "Check persistence (Findings page, Persistence source) in case it reinstalls itself on reboot."
    ),
    "Comprueba quién lo publica y si reconoces el programa.": "Check who publishes it and whether you recognise the program.",
    "Vuelve a consultarlo en VirusTotal dentro de unos días: las detecciones suelen aumentar si es malicioso.": (
        "Check it again on VirusTotal in a few days: detections usually increase if it is malicious."
    ),
    "Abre Seguridad de Windows → Historial de protección y comprueba que la amenaza está en cuarentena o eliminada.": (
        "Open Windows Security → Protection history and check the threat is quarantined or removed."
    ),
    "Si aparece como «activa» o «permitida», pulsa Quitar y reinicia.": (
        "If it shows as “active” or “allowed”, press Remove and restart."
    ),
    "Busca en Hallazgos otros elementos con la misma ruta o fecha.": (
        "Look in Findings for other items with the same path or date."
    ),
    "Mira la línea de comandos y el proceso padre: ¿fuiste tú o un programa que reconoces?": (
        "Look at the command line and parent process: was it you or a program you recognise?"
    ),
    "Si no lo reconoces, busca el ejecutable en Hallazgos y revisa su puntuación y firma.": (
        "If you do not recognise it, find the executable in Findings and check its score and signature."
    ),
    "Activa Sysmon si no lo tienes: da mucho más contexto para la próxima vez.": (
        "Enable Sysmon if you do not have it: it gives much more context next time."
    ),
    "Identifica el proceso en la página Red y comprueba si es un programa que usas.": (
        "Identify the process on the Network page and check whether it is a program you use."
    ),
    "Si no lo reconoces, bloquéalo en el Firewall de Windows o desconecta el equipo.": (
        "If you do not recognise it, block it in Windows Firewall or disconnect the computer."
    ),
    "Revisa si arranca solo (Persistencia) para evitar que vuelva a conectarse.": (
        "Check whether it starts automatically (Persistence) to stop it reconnecting."
    ),
    "Cierra el documento y no habilites macros ni «contenido».": "Close the document and do not enable macros or “content”.",
    "Recuerda de dónde vino el documento (correo, descarga) y no lo vuelvas a abrir.": (
        "Remember where the document came from (email, download) and do not open it again."
    ),
    "Analiza el equipo con Defender y revisa la persistencia creada después de esa hora.": (
        "Scan the computer with Defender and review persistence created after that time."
    ),
    "Es una puerta trasera conocida: trátalo como una intrusión.": "It is a known backdoor: treat it as an intrusion.",
    "Restaura los archivos del sistema con «sfc /scannow» en una consola de administrador.": (
        "Restore system files with “sfc /scannow” in an administrator console."
    ),
    "Revisa la clave de registro Image File Execution Options indicada en la ubicación y elimina el valor.": (
        "Check the Image File Execution Options registry key shown in the location and remove the value."
    ),
    "Copia el texto tras -enc y decodifícalo (Base64, UTF-16) para ver el comando real.": (
        "Copy the text after -enc and decode it (Base64, UTF-16) to see the real command."
    ),
    "Si descarga algo de Internet o no reconoces el autor, desactiva la entrada de arranque.": (
        "If it downloads something from the Internet or you do not recognise the author, disable the startup entry."
    ),
    "Lee la línea de comandos completa: ¿apunta a una URL o a un script que no conoces?": (
        "Read the full command line: does it point to a URL or a script you do not know?"
    ),
    "Si no la reconoces, desactiva la entrada (Autoruns o Programador de tareas) antes de borrar nada.": (
        "If you do not recognise it, disable the entry (Autoruns or Task Scheduler) before deleting anything."
    ),
    "Comprueba si corresponde a un programa que instalaste tú.": "Check whether it belongs to a program you installed.",
    "Si no, desactívalo primero (Autoruns permite desmarcarlo) y observa unos días antes de borrarlo.": (
        "If not, disable it first (Autoruns lets you untick it) and watch for a few days before deleting it."
    ),
    "Comprueba el nombre y la ruta del servicio en services.msc.": "Check the service name and path in services.msc.",
    "Si ejecuta un intérprete (cmd, PowerShell) o vive en una carpeta de usuario, deténlo y desactívalo.": (
        "If it runs an interpreter (cmd, PowerShell) or lives in a user folder, stop and disable it."
    ),
    "Ábrela en el Programador de tareas y mira qué ejecuta y cuándo.": "Open it in Task Scheduler and see what it runs and when.",
    "Si no la reconoces, desactívala (no la borres todavía, por si hace falta como evidencia).": (
        "If you do not recognise it, disable it (do not delete it yet, in case it is needed as evidence)."
    ),
    "Abre la página de extensiones del navegador y comprueba si la instalaste tú.": (
        "Open the browser's extensions page and check whether you installed it."
    ),
    "Si no la reconoces o no la usas, quítala.": "If you do not recognise it or do not use it, remove it.",
    "Si tenía acceso a todos los sitios y no la reconoces, cambia las contraseñas guardadas en el navegador.": (
        "If it had access to all sites and you do not recognise it, change the passwords saved in the browser."
    ),
    "Compara la ruta con la del archivo legítimo (normalmente C:\\Windows\\System32).": (
        "Compare the path with the legitimate file's (usually C:\\Windows\\System32)."
    ),
    "Un svchost.exe o similar fuera de System32 casi nunca es legítimo: analízalo con Defender.": (
        "An svchost.exe or similar outside System32 is almost never legitimate: scan it with Defender."
    ),
    "Súbelo a VirusTotal (activa el módulo) para tener una segunda opinión antes de decidir.": (
        "Check it on VirusTotal (enable the module) for a second opinion before deciding."
    ),
    "Consulta el nombre de la regla en la evidencia y analiza el archivo con Defender.": (
        "Check the rule name in the evidence and scan the file with Defender."
    ),
    "Muchos programas legítimos lo hacen (Teams, Discord…): comprueba el editor y la firma.": (
        "Many legitimate programs do this (Teams, Discord…): check the publisher and signature."
    ),
    "No es malicioso por sí mismo, pero combinado con otras señales aumenta el riesgo.": (
        "It is not malicious by itself, but combined with other signals it raises the risk."
    ),
    "Sigue los pasos de arriba y marca el elemento como «Confirmado» o «Falso positivo» al terminar.": (
        "Follow the steps above and mark the item as “Confirmed” or “False positive” when done."
    ),
    "Si reconoces el programa y el editor, márcalo como «Falso positivo» o añádelo a la lista blanca.": (
        "If you recognise the program and publisher, mark it as “False positive” or add it to the allowlist."
    ),
    "Si no, activa VirusTotal y vuelve a analizar.": "If not, enable VirusTotal and scan again.",
    "No hace falta hacer nada.": "Nothing needs to be done.",
    # ---------------------------------------------------------------- señales
    "0 detecciones en VirusTotal": "0 detections on VirusTotal",
    "Complemento de Firefox sin firma de Mozilla": "Firefox add-on not signed by Mozilla",
    "Conexiones de red activas hacia el exterior": "Active outbound network connections",
    "Conexiones de red activas": "Active network connections",
    "Detectado por antivirus en VirusTotal": "Detected by antivirus engines on VirusTotal",
    "Doble extensión engañosa": "Misleading double extension",
    "Ejecutable en carpeta escribible por el usuario": "Executable in a user-writable folder",
    "El ejecutable ya no existe en disco": "The executable no longer exists on disk",
    "Extensión instalada fuera de la tienda oficial": "Extension installed outside the official store",
    "Extensión sin empaquetar (modo desarrollador)": "Unpacked extension (developer mode)",
    "Fecha de compilación imposible": "Impossible compile date",
    "Firma digital válida": "Valid digital signature",
    "Hash conocido en MalwareBazaar": "Hash known on MalwareBazaar",
    "IP con mala reputación en AbuseIPDB": "IP with bad reputation on AbuseIPDB",
    "IP denunciada en AbuseIPDB": "IP reported on AbuseIPDB",
    "Importa APIs de inyección en procesos": "Imports process-injection APIs",
    "La entrada apunta a un fichero que ya no existe": "The entry points to a file that no longer exists",
    "La persistencia lanza un LOLBin con argumentos sospechosos": "Persistence launches a LOLBin with suspicious arguments",
    "Marcado como sospechoso en VirusTotal": "Marked as suspicious on VirusTotal",
    "Microsoft Defender detectó una amenaza": "Microsoft Defender detected a threat",
    "Muy pocos imports y alta entropía": "Very few imports and high entropy",
    "Permisos sensibles": "Sensitive permissions",
    "PowerShell con comando codificado en Base64": "PowerShell with a Base64-encoded command",
    "PowerShell descarga contenido de Internet": "PowerShell downloads content from the Internet",
    "PowerShell en ventana oculta": "PowerShell in a hidden window",
    "Puede leer y cambiar todos los sitios web": "Can read and change all websites",
    "Secciones con entropía muy alta (cifrado/empaquetado)": "Sections with very high entropy (encrypted/packed)",
    "Secciones de empaquetador conocido": "Known packer sections",
    "Servicio instalado recientemente": "Recently installed service",
    "Sin firma digital válida": "No valid digital signature",
    "Tarea programada creada recientemente": "Recently created scheduled task",
    "Windows Script Host ejecuta un script": "Windows Script Host runs a script",
    "bitsadmin descarga ficheros": "bitsadmin downloads files",
    "certutil usado para descargar o decodificar": "certutil used to download or decode",
    "cmd /c encadena una herramienta de descarga o ejecución": "cmd /c chains a download or execution tool",
    "mshta ejecuta script remoto o en línea": "mshta runs a remote or inline script",
    "regsvr32 carga un scriptlet remoto (Squiblydoo)": "regsvr32 loads a remote scriptlet (Squiblydoo)",
    "rundll32 con script, URL o ruta UNC": "rundll32 with script, URL or UNC path",
    # ---------------------------------------------------------------- secciones del motor
    "Persistencia (Autoruns)": "Persistence (Autoruns)",
    "Carpetas de usuario (Sigcheck) — sin firma válida": "User folders (Sigcheck) — no valid signature",
    "Procesos en ejecución — sospechosos": "Running processes — suspicious",
    "Eventos de Windows — servicios, tareas y Defender": "Windows events — services, tasks and Defender",
    "Reglas Sigma — Sysmon, 4688, PowerShell": "Sigma rules — Sysmon, 4688, PowerShell",
}

PATTERNS = compile_patterns(
    [
        (r"Creado hace menos de (\d+) días", "Created less than {0} days ago"),
        (r"(\d+) consultas nuevas · (\d+) desde caché · (\d+) errores · (\d+) omitidas",
         "{0} new lookups · {1} from cache · {2} errors · {3} skipped"),
        (r"(\d+) IP \((\d+) maliciosas\) · (\d+) hashes \((\d+) en MalwareBazaar\)",
         "{0} IPs ({1} malicious) · {2} hashes ({3} on MalwareBazaar)"),
        (r"(\d+) elemento\(s\) detectados por motores de VirusTotal\.", "{0} item(s) detected by VirusTotal engines."),
        (r"Nombre muy parecido a (.+)", "Name very similar to {0}"),
        (r"(.+) con padre inusual \((.+)\)", "{0} with an unusual parent ({1})"),
        (r"(.+) fuera de System32", "{0} outside System32"),
        (r"(.+) lanzó (.+)", "{0} launched {1}"),
        (r"Sigma: (.+)", "Sigma: {0}"),
        (r"Hallazgos  \((\d+)\)", "Findings  ({0})"),
        (r"Historial  \((\d+)\)", "History  ({0})"),
        (r"Red  \((\d+)\)", "Network  ({0})"),
        (r"IFEO secuestra (.+) \(puerta trasera en la pantalla de inicio\)", "IFEO hijacks {0} (sign-in screen backdoor)"),
        (r"Nuevos \((\d+)\)", "New ({0})"),
        (r"Resueltos \((\d+)\)", "Resolved ({0})"),
        (r"Empeoran \((\d+)\)", "Worse ({0})"),
        (r"Mejoran \((\d+)\)", "Better ({0})"),
        (r"Versión instalada: (.+)\. Solo se consulta GitHub cuando lo pides\.",
         "Installed version: {0}. GitHub is only checked when you ask."),
        (r"Revisados (\d+)/(\d+)(.*)", "Reviewed {0}/{1}{2}"),
        (r"Exportado: (.+)", "Exported: {0}"),
        (r"Informe guardado: (.+)", "Report saved: {0}"),
        (r"Clave de (.+) guardada\.", "{0} key saved."),
        (r"Clave de (.+)…", "{0} key…"),
        (r"Análisis terminado en (\d+) s\.", "Scan finished in {0} s."),
        (r"(\d+) elementos detectados", "{0} items detected"),
    ]
)  # fmt: skip
