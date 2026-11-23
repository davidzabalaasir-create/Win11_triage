"""«¿Qué hago con esto?»: explicación en lenguaje llano y pasos recomendados para cada hallazgo.

Las recomendaciones son conservadoras: primero comprobar, después contener. Nunca se borra nada
automáticamente; el usuario decide.
"""

from __future__ import annotations

from dataclasses import dataclass

from .models import Finding, Status


@dataclass(frozen=True)
class Advice:
    summary: str  # una frase: qué significa
    steps: tuple[str, ...]  # pasos concretos, en orden


# Por prefijo de id de señal; se usa el más específico (más largo) que coincida.
BY_SIGNAL: dict[str, Advice] = {
    "VT_DETECTED": Advice(
        "Varios antivirus de VirusTotal identifican este archivo como malicioso.",
        (
            "Desconecta el equipo de la red (Wi-Fi o cable) si el archivo se está ejecutando.",
            "Ejecuta un análisis completo con Microsoft Defender (Seguridad de Windows → Protección contra virus).",
            "Abre el enlace de VirusTotal para ver el nombre de la amenaza y busca guías de limpieza específicas.",
            "Cambia desde OTRO dispositivo las contraseñas que hayas usado en este equipo (correo y banco primero).",
        ),
    ),
    "INTEL_MB_KNOWN": Advice(
        "El hash aparece en MalwareBazaar, una base de datos de muestras de malware confirmadas.",
        (
            "Trátalo como malware confirmado: aísla el equipo de la red.",
            "Anota la ruta y el nombre de la familia; elimina el archivo con Defender (no a mano si se está ejecutando).",
            "Revisa la persistencia (página Hallazgos, origen Persistencia) por si vuelve a instalarse al reiniciar.",
        ),
    ),
    "VT_SUSPICIOUS": Advice(
        "Pocos motores lo marcan: puede ser un falso positivo o algo muy nuevo.",
        (
            "Comprueba quién lo publica y si reconoces el programa.",
            "Vuelve a consultarlo en VirusTotal dentro de unos días: las detecciones suelen aumentar si es malicioso.",
        ),
    ),
    "DEFENDER_DETECTION": Advice(
        "Microsoft Defender ya detectó una amenaza en este equipo.",
        (
            "Abre Seguridad de Windows → Historial de protección y comprueba que la amenaza está en cuarentena o eliminada.",
            "Si aparece como «activa» o «permitida», pulsa Quitar y reinicia.",
            "Busca en Hallazgos otros elementos con la misma ruta o fecha.",
        ),
    ),
    "SIGMA_": Advice(
        "Una regla de detección (Sigma) coincide con la actividad registrada en los eventos de Windows.",
        (
            "Mira la línea de comandos y el proceso padre: ¿fuiste tú o un programa que reconoces?",
            "Si no lo reconoces, busca el ejecutable en Hallazgos y revisa su puntuación y firma.",
            "Activa Sysmon si no lo tienes: da mucho más contexto para la próxima vez.",
        ),
    ),
    "INTEL_IP": Advice(
        "El programa se conecta a una dirección IP denunciada por actividad maliciosa.",
        (
            "Identifica el proceso en la página Red y comprueba si es un programa que usas.",
            "Si no lo reconoces, bloquéalo en el Firewall de Windows o desconecta el equipo.",
            "Revisa si arranca solo (Persistencia) para evitar que vuelva a conectarse.",
        ),
    ),
    "PROC_OFFICE_SPAWNS_SHELL": Advice(
        "Un documento de Office lanzó una consola: es la forma típica en que actúan las macros maliciosas.",
        (
            "Cierra el documento y no habilites macros ni «contenido».",
            "Recuerda de dónde vino el documento (correo, descarga) y no lo vuelvas a abrir.",
            "Analiza el equipo con Defender y revisa la persistencia creada después de esa hora.",
        ),
    ),
    "PERSIST_ACCESSIBILITY_BACKDOOR": Advice(
        "Una herramienta de accesibilidad (sethc, utilman…) se sustituyó: permite abrir una consola sin contraseña.",
        (
            "Es una puerta trasera conocida: trátalo como una intrusión.",
            "Restaura los archivos del sistema con «sfc /scannow» en una consola de administrador.",
            "Revisa la clave de registro Image File Execution Options indicada en la ubicación y elimina el valor.",
        ),
    ),
    "CMD_PS_ENCODED": Advice(
        "PowerShell se lanza con un comando codificado: se usa para esconder lo que hace.",
        (
            "Copia el texto tras -enc y decodifícalo (Base64, UTF-16) para ver el comando real.",
            "Si descarga algo de Internet o no reconoces el autor, desactiva la entrada de arranque.",
        ),
    ),
    "CMD_": Advice(
        "Se usa un programa del propio Windows para descargar o ejecutar código (técnica «Living off the Land»).",
        (
            "Lee la línea de comandos completa: ¿apunta a una URL o a un script que no conoces?",
            "Si no la reconoces, desactiva la entrada (Autoruns o Programador de tareas) antes de borrar nada.",
        ),
    ),
    "PERSIST_": Advice(
        "Este elemento hace que algo se ejecute solo al iniciar Windows o con un desencadenante.",
        (
            "Comprueba si corresponde a un programa que instalaste tú.",
            "Si no, desactívalo primero (Autoruns permite desmarcarlo) y observa unos días antes de borrarlo.",
        ),
    ),
    "EVT_SERVICE_INSTALLED": Advice(
        "Se instaló un servicio nuevo. Los atacantes los usan para persistir o moverse por la red.",
        (
            "Comprueba el nombre y la ruta del servicio en services.msc.",
            "Si ejecuta un intérprete (cmd, PowerShell) o vive en una carpeta de usuario, deténlo y desactívalo.",
        ),
    ),
    "EVT_TASK_CREATED": Advice(
        "Se creó una tarea programada.",
        (
            "Ábrela en el Programador de tareas y mira qué ejecuta y cuándo.",
            "Si no la reconoces, desactívala (no la borres todavía, por si hace falta como evidencia).",
        ),
    ),
    "EXT_": Advice(
        "Una extensión del navegador tiene permisos amplios o no viene de la tienda oficial.",
        (
            "Abre la página de extensiones del navegador y comprueba si la instalaste tú.",
            "Si no la reconoces o no la usas, quítala.",
            "Si tenía acceso a todos los sitios y no la reconoces, cambia las contraseñas guardadas en el navegador.",
        ),
    ),
    "MASQ_": Advice(
        "El nombre imita a un archivo de Windows o a un programa conocido, pero está en otro sitio.",
        (
            "Compara la ruta con la del archivo legítimo (normalmente C:\\Windows\\System32).",
            "Un svchost.exe o similar fuera de System32 casi nunca es legítimo: analízalo con Defender.",
        ),
    ),
    "PE_": Advice(
        "El contenido del ejecutable tiene rasgos típicos de malware (empaquetado, imports de inyección…).",
        ("Súbelo a VirusTotal (activa el módulo) para tener una segunda opinión antes de decidir.",),
    ),
    "YARA_": Advice(
        "Una regla YARA reconoce patrones de malware dentro del archivo.",
        ("Consulta el nombre de la regla en la evidencia y analiza el archivo con Defender.",),
    ),
    "PATH_USER_WRITABLE": Advice(
        "Se ejecuta desde una carpeta en la que cualquier programa puede escribir (Temp, AppData, Descargas).",
        ("Muchos programas legítimos lo hacen (Teams, Discord…): comprueba el editor y la firma.",),
    ),
    "SIG_UNSIGNED": Advice(
        "El archivo no tiene firma digital válida, así que no se puede saber quién lo creó.",
        ("No es malicioso por sí mismo, pero combinado con otras señales aumenta el riesgo.",),
    ),
}

BY_STATUS = {
    Status.DETECTED: Advice(
        "Prioridad alta: revisa este elemento hoy.",
        ("Sigue los pasos de arriba y marca el elemento como «Confirmado» o «Falso positivo» al terminar.",),
    ),
    Status.UNKNOWN: Advice(
        "No es necesariamente malo, pero tiene rasgos que conviene comprobar.",
        (
            "Si reconoces el programa y el editor, márcalo como «Falso positivo» o añádelo a la lista blanca.",
            "Si no, activa VirusTotal y vuelve a analizar.",
        ),
    ),
    Status.CLEAN: Advice("No hay indicios de riesgo.", ("No hace falta hacer nada.",)),
}


def _match(signal_id: str) -> Advice | None:
    best = max((k for k in BY_SIGNAL if signal_id.startswith(k)), key=len, default=None)
    return BY_SIGNAL[best] if best else None


def advice_for(f: Finding, limit: int = 6) -> Advice:
    """Explicación del motivo principal y pasos combinados (sin repetir), en orden de gravedad."""
    summaries: list[str] = []
    steps: list[str] = []
    for s in f.unique_signals:
        if s.weight <= 0:
            continue
        a = _match(s.id)
        if a is None:
            continue
        if a.summary not in summaries:
            summaries.append(a.summary)
        steps += [x for x in a.steps if x not in steps]
    general = BY_STATUS[f.status]
    if not summaries:
        summaries.append(general.summary)
    steps = steps[:limit] + [x for x in general.steps if x not in steps]
    return Advice(" ".join(summaries[:2]), tuple(steps))


def as_text(f: Finding) -> str:
    a = advice_for(f)
    return a.summary + "\n" + "\n".join(f"{i}. {s}" for i, s in enumerate(a.steps, 1))
