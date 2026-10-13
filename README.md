# Centinela del PC (PowerShell)

Saber **quién está conectado a tu PC** y **quién intentó iniciar sesión**, con un clic. Muestra las IP conectadas a tu equipo ahora mismo (con el programa que las usa y si son conocidas o nuevas), los puertos que tienes abiertos, y lee el registro de seguridad de Windows para detectar intentos de inicio de sesión fallidos (fuerza bruta) y accesos remotos. Genera un reporte HTML.

Herramienta **defensiva (blue-team)** para tu propio equipo. Funciona en Windows PowerShell 5.1 o PowerShell 7. No necesita instalar nada.

---

## Tabla de contenidos
- [Para qué sirve](#para-qué-sirve)
- [Qué revisa](#qué-revisa)
- [Instalación](#instalación)
- [Uso](#uso)
- [Marcar IP como conocidas](#marcar-ip-como-conocidas)
- [Cómo leer el reporte](#cómo-leer-el-reporte)
- [Por qué pide permisos de administrador](#por-qué-pide-permisos-de-administrador)
- [Estructura del proyecto](#estructura-del-proyecto)
- [Preguntas frecuentes](#preguntas-frecuentes)
- [Conceptos aplicados](#conceptos-aplicados)
- [Aviso](#aviso)

---

## Para qué sirve

Dos preguntas de seguridad muy concretas: *¿hay alguna IP que no reconozco conectada a mi PC?* y *¿alguien está intentando entrar a mi sesión?* El Centinela las responde mirando las conexiones de red activas y el registro de eventos de Windows, y te deja un reporte claro con lo que conviene revisar. No ataca ni escanea a nadie: solo observa tu propio equipo.

---

## Qué revisa

**Conexiones activas**
- Las IP conectadas a tu PC ahora, con el **programa** que las usa.
- Clasifica cada IP: *Local*, *Red local*, *CGNAT* o *Internet*.
- Marca como **nueva** cualquier IP de internet que no esté en tu lista de conocidas.
- Los **puertos a la escucha** (abiertos) y cuáles son riesgosos si están expuestos (RDP 3389, SMB 445, VNC, Telnet, etc.).

**Intentos de inicio de sesión** (necesita administrador)
- **Fallidos** (evento 4625): agrupa por origen y usuario, y marca como sospechoso cuando hay 5 o más intentos (posible fuerza bruta).
- **Exitosos remotos** (evento 4624, tipo RDP o red): para que veas si alguien entró desde fuera.
- **Cuenta bloqueada** (evento 4740).

---

## Instalación

No hay instalación. Solo la carpeta con los archivos y Windows.

Doble clic en **`Centinela.cmd`**. Te pedirá permisos de administrador (UAC) para poder leer los intentos de inicio de sesión; acepta.

---

## Uso

| Acción | Qué hace |
| --- | --- |
| **`Centinela.cmd`** | Revisión completa (conexiones + intentos de login) y abre el reporte |
| **`VigilarContinuo.cmd`** | Vigila cada 10 minutos y avisa si aparece una IP nueva que no reconoces |

Por línea de comandos:

```powershell
.\Centinela.ps1                  # revisión completa
.\Centinela.ps1 -Horas 72        # mira 72 h de eventos
.\Centinela.ps1 -SoloConexiones  # solo conexiones (no necesita administrador)
.\Centinela.ps1 -Continuo        # vigilancia continua
```

---

## Marcar IP como conocidas

La primera vez verás varias IP de internet marcadas como **nuevas**: casi todas serán cosas normales (Discord, Steam, tu navegador, tu nube). Cuando reconozcas una, agrégala a **`Conocidas.txt`**, una por línea:

```
162.159.128.233   Discord
23.52.11.9         Steam
142.250.78.14      Google / YouTube
```

A partir de ahí dejan de marcarse, y lo que quede en amarillo es lo que de verdad vale la pena mirar.

---

## Cómo leer el reporte

- **Amarillo en conexiones** = IP de internet que no tienes como conocida. Revisa el programa: si es uno que reconoces, agrégala a `Conocidas.txt`.
- **Puerto 3389 (RDP) o 445 (SMB) "a toda la red"** = tu PC acepta conexiones de ese tipo desde fuera. Si no lo usas, conviene desactivarlo.
- **Muchos intentos fallidos desde una misma IP** = posible ataque de fuerza bruta.
- **Un inicio de sesión remoto que no reconozcas** = la señal más importante. Si pasa, cambia tu contraseña y, ante la duda, desconéctate de internet.

---

## Por qué pide permisos de administrador

El registro de seguridad de Windows (donde quedan los intentos de inicio de sesión) solo se puede leer como administrador. Por eso `Centinela.cmd` se autoeleva con una ventana de UAC. Si lo ejecutas sin administrador, igual funciona la parte de **conexiones**; la de intentos de login aparecerá como no disponible.

---

## Estructura del proyecto

```
centinela-pc/
├─ Centinela.ps1          # script principal
├─ Centinela.cmd          # revisión completa (se autoeleva)
├─ VigilarContinuo.cmd    # vigilancia cada 10 min
├─ Conocidas.txt          # tus IP conocidas (editable)
├─ README.md
└─ datos/ , reportes/     # se crean solos (no se suben)
```

---

## Preguntas frecuentes

**¿Esto espía a otros o escanea redes?** No. Solo mira las conexiones y los eventos de **tu propio equipo**.

**Me marca muchísimas IP nuevas.** Es normal al principio. Ve agregando a `Conocidas.txt` las que reconozcas (navegador, juegos, nube) y la lista se limpia sola.

**No aparecen los intentos de login.** Ejecútalo como administrador (el `.cmd` lo pide solo). Si aun así no hay nada, es que no ha habido intentos, lo cual es bueno.

**¿Sirve si no tengo RDP?** Sí. Aunque no uses escritorio remoto, igual ves las conexiones y los intentos sobre tu cuenta local.

---

## Conceptos aplicados

Análisis de conexiones de red (`Get-NetTCPConnection`), clasificación de direcciones IP (privada, CGNAT, pública), lectura e interpretación del registro de eventos de seguridad de Windows (4625 / 4624 / 4740), detección de patrones de fuerza bruta, lista de confianza (allowlist) y reportes HTML. Enfoque defensivo / blue-team.

---

## Aviso

Úsalo solo en tu propio equipo. Es una herramienta de observación y diagnóstico; no bloquea conexiones ni modifica el sistema. Ante una sospecha real de intrusión, cambia tus contraseñas y busca apoyo especializado.
