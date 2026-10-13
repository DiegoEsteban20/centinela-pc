<#
.SYNOPSIS
  Centinela del PC: quién está conectado a tu equipo y quién intentó iniciar sesión.
.DESCRIPTION
  Dos vistas, sobre TU propio equipo:
   1) Conexiones activas: las IP conectadas a tu PC ahora mismo, con el programa que las usa,
      si son de tu red o de internet, y si son conocidas o nuevas (según Conocidas.txt).
   2) Intentos de inicio de sesión: lee el registro de seguridad de Windows (eventos 4625 fallidos,
      4624 exitosos, 4740 cuenta bloqueada) y marca posibles ataques de fuerza bruta o accesos
      remotos. Esta parte necesita permisos de administrador.
  Genera un reporte HTML y un resumen en consola. Guarda historial en datos\.

  Herramienta defensiva para tu propio equipo.
.PARAMETER Horas
  Cuántas horas hacia atrás mirar en el registro de eventos (por defecto 24).
.PARAMETER Continuo
  Revisa cada N minutos sin parar y avisa si aparece algo nuevo.
.PARAMETER SoloConexiones
  No lee el registro de eventos (no necesita administrador).
.EXAMPLE
  .\Centinela.ps1
  .\Centinela.ps1 -Horas 72
  .\Centinela.ps1 -Continuo
.NOTES
  Autor: Diego Molina (github.com/DiegoEsteban20). Windows PowerShell 5.1 y PowerShell 7.
#>
[CmdletBinding()]
param(
    [int]$Horas = 24,
    [switch]$Continuo,
    [int]$MinutosCiclo = 10,
    [switch]$SoloConexiones,
    [switch]$SoloAccesos,
    [switch]$NoAbrir
)

$ErrorActionPreference = 'Stop'
$Base = Split-Path -Parent $MyInvocation.MyCommand.Path
$DirDatos = Join-Path $Base 'datos'
$DirReportes = Join-Path $Base 'reportes'
if (-not (Test-Path $DirDatos)) { New-Item -ItemType Directory -Path $DirDatos | Out-Null }
$ArchConocidas = Join-Path $Base 'Conocidas.txt'
$ArchLog = Join-Path $Base 'Centinela.log'

function Log([string]$m, [string]$color = 'Gray') {
    Add-Content -Path $ArchLog -Value ('{0:yyyy-MM-dd HH:mm:ss}  {1}' -f (Get-Date), $m) -Encoding UTF8
    Write-Host $m -ForegroundColor $color
}

function Es-Admin {
    try {
        $id = [Security.Principal.WindowsIdentity]::GetCurrent()
        return ([Security.Principal.WindowsPrincipal]$id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch { return $false }
}

# ------------------------------------------------------------------ clasificar IP
function Clasificar-IP([string]$ip) {
    if (-not $ip -or $ip -eq '0.0.0.0' -or $ip -eq '::' ) { return 'Local' }
    if ($ip -eq '127.0.0.1' -or $ip -eq '::1' -or $ip -like 'fe80:*') { return 'Local' }
    if ($ip -like '10.*' -or $ip -like '192.168.*' -or $ip -like '169.254.*') { return 'Red local' }
    if ($ip -match '^172\.(1[6-9]|2[0-9]|3[0-1])\.') { return 'Red local' }
    if ($ip -match '^100\.(6[4-9]|[7-9][0-9]|1[0-1][0-9]|12[0-7])\.') { return 'CGNAT' }
    if ($ip -like '::ffff:*') { return (Clasificar-IP ($ip -replace '^::ffff:', '')) }
    if ($ip -like '*:*') { return 'Internet' }   # IPv6 pública
    return 'Internet'
}

function Nombre-Host([string]$ip) {
    try {
        $r = Resolve-DnsName -Name $ip -Type PTR -QuickTimeout -ErrorAction SilentlyContinue
        if ($r) { return ($r | Where-Object { $_.NameHost } | Select-Object -First 1).NameHost }
    } catch { }
    return ''
}

function Leer-Conocidas {
    $set = @{}
    if (Test-Path $ArchConocidas) {
        foreach ($l in Get-Content $ArchConocidas) {
            $l = $l.Trim()
            if (-not $l -or $l.StartsWith('#')) { continue }
            $set[($l -split '\s+')[0].ToLower()] = $true
        }
    }
    return $set
}

# ------------------------------------------------------------------ conexiones
function Obtener-Conexiones {
    $conocidas = Leer-Conocidas
    $procCache = @{}
    $resultado = New-Object System.Collections.Generic.List[object]

    $conns = @(Get-NetTCPConnection -ErrorAction SilentlyContinue |
               Where-Object { $_.State -eq 'Established' -or $_.State -eq 'Listen' })
    foreach ($c in $conns) {
        $procId = $c.OwningProcess
        if (-not $procCache.ContainsKey($procId)) {
            $p = Get-Process -Id $procId -ErrorAction SilentlyContinue
            $procCache[$procId] = if ($p) { $p.ProcessName } else { '?' }
        }
        $remota = $c.RemoteAddress
        $tipo = Clasificar-IP $remota
        $esConocida = $conocidas.ContainsKey($remota.ToLower())
        $resultado.Add([pscustomobject]@{
            Estado   = $c.State.ToString()
            Proceso  = $procCache[$procId]
            PID      = $procId
            Local    = "$($c.LocalAddress):$($c.LocalPort)"
            Remota   = if ($c.State -eq 'Listen') { '(a la escucha)' } else { "$remota`:$($c.RemotePort)" }
            IP       = $remota
            Tipo     = $tipo
            Conocida = $esConocida
            PuertoL  = [int]$c.LocalPort
        })
    }
    return $resultado
}

$PUERTOS_RIESGO = @{
    3389 = 'Escritorio remoto (RDP)'; 445 = 'Compartir archivos (SMB)'; 139 = 'NetBIOS'
    5900 = 'VNC'; 23 = 'Telnet'; 21 = 'FTP'; 135 = 'RPC'; 5985 = 'WinRM'; 5986 = 'WinRM'
}

# ------------------------------------------------------------------ accesos (eventos)
function Obtener-Accesos([int]$horas) {
    $desde = (Get-Date).AddHours(-$horas)
    $eventos = $null
    try {
        $eventos = @(Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4625, 4624, 4740; StartTime = $desde } -ErrorAction Stop)
    } catch {
        if ($_.Exception.Message -match 'No events were found') { return @{ ok = $true; lista = @() } }
        return @{ ok = $false; error = $_.Exception.Message }
    }
    $lista = New-Object System.Collections.Generic.List[object]
    foreach ($e in $eventos) {
        $x = [xml]$e.ToXml()
        $d = @{}
        foreach ($n in $x.Event.EventData.Data) { $d[$n.Name] = $n.'#text' }
        $tipoLogon = $d['LogonType']
        $lista.Add([pscustomobject]@{
            Fecha   = $e.TimeCreated
            Id      = $e.Id
            Clase   = switch ($e.Id) { 4625 { 'Fallido' } 4624 { 'Exitoso' } 4740 { 'Bloqueo' } default { $e.Id } }
            Usuario = $d['TargetUserName']
            Origen  = if ($d['IpAddress'] -and $d['IpAddress'] -ne '-') { $d['IpAddress'] } else { $d['WorkstationName'] }
            Logon   = $tipoLogon
            Remoto  = ($tipoLogon -eq '10' -or $tipoLogon -eq '3')   # 10=RDP, 3=red
        })
    }
    return @{ ok = $true; lista = $lista }
}

function Resumir-Fuerzabruta($accesos) {
    # Agrupa los fallidos por origen+usuario; marca ráfagas
    $fallidos = @($accesos | Where-Object { $_.Clase -eq 'Fallido' })
    $grupos = $fallidos | Group-Object { "$($_.Origen)|$($_.Usuario)" } |
        ForEach-Object {
            $o, $u = $_.Name -split '\|', 2
            [pscustomobject]@{
                Origen = $o; Usuario = $u; Intentos = $_.Count
                Primero = ($_.Group | Sort-Object Fecha | Select-Object -First 1).Fecha
                Ultimo  = ($_.Group | Sort-Object Fecha | Select-Object -Last 1).Fecha
                Sospechoso = $_.Count -ge 5
            }
        } | Sort-Object Intentos -Descending
    return @($grupos)
}

# ------------------------------------------------------------------ reporte HTML
function Generar-Reporte($conns, $accesosInfo) {
    if (-not (Test-Path $DirReportes)) { New-Item -ItemType Directory -Path $DirReportes | Out-Null }
    $ruta = Join-Path $DirReportes 'centinela.html'

    $establecidas = @($conns | Where-Object { $_.Estado -eq 'Established' })
    $escucha = @($conns | Where-Object { $_.Estado -eq 'Listen' })
    $internet = @($establecidas | Where-Object { $_.Tipo -eq 'Internet' -or $_.Tipo -eq 'CGNAT' })
    $desconocidas = @($internet | Where-Object { -not $_.Conocida })

    # filas conexiones a internet
    $filasConex = ''
    foreach ($c in ($establecidas | Sort-Object Tipo, Proceso)) {
        $nombreHost = if ($c.Tipo -eq 'Internet') { Nombre-Host $c.IP } else { '' }
        $marca = if ($c.Tipo -eq 'Internet' -and -not $c.Conocida) { 'nueva' } elseif ($c.Conocida) { 'conocida' } else { '' }
        $cls = switch ($c.Tipo) { 'Internet' { if ($c.Conocida) { 'ok' } else { 'warn' } } 'CGNAT' { 'warn' } default { '' } }
        $filasConex += "<tr class='$cls'><td>$($c.Proceso)</td><td>$($c.Remota)</td><td>$($c.Tipo)</td><td>$nombreHost</td><td>$marca</td></tr>"
    }
    if (-not $filasConex) { $filasConex = "<tr><td colspan='5'>Sin conexiones establecidas</td></tr>" }

    # puertos a la escucha, con riesgo
    $filasEscucha = ''
    foreach ($e in ($escucha | Sort-Object PuertoL -Unique)) {
        $riesgo = $PUERTOS_RIESGO[$e.PuertoL]
        $cls = if ($riesgo) { 'warn' } else { '' }
        $abierto = if ($e.Local -like '0.0.0.0*' -or $e.Local -like '*::*') { 'a toda la red' } else { 'solo local' }
        $filasEscucha += "<tr class='$cls'><td>$($e.PuertoL)</td><td>$($e.Proceso)</td><td>$abierto</td><td>$riesgo</td></tr>"
    }
    if (-not $filasEscucha) { $filasEscucha = "<tr><td colspan='4'>—</td></tr>" }

    # accesos
    $bloqueAccesos = ''
    if (-not $accesosInfo.ok) {
        $bloqueAccesos = "<div class='nota'>Para ver los intentos de inicio de sesión, ejecuta <b>Centinela.cmd</b> como administrador. ($($accesosInfo.error))</div>"
    } else {
        $accesos = $accesosInfo.lista
        $fb = Resumir-Fuerzabruta $accesos
        $exitososRemotos = @($accesos | Where-Object { $_.Clase -eq 'Exitoso' -and $_.Remoto })
        $filasFB = ''
        foreach ($g in ($fb | Select-Object -First 15)) {
            $cls = if ($g.Sospechoso) { 'warn' } else { '' }
            $filasFB += "<tr class='$cls'><td>$($g.Origen)</td><td>$($g.Usuario)</td><td>$($g.Intentos)</td><td>$($g.Ultimo)</td></tr>"
        }
        if (-not $filasFB) { $filasFB = "<tr><td colspan='4'>Sin intentos fallidos 🎉</td></tr>" }
        $filasRem = ''
        foreach ($r in ($exitososRemotos | Sort-Object Fecha -Descending | Select-Object -First 15)) {
            $filasRem += "<tr class='warn'><td>$($r.Fecha)</td><td>$($r.Usuario)</td><td>$($r.Origen)</td><td>Tipo $($r.Logon)</td></tr>"
        }
        if (-not $filasRem) { $filasRem = "<tr><td colspan='4'>Ningún inicio de sesión remoto ✔</td></tr>" }
        $bloqueAccesos = @"
<h2>Intentos de inicio de sesión fallidos (últimas $Horas h)</h2>
<table><tr><th>Origen</th><th>Usuario probado</th><th>Intentos</th><th>Último</th></tr>$filasFB</table>
<h2>Inicios de sesión remotos exitosos</h2>
<table><tr><th>Fecha</th><th>Usuario</th><th>Origen</th><th>Logon</th></tr>$filasRem</table>
"@
    }

    $tiles = @(
        ('Conexiones a internet', $internet.Count),
        ('IP no conocidas', $desconocidas.Count),
        ('Puertos a la escucha', (@($escucha | Select-Object -ExpandProperty PuertoL -Unique)).Count)
    )
    $tilesHtml = ($tiles | ForEach-Object {
        "<div class='tile'><div class='tval'>$($_[1])</div><div class='tlab'>$($_[0])</div></div>"
    }) -join ''

    $html = @"
<!doctype html><html lang='es'><head><meta charset='utf-8'>
<meta name='viewport' content='width=device-width, initial-scale=1'>
<title>Centinela del PC</title>
<style>
body{font-family:Segoe UI,Arial,sans-serif;margin:0;background:#f1f5f9;color:#0f172a}
.wrap{max-width:860px;margin:0 auto;padding:20px}
h1{margin:0 0 2px} .sub{color:#64748b;margin:0 0 16px}
.tiles{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:16px}
.tile{flex:1;min-width:150px;background:#fff;border:1px solid #e2e8f0;border-radius:10px;padding:12px}
.tval{font-size:24px;font-weight:700} .tlab{color:#64748b;font-size:12px}
h2{font-size:16px;margin:18px 0 8px}
table{width:100%;border-collapse:collapse;background:#fff;border:1px solid #e2e8f0;border-radius:10px;overflow:hidden}
th,td{padding:7px 10px;text-align:left;font-size:13px;border-bottom:1px solid #eef2f7}
th{background:#0f172a;color:#fff}
tr.warn td{background:#fef3c7} tr.ok td{background:#ecfdf5}
.nota{background:#fff7ed;border:1px solid #fed7aa;color:#9a3412;padding:10px 12px;border-radius:8px}
.pie{color:#94a3b8;font-size:12px;margin-top:16px}
code{background:#e2e8f0;padding:1px 5px;border-radius:4px}
</style></head><body><div class='wrap'>
<h1>Centinela del PC</h1>
<p class='sub'>$(Get-Date -Format 'dd-MM-yyyy HH:mm') · equipo $env:COMPUTERNAME</p>
<div class='tiles'>$tilesHtml</div>
<h2>Conexiones activas hacia internet</h2>
<p class='sub'>Amarillo = IP de internet que no está en tu lista de conocidas. Si reconoces una (un juego, Discord, tu nube), agrégala a <code>Conocidas.txt</code>.</p>
<table><tr><th>Programa</th><th>IP remota</th><th>Tipo</th><th>Nombre</th><th></th></tr>$filasConex</table>
<h2>Puertos abiertos en tu PC (a la escucha)</h2>
<table><tr><th>Puerto</th><th>Programa</th><th>Expuesto</th><th>Riesgo</th></tr>$filasEscucha</table>
$bloqueAccesos
<p class='pie'>Muchos intentos fallidos desde una misma IP = posible ataque de fuerza bruta. Un inicio remoto que no reconozcas es la señal más importante: cambia tu contraseña y desconéctate de internet si dudas.</p>
</div></body></html>
"@
    Set-Content -Path $ruta -Value $html -Encoding UTF8
    return @{ ruta = $ruta; internet = $internet.Count; desconocidas = $desconocidas.Count }
}

# ------------------------------------------------------------------ una pasada
function Una-Pasada([bool]$abrir) {
    $conns = if ($SoloAccesos) { @() } else { Obtener-Conexiones }
    $accesosInfo = if ($SoloConexiones) { @{ ok = $true; lista = @() } } else { Obtener-Accesos $Horas }

    $info = Generar-Reporte $conns $accesosInfo
    Log ("Conexiones a internet: {0} | IP no conocidas: {1}" -f $info.internet, $info.desconocidas) 'Cyan'
    if ($info.desconocidas -gt 0) {
        Log ("  Hay {0} IP de internet que no reconoces. Revisa el reporte." -f $info.desconocidas) 'Yellow'
    }
    if (-not $SoloConexiones -and -not $accesosInfo.ok) {
        Log '  (Para ver los intentos de inicio de sesión, ejecuta como administrador.)' 'DarkYellow'
    }
    if ($abrir -and $info.ruta) { Start-Process ("file:///" + ($info.ruta -replace '\\', '/')) }
    return $info
}

# ------------------------------------------------------------------ main
Write-Host "== CENTINELA DEL PC ==" -ForegroundColor Cyan
if (-not (Es-Admin) -and -not $SoloConexiones) {
    Write-Host "Sugerencia: ejecútalo como administrador para ver los intentos de inicio de sesión." -ForegroundColor DarkYellow
}

if ($Continuo) {
    Write-Host "Vigilando cada $MinutosCiclo min. Cierra la ventana para detener.`n" -ForegroundColor DarkCyan
    $previo = -1
    while ($true) {
        $info = Una-Pasada $false
        if ($previo -ge 0 -and $info.desconocidas -gt $previo) {
            Write-Host "`a¡Apareció una conexión nueva que no reconoces!" -ForegroundColor Red
        }
        $previo = $info.desconocidas
        Start-Sleep -Seconds ([math]::Max($MinutosCiclo, 1) * 60)
    }
} else {
    Una-Pasada (-not $NoAbrir) | Out-Null
    if (-not $NoAbrir) { Read-Host "`nEnter para salir" }
}
