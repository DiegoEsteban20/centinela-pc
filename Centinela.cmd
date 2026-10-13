@echo off
chcp 65001 >NUL
cd /d "%~dp0"
net session >NUL 2>&1
if %errorlevel% NEQ 0 (
  echo Pidiendo permisos de administrador para leer los intentos de inicio de sesion...
  powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -ArgumentList '%*' -Verb RunAs"
  exit /b
)
powershell -NoProfile -ExecutionPolicy Bypass -File "Centinela.ps1" %*
