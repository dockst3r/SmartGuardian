@echo off
title SmartGuardian
chcp 65001 >nul
cd /d "%~dp0"
rem Sem administrador o Windows esconde o caminho de boa parte dos processos.
net session >nul 2>&1 || (
    powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)
if not exist ".venv\Scripts\python.exe" (
    echo Primeira vez: rode Instalar.bat antes; criando o ambiente agora...
    python -m venv .venv || goto :erro
    ".venv\Scripts\python.exe" -m pip install -q -r requirements.txt || goto :erro
)
".venv\Scripts\python.exe" sg.py processos %*
pause
exit /b
:erro
echo Falha ao preparar o ambiente. O Python esta instalado?
pause
