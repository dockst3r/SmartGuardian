@echo off
rem Instala ou atualiza o SmartGuardian: ambiente do Python, bibliotecas, atalho no menu Iniciar.
rem Pode rodar de novo depois de um "git pull" para pegar bibliotecas novas.
title SmartGuardian - instalar ou atualizar
chcp 65001 >nul
cd /d "%~dp0"
echo SmartGuardian: instalar ou atualizar
echo.
rem Administrador: a pasta pode estar protegida (Configurações -> Proteger a pasta) e o app roda elevado.
net session >nul 2>&1 || (
    echo Pedindo permissao de administrador...
    powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)

if exist ".venv\Scripts\python.exe" goto :libs
set "PY="
where py >nul 2>&1 && set "PY=py -3"
if not defined PY where python >nul 2>&1 && set "PY=python"
if not defined PY goto :sempython
echo [1/3] Criando o ambiente do Python...
%PY% -m venv .venv || goto :erro

:libs
".venv\Scripts\python.exe" -c "import sys; sys.exit(sys.version_info < (3, 10))" || goto :velho
echo [2/3] Instalando ou atualizando as bibliotecas...
".venv\Scripts\python.exe" -m pip install -q --disable-pip-version-check -r requirements.txt || goto :erro

echo [3/3] Criando o atalho no menu Iniciar...
".venv\Scripts\python.exe" -c "from ui import win; win.set_start_menu(True)" || goto :erro

echo.
echo Pronto. O SmartGuardian aparece na busca do menu Iniciar.
echo Abrindo agora...
start "" ".venv\Scripts\pythonw.exe" "%~dp0tray.py"
ping -n 6 127.0.0.1 >nul
exit /b

:sempython
echo Nao encontrei o Python. Instale o Python 3.12 em https://www.python.org/downloads/
echo (marque "Add python.exe to PATH" na instalacao) e rode este arquivo de novo.
pause
exit /b 1

:velho
echo O Python deste ambiente e antigo demais (precisa ser 3.10 ou mais novo).
echo Apague a pasta .venv, instale o Python 3.12 e rode este arquivo de novo.
pause
exit /b 1

:erro
echo.
echo Algo deu errado (veja a mensagem acima). Confira a conexao com a internet e tente de novo.
pause
exit /b 1
