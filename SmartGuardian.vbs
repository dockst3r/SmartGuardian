' Abre o SmartGuardian na bandeja, sem janela de console. O próprio app pede administrador (UAC).
Set fso = CreateObject("Scripting.FileSystemObject")
dir = fso.GetParentFolderName(WScript.ScriptFullName)
pythonw = dir & "\.venv\Scripts\pythonw.exe"
If Not fso.FileExists(pythonw) Then
    MsgBox "Ambiente nao encontrado. Rode 'SmartGuardian (terminal).bat' uma vez para prepara-lo.", 48, "SmartGuardian"
    WScript.Quit 1
End If
Set shell = CreateObject("Shell.Application")
shell.ShellExecute pythonw, """" & dir & "\tray.py""", dir, "runas", 1
