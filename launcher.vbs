Dim shell
Set shell = CreateObject("WScript.Shell")

' Start Node server silently in background
shell.Run "cmd /c cd /d ""G:\Claude Code\notes-api"" && node server.js", 0, False

' Wait 2 seconds for server to boot
WScript.Sleep 2000

' Open the app in the default browser
shell.Run "http://localhost:3001", 1, False
