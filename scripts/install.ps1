<#
.SYNOPSIS
    Installs the secret-broker command for the current Windows user.

.DESCRIPTION
    Creates the venv in ~/.claude/tools/secret-broker/.venv and writes the `secret-broker` (sh) and
    `secret-broker.cmd` shims into ~/.local/bin, both pointing at secret_broker.py in this repository.
    The venv lives outside the repo so a `git clean` never breaks the command.
#>
$ErrorActionPreference = 'Stop'

$script = Join-Path $PSScriptRoot 'secret_broker.py'
$home_  = $env:USERPROFILE
$venv   = Join-Path $home_ '.claude\tools\secret-broker\.venv'
$bin    = Join-Path $home_ '.local\bin'
$python = Join-Path $venv 'Scripts\python.exe'

if (-not (Test-Path $python)) {
    # tkinter is required for the approval windows; python.org / uv builds include it.
    uv venv --python 3.12 $venv
}
uv pip install --python $python --require-hashes -r (Join-Path $PSScriptRoot 'requirements.txt')

New-Item -ItemType Directory -Force $bin | Out-Null
$posix = '/' + $script.Substring(0, 1).ToLower() + ($script.Substring(2) -replace '\\', '/')
$sh = "#!/bin/sh`nexec `"`$HOME/.claude/tools/secret-broker/.venv/Scripts/python.exe`" `"$posix`" `"`$@`"`n"
[IO.File]::WriteAllText((Join-Path $bin 'secret-broker'), $sh, (New-Object Text.UTF8Encoding($false)))
$cmd = "@`"%USERPROFILE%\.claude\tools\secret-broker\.venv\Scripts\python.exe`" `"$script`" %*`r`n"
[IO.File]::WriteAllText((Join-Path $bin 'secret-broker.cmd'), $cmd, (New-Object Text.UTF8Encoding($false)))

# The tray icon (notifications, mode, history) starts with Windows; `get` in notify mode also starts it on demand.
$pythonw = Join-Path $venv 'Scripts\pythonw.exe'
$startup = [Environment]::GetFolderPath('Startup')
$lnk = (New-Object -ComObject WScript.Shell).CreateShortcut((Join-Path $startup 'secret-broker tray.lnk'))
$lnk.TargetPath = $pythonw
$lnk.Arguments = "`"$script`" tray"
$lnk.WorkingDirectory = $home_
$lnk.Save()

Write-Host "secret-broker -> $script"
Write-Host "Claude Code hook (PreToolUse, matcher Write|Edit|MultiEdit|NotebookEdit|Bash|PowerShell):"
Write-Host "  `"$($python -replace '\\','/')`" `"$($script -replace '\\','/')`" guard-hook"
