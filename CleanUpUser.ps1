# ----------------- CLEANUP ACTIONS -----------------

# 1. Clear Browser Data
# Clearing Edge and Internet Explorer browser data
try {
    RunDll32.exe InetCpl.cpl,ClearMyTracksByProcess 255  # Clear all browsing history for IE and Edge
    Write-Host "Cleared browser cache, cookies, and history (Edge & IE)."
} catch {
    Write-Host "Error clearing browser data."
}

# 2. Clear Recent File History
try {
    Remove-Item -Path "$env:APPDATA\Microsoft\Windows\Recent\*" -Recurse -Force
    Remove-Item -Path "$env:APPDATA\Microsoft\Windows\Recent Items\*" -Recurse -Force
    Clear-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU" -Name "*"
    Write-Host "Cleared recent file history."
} catch {
    Write-Host "Error clearing recent file history."
}

# 3. Clear PowerShell History
try {
    $psHistoryPath = "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
    if (Test-Path $psHistoryPath) {
        Remove-Item -Path $psHistoryPath -Force
        Write-Host "Cleared PowerShell command history."
    }
} catch {
    Write-Host "Error clearing PowerShell history."
}

# 4. Clear Clipboard
try {
    Set-Clipboard -Value ""
    Write-Host "Cleared clipboard data."
} catch {
    Write-Host "Error clearing clipboard."
}

# 5. Clear Temp Files
try {
    Remove-Item -Path "$env:TEMP\*" -Recurse -Force
    Write-Host "Cleared temporary files."
} catch {
    Write-Host "Error clearing temporary files."
}

# 6. Clear Windows Prefetch Files
try {
    Remove-Item -Path "C:\Windows\Prefetch\*" -Recurse -Force
    Write-Host "Cleared Windows prefetch files."
} catch {
    Write-Host "Error clearing Windows prefetch files."
}

# Final message to indicate cleanup is complete
Write-Host "System cleanup completed."