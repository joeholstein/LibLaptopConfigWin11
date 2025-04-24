# Add a switch for testing
param (
    [switch]$WhatIf
)

# ----------------- CLEANUP ACTIONS -----------------

# Function to log messages to a file
function Write-Log {
    param ([string]$Message)
    $logFile = "$env:USERPROFILE\Desktop\CleanupLog.txt"
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$timestamp $Message" | Out-File -FilePath $logFile -Append
}

# 1. Clear Browser Data
# Clearing Edge and Internet Explorer browser data
try {
    RunDll32.exe InetCpl.cpl,ClearMyTracksByProcess 255  # Clear all browsing history for IE and Edge
    Write-Host "Cleared browser cache, cookies, and history (Edge & IE)."
} catch {
    Write-Host "Error clearing browser data: $_" -ForegroundColor Red
    Write-Log "Error clearing browser data: $_"
}

# 2. Clear Recent File History
try {
    # Check and clear recent files
    $recentPath = "$env:APPDATA\Microsoft\Windows\Recent\*"
    if (Test-Path $recentPath) {
        Remove-Item -Path $recentPath -Recurse -Force
        Write-Host "Cleared recent files."
        Write-Log "Cleared recent files."
    } else {
        Write-Host "Recent files path not found. Skipping."
        Write-Log "Recent files path not found. Skipping."
    }

    # Check and clear recent items
    $recentItemsPath = "$env:APPDATA\Microsoft\Windows\Recent Items\*"
    if (Test-Path $recentItemsPath) {
        Remove-Item -Path $recentItemsPath -Recurse -Force
        Write-Host "Cleared recent items."
        Write-Log "Cleared recent items."
    } else {
        Write-Host "Recent items path not found. Skipping."
        Write-Log "Recent items path not found. Skipping."
    }

    # Check and clear RunMRU registry keys
    if (Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU") {
        Clear-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU" -Name "*" -ErrorAction SilentlyContinue
        Write-Host "Cleared recent file history from RunMRU."
        Write-Log "Cleared recent file history from RunMRU."
    } else {
        Write-Host "RunMRU registry key not found. Skipping."
        Write-Log "RunMRU registry key not found. Skipping."
    }
} catch {
    Write-Host "Error clearing recent file history: $_" -ForegroundColor Red
    Write-Log "Error clearing recent file history: $_"
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
    if (Get-Command Clear-Clipboard -ErrorAction SilentlyContinue) {
        Clear-Clipboard
    } else {
        Set-Clipboard -Value "."
    }
    Write-Host "Cleared clipboard data."
    Write-Log "Cleared clipboard data."
} catch {
    Write-Host "Error clearing clipboard: $_" -ForegroundColor Red
    Write-Log "Error clearing clipboard: $_"
}

# 5. Clear Temp Files
try {
    Get-ChildItem -Path "$env:TEMP\*" -Recurse -Force | Remove-Item -Force -ErrorAction SilentlyContinue
    Write-Host "Cleared temporary files."
    Write-Log "Cleared temporary files."
} catch {
    Write-Host "Error clearing temporary files: $_" -ForegroundColor Red
    Write-Log "Error clearing temporary files: $_"
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
Write-Host "`nCleanup completed. Check the log file for details: $logFile" -ForegroundColor Green
Write-Log "Cleanup completed."