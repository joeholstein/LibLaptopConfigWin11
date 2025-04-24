# Enable TLS for secure downloads
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# Set up log file with timestamp (YearMonthDayHourMinute)
$timestamp = Get-Date -Format "yyyyMMddHHmm"
$logPath = "$env:USERPROFILE\Desktop\install_log_$timestamp.txt"

# Remove log files older than 7 days
Get-ChildItem -Path "$env:USERPROFILE\Desktop" -Filter "install_log_*.txt" |
    Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-7) } |
    Remove-Item -Force

# Function to log messages to both console and file
function Write-Log {
    param (
        [string]$Message
    )
    $Message | Tee-Object -FilePath $logPath -Append
}

# Check if winget is available
if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
    Write-Log "❌ Winget is not installed or not available in PATH. Exiting..."
    exit 1
}

# Function to install or upgrade applications with Winget
function Install-Or-UpgradeApp {
    param ($AppId)

    Write-Log "`nChecking $AppId..."

    try {
        # Wrap the AppId in double quotes to handle special characters
        $installed = winget list --id "`"$AppId`"" -e | Select-String $AppId

        if ($installed) {
            Write-Log "$AppId is already installed. Attempting to upgrade..."
            winget upgrade --id "`"$AppId`"" -e --accept-package-agreements --accept-source-agreements 2>&1 | Tee-Object -FilePath $logPath -Append
        } else {
            Write-Log "$AppId is not installed. Installing..."
            winget install --id "`"$AppId`"" -e --accept-package-agreements --accept-source-agreements 2>&1 | Tee-Object -FilePath $logPath -Append
        }
    } catch {
        Write-Log "❌ Error processing ${AppId}: $_"
        Write-Log "Command that failed: winget list --id $AppId -e"
    }
}

# List of apps to install or upgrade
$apps = @(
    "git.git",
    'Notepad++.Notepad++',
    "7zip.7zip",
    "VLC.VLC",
    "Adobe.Acrobat.Reader.64-bit",
    "Bambulab.Bambustudio",
    "Flashforge.FlashPrint",
    "Inkscape.Inkscape",
    "OrcaSlicer",
    "PDFgear.PDFgear"
)

# Start logging
Write-Log "===== Application Installation Started: $(Get-Date) ====="

foreach ($app in $apps) {
    if ($app -notmatch "^[a-zA-Z0-9\.\+\-]+$") {
        Write-Log "❌ Invalid AppId format: $app. Skipping..."
        continue
    }
    Install-Or-UpgradeApp -AppId $app
}

Write-Log "`n✅ All applications are now up to date!"
Write-Log "===== Script Completed: $(Get-Date) ====="

# Summary report
Write-Log "`n===== Summary Report ====="
Write-Log "Installed or Upgraded Applications:"
$apps | ForEach-Object { Write-Log "- $_" }
Write-Log "Check the log file for details: $logPath"
