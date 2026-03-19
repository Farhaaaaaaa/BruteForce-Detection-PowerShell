# -----------------------------------
# Brute Force Detection Script (v4)
# Enhanced Detection + Context + Logging
# -----------------------------------

# Detection threshold
$threshold = 5

# Check interval
$checkInterval = 30

# Log file
$logFile = "incident_log.txt"

Write-Host "Starting Brute Force Monitor..." -ForegroundColor Green

while ($true) {

    $ipTable = @{}
    $userTable = @{}

    # Get failed login events
    $failedEvents = Get-WinEvent -FilterHashtable @{
        LogName = 'Security'
        Id = 4625
    }

    foreach ($event in $failedEvents) {

        $message = $event.Message

        # Extract Source IP
        if ($message -match "Source Network Address:\s+(\S+)") {
            $ip = $matches[1]
        }

        # Extract Username
        if ($message -match "Account Name:\s+(\S+)") {
            $username = $matches[1]
        }

        if ($ip) {

            if ($ipTable.ContainsKey($ip)) {
                $ipTable[$ip]++
            }
            else {
                $ipTable[$ip] = 1
                $userTable[$ip] = $username
            }
        }
    }

    Write-Host "`nChecking login attempts..." -ForegroundColor Cyan

    foreach ($ip in $ipTable.Keys) {

        $attempts = $ipTable[$ip]
        $username = $userTable[$ip]

        if ($attempts -ge $threshold) {

            # Check for successful login (4624)
            $successEvents = Get-WinEvent -FilterHashtable @{
                LogName = 'Security'
                Id = 4624
            }

            $successDetected = $false

            foreach ($success in $successEvents) {

                if ($success.Message -match "Source Network Address:\s+$ip") {
                    $successDetected = $true
                }
            }

            if (-not $successDetected) {

                Write-Host "`n⚠ BRUTE FORCE DETECTED" -ForegroundColor Red
                Write-Host "IP Address: $ip"
                Write-Host "Target Username: $username"
                Write-Host "Failed Attempts: $attempts"

                $alertMessage = @"

[ALERT]
Time: $(Get-Date)
IP Address: $ip
Target Username: $username
Failed Attempts: $attempts
----------------------------------

"@

                $alertMessage | Out-File -FilePath $logFile -Append
            }
        }
    }

    Start-Sleep -Seconds $checkInterval
}