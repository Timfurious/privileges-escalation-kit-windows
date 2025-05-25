<#
.SYNOPSIS
    Creates a deliberately misconfigured Windows service to demonstrate insecure service permissions.

.DESCRIPTION
    This PowerShell script sets up a vulnerable Windows service by:
    - Creating a directory and dummy executable
    - Giving a low-privileged user full control of the service path
    - Creating a service running as SYSTEM
    - Applying insecure service permissions

.NOTES
    Author: Timfurious
    Date: 2025-05-25
    For lab use only.
#>

# ----------------------------
# Configuration
# ----------------------------

# Replace with your local user (no domain)
$User = "test"

# Service details
$ServiceName = "VulnService"
$ServiceDisplayName = "Vulnerable Service"
$ServiceFolder = "C:\VulnService"
$ServiceExePath = "$ServiceFolder\service.exe"

# ----------------------------
# Step 1: Create the service folder
# ----------------------------

Write-Host "[+] Creating service folder at $ServiceFolder"
New-Item -Path $ServiceFolder -ItemType Directory -Force | Out-Null

Write-Host "[+] Creating dummy executable at $ServiceExePath"
"echo Hello from SYSTEM!" | Out-File -FilePath $ServiceExePath -Encoding ASCII -Force

# ----------------------------
# Step 2: Set permissions on folder
# ----------------------------

Write-Host "[+] Granting full control of folder to user '$User'"
icacls $ServiceFolder /grant "$User:(OI)(CI)F" /T

# ----------------------------
# Step 3: Create the service
# ----------------------------

Write-Host "[+] Creating Windows service '$ServiceName'"
New-Service -Name $ServiceName `
            -BinaryPathName "`"$ServiceExePath`"" `
            -DisplayName $ServiceDisplayName `
            -StartupType Manual

# ----------------------------
# Step 4: Apply insecure permissions
# ----------------------------

# This SDDL gives "Authenticated Users" full control over the service config
$InsecureSDDL = "D:(A;;CCLCSWRPWPDTLOCRRC;;;AU)"

Write-Host "[+] Applying insecure service permissions"
Start-Process -FilePath "sc.exe" -ArgumentList "sdset $ServiceName $InsecureSDDL" -Wait -NoNewWindow

# ----------------------------
# Done
# ----------------------------

Write-Host "`n[+] Done!"
Write-Host "[!] '$User' now has full control over the service and its binary."
