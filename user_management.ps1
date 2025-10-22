#requires -Version 5.1
#requires -RunAsAdministrator

<#
.SYNOPSIS
    Windows Local User Management Script
.DESCRIPTION
    Comprehensive script for managing local Windows users including creation, deletion, 
    enabling/disabling, password management, and group modifications.
.NOTES
    Must be run with Administrator privileges
#>

# Function to display menu
function Show-Menu {
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "   Windows User Management Script" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "1.  Create a new user"
    Write-Host "2.  Delete an existing user"
    Write-Host "3.  Enable an existing user"
    Write-Host "4.  Disable an existing user"
    Write-Host "5.  List all users"
    Write-Host "6.  Give existing user admin rights"
    Write-Host "7.  Remove admin rights from a user"
    Write-Host "8.  Change user password"
    Write-Host "9.  Modify user groups"
    Write-Host "10. Exit"
    Write-Host "========================================" -ForegroundColor Cyan
}

# Function to generate random password
function New-RandomPassword {
    param(
        [int]$Length = 12
    )
    
    if ($Length -lt 8) {
        $Length = 8
    }
    
    Add-Type -AssemblyName 'System.Web'
    return [System.Web.Security.Membership]::GeneratePassword($Length, 2)
}

# Function to create secure string from plain text
function ConvertTo-SecureStringFromPlain {
    param([string]$PlainText)
    return ConvertTo-SecureString $PlainText -AsPlainText -Force
}

# Function to force logoff user
function Invoke-ForceLogoff {
    param([string]$Username)
    
    try {
        # Get all sessions for the user
        $sessions = quser | Where-Object { $_ -match $Username }
        
        if ($sessions) {
            Write-Host "Logging off user $Username..." -ForegroundColor Yellow
            
            foreach ($session in $sessions) {
                # Extract session ID
                if ($session -match '\s+(\d+)\s+') {
                    $sessionId = $Matches[1]
                    logoff $sessionId /V 2>$null
                    Write-Host "  Session $sessionId logged off" -ForegroundColor Green
                }
            }
            Start-Sleep -Seconds 2
        }
        
        # Kill all user processes
        $processes = Get-Process -IncludeUserName -ErrorAction SilentlyContinue | 
                     Where-Object { $_.UserName -like "*\$Username" }
        
        if ($processes) {
            Write-Host "Terminating processes for user $Username..." -ForegroundColor Yellow
            $processes | Stop-Process -Force -ErrorAction SilentlyContinue
            Write-Host "  Processes terminated" -ForegroundColor Green
            Start-Sleep -Seconds 1
        }
        
        return $true
    }
    catch {
        Write-Host "Warning: Error during logoff - $($_.Exception.Message)" -ForegroundColor Yellow
        return $false
    }
}

# Function to create a new user
function New-LocalUserAccount {
    Write-Host "`n--- Create New User ---" -ForegroundColor Cyan
    
    $username = Read-Host "Enter username"
    
    # Check if user already exists
    if (Get-LocalUser -Name $username -ErrorAction SilentlyContinue) {
        Write-Host "Error: User '$username' already exists." -ForegroundColor Red
        return
    }
    
    $description = Read-Host "Enter the description of the user (or press Enter to skip)"
    
    # Password setup
    $passChoice = Read-Host "Set password automatically or manually? (a/m)"
    
    if ($passChoice -eq 'a') {
        $passLength = Read-Host "Enter desired password length (minimum 8)"
        [int]$length = 8
        if ([int]::TryParse($passLength, [ref]$length) -and $length -ge 8) {
            $password = New-RandomPassword -Length $length
            Write-Host "Generated password: $password" -ForegroundColor Green
        }
        else {
            Write-Host "Invalid length. Using minimum length of 8." -ForegroundColor Yellow
            $password = New-RandomPassword -Length 8
            Write-Host "Generated password: $password" -ForegroundColor Green
        }
    }
    else {
        $securePassword = Read-Host "Enter a strong password (minimum 8 characters)" -AsSecureString
        $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($securePassword)
        $password = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)
        
        if ($password.Length -lt 8) {
            Write-Host "Error: Password must be at least 8 characters long." -ForegroundColor Red
            return
        }
    }
    
    try {
        # Create the user
        $securePass = ConvertTo-SecureStringFromPlain -PlainText $password
        
        $userParams = @{
            Name        = $username
            Password    = $securePass
            FullName    = $username
            Description = if ($description) { $description } else { "" }
        }
        
        New-LocalUser @userParams -ErrorAction Stop | Out-Null
        Write-Host "User '$username' created successfully." -ForegroundColor Green
        
        # Add to Remote Desktop Users group for RDP access
        try {
            Add-LocalGroupMember -Group "Remote Desktop Users" -Member $username -ErrorAction Stop
            Write-Host "User added to 'Remote Desktop Users' group for RDP access." -ForegroundColor Green
        }
        catch {
            Write-Host "Warning: Could not add user to Remote Desktop Users group - $($_.Exception.Message)" -ForegroundColor Yellow
        }
        
        # Ask if user should be added to Administrators group
        $addAdmin = Read-Host "`nAdd user to Administrators group? (Y/N)"
        if ($addAdmin -eq 'Y' -or $addAdmin -eq 'y') {
            try {
                Add-LocalGroupMember -Group "Administrators" -Member $username -ErrorAction Stop
                Write-Host "User added to 'Administrators' group successfully." -ForegroundColor Green
            }
            catch {
                Write-Host "Error: Failed to add user to Administrators group - $($_.Exception.Message)" -ForegroundColor Red
            }
        }
        else {
            Write-Host "User not added to Administrators group." -ForegroundColor Yellow
        }
    }
    catch {
        Write-Host "Error: Failed to create user - $($_.Exception.Message)" -ForegroundColor Red
    }
}

# Function to delete an existing user
function Remove-LocalUserAccount {
    Write-Host "`n--- Delete User ---" -ForegroundColor Cyan
    
    $username = Read-Host "Enter the username to delete"
    
    # Check if user exists
    $user = Get-LocalUser -Name $username -ErrorAction SilentlyContinue
    if (-not $user) {
        Write-Host "Error: User '$username' does not exist." -ForegroundColor Red
        return
    }
    
    # Prevent deletion of critical accounts
    if ($username -eq "Administrator" -or $username -eq $env:USERNAME) {
        Write-Host "Error: Cannot delete Administrator or currently logged-in user." -ForegroundColor Red
        return
    }
    
    # Check if user is logged in
    $loggedIn = quser 2>$null | Select-String -Pattern $username
    if ($loggedIn) {
        Write-Host "Warning: User '$username' is currently logged in." -ForegroundColor Yellow
        $forceLogout = Read-Host "Do you want to force logout and delete? (Y/N)"
        if ($forceLogout -ne 'Y' -and $forceLogout -ne 'y') {
            Write-Host "User deletion cancelled." -ForegroundColor Yellow
            return
        }
    }
    
    # Check for running processes
    $userProcesses = Get-Process -IncludeUserName -ErrorAction SilentlyContinue | 
                     Where-Object { $_.UserName -like "*\$username" }
    
    if ($userProcesses) {
        Write-Host "Warning: User '$username' has running processes (Count: $($userProcesses.Count))" -ForegroundColor Yellow
        $killProcesses = Read-Host "Do you want to kill all processes and delete? (Y/N)"
        if ($killProcesses -ne 'Y' -and $killProcesses -ne 'y') {
            Write-Host "User deletion cancelled." -ForegroundColor Yellow
            return
        }
    }
    
    # Final confirmation
    $confirmation = Read-Host "Are you sure you want to delete user '$username'? (Y/N)"
    if ($confirmation -ne 'Y' -and $confirmation -ne 'y') {
        Write-Host "User deletion cancelled." -ForegroundColor Yellow
        return
    }
    
    Write-Host "Starting user deletion process..." -ForegroundColor Yellow
    
    # Force logoff and kill processes
    Invoke-ForceLogoff -Username $username
    
    # Remove from Administrators group if member
    try {
        $adminMembers = Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue
        if ($adminMembers.Name -contains "$env:COMPUTERNAME\$username") {
            Remove-LocalGroupMember -Group "Administrators" -Member $username -ErrorAction Stop
            Write-Host "Removed user from Administrators group." -ForegroundColor Green
        }
    }
    catch {
        Write-Host "Warning: Could not remove from Administrators group - $($_.Exception.Message)" -ForegroundColor Yellow
    }
    
    # Delete the user
    try {
        Remove-LocalUser -Name $username -ErrorAction Stop
        Write-Host "User '$username' deleted successfully." -ForegroundColor Green
        
        # Delete user profile
        $profilePath = "C:\Users\$username"
        if (Test-Path $profilePath) {
            $deleteProfile = Read-Host "Delete user profile folder '$profilePath'? (Y/N)"
            if ($deleteProfile -eq 'Y' -or $deleteProfile -eq 'y') {
                try {
                    Remove-Item -Path $profilePath -Recurse -Force -ErrorAction Stop
                    Write-Host "User profile deleted successfully." -ForegroundColor Green
                }
                catch {
                    Write-Host "Warning: Could not delete profile folder - $($_.Exception.Message)" -ForegroundColor Yellow
                }
            }
        }
    }
    catch {
        Write-Host "Error: Failed to delete user - $($_.Exception.Message)" -ForegroundColor Red
    }
}

# Function to enable an existing user
function Enable-LocalUserAccount {
    Write-Host "`n--- Enable User ---" -ForegroundColor Cyan
    
    $username = Read-Host "Enter the username to enable"
    
    $user = Get-LocalUser -Name $username -ErrorAction SilentlyContinue
    if (-not $user) {
        Write-Host "Error: User '$username' does not exist." -ForegroundColor Red
        return
    }
    
    try {
        Enable-LocalUser -Name $username -ErrorAction Stop
        Write-Host "User '$username' enabled successfully." -ForegroundColor Green
    }
    catch {
        Write-Host "Error: Failed to enable user - $($_.Exception.Message)" -ForegroundColor Red
    }
}

# Function to disable an existing user
function Disable-LocalUserAccount {
    Write-Host "`n--- Disable User ---" -ForegroundColor Cyan
    
    $username = Read-Host "Enter the username to disable"
    
    $user = Get-LocalUser -Name $username -ErrorAction SilentlyContinue
    if (-not $user) {
        Write-Host "Error: User '$username' does not exist." -ForegroundColor Red
        return
    }
    
    # Prevent disabling critical accounts
    if ($username -eq "Administrator" -or $username -eq $env:USERNAME) {
        Write-Host "Error: Cannot disable Administrator or currently logged-in user." -ForegroundColor Red
        return
    }
    
    # Check if user is logged in
    $loggedIn = quser 2>$null | Select-String -Pattern $username
    if ($loggedIn) {
        Write-Host "Warning: User '$username' is currently logged in." -ForegroundColor Yellow
        $forceLogout = Read-Host "Do you want to force logout and disable? (Y/N)"
        if ($forceLogout -ne 'Y' -and $forceLogout -ne 'y') {
            Write-Host "User disabling cancelled." -ForegroundColor Yellow
            return
        }
    }
    
    # Check for running processes
    $userProcesses = Get-Process -IncludeUserName -ErrorAction SilentlyContinue | 
                     Where-Object { $_.UserName -like "*\$username" }
    
    if ($userProcesses) {
        Write-Host "Warning: User '$username' has running processes (Count: $($userProcesses.Count))" -ForegroundColor Yellow
        $killProcesses = Read-Host "Do you want to kill all processes and disable? (Y/N)"
        if ($killProcesses -ne 'Y' -and $killProcesses -ne 'y') {
            Write-Host "User disabling cancelled." -ForegroundColor Yellow
            return
        }
    }
    
    # Final confirmation
    $confirmation = Read-Host "Are you sure you want to disable user '$username'? (Y/N)"
    if ($confirmation -ne 'Y' -and $confirmation -ne 'y') {
        Write-Host "User disabling cancelled." -ForegroundColor Yellow
        return
    }
    
    Write-Host "Starting user disabling process..." -ForegroundColor Yellow
    
    # Force logoff and kill processes
    Invoke-ForceLogoff -Username $username
    
    # Disable the user
    try {
        Disable-LocalUser -Name $username -ErrorAction Stop
        Write-Host "User '$username' disabled successfully." -ForegroundColor Green
    }
    catch {
        Write-Host "Error: Failed to disable user - $($_.Exception.Message)" -ForegroundColor Red
    }
}

# Function to list all users
function Show-AllUsers {
    Write-Host "`n--- List All Local Users ---" -ForegroundColor Cyan
    
    try {
        $users = Get-LocalUser | Select-Object Name, Enabled, Description, 
                                               @{Name="LastLogon";Expression={$_.LastLogon}},
                                               @{Name="PasswordExpires";Expression={$_.PasswordExpires}}
        
        $users | Format-Table -AutoSize
        
        Write-Host "Total users: $($users.Count)" -ForegroundColor Green
    }
    catch {
        Write-Host "Error: Failed to list users - $($_.Exception.Message)" -ForegroundColor Red
    }
}

# Function to give admin rights
function Grant-AdminRights {
    Write-Host "`n--- Give Admin Rights ---" -ForegroundColor Cyan
    
    $username = Read-Host "Enter the username to give admin rights"
    
    $user = Get-LocalUser -Name $username -ErrorAction SilentlyContinue
    if (-not $user) {
        Write-Host "Error: User '$username' does not exist." -ForegroundColor Red
        return
    }
    
    # Check if already admin
    $adminMembers = Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue
    if ($adminMembers.Name -contains "$env:COMPUTERNAME\$username") {
        Write-Host "User '$username' already has admin rights." -ForegroundColor Yellow
        return
    }
    
    try {
        Add-LocalGroupMember -Group "Administrators" -Member $username -ErrorAction Stop
        Write-Host "Admin rights granted to user '$username' successfully." -ForegroundColor Green
    }
    catch {
        Write-Host "Error: Failed to grant admin rights - $($_.Exception.Message)" -ForegroundColor Red
    }
}

# Function to remove admin rights
function Revoke-AdminRights {
    Write-Host "`n--- Remove Admin Rights ---" -ForegroundColor Cyan
    
    $username = Read-Host "Enter the username to remove admin rights"
    
    $user = Get-LocalUser -Name $username -ErrorAction SilentlyContinue
    if (-not $user) {
        Write-Host "Error: User '$username' does not exist." -ForegroundColor Red
        return
    }
    
    # Prevent removing admin rights from Administrator
    if ($username -eq "Administrator") {
        Write-Host "Error: Cannot remove admin rights from Administrator account." -ForegroundColor Red
        return
    }
    
    # Check if user is logged in
    $loggedIn = quser 2>$null | Select-String -Pattern $username
    if ($loggedIn) {
        Write-Host "Warning: User '$username' is currently logged in." -ForegroundColor Yellow
        $proceed = Read-Host "Do you want to proceed with removing admin rights? (Y/N)"
        if ($proceed -ne 'Y' -and $proceed -ne 'y') {
            Write-Host "Operation cancelled." -ForegroundColor Yellow
            return
        }
    }
    
    # Check for running processes
    $userProcesses = Get-Process -IncludeUserName -ErrorAction SilentlyContinue | 
                     Where-Object { $_.UserName -like "*\$username" }
    
    if ($userProcesses) {
        Write-Host "Warning: User '$username' has running processes (Count: $($userProcesses.Count))" -ForegroundColor Yellow
        $proceed = Read-Host "Do you want to proceed with removing admin rights? (Y/N)"
        if ($proceed -ne 'Y' -and $proceed -ne 'y') {
            Write-Host "Operation cancelled." -ForegroundColor Yellow
            return
        }
    }
    
    # Final confirmation
    $confirmation = Read-Host "Are you sure you want to remove admin rights from '$username'? (Y/N)"
    if ($confirmation -ne 'Y' -and $confirmation -ne 'y') {
        Write-Host "Operation cancelled." -ForegroundColor Yellow
        return
    }
    
    # Force logoff if needed
    if ($loggedIn -or $userProcesses) {
        Invoke-ForceLogoff -Username $username
    }
    
    # Check if user is in Administrators group
    $adminMembers = Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue
    if ($adminMembers.Name -notcontains "$env:COMPUTERNAME\$username") {
        Write-Host "User '$username' does not have admin rights." -ForegroundColor Yellow
        return
    }
    
    try {
        Remove-LocalGroupMember -Group "Administrators" -Member $username -ErrorAction Stop
        Write-Host "Admin rights removed from user '$username' successfully." -ForegroundColor Green
    }
    catch {
        Write-Host "Error: Failed to remove admin rights - $($_.Exception.Message)" -ForegroundColor Red
    }
}

# Function to change user password
function Set-UserPassword {
    Write-Host "`n--- Change User Password ---" -ForegroundColor Cyan
    
    $username = Read-Host "Enter the username to change password"
    
    $user = Get-LocalUser -Name $username -ErrorAction SilentlyContinue
    if (-not $user) {
        Write-Host "Error: User '$username' does not exist." -ForegroundColor Red
        return
    }
    
    # Password setup
    $passChoice = Read-Host "Set password automatically or manually? (a/m)"
    
    if ($passChoice -eq 'a') {
        $passLength = Read-Host "Enter desired password length (minimum 8)"
        [int]$length = 8
        if ([int]::TryParse($passLength, [ref]$length) -and $length -ge 8) {
            $password = New-RandomPassword -Length $length
            Write-Host "Generated password: $password" -ForegroundColor Green
        }
        else {
            Write-Host "Invalid length. Using minimum length of 8." -ForegroundColor Yellow
            $password = New-RandomPassword -Length 8
            Write-Host "Generated password: $password" -ForegroundColor Green
        }
    }
    else {
        $securePassword = Read-Host "Enter a strong password (minimum 8 characters)" -AsSecureString
        $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($securePassword)
        $password = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)
        
        if ($password.Length -lt 8) {
            Write-Host "Error: Password must be at least 8 characters long." -ForegroundColor Red
            return
        }
    }
    
    try {
        $securePass = ConvertTo-SecureStringFromPlain -PlainText $password
        Set-LocalUser -Name $username -Password $securePass -ErrorAction Stop
        Write-Host "Password changed successfully for user '$username'." -ForegroundColor Green
        
        # Check if user is logged in and force logout
        $loggedIn = quser 2>$null | Select-String -Pattern $username
        if ($loggedIn) {
            Write-Host "User '$username' is currently logged in." -ForegroundColor Yellow
            $forceLogout = Read-Host "Force logout user? (Y/N)"
            if ($forceLogout -eq 'Y' -or $forceLogout -eq 'y') {
                Invoke-ForceLogoff -Username $username
            }
        }
    }
    catch {
        Write-Host "Error: Failed to change password - $($_.Exception.Message)" -ForegroundColor Red
    }
}

# Function to modify user groups
function Update-UserGroups {
    Write-Host "`n--- Modify User Groups ---" -ForegroundColor Cyan
    
    $username = Read-Host "Enter the username to modify groups"
    
    $user = Get-LocalUser -Name $username -ErrorAction SilentlyContinue
    if (-not $user) {
        Write-Host "Error: User '$username' does not exist." -ForegroundColor Red
        return
    }
    
    # Show current groups
    Write-Host "`nCurrent groups for user '$username':" -ForegroundColor Yellow
    try {
        $currentGroups = Get-LocalGroup | Where-Object {
            (Get-LocalGroupMember -Group $_.Name -ErrorAction SilentlyContinue).Name -contains "$env:COMPUTERNAME\$username"
        }
        $currentGroups | ForEach-Object { Write-Host "  - $($_.Name)" }
    }
    catch {
        Write-Host "Could not retrieve current groups." -ForegroundColor Yellow
    }
    
    # Show available groups
    Write-Host "`nAvailable local groups:" -ForegroundColor Cyan
    $allGroups = Get-LocalGroup
    $allGroups | ForEach-Object { Write-Host "  - $($_.Name)" }
    
    $groupsToAdd = Read-Host "`nEnter the groups to add the user to (comma-separated)"
    
    if ([string]::IsNullOrWhiteSpace($groupsToAdd)) {
        Write-Host "No groups specified. Operation cancelled." -ForegroundColor Yellow
        return
    }
    
    $groupsArray = $groupsToAdd -split ',' | ForEach-Object { $_.Trim() }
    
    foreach ($group in $groupsArray) {
        if ([string]::IsNullOrWhiteSpace($group)) { continue }
        
        # Check if group exists
        $groupExists = Get-LocalGroup -Name $group -ErrorAction SilentlyContinue
        if (-not $groupExists) {
            Write-Host "Error: Group '$group' does not exist." -ForegroundColor Red
            Write-Host "Please make sure to add and configure the group first." -ForegroundColor Yellow
            continue
        }
        
        # Check if user is already in the group
        $members = Get-LocalGroupMember -Group $group -ErrorAction SilentlyContinue
        if ($members.Name -contains "$env:COMPUTERNAME\$username") {
            Write-Host "User '$username' is already a member of group '$group'." -ForegroundColor Yellow
            continue
        }
        
        try {
            Add-LocalGroupMember -Group $group -Member $username -ErrorAction Stop
            Write-Host "User '$username' added to group '$group' successfully." -ForegroundColor Green
        }
        catch {
            Write-Host "Error: Failed to add user to group '$group' - $($_.Exception.Message)" -ForegroundColor Red
        }
    }
}

# Main script loop
try {
    # Check if running as administrator
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    
    if (-not $isAdmin) {
        Write-Host "Error: This script must be run as Administrator!" -ForegroundColor Red
        Write-Host "Right-click PowerShell and select 'Run as Administrator'" -ForegroundColor Yellow
        pause
        exit 1
    }
    
    Write-Host "Windows User Management Script" -ForegroundColor Green
    Write-Host "Running with Administrator privileges`n" -ForegroundColor Green
    
    while ($true) {
        Show-Menu
        $choice = Read-Host "`nChoose an option (1-10)"
        
        switch ($choice) {
            '1'  { New-LocalUserAccount }
            '2'  { Remove-LocalUserAccount }
            '3'  { Enable-LocalUserAccount }
            '4'  { Disable-LocalUserAccount }
            '5'  { Show-AllUsers }
            '6'  { Grant-AdminRights }
            '7'  { Revoke-AdminRights }
            '8'  { Set-UserPassword }
            '9'  { Update-UserGroups }
            '10' { 
                Write-Host "`nExiting..." -ForegroundColor Green
                exit 0 
            }
            default { 
                Write-Host "Invalid option. Please choose a number between 1 and 10." -ForegroundColor Red 
            }
        }
        
        Write-Host ""
        pause
    }
}
catch {
    Write-Host "Critical Error: $($_.Exception.Message)" -ForegroundColor Red
    pause
    exit 1
}