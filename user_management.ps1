#requires -Version 5.1
#requires -RunAsAdministrator

<#
.SYNOPSIS
    Windows Local User Management Script
.DESCRIPTION
    Comprehensive script for managing local Windows users including creation, deletion, 
    enabling/disabling, password management, and group modifications.
    Uses GUID as username with FirstName, LastName, and Title for user details.
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
    Write-Host "6.  List all existing groups"
    Write-Host "7.  Give existing user admin rights"
    Write-Host "8.  Remove admin rights from a user"
    Write-Host "9.  Change user password"
    Write-Host "10. Modify user groups"
    Write-Host "11. Exit"
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
    
    # Get GUID (username)
    $guid = Read-Host "Enter employee GUID (This will be the username)"
    
    # Check if user already exists
    if (Get-LocalUser -Name $guid -ErrorAction SilentlyContinue) {
        Write-Host "Error: User with GUID '$guid' already exists." -ForegroundColor Red
        return
    }
    
    # Get employee details
    $firstName = Read-Host "Enter First Name"
    $lastName = Read-Host "Enter Last Name"
    $title = Read-Host "Enter Job Title (or press Enter to skip)"
    
    # Construct full name and description
    $fullName = "$firstName $lastName".Trim()
    
    if ([string]::IsNullOrWhiteSpace($title)) {
        $description = $fullName
    }
    else {
        $description = "$fullName - $title"
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
        # Create the user
        $securePass = ConvertTo-SecureStringFromPlain -PlainText $password
        
        $userParams = @{
            Name        = $guid
            Password    = $securePass
            FullName    = $fullName
            Description = $description
        }
        
        New-LocalUser @userParams -ErrorAction Stop | Out-Null
        Write-Host "User '$guid' created successfully." -ForegroundColor Green
        Write-Host "  Full Name: $fullName" -ForegroundColor Cyan
        if (-not [string]::IsNullOrWhiteSpace($title)) {
            Write-Host "  Title: $title" -ForegroundColor Cyan
        }
        
        # Add to Remote Desktop Users group for RDP access
        try {
            Add-LocalGroupMember -Group "Remote Desktop Users" -Member $guid -ErrorAction Stop
            Write-Host "User added to 'Remote Desktop Users' group for RDP access." -ForegroundColor Green
        }
        catch {
            Write-Host "Warning: Could not add user to Remote Desktop Users group - $($_.Exception.Message)" -ForegroundColor Yellow
        }
        
        # Ask if user should be added to Administrators group
        $addAdmin = Read-Host "`nAdd user to Administrators group? (Y/N)"
        if ($addAdmin -eq 'Y' -or $addAdmin -eq 'y') {
            try {
                Add-LocalGroupMember -Group "Administrators" -Member $guid -ErrorAction Stop
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
    
    $guid = Read-Host "Enter the GUID (username) to delete"
    
    # Check if user exists
    $user = Get-LocalUser -Name $guid -ErrorAction SilentlyContinue
    if (-not $user) {
        Write-Host "Error: User with GUID '$guid' does not exist." -ForegroundColor Red
        return
    }
    
    # Display user details
    Write-Host "`nUser Details:" -ForegroundColor Yellow
    Write-Host "  GUID: $($user.Name)"
    Write-Host "  Full Name: $($user.FullName)"
    Write-Host "  Description: $($user.Description)"
    
    # Prevent deletion of critical accounts
    if ($guid -eq "Administrator" -or $guid -eq $env:USERNAME) {
        Write-Host "Error: Cannot delete Administrator or currently logged-in user." -ForegroundColor Red
        return
    }
    
    # Check if user is logged in
    $loggedIn = quser 2>$null | Select-String -Pattern $guid
    if ($loggedIn) {
        Write-Host "Warning: User '$guid' is currently logged in." -ForegroundColor Yellow
        $forceLogout = Read-Host "Do you want to force logout and delete? (Y/N)"
        if ($forceLogout -ne 'Y' -and $forceLogout -ne 'y') {
            Write-Host "User deletion cancelled." -ForegroundColor Yellow
            return
        }
    }
    
    # Check for running processes
    $userProcesses = Get-Process -IncludeUserName -ErrorAction SilentlyContinue | 
                     Where-Object { $_.UserName -like "*\$guid" }
    
    if ($userProcesses) {
        Write-Host "Warning: User '$guid' has running processes (Count: $($userProcesses.Count))" -ForegroundColor Yellow
        $killProcesses = Read-Host "Do you want to kill all processes and delete? (Y/N)"
        if ($killProcesses -ne 'Y' -and $killProcesses -ne 'y') {
            Write-Host "User deletion cancelled." -ForegroundColor Yellow
            return
        }
    }
    
    # Final confirmation
    $confirmation = Read-Host "Are you sure you want to delete user '$guid'? (Y/N)"
    if ($confirmation -ne 'Y' -and $confirmation -ne 'y') {
        Write-Host "User deletion cancelled." -ForegroundColor Yellow
        return
    }
    
    Write-Host "Starting user deletion process..." -ForegroundColor Yellow
    
    # Force logoff and kill processes
    Invoke-ForceLogoff -Username $guid
    
    # Remove from Administrators group if member
    try {
        $adminMembers = Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue
        if ($adminMembers.Name -contains "$env:COMPUTERNAME\$guid") {
            Remove-LocalGroupMember -Group "Administrators" -Member $guid -ErrorAction Stop
            Write-Host "Removed user from Administrators group." -ForegroundColor Green
        }
    }
    catch {
        Write-Host "Warning: Could not remove from Administrators group - $($_.Exception.Message)" -ForegroundColor Yellow
    }
    
    # Delete the user
    try {
        Remove-LocalUser -Name $guid -ErrorAction Stop
        Write-Host "User '$guid' deleted successfully." -ForegroundColor Green
        
        # Delete user profile
        $profilePath = "C:\Users\$guid"
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
    
    $guid = Read-Host "Enter the GUID (username) to enable"
    
    $user = Get-LocalUser -Name $guid -ErrorAction SilentlyContinue
    if (-not $user) {
        Write-Host "Error: User with GUID '$guid' does not exist." -ForegroundColor Red
        return
    }
    
    # Display user details
    Write-Host "`nUser Details:" -ForegroundColor Yellow
    Write-Host "  GUID: $($user.Name)"
    Write-Host "  Full Name: $($user.FullName)"
    Write-Host "  Description: $($user.Description)"
    
    try {
        Enable-LocalUser -Name $guid -ErrorAction Stop
        Write-Host "User '$guid' enabled successfully." -ForegroundColor Green
    }
    catch {
        Write-Host "Error: Failed to enable user - $($_.Exception.Message)" -ForegroundColor Red
    }
}

# Function to disable an existing user
function Disable-LocalUserAccount {
    Write-Host "`n--- Disable User ---" -ForegroundColor Cyan
    
    $guid = Read-Host "Enter the GUID (username) to disable"
    
    $user = Get-LocalUser -Name $guid -ErrorAction SilentlyContinue
    if (-not $user) {
        Write-Host "Error: User with GUID '$guid' does not exist." -ForegroundColor Red
        return
    }
    
    # Display user details
    Write-Host "`nUser Details:" -ForegroundColor Yellow
    Write-Host "  GUID: $($user.Name)"
    Write-Host "  Full Name: $($user.FullName)"
    Write-Host "  Description: $($user.Description)"
    
    # Prevent disabling critical accounts
    if ($guid -eq "Administrator" -or $guid -eq $env:USERNAME) {
        Write-Host "Error: Cannot disable Administrator or currently logged-in user." -ForegroundColor Red
        return
    }
    
    # Check if user is logged in
    $loggedIn = quser 2>$null | Select-String -Pattern $guid
    if ($loggedIn) {
        Write-Host "Warning: User '$guid' is currently logged in." -ForegroundColor Yellow
        $forceLogout = Read-Host "Do you want to force logout and disable? (Y/N)"
        if ($forceLogout -ne 'Y' -and $forceLogout -ne 'y') {
            Write-Host "User disabling cancelled." -ForegroundColor Yellow
            return
        }
    }
    
    # Check for running processes
    $userProcesses = Get-Process -IncludeUserName -ErrorAction SilentlyContinue | 
                     Where-Object { $_.UserName -like "*\$guid" }
    
    if ($userProcesses) {
        Write-Host "Warning: User '$guid' has running processes (Count: $($userProcesses.Count))" -ForegroundColor Yellow
        $killProcesses = Read-Host "Do you want to kill all processes and disable? (Y/N)"
        if ($killProcesses -ne 'Y' -and $killProcesses -ne 'y') {
            Write-Host "User disabling cancelled." -ForegroundColor Yellow
            return
        }
    }
    
    # Final confirmation
    $confirmation = Read-Host "Are you sure you want to disable user '$guid'? (Y/N)"
    if ($confirmation -ne 'Y' -and $confirmation -ne 'y') {
        Write-Host "User disabling cancelled." -ForegroundColor Yellow
        return
    }
    
    Write-Host "Starting user disabling process..." -ForegroundColor Yellow
    
    # Force logoff and kill processes
    Invoke-ForceLogoff -Username $guid
    
    # Disable the user
    try {
        Disable-LocalUser -Name $guid -ErrorAction Stop
        Write-Host "User '$guid' disabled successfully." -ForegroundColor Green
    }
    catch {
        Write-Host "Error: Failed to disable user - $($_.Exception.Message)" -ForegroundColor Red
    }
}

# Function to list all users
function Show-AllUsers {
    Write-Host "`n--- List All Local Users ---" -ForegroundColor Cyan
    
    try {
        $users = Get-LocalUser | Select-Object @{Name="GUID";Expression={$_.Name}}, 
                                               @{Name="FullName";Expression={$_.FullName}},
                                               @{Name="Description";Expression={$_.Description}},
                                               Enabled,
                                               @{Name="LastLogon";Expression={$_.LastLogon}},
                                               @{Name="PasswordExpires";Expression={$_.PasswordExpires}}
        
        $users | Format-Table -AutoSize -Wrap
        
        Write-Host "Total users: $($users.Count)" -ForegroundColor Green
    }
    catch {
        Write-Host "Error: Failed to list users - $($_.Exception.Message)" -ForegroundColor Red
    }
}

# Function to list all existing groups
function Show-AllGroups {
    Write-Host "`n--- List All Local Groups ---" -ForegroundColor Cyan
    
    try {
        $groups = Get-LocalGroup | Select-Object Name, Description, 
                                                 @{Name="MemberCount";Expression={
                                                     (Get-LocalGroupMember -Group $_.Name -ErrorAction SilentlyContinue).Count
                                                 }}
        
        Write-Host "`nLocal Groups on this system:" -ForegroundColor Yellow
        Write-Host ("=" * 80) -ForegroundColor Gray
        
        foreach ($group in $groups) {
            Write-Host "`nGroup Name: " -NoNewline -ForegroundColor Cyan
            Write-Host $group.Name -ForegroundColor White
            Write-Host "Description: " -NoNewline -ForegroundColor Cyan
            Write-Host $group.Description -ForegroundColor Gray
            Write-Host "Members: " -NoNewline -ForegroundColor Cyan
            Write-Host $group.MemberCount -ForegroundColor Green
            
            # Show members if any
            if ($group.MemberCount -gt 0) {
                $members = Get-LocalGroupMember -Group $group.Name -ErrorAction SilentlyContinue
                Write-Host "  Members List:" -ForegroundColor Yellow
                foreach ($member in $members) {
                    $memberName = $member.Name -replace "^$env:COMPUTERNAME\\", ""
                    Write-Host "    - $memberName ($($member.ObjectClass))" -ForegroundColor Gray
                }
            }
            Write-Host ("-" * 80) -ForegroundColor DarkGray
        }
        
        Write-Host "`nTotal groups: $($groups.Count)" -ForegroundColor Green
    }
    catch {
        Write-Host "Error: Failed to list groups - $($_.Exception.Message)" -ForegroundColor Red
    }
}

# Function to give admin rights
function Grant-AdminRights {
    Write-Host "`n--- Give Admin Rights ---" -ForegroundColor Cyan
    
    $guid = Read-Host "Enter the GUID (username) to give admin rights"
    
    $user = Get-LocalUser -Name $guid -ErrorAction SilentlyContinue
    if (-not $user) {
        Write-Host "Error: User with GUID '$guid' does not exist." -ForegroundColor Red
        return
    }
    
    # Display user details
    Write-Host "`nUser Details:" -ForegroundColor Yellow
    Write-Host "  GUID: $($user.Name)"
    Write-Host "  Full Name: $($user.FullName)"
    Write-Host "  Description: $($user.Description)"
    
    # Check if already admin
    $adminMembers = Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue
    if ($adminMembers.Name -contains "$env:COMPUTERNAME\$guid") {
        Write-Host "User '$guid' already has admin rights." -ForegroundColor Yellow
        return
    }
    
    try {
        Add-LocalGroupMember -Group "Administrators" -Member $guid -ErrorAction Stop
        Write-Host "Admin rights granted to user '$guid' successfully." -ForegroundColor Green
    }
    catch {
        Write-Host "Error: Failed to grant admin rights - $($_.Exception.Message)" -ForegroundColor Red
    }
}

# Function to remove admin rights
function Revoke-AdminRights {
    Write-Host "`n--- Remove Admin Rights ---" -ForegroundColor Cyan
    
    $guid = Read-Host "Enter the GUID (username) to remove admin rights"
    
    $user = Get-LocalUser -Name $guid -ErrorAction SilentlyContinue
    if (-not $user) {
        Write-Host "Error: User with GUID '$guid' does not exist." -ForegroundColor Red
        return
    }
    
    # Display user details
    Write-Host "`nUser Details:" -ForegroundColor Yellow
    Write-Host "  GUID: $($user.Name)"
    Write-Host "  Full Name: $($user.FullName)"
    Write-Host "  Description: $($user.Description)"
    
    # Prevent removing admin rights from Administrator
    if ($guid -eq "Administrator") {
        Write-Host "Error: Cannot remove admin rights from Administrator account." -ForegroundColor Red
        return
    }
    
    # Check if user is logged in
    $loggedIn = quser 2>$null | Select-String -Pattern $guid
    if ($loggedIn) {
        Write-Host "Warning: User '$guid' is currently logged in." -ForegroundColor Yellow
        $proceed = Read-Host "Do you want to proceed with removing admin rights? (Y/N)"
        if ($proceed -ne 'Y' -and $proceed -ne 'y') {
            Write-Host "Operation cancelled." -ForegroundColor Yellow
            return
        }
    }
    
    # Check for running processes
    $userProcesses = Get-Process -IncludeUserName -ErrorAction SilentlyContinue | 
                     Where-Object { $_.UserName -like "*\$guid" }
    
    if ($userProcesses) {
        Write-Host "Warning: User '$guid' has running processes (Count: $($userProcesses.Count))" -ForegroundColor Yellow
        $proceed = Read-Host "Do you want to proceed with removing admin rights? (Y/N)"
        if ($proceed -ne 'Y' -and $proceed -ne 'y') {
            Write-Host "Operation cancelled." -ForegroundColor Yellow
            return
        }
    }
    
    # Final confirmation
    $confirmation = Read-Host "Are you sure you want to remove admin rights from '$guid'? (Y/N)"
    if ($confirmation -ne 'Y' -and $confirmation -ne 'y') {
        Write-Host "Operation cancelled." -ForegroundColor Yellow
        return
    }
    
    # Force logoff if needed
    if ($loggedIn -or $userProcesses) {
        Invoke-ForceLogoff -Username $guid
    }
    
    # Check if user is in Administrators group
    $adminMembers = Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue
    if ($adminMembers.Name -notcontains "$env:COMPUTERNAME\$guid") {
        Write-Host "User '$guid' does not have admin rights." -ForegroundColor Yellow
        return
    }
    
    try {
        Remove-LocalGroupMember -Group "Administrators" -Member $guid -ErrorAction Stop
        Write-Host "Admin rights removed from user '$guid' successfully." -ForegroundColor Green
    }
    catch {
        Write-Host "Error: Failed to remove admin rights - $($_.Exception.Message)" -ForegroundColor Red
    }
}

# Function to change user password
function Set-UserPassword {
    Write-Host "`n--- Change User Password ---" -ForegroundColor Cyan
    
    $guid = Read-Host "Enter the GUID (username) to change password"
    
    $user = Get-LocalUser -Name $guid -ErrorAction SilentlyContinue
    if (-not $user) {
        Write-Host "Error: User with GUID '$guid' does not exist." -ForegroundColor Red
        return
    }
    
    # Display user details
    Write-Host "`nUser Details:" -ForegroundColor Yellow
    Write-Host "  GUID: $($user.Name)"
    Write-Host "  Full Name: $($user.FullName)"
    Write-Host "  Description: $($user.Description)"
    
    # Password setup
    $passChoice = Read-Host "`nSet password automatically or manually? (a/m)"
    
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
        Set-LocalUser -Name $guid -Password $securePass -ErrorAction Stop
        Write-Host "Password changed successfully for user '$guid'." -ForegroundColor Green
        
        # Check if user is logged in and force logout
        $loggedIn = quser 2>$null | Select-String -Pattern $guid
        if ($loggedIn) {
            Write-Host "User '$guid' is currently logged in." -ForegroundColor Yellow
            $forceLogout = Read-Host "Force logout user? (Y/N)"
            if ($forceLogout -eq 'Y' -or $forceLogout -eq 'y') {
                Invoke-ForceLogoff -Username $guid
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
    
    $guid = Read-Host "Enter the GUID (username) to modify groups"
    
    $user = Get-LocalUser -Name $guid -ErrorAction SilentlyContinue
    if (-not $user) {
        Write-Host "Error: User with GUID '$guid' does not exist." -ForegroundColor Red
        return
    }
    
    # Display user details
    Write-Host "`nUser Details:" -ForegroundColor Yellow
    Write-Host "  GUID: $($user.Name)"
    Write-Host "  Full Name: $($user.FullName)"
    Write-Host "  Description: $($user.Description)"
    
    # Show current groups
    Write-Host "`nCurrent groups for user '$guid':" -ForegroundColor Yellow
    try {
        $currentGroups = Get-LocalGroup | Where-Object {
            (Get-LocalGroupMember -Group $_.Name -ErrorAction SilentlyContinue).Name -contains "$env:COMPUTERNAME\$guid"
        }
        if ($currentGroups) {
            $currentGroups | ForEach-Object { Write-Host "  - $($_.Name)" -ForegroundColor Cyan }
        }
        else {
            Write-Host "  (No group memberships)" -ForegroundColor Gray
        }
    }
    catch {
        Write-Host "Could not retrieve current groups." -ForegroundColor Yellow
    }
    
    # Show available groups
    Write-Host "`nAvailable local groups:" -ForegroundColor Cyan
    $allGroups = Get-LocalGroup
    $allGroups | ForEach-Object { Write-Host "  - $($_.Name)" -ForegroundColor Gray }
    
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
        if ($members.Name -contains "$env:COMPUTERNAME\$guid") {
            Write-Host "User '$guid' is already a member of group '$group'." -ForegroundColor Yellow
            continue
        }
        
        try {
            Add-LocalGroupMember -Group $group -Member $guid -ErrorAction Stop
            Write-Host "User '$guid' added to group '$group' successfully." -ForegroundColor Green
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
        $choice = Read-Host "`nChoose an option (1-11)"
        
        switch ($choice) {
            '1'  { New-LocalUserAccount }
            '2'  { Remove-LocalUserAccount }
            '3'  { Enable-LocalUserAccount }
            '4'  { Disable-LocalUserAccount }
            '5'  { Show-AllUsers }
            '6'  { Show-AllGroups }
            '7'  { Grant-AdminRights }
            '8'  { Revoke-AdminRights }
            '9'  { Set-UserPassword }
            '10' { Update-UserGroups }
            '11' { 
                Write-Host "`nExiting..." -ForegroundColor Green
                exit 0 
            }
            default { 
                Write-Host "Invalid option. Please choose a number between 1 and 11." -ForegroundColor Red 
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