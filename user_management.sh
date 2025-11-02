#!/bin/bash

# Ensure the script is run as root
if [ "$EUID" -ne 0 ]; then
    echo "This script must be run as root. Please run with sudo or as root user."
    exit 1
fi

# Function to display menu
display_menu() {
    echo "User Management Script"
    echo "1. Create a new user"
    echo "2. Delete an existing user"
    echo "3. Enable an existing user"
    echo "4. Disable an existing user"
    echo "5. List all users"
    echo "6. List all existing groups"
    echo "7. Give existing user admin rights"
    echo "8. Remove admin rights from a user"
    echo "9. Change user password"
    echo "10. Modify user groups"
    echo "11. View logs"
    echo "12. Exit"
}

#Function to detect Linux distro
get_linux_distribution() {
    if [ -f /etc/os-release ]; then
        # Source /etc/os-release to load distribution variables (e.g. ID, NAME,
        # VERSION_ID). This makes $ID available for distro detection. Sourcing
        # is common and acceptable on managed Linux servers; if you prefer not
        # to execute the file, parse it instead (for example with awk/grep).
        . /etc/os-release
        echo "$ID"
    elif [ -f /etc/debian_version ]; then
        echo "debian"
    elif [ -f /etc/redhat-release ]; then
        echo "rhel"
    else
        echo "unknown"
    fi
    log_activity "Detected Linux distribution: $ID"
}

# Function to logging user management activities
log_activity(){
    log_message=$1
    log_file="/var/log/user_management.log"
    if [ ! -f "$log_file" ]; then
        touch "$log_file"
        chmod 600 "$log_file"
    fi
     # Verify if the logfile is created successfully
    if [ $? -ne 0 ]; then 
       echo "Error: Failed to create log file $log_file"
       return 1
    else 
        echo "Log file created successfully: $log_file"
    fi   

    # Append log message with timestamp
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $log_message" >> "$log_file"
}

# Function to view and monitor logs
view_logs() {
    log_file="/var/log/user_management.log"
    if [ ! -f "$log_file" ]; then
        echo "Log file does not exist."
        return 1
    fi

    echo "The viewing is using 'less' command. Use 'q' to quit."
    echo "Displaying log file: $log_file"
    less "$log_file"
}

# Function to set user password based on OS distro
set_user_password() {
    username=$1
    password=$2
    distro=$(get_linux_distribution)
    # distro=$(awk -F= '/^ID=/{gsub(/"/,"",$2); print $2; exit}' /etc/os-release)

    case "$distro" in 
        "ubuntu"|"debian"|"pop"|"mint"|"kali")
            # Debian/Ubuntu based systems
            echo "$username:$password" | chpasswd
            ;;
        "rhel"|"centos"|"fedora"|"rocky"|"alma"|"amazon"|"oracle"|"ol"|"amzn"|"almalinux")
            # RHEL based systems
            echo "$password" | passwd --stdin "$username"
            ;;  
        "suse"|"opensuse"|"sles")
            # SUSE based systems
            echo "$password" | passwd --stdin "$username"
            ;;
        "arch"|"manjaro")
            # Arch based systems
            echo "$username:$password" | chpasswd
            ;;
        *) 
           # Fallback method that works on most Linux distros
           (echo "$password"; echo "$password") | passwd "$username"
           ;;
    esac

    # Verify if the password is set successfully
    if [ $? -ne 0 ]; then 
       echo "Error: Failed to set password for user $username"
       log_activity "Failed to set password for user $username"
       return 1
    else 
        echo "Password set successfully for user $username"
        log_activity "Password set successfully for user $username"
    fi          
}

# Function to create a new user
create_user() {
    read -p "Enter username: " username
    read -p "Enter the guid for the user (This is mandatory): " user_guid
    if id -u "$user_guid" >/dev/null 2>&1; then
        echo "User with guid $user_guid already exists. Please choose a different guid."
        log_activity "Attempted to create user with existing guid $user_guid"
        return
    fi
    
    read -p "Enter the description of the user (or press Enter to skip): " user_desc
    read -p "Set password automatically or manually? (a/m): " pass_choice
    if [ "$pass_choice" == "a" ]; then
        read -p "Enter desired password length (minimum 8): " pass_length
        if [ "$pass_length" -lt 8 ]; then
            echo "Password length must be at least 8 characters."
            log_activity "Failed to create user $user_guid: Password length must be at least 8 characters."
            return
        fi
        # Try to generate password with OpenSSL first
        if command -v openssl &>/dev/null; then
            password=$(openssl rand -base64 $((pass_length * 3 / 4)) 2>/dev/null)
            if [ $? -ne 0 ] || [ -z "$password" ]; then
                echo "Warning: OpenSSL failed. Using alternative method..."
                log_activity "Failed to create user $user_guid: OpenSSL failed."
                password=$(tr -dc 'A-Za-z0-9!@#$%^&*()_+' < /dev/urandom | head -c "$pass_length")
            fi
        else
            echo "Warning: OpenSSL not found. Using alternative password generation method..."
            log_activity "Failed to create user $user_guid: OpenSSL not found."
            password=$(tr -dc 'A-Za-z0-9!@#$%^&*()_+' < /dev/urandom | head -c "$pass_length")
            
        fi
        echo "Generated password: $password"
    else
        read -s -p "Enter a strong password with minimum 8 characters: " password
        if [ ${#password} -lt 8 ]; then
            echo
            echo "Password must be at least 8 characters long."
            log_activity "Failed to create user $user_guid: Password length must be at least 8 characters."
            return
        fi
    fi

    useradd -c "$username - $user_desc" -d "/home/$user_guid" -m -s /bin/bash "$user_guid"
    if [ $? -ne 0 ]; then
        echo "Error: Failed to create user $user_guid."
        log_activity "Failed to create user $user_guid"
        return 1
    fi

    set_user_password "$user_guid" "$password"

    if [ $? -ne 0 ]; then
        echo "Error: Failed to set password for user $user_guid."
        log_activity "Failed to set password for user $user_guid after creation."
        return 1
    fi
    
    echo "User $user_guid created successfully."
    log_activity "User $user_guid created successfully."
}

# Function to delete an existing user (In industry, we doesn't prefer to delete a user permanently for audit and compliance reasons.)
# Function to delete an existing user with process termination and sudo cleanup
delete_user() {
    read -p "Enter the username(guid) of the user to delete: " user_guid
    
    if ! getent passwd "$user_guid" >/dev/null; then
        echo "User $user_guid does not exist."
        log_activity "Attempted to delete non-existent user $user_guid"
        return
    fi
    
    # Prevent deletion of root user
    if [ "$user_guid" == "root" ]; then
        echo "Error: Cannot delete root user."
        log_activity "Attempted to delete root user"
        return
    fi
    
    # Check if user is currently logged in
    if who | grep -q "^$user_guid "; then
        echo "Warning: User $user_guid is currently logged in."
        read -p "Do you want to force logout and delete? (y/n): " force_logout
        if [ "$force_logout" != "y" ]; then
            echo "User deletion cancelled."
            log_activity "Cancelled deletion of logged-in user $user_guid"
            return
        fi
    fi
    
    # Check if user has running processes
    user_processes=$(pgrep -u "$user_guid" 2>/dev/null)
    if [ -n "$user_processes" ]; then
        echo "Warning: User $user_guid has running processes (PIDs: $(echo $user_processes | tr '\n' ' '))"
        read -p "Do you want to kill all processes and delete? (y/n): " kill_processes
        if [ "$kill_processes" != "y" ]; then
            echo "User deletion cancelled."
            log_activity "Cancelled deletion of user $user_guid with running processes"
            return
        fi
    fi
    
    # Final confirmation
    echo "Are you sure you want to delete user $user_guid? (y/n): "
    read confirmation
    if [ "$confirmation" != "y" ]; then
        echo "User deletion cancelled."
        log_activity "Cancelled deletion of user $user_guid"
        return
    fi
    
    echo "Starting user deletion process..."
    
    # Step 1: Kill all user processes
    if [ -n "$user_processes" ]; then
        echo "Terminating user processes..."
        pkill -9 -u "$user_guid" 2>/dev/null
        log_activity "Terminated processes of user $user_guid"
        sleep 1
        
        # Force kill any remaining processes
        if pgrep -u "$user_guid" >/dev/null 2>&1; then
            echo "Force killing remaining processes..."
            pkill -9 -u "$user_guid" 2>/dev/null
            log_activity "Force killed remaining processes of user $user_guid"
            sleep 1
        fi
    fi
    
    # Step 2: Logout user sessions
    if who | grep -q "^$user_guid "; then
        echo "Logging out user sessions..."
        # Kill all login shells and sessions
        pkill -KILL -u "$user_guid" 2>/dev/null
        log_activity "Logged out sessions of user $user_guid"
        sleep 1
    fi
    
    # Step 3: Remove sudo privileges
    echo "Checking and removing sudo privileges..."
    
    # Check if user has sudo privileges in /etc/sudoers.d/
    if [ -f "/etc/sudoers.d/$user_guid" ]; then
        echo "Commenting out sudo entry in /etc/sudoers.d/$user_guid"
        sed -i "s/^$user_guid\s/#$user_guid /" "/etc/sudoers.d/$user_guid"
        log_activity "Commented out sudo entry in /etc/sudoers.d/$user_guid"
        # Optionally delete the file instead
        # rm -f "/etc/sudoers.d/$user_guid"
    fi
    
    # Check and comment out entries in /etc/sudoers
    if grep -q "^[[:space:]]*$user_guid[[:space:]]" /etc/sudoers; then
        echo "Commenting out sudo entry in /etc/sudoers"
        # Create backup
        cp /etc/sudoers /etc/sudoers.bak.$(date +%Y%m%d_%H%M%S)
        # Comment out the user's sudo line
        sed -i "s/^[[:space:]]*$user_guid[[:space:]]/#$user_guid /" /etc/sudoers
        log_activity "Commented out sudo entry in /etc/sudoers for user $user_guid"
    fi

     # For redhat based system remove from wheel group
    distro=$(get_linux_distribution)
    if [[ "$distro" == "rhel" || "$distro" == "centos" || "$distro" == "fedora" || "$distro" == "rocky" || "$distro" == "alma" || "$distro" == "amazon" || "$distro" == "oracle" || "$distro" == "ol" || "$distro" == "amzn" || "$distro" == "almalinux" ]]; then
        if groups "$user_guid" | grep -q "\bwheel\b"; then
            echo "Removing user $user_guid from wheel group"
            gpasswd -d "$user_guid" wheel
            log_activity "Removed user $user_guid from wheel group"
        fi
    elif [[ "$distro" == "debian" || "$distro" == "ubuntu" || "$distro" == "pop" || "$distro" == "mint" || "$distro" == "kali" ]]; then
        # For Debian based systems remove from sudo group
        if groups "$user_guid" | grep -q "\bsudo\b"; then
            echo "Removing user $user_guid from sudo group"
            gpasswd -d "$user_guid" sudo
            log_activity "Removed user $user_guid from sudo group"
        fi    
    fi  

    # Verification
    user_groups=$(groups "$user_guid" 2>/dev/null)

    # Check for ACTIVE (uncommented) sudoers entries in /etc/sudoers
    active_sudoers=$(grep -E "^[[:space:]]*${user_guid}[[:space:]]" /etc/sudoers 2>/dev/null)

    # Check for ACTIVE (uncommented) sudoers entries in /etc/sudoers.d/ file
    active_sudoers_d=""
    if [ -f "/etc/sudoers.d/$user_guid" ]; then
        active_sudoers_d=$(grep -E "^[[:space:]]*${user_guid}[[:space:]]" "/etc/sudoers.d/$user_guid" 2>/dev/null)
    fi

    # Check if user still has admin rights
    if [ -n "$active_sudoers" ] || [ -n "$active_sudoers_d" ] || [[ "$user_groups" =~ \b(wheel|sudo)\b ]]; then
        echo "Error: Failed to remove admin rights from user $user_guid."
        log_activity "Failed to remove admin rights from user $user_guid."
    else
        echo "Admin rights removed from user $user_guid successfully."
        log_activity "Successfully removed admin rights from user $user_guid."
    fi

    
    # Step 4: Delete the user
    echo "Deleting user account and home directory..."
    userdel -r "$user_guid" 2>/dev/null
    
    if [ $? -ne 0 ]; then
        echo "Error: Failed to delete user $user_guid."
        echo "Attempting force deletion..."
        userdel -f -r "$user_guid" 2>/dev/null
        
        if [ $? -ne 0 ]; then
            echo "Error: Force deletion also failed. Manual intervention may be required."
            log_activity "Failed to delete user $user_guid even after force deletion."
            return 1
        else
            echo "User $user_guid force deleted successfully."
            log_activity "User $user_guid force deleted successfully."
        fi
    else
        echo "User $user_guid deleted successfully."
        log_activity "User $user_guid deleted successfully."
    fi
    
    # Step 5: Verify deletion
    if getent passwd "$user_guid" >/dev/null 2>&1; then
        echo "Warning: User still exists in the system. Manual cleanup may be required."
        log_activity "User $user_guid still exists after deletion attempt."
    else
        echo "User deletion completed and verified."
        log_activity "User $user_guid deletion completed and verified."
    fi
}

# Function to enable an existing user
enable_user() {
    read -p "Enter the username(guid) of the user to enable: " user_guid
    if ! getent passwd "$user_guid" >/dev/null; then
        echo "User $user_guid does not exist."
        log_activity "Attempted to enable non-existent user $user_guid."
        return
    else
        usermod -U "$user_guid"
        if [ $? -ne 0 ]; then
            echo "Error: Failed to enable user $user_guid."
            log_activity "Failed to enable user $user_guid."
        else
            echo "User $user_guid enabled successfully."
            log_activity "User $user_guid enabled successfully."
        fi
    fi
}

# Function to disable an existing user
disable_user() {
    read -p "Enter the username(guid) of the user to disable: " user_guid

    if ! getent passwd "$user_guid" >/dev/null; then
        echo "User $user_guid does not exist."
        log_activity "Attempted to disable non-existent user $user_guid."
        return
    fi

    if [ "$user_guid" == "root" ] || [ "$user_guid" == "$(whoami)" ]; then
        echo "Error: Cannot disable root or the currently logged-in user."
        log_activity "Attempted to disable root or currently logged-in user $user_guid."
        return
    fi
    
    # Check if user is currently logged in
    if who | grep -q "^$user_guid "; then
        echo "Warning: User $user_guid is currently logged in."
        read -p "Do you want to force logout and disable? (y/n): " force_logout
        if [ "$force_logout" != "y" ]; then
            echo "User disabling cancelled."
            log_activity "User disabling cancelled for $user_guid."
            return
        fi
    fi

    # Check if user has running processes
    user_processes=$(pgrep -u "$user_guid" 2>/dev/null)
    if [ -n "$user_processes" ]; then
        echo "Warning: User $user_guid has running processes (PIDs: $(echo "$user_processes" | tr '\n' ' '))"
        read -p "Do you want to kill all processes and disable? (y/n): " kill_processes
        if [ "$kill_processes" != "y" ]; then
            echo "User disabling cancelled."
            log_activity "User disabling cancelled for $user_guid due to running processes."
            return
        fi
    fi

    # Final confirmation
    read -p "Are you sure you want to disable user $user_guid? (y/n): " confirmation
    if [ "$confirmation" != "y" ]; then
        echo "User disabling cancelled."
        log_activity "User disabling cancelled for $user_guid."
        return
    fi

    echo "Starting user disabling process..."
    
    # Step 1: Kill all user processes
    if [ -n "$user_processes" ]; then
        echo "Terminating user processes..."
        pkill -9 -u "$user_guid" 2>/dev/null
        log_activity "Terminated processes of user $user_guid"
        sleep 1
        
        # Force kill any remaining processes
        if pgrep -u "$user_guid" >/dev/null 2>&1; then
            echo "Force killing remaining processes..."
            pkill -9 -u "$user_guid" 2>/dev/null
            log_activity "Force killed remaining processes of user $user_guid"
            sleep 1
        fi
    fi
    
    # Step 2: Logout user sessions
    if who | grep -q "^$user_guid "; then
        echo "Logging out user sessions..."
        pkill -KILL -u "$user_guid" 2>/dev/null
        log_activity "Logged out sessions of user $user_guid"
        sleep 1
    fi

    # Disable the user account
    usermod -L "$user_guid"
    
    if [ $? -ne 0 ]; then
        echo "Error: Failed to disable user $user_guid."
        log_activity "Failed to disable user $user_guid."
    else
        echo "User $user_guid disabled successfully."
        log_activity "User $user_guid disabled successfully."
    fi
}

# List all users
list_users() {
    printf "%-20s %-6s %-12s %-30s %-20s\n" "USER" "UID" "GROUP" "HOME" "SHELL"
    while IFS=: read -r user _ uid gid gecos home shell; do
      group_name=$(getent group "$gid" | cut -d: -f1)
      printf "%-20s %-6s %-12s %-30s %-20s\n" "$user" "$uid" "$group_name" "$home" "$shell"
    done < <(getent passwd)
    log_activity "Listed all users"
}

# List all existing groups
list_groups() {
    printf "%-20s %-6s %-50s\n" "GROUP" "GID" "MEMBERS"
    while IFS=: read -r group _ gid members; do
      printf "%-20s %-6s %-50s\n" "$group" "$gid" "$members"
    done < <(getent group)
    log_activity "Listed all groups"
}

# Give a existing user admin rights
give_admin_rights() {
    read -p "Enter the guid of the user to give admin rights: " user_guid
    if ! id "$user_guid" &>/dev/null; then
        echo "Error: User $user_guid does not exist."
        log_activity "Failed to give admin rights to non-existent user $user_guid."
        return 1
    fi

    if grep -E -q "^\s*${user_guid}\s+ALL=\(ALL\)\s+ALL\b" /etc/sudoers; then
        echo "User $user_guid already has admin rights."
        log_activity "User $user_guid already has admin rights."
        return 0
    elif [ -f "/etc/sudoers.d/$user_guid" ] && grep -E -q "^[[:space:]]*${user_guid}[[:space:]]" "/etc/sudoers.d/$user_guid"; then
        echo "User $user_guid already has admin rights."
        log_activity "User $user_guid already has admin rights."
        return 0  
    else
        echo "Granting admin rights to user $user_guid..."  
        echo "$user_guid    ALL=(ALL)       ALL" > "/etc/sudoers.d/$user_guid"  
        chmod 440 "/etc/sudoers.d/$user_guid"  
    fi
    
    # Alternative approach (appending to /etc/sudoers directly) - not recommended
    # echo "$user_guid    ALL=(ALL)       ALL" >> /etc/sudoers

    if [ $? -ne 0 ]; then
        echo "Error: Failed to give admin rights to user $user_guid."
        echo "Error: Invalid sudoers entry. Admin rights not granted to user $user_guid."
        log_activity "Failed to give admin rights to user $user_guid due to invalid sudoers entry."
    else
        echo "Admin rights granted to user $user_guid successfully."
        log_activity "Admin rights granted to user $user_guid successfully."
    fi
}

# Function to remove admin rights from a user
remove_admin_rights() {
    read -p "Enter the guid of the user to remove admin rights: " user_guid
    if ! id "$user_guid" &>/dev/null; then
        echo "Error: User $user_guid does not exist."
        log_activity "Failed to remove admin rights from non-existent user $user_guid."
        return 1
    fi

    # Prevent admin rights removal from root user
    if [ "$user_guid" == "root" ]; then
        echo "Error: Cannot remove admin rights from root user."
        log_activity "Attempted to remove admin rights from root user."
        return
    fi  
  
    # Check if the user is currently logged in
    if who | grep -q "$user_guid"; then 
        echo "Warning: User $user_guid is currently logged in."
        read -p "Do you want to proceed with removing admin rights? (y/n): " proceed
        if [ "$proceed" != "y" ]; then
            echo "Operation cancelled."
            log_activity "User $user_guid admin rights removal cancelled due to active session."
            return
        fi
    fi

    # Check if user has running processes
    user_processes=$(pgrep -u "$user_guid" 2>/dev/null)
    if [ -n "$user_processes" ]; then
        echo "Warning: User $user_guid has running processes (PIDs: $(echo $user_processes | tr '\n' ' '))"
        read -p "Do you want to proceed with removing admin rights? (y/n): " proceed
        if [ "$proceed" != "y" ]; then
            echo "Operation cancelled."
            log_activity "User $user_guid admin rights removal cancelled due to running processes."
            return
        fi
    fi

    # Final confirmation
    echo "Are you sure you want to remove admin rights from user $user_guid? (y/n): "
    read confirmation
    if [ "$confirmation" != "y" ]; then
        echo "Operation cancelled."
        log_activity "User $user_guid admin rights removal cancelled by user."
        return
    fi

    # Step 1: Kill all user processes
    if [ -n "$user_processes" ]; then
        echo "Terminating user processes..."
        pkill -9 -u "$user_guid" 2>/dev/null
        log_activity "Terminated processes of user $user_guid"
        sleep 1

    # Force kill any remaining processes
        if pgrep -u "$user_guid" >/dev/null 2>&1; then
            echo "Force killing remaining processes..."
            pkill -9 -u "$user_guid" 2>/dev/null
            log_activity "Force killed remaining processes of user $user_guid"
            sleep 1
        fi
    fi

    # Step 2: Logout user sessions
    if who | grep -q "^$user_guid"; then
        echo "Logging out user sessions..."
        # Kill all login shells and sessions
        pkill -KILL -u "$user_guid" 2>/dev/null
        log_activity "Logged out sessions of user $user_guid"
        sleep 1
    fi

    # Step 3: Remove sudo privileges
    echo "Checking and removing sudo privileges..."
    
    # Check if user has sudo privileges in /etc/sudoers.d/
    if [ -f "/etc/sudoers.d/$user_guid" ]; then
        echo "Commenting out sudo entry in /etc/sudoers.d/$user_guid"
        sed -i "s/^$user_guid\s/#$user_guid /" "/etc/sudoers.d/$user_guid"
        log_activity "Commented out sudo entry in /etc/sudoers.d/$user_guid"
        # Optionally delete the file instead
        # rm -f "/etc/sudoers.d/$user_guid"
    fi
    
    # Check and comment out entries in /etc/sudoers
    if grep -q "^[[:space:]]*$user_guid[[:space:]]" /etc/sudoers; then
        echo "Commenting out sudo entry in /etc/sudoers"
        # Create backup
        cp /etc/sudoers /etc/sudoers.bak.$(date +%Y%m%d_%H%M%S)
        # Comment out the user's sudo line
        sed -i "s/^[[:space:]]*$user_guid[[:space:]]/#$user_guid /" /etc/sudoers
        log_activity "Commented out sudo entry in /etc/sudoers for user $user_guid"
    fi

    # For redhat based system remove from wheel group
    distro=$(get_linux_distribution)
    if [[ "$distro" == "rhel" || "$distro" == "centos" || "$distro" == "fedora" || "$distro" == "rocky" || "$distro" == "alma" || "$distro" == "amazon" || "$distro" == "oracle" || "$distro" == "ol" || "$distro" == "amzn" || "$distro" == "almalinux" ]]; then
        if groups "$user_guid" | grep -q "\bwheel\b"; then
            echo "Removing user $user_guid from wheel group"
            gpasswd -d "$user_guid" wheel
            log_activity "Removed user $user_guid from wheel group"
        fi
    elif [[ "$distro" == "debian" || "$distro" == "ubuntu" || "$distro" == "pop" || "$distro" == "mint" || "$distro" == "kali" ]]; then
        # For Debian based systems remove from sudo group
        if groups "$user_guid" | grep -q "\bsudo\b"; then
            echo "Removing user $user_guid from sudo group"
            gpasswd -d "$user_guid" sudo
            log_activity "Removed user $user_guid from sudo group"
        fi 
    fi

    # Verification
    user_groups=$(groups "$user_guid" 2>/dev/null)

    # Check for ACTIVE (uncommented) sudoers entries in /etc/sudoers
    active_sudoers=$(grep -E "^[[:space:]]*${user_guid}[[:space:]]" /etc/sudoers 2>/dev/null)

    # Check for ACTIVE (uncommented) sudoers entries in /etc/sudoers.d/ file
    active_sudoers_d=""
    if [ -f "/etc/sudoers.d/$user_guid" ]; then
        active_sudoers_d=$(grep -E "^[[:space:]]*${user_guid}[[:space:]]" "/etc/sudoers.d/$user_guid" 2>/dev/null)
    fi

    # Check if user still has admin rights
    if [ -n "$active_sudoers" ] || [ -n "$active_sudoers_d" ] || [[ "$user_groups" =~ \b(wheel|sudo)\b ]]; then
        echo "Error: Failed to remove admin rights from user $user_guid."
        log_activity "Failed to remove admin rights from user $user_guid."
    else
        echo "Admin rights removed from user $user_guid successfully."
        log_activity "Successfully removed admin rights from user $user_guid."
    fi

}

# Change the existing user password
change_user_password() {
    read -p "Enter the guid of the user to change password: " user_guid
    if ! id "$user_guid" &>/dev/null; then
        echo "Error: User $user_guid does not exist."
        log_activity "Failed to change password for non-existent user $user_guid"
        return 1
    fi

    read -p "Set password automatically or manually? (a/m): " pass_choice
    if [ "$pass_choice" == "a" ]; then
        read -p "Enter desired password length (minimum 8): " pass_length
        if [ "$pass_length" -lt 8 ]; then
            echo "Password length must be at least 8 characters."
            log_activity "Failed to change password for user $user_guid: Password length must be at least 8 characters."
            return
        fi
        password=$(openssl rand -base64 $((pass_length * 3 / 4)))
        echo "Generated password: $password"
    else
        read -s -p "Enter a strong password with minimum 8 characters: " password
        if [ ${#password} -lt 8 ]; then
            echo
            echo "Password must be at least 8 characters long."
            log_activity "Failed to change password for user $user_guid: Password length must be at least 8 characters."
            return
        fi
    fi

    set_user_password "$user_guid" "$password"
}

# Modify user groups
modify_user_groups() {
    read -p "Enter the guid of the user to modify groups: " user_guid
    if ! id "$user_guid" &>/dev/null; then
        echo "Error: User $user_guid does not exist."
        log_activity "Failed to modify groups for non-existent user $user_guid"
        return 1
    fi

    echo "Available local groups:"
    list_groups

    read -p "Enter the groups to add the user to (comma-separated): " groups_to_add
    IFS=',' read -ra groups_array <<< "$groups_to_add"
    for group in "${groups_array[@]}"; do
        if ! getent group "$group" &>/dev/null; then
            echo "Group $group does not exist."
            echo "Please make sure to add and configure the group"
            log_activity "Failed to modify groups for user $user_guid: Group $group does not exist."
            return 1 
        fi

        usermod -aG "$group" "$user_guid"
        if [ $? -ne 0 ]; then
            echo "Error: Failed to add user $user_guid to group $group."
            log_activity "Failed to add user $user_guid to group $group."
        else
            echo "User $user_guid added to group $group successfully."
            log_activity "User $user_guid added to group $group successfully."
        fi
    done
}

# Main script loop
while true; do
    display_menu
    read -p "Choose an option (1-11): " choice
    case $choice in
        1) create_user ;;
        2) delete_user ;;
        3) enable_user ;;
        4) disable_user ;;
        5) list_users ;;
        6) list_groups ;;
        7) give_admin_rights ;;
        8) remove_admin_rights ;;
        9) change_user_password ;;
        10) modify_user_groups ;;
        11) view_logs ;;
        12) log_activity "User management script exited."; echo "Exiting..."; exit 0 ;;
        *) echo "Invalid option. Please choose a number between 1 and 12." ;;
    esac
    echo
done    

# # --- IGNORE ---    
# # returns 0 if group exists, 1 if not
# group_exists() {
#   # $1 = group name
#   if getent group "$1" > /dev/null 2>&1; then
#     return 0
#   else
#     return 1
#   fi
# }
# # --- IGNORE ---  END