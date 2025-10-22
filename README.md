# 🧠 Local_User_Manager_Automation_Script

⚙️ **An automation script designed to manage multiple users across cross-platform environments 🌐**

💻 **OS Support:** Linux 🐧 | Windows 🪟

---

## 🚀 Overview

The **Local User Manager Automation Script** provides a unified automation tool to handle user management tasks across Linux and Windows environments.  
It supports operations like user creation, deletion, password management, and privilege control — all from a single script powered by Python 🐍, Bash 💥, and PowerShell ⚡.

---

## 🧩 Tech Stack

| Component | Description |
|------------|--------------|
| 🐍 **Python 3.x** | Core logic & automation control |
| 💥 **Bash** | Linux-specific user management commands |
| ⚡ **PowerShell** | Windows-specific user management automation |
| 🧰 **Modules Used** | `os`, `subprocess`, `platform`, `getpass`, and native OS commands |

---

## ✨ Features

| Feature | Description | Status |
|----------|--------------|--------|
| 🧍 **Create a New User** | Adds a new local user with specified credentials. | ✅ Done *(Working - partially)* |
| ❌ **Delete an Existing User** | Deletes a user and logs them out if currently active. | ✅ Done *(Working - partially)* |
| 🔒 **Disable a User** | Disables a user account and forces logout if logged in. | ⚙️ Partially Done |
| 🔓 **Enable a User** | Re-enables a disabled account. | ✅ Done *(Working - partially)* |
| 📜 **List All Users** | Displays all system users. | ✅ Done *(Working - partially)* |
| 🛡️ **Grant Admin Rights** | Adds user to the administrative group. | ✅ Done *(Working - partially)* |
| 🚫 **Remove Admin Rights** | Removes user from the administrative group. | ✅ Done *(Working - partially)* |
| 🔑 **Change User Password** | Updates the user’s password and enforces logout if active. Supports password aging. | ⚙️ Done *(Working - partially)* |
| 👥 **Modify User Groups** | Adds or removes users from system groups. | ✅ Done *(Working - partially)* |

---

## 🧰 Example Commands

### 🐧 Linux (Bash 💥)
```bash
sudo python3 local_user_manager.py --create user1
sudo python3 local_user_manager.py --delete user1
sudo python3 local_user_manager.py --disable user1

