import platform
import subprocess


# Function for user management on Windows
def user_manager_windows():
    subprocess.run(["powershell.exe", "-File", "user_management.ps1"])  

# Function for user management on Linux
def user_manager_linux():
    subprocess.run(["./user_management.sh"])

def find_os():
    os_type = platform.system()
    if os_type == "Windows":
        try:
            print("Windows OS detected.")
            user_manager_windows()
        except Exception as e:
            print(f"Error occurred while managing users on Windows: {e}")
    elif os_type == "Linux":
        try:
            print("Linux OS detected.")
            user_manager_linux()
        except subprocess.CalledProcessError as e:
            print(f"Error occurred while managing users on Linux: {e}")

# Entry point
if __name__ == "__main__":
    find_os()   

# Note: The actual implementation of user management functions for Windows and Linux
# would involve using appropriate system commands and handling user inputs. 
# This is a skeleton code to demonstrate the structure based on the project plan.
