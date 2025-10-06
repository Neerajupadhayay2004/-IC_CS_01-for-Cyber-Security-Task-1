import subprocess
import sys

def install_dependencies():
    """Install all required Python dependencies"""
    print("Installing Python dependencies for Security Scanner...")
    
    try:
        subprocess.check_call([
            sys.executable, 
            "-m", 
            "pip", 
            "install", 
            "-r", 
            "scripts/requirements.txt"
        ])
        print("✓ All dependencies installed successfully!")
        return True
    except subprocess.CalledProcessError as e:
        print(f"✗ Error installing dependencies: {e}")
        return False

if __name__ == "__main__":
    install_dependencies()
