#!/usr/bin/env python3
"""
Wazuh Configuration Helper
This script helps configure Wazuh connection for the Security Copilot project.
"""

import os
import sys
from pathlib import Path

def configure_wazuh():
    """Interactive Wazuh configuration"""
    
    print("=" * 60)
    print("Wazuh Configuration Helper")
    print("=" * 60)
    print()
    
    print("Current Status:")
    print("❌ No local Wazuh installation found")
    print("❌ Previous Wazuh server (192.168.1.7) is not reachable")
    print()
    
    print("Configuration Options:")
    print("1. Docker Wazuh (Quick Setup - Recommended)")
    print("2. Existing Wazuh Server")
    print("3. Wazuh Cloud")
    print("4. Use Sample Data (No Wazuh)")
    print()
    
    choice = input("Select option (1-4): ").strip()
    
    env_file = Path(__file__).parent / "backend" / ".env"
    
    if choice == "1":
        # Docker Wazuh setup
        print("\n🐳 Docker Wazuh Setup")
        print("=" * 40)
        
        # Get local IP
        local_ip = "192.168.56.1"  # Default to virtual network IP
        print(f"Using local IP: {local_ip}")
        
        # Check if Docker is available
        try:
            import subprocess
            result = subprocess.run("docker --version", capture_output=True, text=True, shell=True, timeout=5)
            if result.returncode != 0:
                print("❌ Docker not found. Please install Docker Desktop first.")
                print("   Download from: https://www.docker.com/products/docker-desktop")
                return False
            print(f"✅ Docker found: {result.stdout.strip()}")
        except subprocess.TimeoutExpired:
            print("❌ Docker command timed out. Docker may not be properly installed.")
            print("   Download from: https://www.docker.com/products/docker-desktop")
            return False
        except Exception as e:
            print(f"❌ Docker not found or error checking: {e}")
            print("   Download from: https://www.docker.com/products/docker-desktop")
            return False
        
        # Configure .env
        env_content = f"""WAZUH_API_URL=https://{local_ip}:55000
WAZUH_USERNAME=wazuh-wui
WAZUH_PASSWORD=wazuh-wui
"""
        
        with open(env_file, 'w') as f:
            f.write(env_content)
        
        print(f"✅ Updated {env_file}")
        print(f"   WAZUH_API_URL=https://{local_ip}:55000")
        print(f"   WAZUH_USERNAME=wazuh-wui")
        print(f"   WAZUH_PASSWORD=wazuh-wui")
        
        print("\n📋 Next Steps:")
        print("1. Run: docker run -d --name wazuh-manager \\")
        print(f"      -e WAZUH_MANAGER_IP={local_ip} \\")
        print("      -p 55000:55000 \\")
        print("      -p 1514:1514/udp \\")
        print("      wazuh/wazuh-manager:4.8.0")
        print("2. Wait for Wazuh to start (check: docker logs -f wazuh-manager)")
        print("3. Test connection: cd backend && python test_wazuh_connection.py")
        print("4. Restart backend server")
        
    elif choice == "2":
        # Existing Wazuh server
        print("\n🌐 Existing Wazuh Server Setup")
        print("=" * 40)
        
        wazuh_ip = input("Enter Wazuh server IP: ").strip()
        wazuh_port = input("Enter Wazuh API port (default 55000): ").strip() or "55000"
        wazuh_user = input("Enter Wazuh username: ").strip()
        wazuh_pass = input("Enter Wazuh password: ").strip()
        
        if not wazuh_ip or not wazuh_user or not wazuh_pass:
            print("❌ Missing required information")
            return False
        
        # Configure .env
        env_content = f"""WAZUH_API_URL=https://{wazuh_ip}:{wazuh_port}
WAZUH_USERNAME={wazuh_user}
WAZUH_PASSWORD={wazuh_pass}
"""
        
        with open(env_file, 'w') as f:
            f.write(env_content)
        
        print(f"✅ Updated {env_file}")
        print(f"   WAZUH_API_URL=https://{wazuh_ip}:{wazuh_port}")
        print(f"   WAZUH_USERNAME={wazuh_user}")
        print(f"   WAZUH_PASSWORD=***")
        
        print("\n📋 Next Steps:")
        print("1. Test connection: cd backend && python test_wazuh_connection.py")
        print("2. Restart backend server")
        
    elif choice == "3":
        # Wazuh Cloud
        print("\n☁️ Wazuh Cloud Setup")
        print("=" * 40)
        
        cloud_url = input("Enter Wazuh Cloud URL (e.g., https://instance.wazuh.com): ").strip()
        cloud_user = input("Enter Wazuh Cloud username: ").strip()
        cloud_pass = input("Enter Wazuh Cloud password: ").strip()
        
        if not cloud_url or not cloud_user or not cloud_pass:
            print("❌ Missing required information")
            return False
        
        # Configure .env
        env_content = f"""WAZUH_API_URL={cloud_url}
WAZUH_USERNAME={cloud_user}
WAZUH_PASSWORD={cloud_pass}
"""
        
        with open(env_file, 'w') as f:
            f.write(env_content)
        
        print(f"✅ Updated {env_file}")
        print(f"   WAZUH_API_URL={cloud_url}")
        print(f"   WAZUH_USERNAME={cloud_user}")
        print(f"   WAZUH_PASSWORD=***")
        
        print("\n📋 Next Steps:")
        print("1. Test connection: cd backend && python test_wazuh_connection.py")
        print("2. Restart backend server")
        
    elif choice == "4":
        # Sample data mode
        print("\n📊 Sample Data Mode")
        print("=" * 40)
        
        # Configure .env without Wazuh
        env_content = """# WAZUH_API_URL=  # Not configured - using sample data
# WAZUH_USERNAME=
# WAZUH_PASSWORD=
"""
        
        with open(env_file, 'w') as f:
            f.write(env_content)
        
        print(f"✅ Updated {env_file}")
        print("   Wazuh not configured - sample data will be used")
        
        print("\n📋 Note:")
        print("The system will show sample alerts for demonstration.")
        print("Configure Wazuh later to display real security alerts.")
        
    else:
        print("❌ Invalid choice")
        return False
    
    print("\n" + "=" * 60)
    print("✅ Configuration complete!")
    print("=" * 60)
    return True

if __name__ == "__main__":
    success = configure_wazuh()
    sys.exit(0 if success else 1)