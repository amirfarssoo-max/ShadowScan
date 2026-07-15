# 🔧 Installation Guide

Detailed step-by-step installation instructions for different environments.

## Table of Contents
1. [Linux/Ubuntu](#linux)
2. [macOS](#macos)
3. [Windows (WSL2)](#windows)
4. [Termux (Android)](#termux)
5. [Docker](#docker)
6. [Troubleshooting](#troubleshooting)

---

## 🐧 Linux/Ubuntu

### Prerequisites
```bash
sudo apt update
sudo apt upgrade
sudo apt install python3 python3-pip git
```

### Installation
```bash
# Clone repository
git clone https://github.com/amirfarssoo-max/ShadowScan.git
cd ShadowScan

# Install dependencies
pip install -r requirements.txt

# Make executable (optional)
chmod +x shadowscan.py

# Test installation
python shadowscan.py --version
```

### Running
```bash
python shadowscan.py https://example.com
```

---

## 🍎 macOS

### Prerequisites
```bash
# Using Homebrew
brew install python3 git

# Or download from python.org
```

### Installation
```bash
git clone https://github.com/amirfarssoo-max/ShadowScan.git
cd ShadowScan
pip3 install -r requirements.txt
python3 shadowscan.py --version
```

### Running
```bash
python3 shadowscan.py https://example.com
```

---

## 🪟 Windows (WSL2)

### Prerequisites
1. Enable WSL2: [Microsoft WSL2 Installation](https://docs.microsoft.com/en-us/windows/wsl/install)
2. Install Ubuntu from Microsoft Store
3. Open Ubuntu terminal

### Installation
```bash
# In WSL2 Ubuntu terminal
sudo apt update && sudo apt upgrade
sudo apt install python3 python3-pip git
git clone https://github.com/amirfarssoo-max/ShadowScan.git
cd ShadowScan
pip install -r requirements.txt
python shadowscan.py --version
```

### Running from Windows PowerShell
```powershell
wsl python shadowscan.py https://example.com
```

---

## 📱 Termux (Android)

### Step 1: Install Termux
Download from [F-Droid](https://f-droid.org/en/packages/com.termux/) (recommended) or Google Play Store.

### Step 2: Update Packages
```bash
pkg update && pkg upgrade -y
```

### Step 3: Install Required Packages
```bash
pkg install python python-pip git
```

### Step 4: Clone Repository
```bash
cd ~
git clone https://github.com/amirfarssoo-max/ShadowScan.git
cd ShadowScan
```

### Step 5: Install Python Dependencies
```bash
pip install -r requirements.txt
```

### Step 6: Verify Installation
```bash
python shadowscan.py --version
```

### Running on Termux
```bash
# Fast mode (recommended for low resources)
python shadowscan.py https://example.com -m fast -t 2

# Standard scan
python shadowscan.py https://example.com

# Keep device awake during scan
termux-wake-lock
python shadowscan.py https://example.com
```

### Termux Tips
```bash
# Store files long-term (survive app restart)
mkdir -p ~/storage/shared/ShadowScan
cd ~/storage/shared/ShadowScan

# Share reports via Termux API
termux-share reports/scan_*.html

# Run in background
nohup python shadowscan.py https://example.com > scan.log 2>&1 &
```

---

## 🐳 Docker

### Create Dockerfile
```dockerfile
FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    git \
    && rm -rf /var/lib/apt/lists/*

# Clone repository
RUN git clone https://github.com/amirfarssoo-max/ShadowScan.git .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Create directories
RUN mkdir -p reports logs data detectors

ENTRYPOINT ["python", "shadowscan.py"]
```

### Build Image
```bash
docker build -t shadowscan:latest .
```

### Run Container
```bash
docker run --rm -v $(pwd)/reports:/app/reports shadowscan:latest https://example.com
```

### Docker Compose
```yaml
version: '3.8'
services:
  shadowscan:
    build: .
    volumes:
      - ./reports:/app/reports
      - ./logs:/app/logs
    command: python shadowscan.py https://example.com -m standard
```

Run with Compose:
```bash
docker-compose up
```

---

## ✅ Verification

After installation, verify everything works:

```bash
# Check version
python shadowscan.py --version

# Run help
python shadowscan.py --help

# Quick test scan (dry run - if available)
python shadowscan.py https://httpbin.org -m fast --max-pages 5
```

---

## 📦 Optional Dependencies

### For Rich Terminal Output (Recommended)
```bash
pip install rich>=13.0.0
```

### For HTML Parsing
```bash
pip install beautifulsoup4>=4.11.0
```

### For YAML Configuration Files
```bash
pip install PyYAML>=6.0
```

### For Browser-Based Detection
```bash
pip install playwright>=1.40.0
playwright install
```

### Install All Optional Packages
```bash
pip install -r requirements.txt
pip install rich beautifulsoup4 PyYAML playwright
playwright install
```

---

## 🐛 Troubleshooting

### Python Version Error
```
Error: Python 3.8+ required
```
**Solution**: Check Python version
```bash
python --version
# If using Python 2.7, use: python3
python3 shadowscan.py --version
```

### Module Not Found Error
```
ModuleNotFoundError: No module named 'httpx'
```
**Solution**: Install dependencies
```bash
pip install -r requirements.txt
# or individually
pip install httpx
```

### SSL Certificate Error
```
ssl.SSLError: CERTIFICATE_VERIFY_FAILED
```
**Solution**: Disable SSL verification (not recommended for production)
```bash
python shadowscan.py https://example.com --no-verify-ssl
```

### Permission Denied (Linux/Termux)
```bash
chmod +x shadowscan.py
# Then run with ./ prefix
./shadowscan.py https://example.com
```

### Timeout/Connection Errors
```bash
# Increase timeout and delay
python shadowscan.py https://example.com --timeout 30 --delay 0.2
```

### Termux - Command Not Found
```bash
# Ensure you're in the correct directory
cd ~/ShadowScan
python shadowscan.py https://example.com
```

### Out of Memory on Termux
```bash
# Use fewer threads and pages
python shadowscan.py https://example.com -m fast -t 2 --max-pages 20
```

---

## 🔄 Upgrading

Update to the latest version:

```bash
cd ShadowScan
git pull origin main
pip install --upgrade -r requirements.txt
```

---

## 🚀 Next Steps

After successful installation:

1. **Read the main README**: `README.md`
2. **Check Examples**: `example_config.yaml`
3. **Run your first scan**: `python shadowscan.py https://example.com`
4. **Create custom detectors**: See README plugin section
5. **Join the community**: Star ⭐ the repository

---

## 📞 Need Help?

- 📖 [GitHub Issues](https://github.com/amirfarssoo-max/ShadowScan/issues)
- 💬 [GitHub Discussions](https://github.com/amirfarssoo-max/ShadowScan/discussions)
- 🐛 Report bugs with Python version and error logs

---

**Happy Scanning! 🔍**
