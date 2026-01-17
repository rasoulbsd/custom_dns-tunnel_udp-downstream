# VPS Setup Guide

## System Requirements

- **OS**: Ubuntu 20.04+ / Debian 11+ (recommended)
- **RAM**: Minimum 512MB, 1GB+ recommended
- **CPU**: 1 core minimum, 2+ cores recommended
- **Storage**: 5GB+ free space
- **Network**: Public IP address with port 53 (UDP) accessible

## Required Dependencies

### 1. Docker & Docker Compose

```bash
# Update package index
sudo apt-get update

# Install prerequisites
sudo apt-get install -y \
    ca-certificates \
    curl \
    gnupg \
    lsb-release

# Add Docker's official GPG key
sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/debian/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
sudo chmod a+r /etc/apt/keyrings/docker.gpg

# Set up Docker repository
echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/debian \
  $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

# Install Docker Engine and Docker Compose
sudo apt-get update
sudo apt-get install -y \
    docker-ce \
    docker-ce-cli \
    containerd.io \
    docker-buildx-plugin \
    docker-compose-plugin

# Verify installation
sudo docker --version
sudo docker compose version

# Add your user to docker group (optional, to run without sudo)
sudo usermod -aG docker $USER
# Log out and back in for group changes to take effect
```

### 2. Git (for cloning repository)

```bash
sudo apt-get install -y git
```

### 3. Build Tools

```bash
sudo apt-get install -y build-essential
```

**Note:** `build-essential` includes:
- `gcc` - C compiler
- `g++` - C++ compiler
- `make` - Build automation tool
- `libc6-dev` - C library development files

### 4. Network Tools (for testing and debugging)

```bash
sudo apt-get install -y \
    netcat-openbsd \
    dnsutils \
    net-tools \
    tcpdump
```

### 5. Firewall Configuration (UFW)

```bash
# Install UFW if not already installed
sudo apt-get install -y ufw

# Allow SSH (important - do this first!)
sudo ufw allow 22/tcp

# Allow DNS port (UDP 53)
sudo ufw allow 53/udp

# Allow other ports if needed (e.g., for monitoring)
sudo ufw allow 8080/udp  # If using echo server for testing

# Enable firewall
sudo ufw enable

# Check status
sudo ufw status
```

### 6. System Utilities

```bash
sudo apt-get install -y \
    htop \
    vim \
    nano \
    wget \
    unzip
```

## Complete Installation Script

Save this as `install-vps-dependencies.sh`:

```bash
#!/bin/bash
set -e

echo "=== VPS Dependencies Installation ==="
echo ""

# Update system
echo "Updating package index..."
sudo apt-get update

# Install basic dependencies
echo "Installing basic dependencies..."
sudo apt-get install -y \
    ca-certificates \
    curl \
    gnupg \
    lsb-release \
    git \
    build-essential \
    netcat-openbsd \
    dnsutils \
    net-tools \
    tcpdump \
    htop \
    vim \
    nano \
    wget \
    unzip

# Install Docker
echo "Installing Docker..."
sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/debian/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
sudo chmod a+r /etc/apt/keyrings/docker.gpg

echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/debian \
  $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

sudo apt-get update
sudo apt-get install -y \
    docker-ce \
    docker-ce-cli \
    containerd.io \
    docker-buildx-plugin \
    docker-compose-plugin

# Install UFW
echo "Installing and configuring firewall..."
sudo apt-get install -y ufw
sudo ufw allow 22/tcp
sudo ufw allow 53/udp
sudo ufw --force enable

# Add user to docker group
echo "Adding user to docker group..."
sudo usermod -aG docker $USER

echo ""
echo "=== Installation Complete ==="
echo ""
echo "Please log out and log back in for docker group changes to take effect."
echo "Then verify installation:"
echo "  docker --version"
echo "  docker compose version"
```

Make it executable and run:
```bash
chmod +x install-vps-dependencies.sh
./install-vps-dependencies.sh
```

## Quick Reference: All Dependencies

### Essential (Required)
- **Docker Engine** - Container runtime
- **Docker Compose** - Multi-container orchestration
- **Git** - Version control (for cloning repo)
- **build-essential** - C/C++ compiler and build tools (gcc, make, libc6-dev)
- **UFW** - Firewall management

### Recommended (For Testing/Debugging)
- **netcat-openbsd** - Network testing tool
- **dnsutils** (dig, nslookup) - DNS testing
- **net-tools** (netstat, ifconfig) - Network utilities
- **tcpdump** - Packet capture for debugging

### Optional (Quality of Life)
- **htop** - Process monitor
- **vim/nano** - Text editors
- **wget/curl** - Download tools
- **unzip** - Archive extraction

## Verification Checklist

After installation, verify everything works:

```bash
# 1. Docker is installed and running
docker --version
docker compose version
sudo systemctl status docker

# 2. User can run Docker without sudo (after logout/login)
docker ps

# 3. Port 53 is accessible
sudo netstat -tulpn | grep :53
# or
sudo ss -tulpn | grep :53

# 4. Firewall is configured
sudo ufw status

# 5. DNS tools are available
dig --version
nc -h
```

## Troubleshooting

### Docker Permission Denied
```bash
# Add user to docker group
sudo usermod -aG docker $USER
# Log out and back in
```

### Port 53 Already in Use
```bash
# Check what's using port 53
sudo lsof -i :53
# or
sudo netstat -tulpn | grep :53

# Stop systemd-resolved if it's using port 53
sudo systemctl stop systemd-resolved
sudo systemctl disable systemd-resolved
```

### Firewall Blocking Traffic
```bash
# Check firewall status
sudo ufw status verbose

# Allow specific port
sudo ufw allow 53/udp

# Check firewall logs
sudo tail -f /var/log/ufw.log
```

## Next Steps

After installing dependencies:

1. **Clone the repository:**
   ```bash
   git clone <repository-url>
   cd dns-tunnel
   ```

2. **Configure the server:**
   - Edit `server-config-prod.json`
   - Set your domain(s)
   - Configure DNS records

3. **Build and run:**
   ```bash
   docker compose -f docker-compose.prod.yml up -d server --build
   ```

4. **Monitor logs:**
   ```bash
   docker compose -f docker-compose.prod.yml logs -f server
   ```

## Minimal Installation (Docker Only)

If you only need Docker and build tools:

```bash
sudo apt-get update
sudo apt-get install -y ca-certificates curl gnupg lsb-release build-essential
sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/debian/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
sudo chmod a+r /etc/apt/keyrings/docker.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/debian $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
sudo usermod -aG docker $USER
```
