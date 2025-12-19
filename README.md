# OpenCloud Unraid Deployment Templates

Complete deployment solution for OpenCloud with Collabora Online integration on Unraid systems. This repository provides XML templates, installation scripts, and NGINX configurations for a production-ready OpenCloud instance with document editing capabilities.

## 📋 Table of Contents

- [`Overview`](#-overview)
- [`Features`](#-features)
- [`Prerequisites`](#-prerequisites)
- [`Installation`](#-installation)
- [`Container Configuration`](#-container-configuration)
- [`Network Setup`](#-network-setup)
- [`NGINX/SWAG Configuration`](#-nginxswag-configuration)
- [`Troubleshooting`](#-troubleshooting)
- [`Contributing`](#-contributing)

---

## 🎯 Overview

This deployment consists of three main components:

1. **OpenCloud** - Core cloud storage platform
2. **Collabora Online** - LibreOffice-based online office suite
3. **Collaboration Server** - WOPI protocol server connecting OpenCloud and Collabora

All containers communicate via a custom Docker network and use SWAG reverse proxy for SSL termination.

---

## ✨ Features

- ✅ Complete Unraid XML templates for all containers
- ✅ Automated setup script for network and configuration files
- ✅ Pre-configured NGINX reverse proxy configurations
- ✅ Document editing integration (DOCX, XLSX, PPTX, ODT, etc.)
- ✅ Content Security Policy (CSP) configuration
- ✅ Password policy with banned password list
- ✅ Custom Docker network with fixed IP addressing
- ✅ SSL termination via SWAG reverse proxy

---

## 📦 Prerequisites

### Required Software

- **Unraid 6.9+** (or any Docker-compatible system)
- **SWAG** (Secure Web Application Gateway) or similar reverse proxy
- **Cloudflare** (or other DNS provider) for SSL certificates
- **Domain names** with SSL certificates for:
  - OpenCloud (e.g., `opencloud.yourdomain.com`)
  - Collabora (e.g., `collabora.yourdomain.com`)
  - WOPI Server (e.g., `wopiserver.yourdomain.com`)

### System Requirements

- **RAM**: 4GB minimum (8GB recommended)
- **Storage**: 10GB+ for application data
- **Network**: Custom Docker network capability

---

## 🚀 Installation

### Step 1: Run the Pre-Installation Script

The installation script creates the Docker network, directory structure, and configuration files.

1. Download the script:

2. Edit the script and configure your domains:
easiest way is to rename the file to.txt and do the changes with any file explorer.
In unraid you can use the plugin "User Scripts" to create and run this script.

Update these variables:
```bash
# Collabora Integration
ENABLE_COLLABORA="true"  #if you like to install collabora, set to true.

# Docker Network Configuration
CUSTOM_NETWORK="true"
NETWORK_NAME="opencloud-net"

# Domain Configuration (without https://)
OCIS_DOMAIN="opencloud.yourdomain.com"
COLLABORA_DOMAIN="collabora.yourdomain.com"
WOPISERVER_DOMAIN="wopiserver.yourdomain.com"

# Installation Paths
OCL_BASE="/mnt/user/appdata/opencloud"
COL_BASE="/mnt/user/appdata/collabora"
```

3. run the script
e.g. use plugin "user scripts" from unraid community store.
- `add new script`
- `name your script an click "ok" `
- `click on the cogwheel`
- `edit script`
- `copy and paste the code of the pre_installation_script and save`
- run script


### Step 2: Install Container Templates

1. Download the XML templates to Unraid:
   - `opencloud.xml`
   - `collabora.xml`
   - `collaboration.xml`

2. Place them in `/boot/config/plugins/dockerMan/templates-user/`
the folder is on your flash drive

3. Access Unraid Docker tab and add containers from templates

### Step 3: Configure SWAG Reverse Proxy

1. Download SWAG configuration files:
   - `opencloud.subdomain.conf`
   - `collabora.subdomain.conf`
   - `wopiserver.subdomain.conf`

2. Place in SWAG proxy-confs directory (default): `/mnt/user/appdata/swag/nginx/proxy-confs/`

3. Check and change the subdomains in each file to match yours.

4. Restart SWAG container

### Step 4: Start Containers in Order

**IMPORTANT**: Start containers in this specific order:

1. **OpenCloud** (wait 2-3 minutes for initialization)
2. **Collabora** (wait until logs show "Ready to accept connections")
3. **Collaboration** (connects to both services)

---

## ⚙️ Container Configuration

### 🔷 OpenCloud Container

#### Required Variables (MUST Configure)

| Variable | Description | Example |
|----------|-------------|---------|
| `IDM_ADMIN_PASSWORD` | Admin password for first login | `YourSecurePassword123!` |
| `OC_URL` | Public URL for OpenCloud | `https://opencloud.yourdomain.com` |

#### Important Variables (Should Configure)

| Variable | Default | Description |
|----------|---------|-------------|
| `PROXY_HTTP_ADDR` | `0.0.0.0:9200` | HTTP listening address |
| `OC_INSECURE` | `true` | Skip certificate validation (true for reverse proxy) |
| `COLLABORA_DOMAIN` | - | Collabora domain for integration |

#### Network Configuration

- **Network**: `opencloud-net` (custom Docker network)
- **Ports**: 
  - `9200` - HTTP (required)
  - `9233` - NATS registry (required for Collaboration)
  - `9142` - Gateway gRPC (optional)

#### Volume Mappings

| Container Path | Host Path | Description |
|----------------|-----------|-------------|
| `/etc/opencloud` | `/mnt/user/appdata/opencloud/config` | Configuration files |
| `/var/lib/opencloud` | `/mnt/user/appdata/opencloud/data` | User data storage |
| `/var/lib/opencloud/web/assets/apps` | `/mnt/user/appdata/opencloud/apps` | Web extensions |

---

### 🔷 Collabora Container

#### Required Variables (MUST Configure)

| Variable | Description | Example |
|----------|-------------|---------|
| `aliasgroup1` | WOPI server URL with port | `https://wopiserver.yourdomain.com:443` |
| `username` | Admin username | `admin` |
| `password` | Admin password | `YourSecurePassword123!` |

#### Important Variables (Should Configure)

| Variable | Default | Description |
|----------|---------|-------------|
| `DONT_GEN_SSL_CERT` | `YES` | Don't generate internal SSL (using reverse proxy) |
| `extra_params` | CHANGE TO YOUR OPENCLOUD DOMAIN | Collabora configuration parameters explained below |

#### Extra Parameters Explained

The `extra_params` variable contains critical settings:

```bash
--o:ssl.enable=false                              # Disable internal SSL
--o:ssl.ssl_verification=false                    # Skip SSL verification
--o:ssl.termination=true                          # SSL terminated at proxy
--o:welcome.enable=false                          # Disable welcome screen
--o:net.frame_ancestors=opencloud.yourdomain.com  # Allow iframe embedding
--o:net.lok_allow.host[14]=opencloud.yourdomain.com  # Allow connections from OpenCloud
--o:home_mode.enable=false                        # Disable home mode
```

**IMPORTANT**: Update `opencloud.yourdomain.com` to your actual OpenCloud domain!

#### Network Configuration

- **Network**: `opencloud-net`
- **Port**: `9980` - HTTP

---

### 🔷 Collaboration Container (WOPI Server)

#### Required Variables (MUST Configure)

| Variable | Description | Example |
|----------|-------------|---------|
| `MICRO_REGISTRY_ADDRESS` | OpenCloud IP:port | e.g.`192.168.x.x:9233` |
| `COLLABORATION_WOPI_SRC` | Public WOPI server URL | `https://wopiserver.yourdomain.com` |
| `COLLABORATION_APP_ADDR` | Public Collabora URL | `https://collabora.yourdomain.com` |
| `OC_URL` | Public OpenCloud URL | `https://opencloud.yourdomain.com` |

#### Important Notes

- **Start Last**: Must start after OpenCloud and Collabora are running
- **Shared Config**: Uses same config directory as OpenCloud (`/etc/opencloud`)
- **Registry Connection**: Must be able to reach OpenCloud's NATS registry (port 9233)

#### Network Configuration

- **Network**: `opencloud-net`
- **Ports**:
  - `9300` - HTTP/WOPI (required)
  - `9301` - gRPC (optional)

#### Volume Mappings

| Container Path | Host Path | Description |
|----------------|-----------|-------------|
| `/etc/opencloud` | `/mnt/user/appdata/opencloud/config` | **SHARED** with OpenCloud container |

---

## 🌐 Network Setup

### Custom Docker Network

The deployment uses a custom Docker network for container communication. The pre_install script can create the custom network.

#### Network Configuration

```bash
Network Name: opencloud-net
Subnet: Auto-assigned by Docker
```

## 🔒 NGINX/SWAG Configuration

### NGINX Configuration Files

Three subdomain configurations are provided:

1. **opencloud.subdomain.conf** - Main OpenCloud interface
2. **collabora.subdomain.conf** - Collabora Online editor
3. **wopiserver.subdomain.conf** - WOPI protocol server

### Possible Required Changes

If you have issues with the NGINX config files, it´s often, that the container name is not detected.
Then update:

```nginx
set $upstream_app containername;  # Replace with your server IP
```

### SSL Configuration

- SSL certificates managed by SWAG
- Internal containers use HTTP (SSL terminated at proxy)
- Ensure Cloudflare/DNS is properly configured for your domains

### Testing NGINX Configuration

After placing config files:

```bash
docker exec swag nginx -t
docker restart swag
```

---

## 🔧 Troubleshooting

### Container Startup Issues

#### OpenCloud won't start
- Check admin password is set
- Verify config directory permissions (1000:1000)
- Check logs: `docker logs opencloud`

#### Collabora won't start
- Verify `aliasgroup1` is correctly formatted
- Check extra_params syntax
- Ensure privileged mode is enabled
- Check logs: `docker logs collabora`

#### Collaboration won't connect
- Verify OpenCloud is fully initialized (wait 2-3 minutes)
- Check `MICRO_REGISTRY_ADDRESS` points to OpenCloud IP:9233
- Verify network connectivity between containers
- Check logs: `docker logs collaboration`

### Document Editing Issues

#### Documents won't open in Collabora

1. **Check CSP Configuration**:
```bash
cat /mnt/user/appdata/opencloud/config/csp.yaml
```
Ensure Collabora domain is in `frame-src` and `img-src`

2. **Verify WOPI Connection**:
```bash
curl -k https://wopiserver.yourdomain.com
```
Should return a response (not connection refused)

3. **Check Collabora Frame Ancestors**:
In `extra_params`, verify:
```bash
--o:net.frame_ancestors=opencloud.yourdomain.com
--o:net.lok_allow.host[14]=opencloud.yourdomain.com
```

#### "Failed to connect to WOPI server"

- Verify all three containers are running
- Check `COLLABORATION_WOPI_SRC` matches NGINX subdomain
- Test WOPI endpoint: `https://wopiserver.yourdomain.com`
- Review Collaboration logs for JWT token errors

### Network Connectivity Issues

#### Test container connectivity:

```bash
# From OpenCloud container
docker exec opencloud ping 172.20.0.3  # Collabora IP

# From Collaboration container
docker exec collaboration nc -zv 172.20.0.2 9233  # OpenCloud NATS
```

### Common Error Messages

| Error | Cause | Solution |
|-------|-------|----------|
| "JWT token validation failed" | Collaboration can't reach OpenCloud | Check MICRO_REGISTRY_ADDRESS |
| "Frame-src CSP violation" | CSP not configured | Add Collabora domain to csp.yaml |
| "Connection refused" | Container not reachable | Verify IPs and network configuration |
| "Failed to register service" | NATS registry unreachable | Check OpenCloud port 9233 is accessible |

---

## 📚 Additional Resources

- [OpenCloud Documentation](https://docs.opencloud.eu/)
- [Collabora Online Documentation](https://www.collaboraonline.com/code/)
- [SWAG Documentation](https://docs.linuxserver.io/general/swag)
- [OpenCloud GitHub](https://github.com/opencloud-eu/opencloud)
- [OpenCloud Compose Reference](https://github.com/opencloud-eu/opencloud-compose)

---

## 🤝 Contributing

Contributions are welcome! Please feel free to submit issues or pull requests.

### How to Contribute

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/improvement`)
3. Commit your changes (`git commit -am 'Add new feature'`)
4. Push to the branch (`git push origin feature/improvement`)
5. Open a Pull Request

---

## 📝 License

This project is provided as-is for educational and deployment purposes. Please refer to individual component licenses:

- OpenCloud: [Apache 2.0](https://github.com/opencloud-eu/opencloud/blob/main/LICENSE)
- Collabora Online: [MPLv2](https://www.collaboraoffice.com/)

---

## ⚠️ Disclaimer

These templates are community-maintained and not officially supported by OpenCloud or Collabora. Use at your own risk in production environments. Always test thoroughly before deploying.

---

## 💡 Tips for Success

1. **Use strong passwords** - Replace all `YourSecurePassword` placeholders
2. **Test incrementally** - Start one container at a time
3. **Check logs frequently** - Use `docker logs <container>` for troubleshooting
4. **Backup configurations** - Save your .env and config files
5. **Update regularly** - Keep container images updated
6. **Monitor resources** - Ensure adequate RAM and storage

---

**Questions or Issues?** Open an issue on GitHub or consult the [OpenCloud community forums](https://central.owncloud.org/).
