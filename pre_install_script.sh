#!/bin/bash
################################################################################
# OpenCloud Setup Script - Network, Folders & Configuration Files
# Creates Docker network, directory structure, CSP config, and banned password list
################################################################################
#name=OpenCloud Network & File Setup
#description=Creates Docker network, folders, and configuration files for OpenCloud
#arrayStarted=false

################################################################################
# USER CONFIGURATION - EDIT THESE VALUES
################################################################################

# Collabora Integration
ENABLE_COLLABORA="true"

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

################################################################################
# SCRIPT START
################################################################################

OCL_CONFIG="${OCL_BASE}/config"
OCL_DATA="${OCL_BASE}/data"
OCL_APPS="${OCL_BASE}/apps"
COL_CONFIG="${COL_BASE}/config"
COLLAB_CONFIG="${OCL_BASE}/collaboration"

GITHUB_BASE="https://raw.githubusercontent.com/opencloud-eu/opencloud-compose/main"
BANNED_PW_URL="${GITHUB_BASE}/config/opencloud/banned-password-list.txt"

echo "================================================"
echo "OpenCloud Network & File Setup"
echo "================================================"
echo "  OCIS Domain:    ${OCIS_DOMAIN}"
if [ "${ENABLE_COLLABORA}" = "true" ]; then
    echo "  Collabora:      ${COLLABORA_DOMAIN}"
    echo "  WOPI Server:    ${WOPISERVER_DOMAIN}"
fi
echo "  Install path:   ${OCL_BASE}"
if [ "${CUSTOM_NETWORK}" = "true" ]; then
    echo "  Docker Network: ${NETWORK_NAME}"
fi
echo "================================================"
echo ""

################################################################################
# Create Docker Network (if enabled)
################################################################################

if [ "${CUSTOM_NETWORK}" = "true" ]; then
    echo ""
    echo "================================================"
    echo "[1/5] Configuring Docker Network"
    echo "================================================"
    
    # Check if Docker is available
    if ! command -v docker &> /dev/null; then
        echo "❌ ERROR: Docker command not found!"
        echo "   Please ensure Docker is installed and running."
        exit 1
    fi
    
    # Check if network already exists
    echo "Checking for existing network '${NETWORK_NAME}'..."
    if docker network inspect "${NETWORK_NAME}" &> /dev/null; then
        echo "✓ Network '${NETWORK_NAME}' already exists - skipping creation"
    else
        echo "Creating new Docker network '${NETWORK_NAME}'..."
        if docker network create "${NETWORK_NAME}" &> /dev/null; then
            echo "✓ Docker network '${NETWORK_NAME}' created successfully"
        else
            echo "❌ ERROR: Failed to create Docker network!"
            echo "   Network name: ${NETWORK_NAME}"
            echo ""
            echo "   Possible causes:"
            echo "   - Network name already in use"
            echo "   - Insufficient Docker permissions"
            echo ""
            echo "   Try: docker network ls"
            exit 1
        fi
    fi
    echo "================================================"
fi

################################################################################
# Create Directories
################################################################################

echo ""
echo "[$([ "${CUSTOM_NETWORK}" = "true" ] && echo "2" || echo "1")/$([ "${CUSTOM_NETWORK}" = "true" ] && echo "5" || echo "4")] Creating directories..."
mkdir -p "${OCL_CONFIG}"
mkdir -p "${OCL_DATA}"
mkdir -p "${OCL_APPS}"

if [ "${ENABLE_COLLABORA}" = "true" ]; then
    mkdir -p "${COL_CONFIG}"
    mkdir -p "${COLLAB_CONFIG}"
fi

echo "✓ Directories created successfully"

################################################################################
# Create CSP Configuration
################################################################################

echo ""
echo "[$([ "${CUSTOM_NETWORK}" = "true" ] && echo "3" || echo "2")/$([ "${CUSTOM_NETWORK}" = "true" ] && echo "5" || echo "4")] Creating CSP configuration..."

# Ensure the file doesn't exist as a directory
if [ -d "${OCL_CONFIG}/csp.yaml" ]; then
    rm -rf "${OCL_CONFIG}/csp.yaml"
fi

if [ "${ENABLE_COLLABORA}" = "true" ]; then
    # Create CSP config with Collabora domains
    cat > "${OCL_CONFIG}/csp.yaml" <<EOF
directives:
  child-src:
    - '''self'''
  connect-src:
    - '''self'''
    - 'blob:'
    - 'https://${OCIS_DOMAIN}'
    - 'wss://${OCIS_DOMAIN}'
    - 'https://raw.githubusercontent.com/opencloud-eu/awesome-apps/'
    - 'https://update.opencloud.eu/'
  default-src:
    - '''none'''
  font-src:
    - '''self'''
  frame-ancestors:
    - '''self'''
  frame-src:
    - '''self'''
    - 'blob:'
    - 'https://embed.diagrams.net/'
    - 'https://${COLLABORA_DOMAIN}'
    - 'https://docs.opencloud.eu'
  img-src:
    - '''self'''
    - 'data:'
    - 'blob:'
    - 'https://raw.githubusercontent.com/opencloud-eu/awesome-apps/'
    - 'https://tile.openstreetmap.org/'
    - 'https://${COLLABORA_DOMAIN}'
  manifest-src:
    - '''self'''
  media-src:
    - '''self'''
  object-src:
    - '''self'''
    - 'blob:'
  script-src:
    - '''self'''
    - '''unsafe-inline'''
  style-src:
    - '''self'''
    - '''unsafe-inline'''
EOF
else
    # Create CSP config without Collabora domains
    cat > "${OCL_CONFIG}/csp.yaml" <<EOF
directives:
  child-src:
    - '''self'''
  connect-src:
    - '''self'''
    - 'blob:'
    - 'https://${OCIS_DOMAIN}'
    - 'wss://${OCIS_DOMAIN}'
    - 'https://raw.githubusercontent.com/opencloud-eu/awesome-apps/'
    - 'https://update.opencloud.eu/'
  default-src:
    - '''none'''
  font-src:
    - '''self'''
  frame-ancestors:
    - '''self'''
  frame-src:
    - '''self'''
    - 'blob:'
    - 'https://embed.diagrams.net/'
    - 'https://docs.opencloud.eu'
  img-src:
    - '''self'''
    - 'data:'
    - 'blob:'
    - 'https://raw.githubusercontent.com/opencloud-eu/awesome-apps/'
    - 'https://tile.openstreetmap.org/'
  manifest-src:
    - '''self'''
  media-src:
    - '''self'''
  object-src:
    - '''self'''
    - 'blob:'
  script-src:
    - '''self'''
    - '''unsafe-inline'''
  style-src:
    - '''self'''
    - '''unsafe-inline'''
EOF
fi

echo "✓ CSP configuration created successfully"

################################################################################
# Create Banned Password List
################################################################################

echo ""
echo "[$([ "${CUSTOM_NETWORK}" = "true" ] && echo "4" || echo "3")/$([ "${CUSTOM_NETWORK}" = "true" ] && echo "5" || echo "4")] Creating banned password list..."

# Ensure the file doesn't exist as a directory
if [ -d "${OCL_CONFIG}/banned-password-list.txt" ]; then
    rm -rf "${OCL_CONFIG}/banned-password-list.txt"
fi

# Download banned passwords list or create default
curl -sL "${BANNED_PW_URL}" -o "${OCL_CONFIG}/banned-password-list.txt" 2>/dev/null || \
cat > "${OCL_CONFIG}/banned-password-list.txt" <<'EOF'
password
12345678
123
OpenCloud
OpenCloud-1
admin
EOF

echo "✓ Banned password list created successfully"

# Verify files were created correctly
echo ""
echo "Verifying configuration files..."
FILE_CHECK_PASSED=true

if [ -f "${OCL_CONFIG}/csp.yaml" ]; then
    echo "  ✓ csp.yaml is a file"
else
    echo "  ❌ ERROR: csp.yaml is not a file!"
    FILE_CHECK_PASSED=false
fi

if [ -f "${OCL_CONFIG}/banned-password-list.txt" ]; then
    echo "  ✓ banned-password-list.txt is a file"
else
    echo "  ❌ ERROR: banned-password-list.txt is not a file!"
    FILE_CHECK_PASSED=false
fi

if [ "${FILE_CHECK_PASSED}" = "false" ]; then
    echo ""
    echo "❌ File creation verification failed!"
    echo "   Please check the errors above and try again."
    exit 1
fi

################################################################################
# Set Permissions
################################################################################

echo ""
echo "[$([ "${CUSTOM_NETWORK}" = "true" ] && echo "5" || echo "4")/$([ "${CUSTOM_NETWORK}" = "true" ] && echo "5" || echo "4")] Setting permissions..."

chown -R 1000:1000 "${OCL_BASE}"
chmod -R 755 "${OCL_BASE}"

if [ "${ENABLE_COLLABORA}" = "true" ]; then
    chown -R 1000:1000 "${COL_BASE}"
    chmod -R 755 "${COL_BASE}"
fi

echo "✓ Permissions set successfully"

################################################################################
# Summary
################################################################################

echo ""
echo "================================================"
echo "✓ Setup Complete!"
echo "================================================"
echo ""

if [ "${CUSTOM_NETWORK}" = "true" ]; then
    echo "Docker Network:"
    echo "  ✓ Network '${NETWORK_NAME}' ready"
    echo ""
fi

echo "Configuration Files:"
echo "  ✓ ${OCL_CONFIG}/csp.yaml"
echo "  ✓ ${OCL_CONFIG}/banned-password-list.txt"
echo ""

echo "Directories:"
echo "  ✓ ${OCL_CONFIG}/ (config)"
echo "  ✓ ${OCL_DATA}/ (data)"
echo "  ✓ ${OCL_APPS}/ (apps)"
if [ "${ENABLE_COLLABORA}" = "true" ]; then
    echo "  ✓ ${COL_CONFIG}/ (collabora config)"
    echo "  ✓ ${COLLAB_CONFIG}/ (collaboration)"
fi
echo ""

echo "================================================"
echo "NEXT STEPS:"
echo "================================================"
echo "1. Update domains in Unraid XML templates:"
echo "   - OpenCloud: https://${OCIS_DOMAIN}"
if [ "${ENABLE_COLLABORA}" = "true" ]; then
    echo "   - Collabora: https://${COLLABORA_DOMAIN}"
    echo "   - WOPI Server: https://${WOPISERVER_DOMAIN}"
fi
echo ""
echo "2. Update YourServerIP in templates with your container IPs"
echo ""
echo "3. Set a secure admin password (replace YourSecurePassword)"
echo ""
echo "4. Ensure all containers use the '${NETWORK_NAME}' network"
echo ""
echo "5. Start containers in this order:"
echo "   a) OpenCloud (wait for initialization)"
echo "   b) Collabora (wait for ready status)"
echo "   c) Collaboration (connects to both)"
echo ""
echo "6. Verify setup:"
echo "   - OpenCloud UI: https://${OCIS_DOMAIN}"
if [ "${ENABLE_COLLABORA}" = "true" ]; then
    echo "   - Collabora UI: https://${COLLABORA_DOMAIN}"
    echo "   - Test document editing in OpenCloud"
fi
echo ""
echo "================================================"
echo ""
echo "For troubleshooting, check container logs:"
echo "  docker logs opencloud"
if [ "${ENABLE_COLLABORA}" = "true" ]; then
    echo "  docker logs collabora"
    echo "  docker logs collaboration"
fi
echo ""
echo "================================================"

exit 0