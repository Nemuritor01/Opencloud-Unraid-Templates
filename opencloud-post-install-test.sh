#!/bin/bash
################################################################################
# OpenCloud + Collabora + WOPI Integration Diagnostic Script
# For Unraid User Scripts Plugin
# Tests connectivity, configuration, and integration between all components
################################################################################
#name=OpenCloud Collabora Diagnostic
#description=Comprehensive diagnostic tool for OpenCloud with Collabora integration
#arrayStarted=true

################################################################################
# USER CONFIGURATION - EDIT THESE VALUES
################################################################################

# Domain Configuration (without https://)
OCIS_DOMAIN="opencloud.yourdomain.com"
COLLABORA_DOMAIN="collabora.yourdomain.com"
WOPISERVER_DOMAIN="wopiserver.yourdomain.com"

# Container Names (as shown in Docker)
OPENCLOUD_CONTAINER="OpenCloud"
COLLABORA_CONTAINER="Collabora"
COLLABORATION_CONTAINER="Collaboration"

# Docker Network Name
NETWORK_NAME="opencloud-net"

# Installation Paths
OCL_CONFIG="/mnt/user/appdata/opencloud/config"
OCL_DATA="/mnt/user/appdata/opencloud/data"

# Reverse Proxy Type (swag, nginx, traefik, caddy, other)
PROXY_TYPE="swag"  # Options: swag, nginx, traefik, caddy, pangolin, other

# Enable Extended Tests (slower but more thorough)
EXTENDED_TESTS="true"

################################################################################
# SCRIPT CONFIGURATION - DO NOT EDIT BELOW THIS LINE
################################################################################

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Test counters
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0
WARNING_TESTS=0

# Result storage
declare -a FAILURES
declare -a WARNINGS
declare -a RECOMMENDATIONS

################################################################################
# HELPER FUNCTIONS
################################################################################

print_header() {
    echo -e "${CYAN}================================================${NC}"
    echo -e "${CYAN}$1${NC}"
    echo -e "${CYAN}================================================${NC}"
}

print_section() {
    echo ""
    echo -e "${BLUE}[TEST] $1${NC}"
    echo "----------------------------------------"
}

test_passed() {
    echo -e "${GREEN}✓ PASS${NC}: $1"
    ((PASSED_TESTS++))
    ((TOTAL_TESTS++))
}

test_failed() {
    echo -e "${RED}✗ FAIL${NC}: $1"
    FAILURES+=("$1")
    ((FAILED_TESTS++))
    ((TOTAL_TESTS++))
}

test_warning() {
    echo -e "${YELLOW}⚠ WARN${NC}: $1"
    WARNINGS+=("$1")
    ((WARNING_TESTS++))
    ((TOTAL_TESTS++))
}

add_recommendation() {
    RECOMMENDATIONS+=("$1")
}

check_command() {
    if command -v "$1" &> /dev/null; then
        return 0
    else
        return 1
    fi
}

################################################################################
# MAIN DIAGNOSTIC SCRIPT
################################################################################

clear
print_header "OpenCloud + Collabora Diagnostic Tool"
echo ""
echo "Configuration:"
echo "  OpenCloud:     https://${OCIS_DOMAIN}"
echo "  Collabora:     https://${COLLABORA_DOMAIN}"
echo "  WOPI Server:   https://${WOPISERVER_DOMAIN}"
echo "  Proxy Type:    ${PROXY_TYPE}"
echo "  Network:       ${NETWORK_NAME}"
echo ""
echo "Starting diagnostics..."
sleep 2

################################################################################
# TEST 1: SYSTEM PREREQUISITES
################################################################################

print_section "System Prerequisites"

# Check Docker
if check_command docker; then
    DOCKER_VERSION=$(docker --version | awk '{print $3}' | tr -d ',')
    test_passed "Docker installed (version: ${DOCKER_VERSION})"
else
    test_failed "Docker not found"
    echo -e "${RED}CRITICAL: Cannot continue without Docker${NC}"
    exit 1
fi

# Check curl
if check_command curl; then
    test_passed "curl command available"
else
    test_failed "curl not found (required for testing)"
    add_recommendation "Install curl: opkg install curl"
fi

# Check jq (optional but helpful)
if check_command jq; then
    test_passed "jq available (JSON parsing enabled)"
else
    test_warning "jq not found (some tests will be limited)"
    add_recommendation "Install jq for better JSON parsing: opkg install jq"
fi

################################################################################
# TEST 2: DOCKER NETWORK
################################################################################

print_section "Docker Network Configuration"

# Check if network exists
if docker network inspect "${NETWORK_NAME}" &> /dev/null; then
    test_passed "Network '${NETWORK_NAME}' exists"
    
    # Get network details
    NETWORK_SUBNET=$(docker network inspect "${NETWORK_NAME}" --format='{{range .IPAM.Config}}{{.Subnet}}{{end}}' 2>/dev/null)
    NETWORK_GATEWAY=$(docker network inspect "${NETWORK_NAME}" --format='{{range .IPAM.Config}}{{.Gateway}}{{end}}' 2>/dev/null)
    
    echo "  Network Details:"
    echo "    Subnet:  ${NETWORK_SUBNET}"
    echo "    Gateway: ${NETWORK_GATEWAY}"
    
    # List containers on network
    echo "  Containers on network:"
    NETWORK_CONTAINERS=$(docker network inspect "${NETWORK_NAME}" --format='{{range .Containers}}{{.Name}} ({{.IPv4Address}}){{println}}{{end}}' 2>/dev/null)
    if [ -n "$NETWORK_CONTAINERS" ]; then
        echo "$NETWORK_CONTAINERS" | while read line; do
            echo "    - $line"
        done
    else
        test_warning "No containers found on network '${NETWORK_NAME}'"
    fi
else
    test_failed "Network '${NETWORK_NAME}' does not exist"
    add_recommendation "Create network: docker network create ${NETWORK_NAME}"
fi

################################################################################
# TEST 3: CONTAINER STATUS
################################################################################

print_section "Container Status"

# Function to check container
check_container() {
    local container_name=$1
    local service_name=$2
    
    if docker ps --format '{{.Names}}' | grep -q "^${container_name}$"; then
        STATUS=$(docker inspect --format='{{.State.Status}}' "${container_name}" 2>/dev/null)
        UPTIME=$(docker inspect --format='{{.State.StartedAt}}' "${container_name}" 2>/dev/null)
        
        if [ "$STATUS" = "running" ]; then
            test_passed "${service_name} container '${container_name}' is running"
            echo "    Started: ${UPTIME}"
            
            # Check if on correct network
            CONTAINER_NETWORKS=$(docker inspect --format='{{range $k,$v := .NetworkSettings.Networks}}{{$k}} {{end}}' "${container_name}" 2>/dev/null)
            if echo "$CONTAINER_NETWORKS" | grep -q "${NETWORK_NAME}"; then
                test_passed "${service_name} is on network '${NETWORK_NAME}'"
            else
                test_failed "${service_name} is NOT on network '${NETWORK_NAME}' (on: ${CONTAINER_NETWORKS})"
                add_recommendation "Connect ${container_name} to network: docker network connect ${NETWORK_NAME} ${container_name}"
            fi
            
            # Get container IP
            CONTAINER_IP=$(docker inspect --format='{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "${container_name}" 2>/dev/null | head -1)
            echo "    Container IP: ${CONTAINER_IP}"
            
            return 0
        else
            test_failed "${service_name} container '${container_name}' is ${STATUS}"
            add_recommendation "Start ${container_name} container"
            return 1
        fi
    else
        test_failed "${service_name} container '${container_name}' not found"
        add_recommendation "Install and start ${service_name} container"
        return 1
    fi
}

# Check each container
OPENCLOUD_RUNNING=false
COLLABORA_RUNNING=false
COLLABORATION_RUNNING=false

if check_container "${OPENCLOUD_CONTAINER}" "OpenCloud"; then
    OPENCLOUD_RUNNING=true
    OPENCLOUD_IP=$(docker inspect --format='{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "${OPENCLOUD_CONTAINER}" 2>/dev/null | head -1)
fi

if check_container "${COLLABORA_CONTAINER}" "Collabora"; then
    COLLABORA_RUNNING=true
    COLLABORA_IP=$(docker inspect --format='{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "${COLLABORA_CONTAINER}" 2>/dev/null | head -1)
fi

if check_container "${COLLABORATION_CONTAINER}" "Collaboration (WOPI)"; then
    COLLABORATION_RUNNING=true
    COLLABORATION_IP=$(docker inspect --format='{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "${COLLABORATION_CONTAINER}" 2>/dev/null | head -1)
fi

################################################################################
# TEST 4: PORT BINDING
################################################################################

print_section "Port Bindings"

check_port_binding() {
    local container_name=$1
    local expected_port=$2
    local service_name=$3
    
    if docker ps --format '{{.Names}}' | grep -q "^${container_name}$"; then
        BOUND_PORTS=$(docker port "${container_name}" 2>/dev/null | grep "${expected_port}/tcp" | awk '{print $3}')
        if [ -n "$BOUND_PORTS" ]; then
            test_passed "${service_name} port ${expected_port} is bound to ${BOUND_PORTS}"
        else
            test_warning "${service_name} port ${expected_port} not found in port bindings"
            echo "    Available ports: $(docker port ${container_name} 2>/dev/null | tr '\n' ' ')"
        fi
    fi
}

if [ "$OPENCLOUD_RUNNING" = true ]; then
    check_port_binding "${OPENCLOUD_CONTAINER}" "9200" "OpenCloud"
    check_port_binding "${OPENCLOUD_CONTAINER}" "9233" "OpenCloud NATS"
fi

if [ "$COLLABORA_RUNNING" = true ]; then
    check_port_binding "${COLLABORA_CONTAINER}" "9980" "Collabora"
fi

if [ "$COLLABORATION_RUNNING" = true ]; then
    check_port_binding "${COLLABORATION_CONTAINER}" "9300" "Collaboration WOPI"
    check_port_binding "${COLLABORATION_CONTAINER}" "9301" "Collaboration gRPC"
fi

################################################################################
# TEST 5: CONFIGURATION FILES
################################################################################

print_section "Configuration Files"

# Check CSP configuration
if [ -f "${OCL_CONFIG}/csp.yaml" ]; then
    test_passed "CSP configuration file exists"
    
    # Check for Collabora domains in CSP
    if grep -q "${COLLABORA_DOMAIN}" "${OCL_CONFIG}/csp.yaml"; then
        test_passed "CSP includes Collabora domain"
    else
        test_failed "CSP does NOT include Collabora domain"
        add_recommendation "Add Collabora domain to ${OCL_CONFIG}/csp.yaml frame-src and img-src"
    fi
else
    test_failed "CSP configuration file missing: ${OCL_CONFIG}/csp.yaml"
    add_recommendation "Create CSP configuration file - this is CRITICAL for Collabora integration"
fi

# Check banned password list
if [ -f "${OCL_CONFIG}/banned-password-list.txt" ]; then
    test_passed "Banned password list exists"
else
    test_warning "Banned password list not found"
fi

# Check if data directory exists
if [ -d "${OCL_DATA}" ]; then
    test_passed "Data directory exists: ${OCL_DATA}"
else
    test_failed "Data directory missing: ${OCL_DATA}"
fi

################################################################################
# TEST 6: INTERNAL CONTAINER CONNECTIVITY
################################################################################

print_section "Internal Container-to-Container Connectivity"

if [ "$OPENCLOUD_RUNNING" = true ] && [ "$COLLABORA_RUNNING" = true ] && [ "$COLLABORATION_RUNNING" = true ]; then
    
    # Test OpenCloud -> Collabora
    echo "Testing: OpenCloud -> Collabora..."
    if docker exec "${OPENCLOUD_CONTAINER}" wget -q -O- --timeout=5 "http://${COLLABORA_IP}:9980/" &> /dev/null; then
        test_passed "OpenCloud can reach Collabora internally (${COLLABORA_IP}:9980)"
    else
        test_failed "OpenCloud CANNOT reach Collabora internally"
        add_recommendation "Check network connectivity and firewall rules"
    fi
    
    # Test OpenCloud -> Collaboration (WOPI)
    echo "Testing: OpenCloud -> Collaboration (WOPI)..."
    if docker exec "${OPENCLOUD_CONTAINER}" wget -q -O- --timeout=5 "http://${COLLABORATION_IP}:9300/wopi" &> /dev/null; then
        test_passed "OpenCloud can reach Collaboration WOPI internally (${COLLABORATION_IP}:9300)"
    else
        test_failed "OpenCloud CANNOT reach Collaboration WOPI internally"
        add_recommendation "Verify WOPI server is running and listening on port 9300"
    fi
    
    # Test Collabora -> Collaboration (WOPI)
    echo "Testing: Collabora -> Collaboration (WOPI)..."
    if docker exec "${COLLABORA_CONTAINER}" wget -q -O- --timeout=5 "http://${COLLABORATION_IP}:9300/wopi" 2>&1 | grep -q "418\|teapot\|OK"; then
        test_passed "Collabora can reach Collaboration WOPI internally (${COLLABORATION_IP}:9300)"
    else
        test_warning "Collabora -> WOPI connection unclear (may still work)"
    fi
    
    # Test Collaboration -> OpenCloud
    echo "Testing: Collaboration -> OpenCloud..."
    if docker exec "${COLLABORATION_CONTAINER}" wget -q -O- --timeout=5 "http://${OPENCLOUD_IP}:9200/" &> /dev/null; then
        test_passed "Collaboration can reach OpenCloud internally (${OPENCLOUD_IP}:9200)"
    else
        test_failed "Collaboration CANNOT reach OpenCloud internally"
        add_recommendation "Verify network connectivity between containers"
    fi
    
else
    test_warning "Skipping internal connectivity tests (not all containers running)"
fi

################################################################################
# TEST 7: EXTERNAL DOMAIN ACCESSIBILITY
################################################################################

print_section "External Domain Accessibility"

# Test OpenCloud domain
echo "Testing: https://${OCIS_DOMAIN}..."
HTTP_CODE=$(curl -k -s -o /dev/null -w "%{http_code}" --max-time 10 "https://${OCIS_DOMAIN}/" 2>/dev/null)
if [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "302" ] || [ "$HTTP_CODE" = "301" ]; then
    test_passed "OpenCloud domain accessible (HTTP ${HTTP_CODE})"
else
    test_failed "OpenCloud domain not accessible (HTTP ${HTTP_CODE})"
    add_recommendation "Check reverse proxy configuration and DNS for ${OCIS_DOMAIN}"
fi

# Test Collabora domain
echo "Testing: https://${COLLABORA_DOMAIN}..."
HTTP_CODE=$(curl -k -s -o /dev/null -w "%{http_code}" --max-time 10 "https://${COLLABORA_DOMAIN}/" 2>/dev/null)
if [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "302" ] || [ "$HTTP_CODE" = "301" ]; then
    test_passed "Collabora domain accessible (HTTP ${HTTP_CODE})"
else
    test_failed "Collabora domain not accessible (HTTP ${HTTP_CODE})"
    add_recommendation "Check reverse proxy configuration and DNS for ${COLLABORA_DOMAIN}"
fi

# Test WOPI Server domain
echo "Testing: https://${WOPISERVER_DOMAIN}/wopi..."
WOPI_RESPONSE=$(curl -k -s --max-time 10 "https://${WOPISERVER_DOMAIN}/wopi" 2>/dev/null)
if echo "$WOPI_RESPONSE" | grep -qi "teapot"; then
    test_passed "WOPI Server domain accessible and responding correctly"
else
    HTTP_CODE=$(curl -k -s -o /dev/null -w "%{http_code}" --max-time 10 "https://${WOPISERVER_DOMAIN}/wopi" 2>/dev/null)
    test_failed "WOPI Server not responding correctly (HTTP ${HTTP_CODE})"
    add_recommendation "Check reverse proxy configuration for ${WOPISERVER_DOMAIN}"
    add_recommendation "Expected response: 'I'm a teapot' (HTTP 418)"
fi

################################################################################
# TEST 8: WOPI DISCOVERY
################################################################################

print_section "WOPI Discovery & Capabilities"

if [ "$COLLABORATION_RUNNING" = true ]; then
    # Test WOPI discovery endpoint
    echo "Testing WOPI discovery endpoint..."
    WOPI_DISCOVERY=$(curl -k -s --max-time 10 "https://${WOPISERVER_DOMAIN}/wopi/cbox/endpoints" 2>/dev/null)
    
    if [ -n "$WOPI_DISCOVERY" ]; then
        test_passed "WOPI discovery endpoint responding"
        
        # Try to parse with jq if available
        if check_command jq; then
            echo "  Supported actions:"
            echo "$WOPI_DISCOVERY" | jq -r '.app.capabilities[] | "    - \(.name)"' 2>/dev/null || echo "    (Unable to parse)"
        fi
    else
        test_failed "WOPI discovery endpoint not responding"
        add_recommendation "Verify Collaboration container environment variables"
    fi
else
    test_warning "Cannot test WOPI discovery (Collaboration container not running)"
fi

################################################################################
# TEST 9: COLLABORA CAPABILITIES
################################################################################

print_section "Collabora Online Capabilities"

if [ "$COLLABORA_RUNNING" = true ]; then
    # Test Collabora hosting discovery
    echo "Testing Collabora discovery..."
    COLLABORA_DISCOVERY=$(curl -k -s --max-time 10 "https://${COLLABORA_DOMAIN}/hosting/discovery" 2>/dev/null)
    
    if echo "$COLLABORA_DISCOVERY" | grep -q "wopi-discovery"; then
        test_passed "Collabora discovery endpoint responding"
        
        # Check for supported extensions
        if echo "$COLLABORA_DISCOVERY" | grep -q "docx"; then
            echo "  ✓ Word documents (.docx) supported"
        fi
        if echo "$COLLABORA_DISCOVERY" | grep -q "xlsx"; then
            echo "  ✓ Excel spreadsheets (.xlsx) supported"
        fi
        if echo "$COLLABORA_DISCOVERY" | grep -q "pptx"; then
            echo "  ✓ PowerPoint presentations (.pptx) supported"
        fi
    else
        test_failed "Collabora discovery endpoint not responding correctly"
        add_recommendation "Check Collabora container status and configuration"
    fi
    
    # Test Collabora admin console
    echo "Testing Collabora admin interface..."
    ADMIN_RESPONSE=$(curl -k -s -o /dev/null -w "%{http_code}" --max-time 10 "https://${COLLABORA_DOMAIN}/browser/dist/admin/admin.html" 2>/dev/null)
    if [ "$ADMIN_RESPONSE" = "200" ] || [ "$ADMIN_RESPONSE" = "401" ]; then
        test_passed "Collabora admin console accessible"
        if [ "$ADMIN_RESPONSE" = "401" ]; then
            echo "    (Protected by authentication - good!)"
        fi
    else
        test_warning "Collabora admin console returned HTTP ${ADMIN_RESPONSE}"
    fi
else
    test_warning "Cannot test Collabora capabilities (container not running)"
fi

################################################################################
# TEST 10: SSL/TLS CONFIGURATION
################################################################################

print_section "SSL/TLS Configuration"

# Check OpenCloud SSL
echo "Testing OpenCloud SSL..."
SSL_INFO=$(echo | openssl s_client -connect "${OCIS_DOMAIN}:443" -servername "${OCIS_DOMAIN}" 2>/dev/null | openssl x509 -noout -subject -dates 2>/dev/null)
if [ -n "$SSL_INFO" ]; then
    test_passed "OpenCloud SSL certificate valid"
    echo "$SSL_INFO" | while read line; do echo "    $line"; done
else
    test_warning "Could not verify OpenCloud SSL certificate"
    add_recommendation "Verify SSL certificate for ${OCIS_DOMAIN}"
fi

# Check Collabora SSL
echo "Testing Collabora SSL..."
SSL_INFO=$(echo | openssl s_client -connect "${COLLABORA_DOMAIN}:443" -servername "${COLLABORA_DOMAIN}" 2>/dev/null | openssl x509 -noout -subject -dates 2>/dev/null)
if [ -n "$SSL_INFO" ]; then
    test_passed "Collabora SSL certificate valid"
else
    test_warning "Could not verify Collabora SSL certificate"
fi

# Check WOPI SSL
echo "Testing WOPI Server SSL..."
SSL_INFO=$(echo | openssl s_client -connect "${WOPISERVER_DOMAIN}:443" -servername "${WOPISERVER_DOMAIN}" 2>/dev/null | openssl x509 -noout -subject -dates 2>/dev/null)
if [ -n "$SSL_INFO" ]; then
    test_passed "WOPI Server SSL certificate valid"
else
    test_warning "Could not verify WOPI Server SSL certificate"
fi

################################################################################
# TEST 11: WEBSOCKET SUPPORT
################################################################################

print_section "WebSocket Support"

if [ "$COLLABORA_RUNNING" = true ]; then
    # Test WebSocket endpoint
    echo "Testing WebSocket endpoint..."
    WS_RESPONSE=$(curl -k -s -o /dev/null -w "%{http_code}" --max-time 5 \
        -H "Upgrade: websocket" \
        -H "Connection: Upgrade" \
        "https://${COLLABORA_DOMAIN}/cool/adminws" 2>/dev/null)
    
    if [ "$WS_RESPONSE" = "101" ] || [ "$WS_RESPONSE" = "401" ] || [ "$WS_RESPONSE" = "403" ]; then
        test_passed "WebSocket upgrade supported (HTTP ${WS_RESPONSE})"
    else
        test_warning "WebSocket response unclear (HTTP ${WS_RESPONSE})"
        add_recommendation "Verify reverse proxy supports WebSocket connections"
    fi
else
    test_warning "Cannot test WebSocket (Collabora not running)"
fi

################################################################################
# TEST 12: CONTAINER ENVIRONMENT VARIABLES
################################################################################

print_section "Critical Environment Variables"

if [ "$OPENCLOUD_RUNNING" = true ]; then
    echo "Checking OpenCloud environment..."
    
    # Check OC_URL
    OC_URL=$(docker exec "${OPENCLOUD_CONTAINER}" printenv OC_URL 2>/dev/null)
    if [ "$OC_URL" = "https://${OCIS_DOMAIN}" ]; then
        test_passed "OC_URL correctly set to https://${OCIS_DOMAIN}"
    else
        test_failed "OC_URL mismatch: Expected 'https://${OCIS_DOMAIN}', Got '${OC_URL}'"
        add_recommendation "Update OC_URL in OpenCloud container configuration"
    fi
    
    # Check CSP config location
    CSP_LOC=$(docker exec "${OPENCLOUD_CONTAINER}" printenv PROXY_CSP_CONFIG_FILE_LOCATION 2>/dev/null)
    if [ -n "$CSP_LOC" ]; then
        test_passed "CSP config location set: ${CSP_LOC}"
    else
        test_warning "CSP config location not explicitly set"
    fi
fi

if [ "$COLLABORA_RUNNING" = true ]; then
    echo "Checking Collabora environment..."
    
    # Check aliasgroup1
    ALIAS=$(docker exec "${COLLABORA_CONTAINER}" printenv aliasgroup1 2>/dev/null)
    if echo "$ALIAS" | grep -q "${WOPISERVER_DOMAIN}"; then
        test_passed "Collabora aliasgroup1 includes WOPI domain"
    else
        test_failed "Collabora aliasgroup1 missing or incorrect: ${ALIAS}"
        add_recommendation "Set aliasgroup1=https://${WOPISERVER_DOMAIN}:443"
    fi
    
    # Check SSL settings
    EXTRA_PARAMS=$(docker exec "${COLLABORA_CONTAINER}" printenv extra_params 2>/dev/null)
    if echo "$EXTRA_PARAMS" | grep -q "ssl.enable=false"; then
        test_passed "SSL disabled in Collabora (correct for reverse proxy)"
    else
        test_warning "SSL settings unclear in Collabora"
    fi
fi

if [ "$COLLABORATION_RUNNING" = true ]; then
    echo "Checking Collaboration (WOPI) environment..."
    
    # Check COLLABORATION_WOPI_SRC
    WOPI_SRC=$(docker exec "${COLLABORATION_CONTAINER}" printenv COLLABORATION_WOPI_SRC 2>/dev/null)
    if [ "$WOPI_SRC" = "https://${WOPISERVER_DOMAIN}" ]; then
        test_passed "COLLABORATION_WOPI_SRC correctly set"
    else
        test_failed "COLLABORATION_WOPI_SRC mismatch: ${WOPI_SRC}"
        add_recommendation "Set COLLABORATION_WOPI_SRC=https://${WOPISERVER_DOMAIN}"
    fi
    
    # Check COLLABORATION_APP_ADDR
    APP_ADDR=$(docker exec "${COLLABORATION_CONTAINER}" printenv COLLABORATION_APP_ADDR 2>/dev/null)
    if [ "$APP_ADDR" = "https://${COLLABORA_DOMAIN}" ]; then
        test_passed "COLLABORATION_APP_ADDR correctly set"
    else
        test_failed "COLLABORATION_APP_ADDR mismatch: ${APP_ADDR}"
        add_recommendation "Set COLLABORATION_APP_ADDR=https://${COLLABORA_DOMAIN}"
    fi
fi

################################################################################
# TEST 13: CONTAINER LOGS ANALYSIS
################################################################################

if [ "$EXTENDED_TESTS" = "true" ]; then
    print_section "Container Logs Analysis (Last 50 lines)"
    
    if [ "$OPENCLOUD_RUNNING" = true ]; then
        echo "Analyzing OpenCloud logs for errors..."
        ERROR_COUNT=$(docker logs "${OPENCLOUD_CONTAINER}" --tail 50 2>&1 | grep -i "error\|fatal\|panic" | wc -l)
        if [ "$ERROR_COUNT" -eq 0 ]; then
            test_passed "No recent errors in OpenCloud logs"
        else
            test_warning "Found ${ERROR_COUNT} error messages in OpenCloud logs"
            echo "  Recent errors:"
            docker logs "${OPENCLOUD_CONTAINER}" --tail 50 2>&1 | grep -i "error\|fatal\|panic" | tail -3 | while read line; do
                echo "    $line"
            done
        fi
    fi
    
    if [ "$COLLABORA_RUNNING" = true ]; then
        echo "Analyzing Collabora logs for errors..."
        ERROR_COUNT=$(docker logs "${COLLABORA_CONTAINER}" --tail 50 2>&1 | grep -i "error\|fatal\|err:" | wc -l)
        if [ "$ERROR_COUNT" -eq 0 ]; then
            test_passed "No recent errors in Collabora logs"
        else
            test_warning "Found ${ERROR_COUNT} error messages in Collabora logs"
        fi
    fi
    
    if [ "$COLLABORATION_RUNNING" = true ]; then
        echo "Analyzing Collaboration logs for errors..."
        ERROR_COUNT=$(docker logs "${COLLABORATION_CONTAINER}" --tail 50 2>&1 | grep -i "error\|fatal\|panic" | wc -l)
        if [ "$ERROR_COUNT" -eq 0 ]; then
            test_passed "No recent errors in Collaboration logs"
        else
            test_warning "Found ${ERROR_COUNT} error messages in Collaboration logs"
        fi
    fi
fi

################################################################################
# TEST 14: REVERSE PROXY CONFIGURATION
################################################################################

print_section "Reverse Proxy Configuration"

case "$PROXY_TYPE" in
    swag)
        PROXY_CONF_PATH="/mnt/user/appdata/swag/nginx/proxy-confs"
        if [ -d "$PROXY_CONF_PATH" ]; then
            test_passed "SWAG configuration directory found"
            
            # Check for configuration files
            if ls "${PROXY_CONF_PATH}"/*opencloud*.conf &> /dev/null; then
                test_passed "OpenCloud proxy config exists"
            else
                test_warning "OpenCloud proxy config not found in SWAG"
            fi
            
            if ls "${PROXY_CONF_PATH}"/*collabora*.conf &> /dev/null; then
                test_passed "Collabora proxy config exists"
            else
                test_warning "Collabora proxy config not found in SWAG"
            fi
            
            if ls "${PROXY_CONF_PATH}"/*wopi*.conf &> /dev/null; then
                test_passed "WOPI proxy config exists"
            else
                test_warning "WOPI proxy config not found in SWAG"
            fi
        else
            test_warning "SWAG configuration directory not found at ${PROXY_CONF_PATH}"
        fi
        ;;
    *)
        test_warning "Cannot auto-check ${PROXY_TYPE} configuration"
        echo "  Please manually verify:"
        echo "    - All three domains are proxied correctly"
        echo "    - WebSocket support is enabled"
        echo "    - SSL termination is configured"
        ;;
esac

################################################################################
# FINAL SUMMARY
################################################################################

echo ""
print_header "DIAGNOSTIC SUMMARY"
echo ""
echo "Test Results:"
echo -e "  ${GREEN}Passed:  ${PASSED_TESTS}${NC}"
echo -e "  ${RED}Failed:  ${FAILED_TESTS}${NC}"
echo -e "  ${YELLOW}Warnings: ${WARNING_TESTS}${NC}"
echo -e "  Total:   ${TOTAL_TESTS}"
echo ""

# Calculate success rate
if [ $TOTAL_TESTS -gt 0 ]; then
    SUCCESS_RATE=$((PASSED_TESTS * 100 / TOTAL_TESTS))
    echo "Success Rate: ${SUCCESS_RATE}%"
    echo ""
fi

# Display failures
if [ ${#FAILURES[@]} -gt 0 ]; then
    echo -e "${RED}Critical Failures:${NC}"
    for failure in "${FAILURES[@]}"; do
        echo -e "  ${RED}✗${NC} $failure"
    done
    echo ""
fi

# Display warnings
if [ ${#WARNINGS[@]} -gt 0 ]; then
    echo -e "${YELLOW}Warnings:${NC}"
    for warning in "${WARNINGS[@]}"; do
        echo -e "  ${YELLOW}⚠${NC} $warning"
    done
    echo ""
fi

# Display recommendations
if [ ${#RECOMMENDATIONS[@]} -gt 0 ]; then
    echo -e "${CYAN}Recommendations:${NC}"
    for i in "${!RECOMMENDATIONS[@]}"; do
        echo -e "  $((i+1)). ${RECOMMENDATIONS[$i]}"
    done
    echo ""
fi

# Overall assessment
echo -e "${CYAN}Overall Assessment:${NC}"
if [ $FAILED_TESTS -eq 0 ] && [ $WARNING_TESTS -le 2 ]; then
    echo -e "${GREEN}✓ System appears healthy and properly configured${NC}"
    echo "  OpenCloud + Collabora integration should be working."
elif [ $FAILED_TESTS -le 3 ]; then
    echo -e "${YELLOW}⚠ System has minor issues${NC}"
    echo "  Address the failures above to ensure full functionality."
else
    echo -e "${RED}✗ System has significant issues${NC}"
    echo "  Multiple components need attention. Follow recommendations above."
fi

echo ""
print_header "DIAGNOSTIC COMPLETE"
echo ""
echo "For detailed troubleshooting, check:"
echo "  - Container logs: docker logs <container-name>"
echo "  - Network details: docker network inspect ${NETWORK_NAME}"
echo "  - OpenCloud docs: https://docs.opencloud.eu/"
echo ""

exit 0
