#!/bin/bash
################################################################################
# OpenCloud + Collabora + WOPI Integration Diagnostic Script v2
# For Unraid User Scripts Plugin
# Tests connectivity, configuration, and integration between all components
################################################################################
#name=OpenCloud Collabora Diagnostic v2
#description=Comprehensive diagnostic tool for OpenCloud with Collabora integration
#arrayStarted=true

################################################################################
# USER CONFIGURATION - EDIT THESE VALUES
################################################################################

# Domain Configuration (without https://)
OCIS_DOMAIN="opencloud.yourdomain.com"
COLLABORA_DOMAIN="collabora.yourdomain.com"
WOPISERVER_DOMAIN="wopi.yourdomain.com"

# Container Names (as shown in Docker)
OPENCLOUD_CONTAINER="OpenCloud"
COLLABORA_CONTAINER="Collabora"
COLLABORATION_CONTAINER="Collaboration"

# Docker Network Name
NETWORK_NAME="opencloud-net"

# Installation Paths
OCL_CONFIG="/mnt/user/appdata/opencloud/config"
OCL_DATA="/mnt/user/appdata/opencloud/data"

# Reverse Proxy Type (swag, nginx, traefik, caddy, pangolin, other)
PROXY_TYPE="swag"  # Options: swag, nginx, traefik, caddy, pangolin, other

# Enable Extended Tests (slower but more thorough)
EXTENDED_TESTS="true"

# Hide Sensitive Data (true = safe to share publicly, false = full details)
HIDE_SENSITIVE_DATA="false"  # Set to "true" to sanitize output for sharing

# Diagnostic Report File Location
DIAGNOSTIC_FILE="${OCL_CONFIG}/opencloud-diagnostic-$(date +%Y%m%d-%H%M%S).log"

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

# Component tracking
declare -A COMPONENT_TESTS
declare -A COMPONENT_PASSED
declare -A COMPONENT_FAILED
declare -A COMPONENT_WARNINGS

# Result storage
declare -a FAILURES
declare -a WARNINGS
declare -a RECOMMENDATIONS
declare -a DETAILED_ERRORS

# Critical failure tracking
CRITICAL_FAILURES=false

# Cached IPs for sanitization
OPENCLOUD_IP=""
COLLABORA_IP=""
COLLABORATION_IP=""
HOST_IP=""

################################################################################
# HELPER FUNCTIONS
################################################################################

# Sanitize sensitive data if HIDE_SENSITIVE_DATA is true
sanitize() {
    local text="$1"
    
    if [ "$HIDE_SENSITIVE_DATA" = "true" ]; then
        # Replace specific IPs with generic placeholders
        if [ -n "$OPENCLOUD_IP" ]; then
            text=$(echo "$text" | sed "s/${OPENCLOUD_IP}/[OPENCLOUD-IP]/g")
        fi
        if [ -n "$COLLABORA_IP" ]; then
            text=$(echo "$text" | sed "s/${COLLABORA_IP}/[COLLABORA-IP]/g")
        fi
        if [ -n "$COLLABORATION_IP" ]; then
            text=$(echo "$text" | sed "s/${COLLABORATION_IP}/[WOPI-IP]/g")
        fi
        
        # Replace generic IP patterns
        text=$(echo "$text" | sed -E 's/[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/[IP-HIDDEN]/g')
        
        # Replace password/token patterns
        text=$(echo "$text" | sed -E 's/(PASSWORD|TOKEN|SECRET|KEY)=[^[:space:]]+/\1=[REDACTED]/gi')
        text=$(echo "$text" | sed -E 's/(password|token|secret|key)[:=][^[:space:]]+/\1=[REDACTED]/gi')
        
        # Replace domain names with generic versions (optional - uncomment if needed)
        # text=$(echo "$text" | sed "s/${OCIS_DOMAIN}/opencloud.example.com/g")
        # text=$(echo "$text" | sed "s/${COLLABORA_DOMAIN}/collabora.example.com/g")
        # text=$(echo "$text" | sed "s/${WOPISERVER_DOMAIN}/wopiserver.example.com/g")
        
        # Mark certificate data as hidden
        if echo "$text" | grep -q "BEGIN CERTIFICATE"; then
            text="[SSL-CERTIFICATE-DETAILS-HIDDEN-FOR-PRIVACY]"
        fi
    fi
    
    echo "$text"
}

# Initialize diagnostic file
init_diagnostic_file() {
    mkdir -p "$(dirname "$DIAGNOSTIC_FILE")"
    
    local header="================================================================================
OpenCloud + Collabora + WOPI Integration Diagnostic Report
================================================================================
Generated: $(date '+%Y-%m-%d %H:%M:%S %Z')
Hostname: $(hostname)
Unraid Version: $(cat /etc/unraid-version 2>/dev/null || echo "Unknown")

Configuration:
  OpenCloud:     https://${OCIS_DOMAIN}
  Collabora:     https://${COLLABORA_DOMAIN}
  WOPI Server:   https://${WOPISERVER_DOMAIN}
  Proxy Type:    ${PROXY_TYPE}
  Network:       ${NETWORK_NAME}
  Sensitive Data Hiding: ${HIDE_SENSITIVE_DATA}

================================================================================"
    
    if [ "$HIDE_SENSITIVE_DATA" = "true" ]; then
        header="$header

⚠️ PRIVACY MODE ENABLED ⚠️
This report has been sanitized for public sharing:
  - IP addresses replaced with placeholders
  - Passwords/tokens redacted
  - SSL certificates hidden
  - Some technical details may be obscured for privacy

================================================================================"
    fi
    
    echo "$header" > "$DIAGNOSTIC_FILE"
    echo "" >> "$DIAGNOSTIC_FILE"
}

# Log to both console and file with sanitization
log_both() {
    local sanitized=$(sanitize "$1")
    echo -e "$sanitized" | tee -a "$DIAGNOSTIC_FILE"
}

# Log only to file with sanitization
log_file() {
    local sanitized=$(sanitize "$1")
    echo -e "$sanitized" >> "$DIAGNOSTIC_FILE"
}

print_header() {
    log_both "${CYAN}================================================${NC}"
    log_both "${CYAN}$1${NC}"
    log_both "${CYAN}================================================${NC}"
}

print_section() {
    log_both ""
    log_both "${BLUE}[TEST] $1${NC}"
    log_both "----------------------------------------"
}

# Track component for categorization
track_component() {
    local component="$1"
    COMPONENT_TESTS[$component]=$((${COMPONENT_TESTS[$component]:-0} + 1))
}

test_passed() {
    local message="$1"
    local details="$2"
    local component="${3:-General}"
    
    log_both "${GREEN}✓ PASS${NC}: $message"
    if [ -n "$details" ]; then
        log_file "  Details: $details"
    fi
    ((PASSED_TESTS++))
    ((TOTAL_TESTS++))
    
    track_component "$component"
    COMPONENT_PASSED[$component]=$((${COMPONENT_PASSED[$component]:-0} + 1))
}

test_failed() {
    local message="$1"
    local error_details="$2"
    local component="${3:-General}"
    local is_critical="${4:-false}"
    
    log_both "${RED}✗ FAIL${NC}: $message"
    
    if [ -n "$error_details" ]; then
        log_both "  ${RED}Error:${NC} ${error_details:0:200}"
        log_file "  Full Error Details:"
        log_file "$error_details"
        DETAILED_ERRORS+=("FAIL|$component|$message|$error_details")
    fi
    
    FAILURES+=("$component: $message")
    ((FAILED_TESTS++))
    ((TOTAL_TESTS++))
    
    track_component "$component"
    COMPONENT_FAILED[$component]=$((${COMPONENT_FAILED[$component]:-0} + 1))
    
    if [ "$is_critical" = "true" ]; then
        CRITICAL_FAILURES=true
    fi
}

test_warning() {
    local message="$1"
    local warning_details="$2"
    local component="${3:-General}"
    
    log_both "${YELLOW}⚠ WARN${NC}: $message"
    
    if [ -n "$warning_details" ]; then
        log_both "  ${YELLOW}Details:${NC} ${warning_details:0:200}"
        log_file "$warning_details"
        DETAILED_ERRORS+=("WARN|$component|$message|$warning_details")
    fi
    
    WARNINGS+=("$component: $message")
    ((WARNING_TESTS++))
    ((TOTAL_TESTS++))
    
    track_component "$component"
    COMPONENT_WARNINGS[$component]=$((${COMPONENT_WARNINGS[$component]:-0} + 1))
}

add_recommendation() {
    RECOMMENDATIONS+=("$1")
    log_file "  Recommendation: $1"
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
init_diagnostic_file

print_header "OpenCloud + Collabora Diagnostic Tool v2"
log_both ""
log_both "Configuration:"
log_both "  OpenCloud:     https://${OCIS_DOMAIN}"
log_both "  Collabora:     https://${COLLABORA_DOMAIN}"
log_both "  WOPI Server:   https://${WOPISERVER_DOMAIN}"
log_both "  Proxy Type:    ${PROXY_TYPE}"
log_both "  Network:       ${NETWORK_NAME}"

if [ "$HIDE_SENSITIVE_DATA" = "true" ]; then
    log_both ""
    log_both "${YELLOW}⚠️  Privacy Mode: ENABLED${NC}"
    log_both "  Output sanitized for public sharing"
fi

log_both ""
log_both "Diagnostic report will be saved to:"
log_both "  ${DIAGNOSTIC_FILE}"
log_both ""
log_both "Starting diagnostics..."
sleep 2

################################################################################
# TEST 1: SYSTEM PREREQUISITES
################################################################################

print_section "System Prerequisites"

# Check Docker
if check_command docker; then
    DOCKER_VERSION=$(docker --version 2>&1)
    test_passed "Docker installed" "$DOCKER_VERSION" "System"
    log_file "Docker version: $DOCKER_VERSION"
else
    test_failed "Docker not found" "Docker command not available in PATH" "System" "true"
    log_both "${RED}CRITICAL: Cannot continue without Docker${NC}"
    exit 1
fi

# Check curl
if check_command curl; then
    CURL_VERSION=$(curl --version 2>&1 | head -1)
    test_passed "curl command available" "$CURL_VERSION" "System"
else
    test_failed "curl not found (required for testing)" "curl command not in PATH" "System"
    add_recommendation "Install curl: opkg install curl"
fi

# Check jq
if check_command jq; then
    JQ_VERSION=$(jq --version 2>&1)
    test_passed "jq available (JSON parsing enabled)" "$JQ_VERSION" "System"
else
    test_warning "jq not found (some tests will be limited)" "JSON parsing will be unavailable" "System"
    add_recommendation "Install jq for better JSON parsing: opkg install jq"
fi

################################################################################
# TEST 2: DOCKER NETWORK
################################################################################

print_section "Docker Network Configuration"

NETWORK_INSPECT=$(docker network inspect "${NETWORK_NAME}" 2>&1)
if [ $? -eq 0 ]; then
    test_passed "Network '${NETWORK_NAME}' exists" "" "Network"
    
    log_file "Full network details:"
    log_file "$NETWORK_INSPECT"
    
    NETWORK_SUBNET=$(echo "$NETWORK_INSPECT" | grep -o '"Subnet": "[^"]*"' | head -1 | cut -d'"' -f4)
    NETWORK_GATEWAY=$(echo "$NETWORK_INSPECT" | grep -o '"Gateway": "[^"]*"' | head -1 | cut -d'"' -f4)
    
    log_both "  Network Details:"
    log_both "    Subnet:  ${NETWORK_SUBNET}"
    log_both "    Gateway: ${NETWORK_GATEWAY}"
    
    log_both "  Containers on network:"
    NETWORK_CONTAINERS=$(docker network inspect "${NETWORK_NAME}" --format='{{range .Containers}}{{.Name}} ({{.IPv4Address}}){{println}}{{end}}' 2>/dev/null)
    if [ -n "$NETWORK_CONTAINERS" ]; then
        echo "$NETWORK_CONTAINERS" | while read line; do
            log_both "    - $line"
        done
    else
        test_warning "No containers found on network '${NETWORK_NAME}'" "Network exists but has no connected containers" "Network"
    fi
else
    ERROR_MSG=$(echo "$NETWORK_INSPECT" | tail -5)
    test_failed "Network '${NETWORK_NAME}' does not exist" "$ERROR_MSG" "Network" "true"
    add_recommendation "Create network: docker network create ${NETWORK_NAME}"
fi

################################################################################
# TEST 3: CONTAINER STATUS
################################################################################

print_section "Container Status"

check_container() {
    local container_name=$1
    local service_name=$2
    local component=$3
    
    CONTAINER_PS=$(docker ps -a --filter "name=^${container_name}$" --format "{{.Names}}|{{.Status}}|{{.State}}" 2>&1)
    
    if echo "$CONTAINER_PS" | grep -q "^${container_name}"; then
        STATUS=$(echo "$CONTAINER_PS" | cut -d'|' -f2)
        STATE=$(echo "$CONTAINER_PS" | cut -d'|' -f3)
        
        CONTAINER_DETAILS=$(docker inspect "${container_name}" 2>&1)
        log_file "Container ${container_name} full details:"
        log_file "$CONTAINER_DETAILS"
        
        if [ "$STATE" = "running" ]; then
            UPTIME=$(docker inspect --format='{{.State.StartedAt}}' "${container_name}" 2>/dev/null)
            test_passed "${service_name} container '${container_name}' is running" "Started: ${UPTIME}, Status: ${STATUS}" "$component"
            log_both "    Started: ${UPTIME}"
            
            CONTAINER_NETWORKS=$(docker inspect --format='{{range $k,$v := .NetworkSettings.Networks}}{{$k}} {{end}}' "${container_name}" 2>/dev/null)
            if echo "$CONTAINER_NETWORKS" | grep -q "${NETWORK_NAME}"; then
                test_passed "${service_name} is on network '${NETWORK_NAME}'" "Networks: ${CONTAINER_NETWORKS}" "$component"
            else
                test_failed "${service_name} is NOT on network '${NETWORK_NAME}'" "Current networks: ${CONTAINER_NETWORKS}, Expected: ${NETWORK_NAME}" "$component" "true"
                add_recommendation "Connect ${container_name} to network: docker network connect ${NETWORK_NAME} ${container_name}"
            fi
            
            CONTAINER_IP=$(docker inspect --format='{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "${container_name}" 2>/dev/null | head -1)
            log_both "    Container IP: ${CONTAINER_IP}"
            
            return 0
        else
            CONTAINER_LOGS=$(docker logs "${container_name}" --tail 20 2>&1)
            test_failed "${service_name} container '${container_name}' is ${STATE}" "Status: ${STATUS}\n\nLast 20 log lines:\n${CONTAINER_LOGS}" "$component" "true"
            add_recommendation "Start ${container_name} container"
            return 1
        fi
    else
        test_failed "${service_name} container '${container_name}' not found" "Docker ps output: ${CONTAINER_PS}" "$component" "true"
        add_recommendation "Install and start ${service_name} container"
        return 1
    fi
}

OPENCLOUD_RUNNING=false
COLLABORA_RUNNING=false
COLLABORATION_RUNNING=false

if check_container "${OPENCLOUD_CONTAINER}" "OpenCloud" "OpenCloud"; then
    OPENCLOUD_RUNNING=true
    OPENCLOUD_IP=$(docker inspect --format='{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "${OPENCLOUD_CONTAINER}" 2>/dev/null | head -1)
fi

if check_container "${COLLABORA_CONTAINER}" "Collabora" "Collabora"; then
    COLLABORA_RUNNING=true
    COLLABORA_IP=$(docker inspect --format='{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "${COLLABORA_CONTAINER}" 2>/dev/null | head -1)
fi

if check_container "${COLLABORATION_CONTAINER}" "Collaboration (WOPI)" "WOPI Server"; then
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
    local component=$4
    
    if docker ps --format '{{.Names}}' | grep -q "^${container_name}$"; then
        ALL_PORTS=$(docker port "${container_name}" 2>&1)
        log_file "All ports for ${container_name}:"
        log_file "$ALL_PORTS"
        
        BOUND_PORTS=$(echo "$ALL_PORTS" | grep "${expected_port}/tcp" | awk '{print $3}')
        if [ -n "$BOUND_PORTS" ]; then
            test_passed "${service_name} port ${expected_port} is bound to ${BOUND_PORTS}" "Full port list: ${ALL_PORTS}" "$component"
        else
            test_warning "${service_name} port ${expected_port} not found in port bindings" "Available ports: ${ALL_PORTS}" "$component"
        fi
    fi
}

if [ "$OPENCLOUD_RUNNING" = true ]; then
    check_port_binding "${OPENCLOUD_CONTAINER}" "9200" "OpenCloud" "OpenCloud"
    check_port_binding "${OPENCLOUD_CONTAINER}" "9233" "OpenCloud NATS" "OpenCloud"
fi

if [ "$COLLABORA_RUNNING" = true ]; then
    check_port_binding "${COLLABORA_CONTAINER}" "9980" "Collabora" "Collabora"
fi

if [ "$COLLABORATION_RUNNING" = true ]; then
    check_port_binding "${COLLABORATION_CONTAINER}" "9300" "Collaboration WOPI" "WOPI Server"
    check_port_binding "${COLLABORATION_CONTAINER}" "9301" "Collaboration gRPC" "WOPI Server"
fi

################################################################################
# TEST 5: CONFIGURATION FILES
################################################################################

print_section "Configuration Files"

if [ -f "${OCL_CONFIG}/csp.yaml" ]; then
    test_passed "CSP configuration file exists" "Path: ${OCL_CONFIG}/csp.yaml" "OpenCloud"
    
    CSP_CONTENT=$(cat "${OCL_CONFIG}/csp.yaml" 2>&1)
    log_file "CSP file contents:"
    log_file "$CSP_CONTENT"
    
    if grep -q "${COLLABORA_DOMAIN}" "${OCL_CONFIG}/csp.yaml"; then
        test_passed "CSP includes Collabora domain" "Found ${COLLABORA_DOMAIN} in CSP config" "OpenCloud"
    else
        test_failed "CSP does NOT include Collabora domain" "Expected to find ${COLLABORA_DOMAIN} in frame-src and img-src\n\nCurrent CSP content:\n${CSP_CONTENT}" "OpenCloud" "true"
        add_recommendation "Add Collabora domain to ${OCL_CONFIG}/csp.yaml frame-src and img-src sections"
    fi
else
    test_failed "CSP configuration file missing: ${OCL_CONFIG}/csp.yaml" "File does not exist at expected location" "OpenCloud" "true"
    add_recommendation "Create CSP configuration file - this is CRITICAL for Collabora integration"
fi

if [ -f "${OCL_CONFIG}/banned-password-list.txt" ]; then
    test_passed "Banned password list exists" "Path: ${OCL_CONFIG}/banned-password-list.txt" "OpenCloud"
else
    test_warning "Banned password list not found" "Expected at ${OCL_CONFIG}/banned-password-list.txt" "OpenCloud"
fi

if [ -d "${OCL_DATA}" ]; then
    DATA_SIZE=$(du -sh "${OCL_DATA}" 2>/dev/null | cut -f1)
    test_passed "Data directory exists: ${OCL_DATA}" "Size: ${DATA_SIZE}" "OpenCloud"
else
    test_failed "Data directory missing: ${OCL_DATA}" "Directory does not exist" "OpenCloud" "true"
fi

################################################################################
# TEST 6: INTERNAL CONTAINER CONNECTIVITY
################################################################################

print_section "Internal Container-to-Container Connectivity"

if [ "$OPENCLOUD_RUNNING" = true ] && [ "$COLLABORA_RUNNING" = true ] && [ "$COLLABORATION_RUNNING" = true ]; then
    
    log_both "Testing: OpenCloud -> Collabora..."
    TEST_RESULT=$(docker exec "${OPENCLOUD_CONTAINER}" wget -q -O- --timeout=5 "http://${COLLABORA_IP}:9980/" 2>&1)
    if [ $? -eq 0 ]; then
        test_passed "OpenCloud can reach Collabora internally (${COLLABORA_IP}:9980)" "Response received successfully" "Connectivity"
    else
        test_failed "OpenCloud CANNOT reach Collabora internally" "Target: http://${COLLABORA_IP}:9980/\nError: ${TEST_RESULT}" "Connectivity" "true"
        add_recommendation "Check network connectivity and firewall rules between containers"
    fi
    
    log_both "Testing: OpenCloud -> Collaboration (WOPI)..."
    TEST_RESULT=$(docker exec "${OPENCLOUD_CONTAINER}" wget -q -O- --timeout=5 "http://${COLLABORATION_IP}:9300/wopi" 2>&1)
    # HTTP 418 "I'm a teapot" is the CORRECT response from WOPI server!
    if echo "$TEST_RESULT" | grep -qi "teapot\|418"; then
        test_passed "OpenCloud can reach Collaboration WOPI internally (${COLLABORATION_IP}:9300)" "WOPI server responding correctly with HTTP 418 'I'm a teapot'" "Connectivity"
    elif [ $? -eq 0 ]; then
        test_passed "OpenCloud can reach Collaboration WOPI internally (${COLLABORATION_IP}:9300)" "Response: ${TEST_RESULT:0:100}" "Connectivity"
    else
        test_failed "OpenCloud CANNOT reach Collaboration WOPI internally" "Target: http://${COLLABORATION_IP}:9300/wopi\nError: ${TEST_RESULT}" "Connectivity" "true"
        add_recommendation "Verify WOPI server is running and listening on port 9300"
    fi
    
    log_both "Testing: Collabora -> Collaboration (WOPI)..."
    TEST_RESULT=$(docker exec "${COLLABORA_CONTAINER}" wget -q -O- --timeout=5 "http://${COLLABORATION_IP}:9300/wopi" 2>&1)
    if echo "$TEST_RESULT" | grep -qi "teapot\|418"; then
        test_passed "Collabora can reach Collaboration WOPI internally (${COLLABORATION_IP}:9300)" "WOPI server responding correctly with HTTP 418 'I'm a teapot'" "Connectivity"
    else
        test_warning "Collabora -> WOPI connection unclear (may still work)" "Response: ${TEST_RESULT:0:100}" "Connectivity"
    fi
    
    log_both "Testing: Collaboration -> OpenCloud..."
    TEST_RESULT=$(docker exec "${COLLABORATION_CONTAINER}" wget -q -O- --timeout=5 "http://${OPENCLOUD_IP}:9200/" 2>&1)
    if [ $? -eq 0 ]; then
        test_passed "Collaboration can reach OpenCloud internally (${OPENCLOUD_IP}:9200)" "Connection successful" "Connectivity"
    else
        test_failed "Collaboration CANNOT reach OpenCloud internally" "Target: http://${OPENCLOUD_IP}:9200/\nError: ${TEST_RESULT}" "Connectivity" "true"
        add_recommendation "Verify network connectivity between containers"
    fi
    
else
    test_warning "Skipping internal connectivity tests (not all containers running)" "OpenCloud: ${OPENCLOUD_RUNNING}, Collabora: ${COLLABORA_RUNNING}, Collaboration: ${COLLABORATION_RUNNING}" "Connectivity"
fi

################################################################################
# TEST 7: EXTERNAL DOMAIN ACCESSIBILITY
################################################################################

print_section "External Domain Accessibility"

log_both "Testing: https://${OCIS_DOMAIN}..."
HTTP_RESPONSE=$(curl -k -s -o /tmp/ocis_response.txt -w "%{http_code}" --max-time 10 "https://${OCIS_DOMAIN}/" 2>&1)
HTTP_CODE="${HTTP_RESPONSE: -3}"
RESPONSE_BODY=$(cat /tmp/ocis_response.txt 2>/dev/null)

if [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "302" ] || [ "$HTTP_CODE" = "301" ]; then
    test_passed "OpenCloud domain accessible (HTTP ${HTTP_CODE})" "URL: https://${OCIS_DOMAIN}/" "Reverse Proxy"
else
    test_failed "OpenCloud domain not accessible (HTTP ${HTTP_CODE})" "URL: https://${OCIS_DOMAIN}/\nHTTP Code: ${HTTP_CODE}\nResponse: ${RESPONSE_BODY:0:500}" "Reverse Proxy" "true"
    add_recommendation "Check reverse proxy configuration and DNS for ${OCIS_DOMAIN}"
fi

log_both "Testing: https://${COLLABORA_DOMAIN}..."
HTTP_RESPONSE=$(curl -k -s -o /tmp/collabora_response.txt -w "%{http_code}" --max-time 10 "https://${COLLABORA_DOMAIN}/" 2>&1)
HTTP_CODE="${HTTP_RESPONSE: -3}"
RESPONSE_BODY=$(cat /tmp/collabora_response.txt 2>/dev/null)

if [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "302" ] || [ "$HTTP_CODE" = "301" ]; then
    test_passed "Collabora domain accessible (HTTP ${HTTP_CODE})" "URL: https://${COLLABORA_DOMAIN}/" "Reverse Proxy"
else
    test_failed "Collabora domain not accessible (HTTP ${HTTP_CODE})" "URL: https://${COLLABORA_DOMAIN}/\nHTTP Code: ${HTTP_CODE}\nResponse: ${RESPONSE_BODY:0:500}" "Reverse Proxy" "true"
    add_recommendation "Check reverse proxy configuration and DNS for ${COLLABORA_DOMAIN}"
fi

log_both "Testing: https://${WOPISERVER_DOMAIN}/wopi..."
WOPI_RESPONSE=$(curl -k -s --max-time 10 "https://${WOPISERVER_DOMAIN}/wopi" 2>&1)
HTTP_CODE=$(curl -k -s -o /dev/null -w "%{http_code}" --max-time 10 "https://${WOPISERVER_DOMAIN}/wopi" 2>/dev/null)

# HTTP 418 "I'm a teapot" is the CORRECT response!
if echo "$WOPI_RESPONSE" | grep -qi "teapot" || [ "$HTTP_CODE" = "418" ]; then
    test_passed "WOPI Server domain accessible and responding correctly" "Response: HTTP 418 'I'm a teapot' (this is correct!)" "Reverse Proxy"
else
    test_failed "WOPI Server not responding correctly (HTTP ${HTTP_CODE})" "URL: https://${WOPISERVER_DOMAIN}/wopi\nHTTP Code: ${HTTP_CODE}\nExpected: HTTP 418 'I'm a teapot'\nReceived: ${WOPI_RESPONSE:0:200}" "Reverse Proxy" "true"
    add_recommendation "Check reverse proxy configuration for ${WOPISERVER_DOMAIN}"
fi

################################################################################
# TEST 8: WOPI DISCOVERY
################################################################################

print_section "WOPI Discovery & Capabilities"

if [ "$COLLABORATION_RUNNING" = true ]; then
    log_both "Testing WOPI discovery endpoint..."
    WOPI_DISCOVERY=$(curl -k -s --max-time 10 "https://${WOPISERVER_DOMAIN}/wopi/cbox/endpoints" 2>&1)
    
    log_file "WOPI Discovery Response:"
    log_file "$WOPI_DISCOVERY"
    
    if [ -n "$WOPI_DISCOVERY" ]; then
        test_passed "WOPI discovery endpoint responding" "Endpoint: https://${WOPISERVER_DOMAIN}/wopi/cbox/endpoints" "WOPI Server"
        
        if check_command jq; then
            log_both "  Supported actions:"
            echo "$WOPI_DISCOVERY" | jq -r '.app.capabilities[]? | "    - \(.name)"' 2>/dev/null | tee -a "$DIAGNOSTIC_FILE" || log_both "    (Unable to parse capabilities)"
        fi
    else
        test_failed "WOPI discovery endpoint not responding" "URL: https://${WOPISERVER_DOMAIN}/wopi/cbox/endpoints\nNo response received" "WOPI Server" "true"
        add_recommendation "Verify Collaboration container environment variables"
    fi
else
    test_warning "Cannot test WOPI discovery (Collaboration container not running)" "Container ${COLLABORATION_CONTAINER} is not in running state" "WOPI Server"
fi

################################################################################
# TEST 9: COLLABORA CAPABILITIES
################################################################################

print_section "Collabora Online Capabilities"

if [ "$COLLABORA_RUNNING" = true ]; then
    log_both "Testing Collabora discovery..."
    COLLABORA_DISCOVERY=$(curl -k -s --max-time 10 "https://${COLLABORA_DOMAIN}/hosting/discovery" 2>&1)
    
    log_file "Collabora Discovery Response:"
    log_file "$COLLABORA_DISCOVERY"
    
    if echo "$COLLABORA_DISCOVERY" | grep -q "wopi-discovery"; then
        test_passed "Collabora discovery endpoint responding" "Endpoint: https://${COLLABORA_DOMAIN}/hosting/discovery" "Collabora"
        
        if echo "$COLLABORA_DISCOVERY" | grep -q "docx"; then
            log_both "  ✓ Word documents (.docx) supported"
        fi
        if echo "$COLLABORA_DISCOVERY" | grep -q "xlsx"; then
            log_both "  ✓ Excel spreadsheets (.xlsx) supported"
        fi
        if echo "$COLLABORA_DISCOVERY" | grep -q "pptx"; then
            log_both "  ✓ PowerPoint presentations (.pptx) supported"
        fi
    else
        test_failed "Collabora discovery endpoint not responding correctly" "URL: https://${COLLABORA_DOMAIN}/hosting/discovery\nExpected: XML with 'wopi-discovery'\nReceived: ${COLLABORA_DISCOVERY:0:500}" "Collabora" "true"
        add_recommendation "Check Collabora container status and configuration"
    fi
    
    log_both "Testing Collabora admin interface..."
    ADMIN_RESPONSE=$(curl -k -s -o /dev/null -w "%{http_code}" --max-time 10 "https://${COLLABORA_DOMAIN}/browser/dist/admin/admin.html" 2>&1)
    if [ "$ADMIN_RESPONSE" = "200" ] || [ "$ADMIN_RESPONSE" = "401" ]; then
        test_passed "Collabora admin console accessible" "HTTP ${ADMIN_RESPONSE}" "Collabora"
        if [ "$ADMIN_RESPONSE" = "401" ]; then
            log_both "    (Protected by authentication - good!)"
        fi
    else
        test_warning "Collabora admin console returned HTTP ${ADMIN_RESPONSE}" "Expected 200 or 401, got ${ADMIN_RESPONSE}" "Collabora"
    fi
else
    test_warning "Cannot test Collabora capabilities (container not running)" "Container ${COLLABORA_CONTAINER} is not in running state" "Collabora"
fi

################################################################################
# TEST 10: SSL/TLS CONFIGURATION
################################################################################

print_section "SSL/TLS Configuration"

log_both "Testing OpenCloud SSL..."
if [ "$HIDE_SENSITIVE_DATA" = "true" ]; then
    SSL_TEST=$(echo | openssl s_client -connect "${OCIS_DOMAIN}:443" -servername "${OCIS_DOMAIN}" 2>&1 | grep -E "Verify return code|subject=|issuer=" | head -3)
    log_file "OpenCloud SSL Details (sanitized):"
    log_file "$SSL_TEST"
    
    if echo "$SSL_TEST" | grep -q "Verify return code: 0"; then
        test_passed "OpenCloud SSL certificate valid" "[Certificate details hidden for privacy]" "Reverse Proxy"
    else
        test_warning "Could not verify OpenCloud SSL certificate" "Connection issue or certificate problem" "Reverse Proxy"
    fi
else
    SSL_INFO=$(echo | openssl s_client -connect "${OCIS_DOMAIN}:443" -servername "${OCIS_DOMAIN}" 2>&1)
    log_file "OpenCloud SSL Details:"
    log_file "$SSL_INFO"
    
    SSL_CERT=$(echo "$SSL_INFO" | openssl x509 -noout -subject -dates 2>/dev/null)
    if [ -n "$SSL_CERT" ]; then
        test_passed "OpenCloud SSL certificate valid" "$SSL_CERT" "Reverse Proxy"
        echo "$SSL_CERT" | while read line; do log_both "    $line"; done
    else
        test_warning "Could not verify OpenCloud SSL certificate" "Connection to ${OCIS_DOMAIN}:443 failed or certificate invalid" "Reverse Proxy"
        add_recommendation "Verify SSL certificate for ${OCIS_DOMAIN}"
    fi
fi

log_both "Testing Collabora SSL..."
if [ "$HIDE_SENSITIVE_DATA" = "true" ]; then
    SSL_TEST=$(echo | openssl s_client -connect "${COLLABORA_DOMAIN}:443" -servername "${COLLABORA_DOMAIN}" 2>&1 | grep -E "Verify return code|subject=|issuer=" | head -3)
    
    if echo "$SSL_TEST" | grep -q "Verify return code: 0"; then
        test_passed "Collabora SSL certificate valid" "[Certificate details hidden for privacy]" "Reverse Proxy"
    else
        test_warning "Could not verify Collabora SSL certificate" "Connection issue or certificate problem" "Reverse Proxy"
    fi
else
    SSL_INFO=$(echo | openssl s_client -connect "${COLLABORA_DOMAIN}:443" -servername "${COLLABORA_DOMAIN}" 2>&1)
    log_file "Collabora SSL Details:"
    log_file "$SSL_INFO"
    
    SSL_CERT=$(echo "$SSL_INFO" | openssl x509 -noout -subject -dates 2>/dev/null)
    if [ -n "$SSL_CERT" ]; then
        test_passed "Collabora SSL certificate valid" "$SSL_CERT" "Reverse Proxy"
    else
        test_warning "Could not verify Collabora SSL certificate" "Connection to ${COLLABORA_DOMAIN}:443 failed or certificate invalid" "Reverse Proxy"
    fi
fi

log_both "Testing WOPI Server SSL..."
if [ "$HIDE_SENSITIVE_DATA" = "true" ]; then
    SSL_TEST=$(echo | openssl s_client -connect "${WOPISERVER_DOMAIN}:443" -servername "${WOPISERVER_DOMAIN}" 2>&1 | grep -E "Verify return code|subject=|issuer=" | head -3)
    
    if echo "$SSL_TEST" | grep -q "Verify return code: 0"; then
        test_passed "WOPI Server SSL certificate valid" "[Certificate details hidden for privacy]" "Reverse Proxy"
    else
        test_warning "Could not verify WOPI Server SSL certificate" "Connection issue or certificate problem" "Reverse Proxy"
    fi
else
    SSL_INFO=$(echo | openssl s_client -connect "${WOPISERVER_DOMAIN}:443" -servername "${WOPISERVER_DOMAIN}" 2>&1)
    log_file "WOPI Server SSL Details:"
    log_file "$SSL_INFO"
    
    SSL_CERT=$(echo "$SSL_INFO" | openssl x509 -noout -subject -dates 2>/dev/null)
    if [ -n "$SSL_CERT" ]; then
        test_passed "WOPI Server SSL certificate valid" "$SSL_CERT" "Reverse Proxy"
    else
        test_warning "Could not verify WOPI Server SSL certificate" "Connection to ${WOPISERVER_DOMAIN}:443 failed or certificate invalid" "Reverse Proxy"
    fi
fi

################################################################################
# TEST 11: WEBSOCKET SUPPORT
################################################################################

print_section "WebSocket Support"

if [ "$COLLABORA_RUNNING" = true ]; then
    log_both "Testing WebSocket endpoint..."
    WS_TEST=$(curl -k -s -o /dev/null -w "%{http_code}" --max-time 5 \
        -H "Upgrade: websocket" \
        -H "Connection: Upgrade" \
        "https://${COLLABORA_DOMAIN}/cool/adminws" 2>&1)
    
    if [ "$WS_TEST" = "101" ] || [ "$WS_TEST" = "401" ] || [ "$WS_TEST" = "403" ]; then
        test_passed "WebSocket upgrade supported (HTTP ${WS_TEST})" "Endpoint: https://${COLLABORA_DOMAIN}/cool/adminws" "Reverse Proxy"
    else
        test_warning "WebSocket response unclear (HTTP ${WS_TEST})" "Expected 101/401/403, got ${WS_TEST}" "Reverse Proxy"
        add_recommendation "Verify reverse proxy supports WebSocket connections"
    fi
else
    test_warning "Cannot test WebSocket (Collabora not running)" "Container ${COLLABORA_CONTAINER} is not in running state" "Reverse Proxy"
fi

################################################################################
# TEST 12: CONTAINER ENVIRONMENT VARIABLES
################################################################################

print_section "Critical Environment Variables"

if [ "$OPENCLOUD_RUNNING" = true ]; then
    log_both "Checking OpenCloud environment..."
    
    ALL_ENV=$(docker exec "${OPENCLOUD_CONTAINER}" env 2>&1 | sort)
    log_file "OpenCloud full environment:"
    log_file "$ALL_ENV"
    
    OC_URL=$(docker exec "${OPENCLOUD_CONTAINER}" printenv OC_URL 2>/dev/null)
    if [ "$OC_URL" = "https://${OCIS_DOMAIN}" ]; then
        test_passed "OC_URL correctly set to https://${OCIS_DOMAIN}" "Value: $OC_URL" "OpenCloud"
    else
        test_failed "OC_URL mismatch" "Expected: https://${OCIS_DOMAIN}\nActual: ${OC_URL}" "OpenCloud" "true"
        add_recommendation "Update OC_URL in OpenCloud container configuration"
    fi
    
    CSP_LOC=$(docker exec "${OPENCLOUD_CONTAINER}" printenv PROXY_CSP_CONFIG_FILE_LOCATION 2>/dev/null)
    if [ -n "$CSP_LOC" ]; then
        test_passed "CSP config location set: ${CSP_LOC}" "" "OpenCloud"
    else
        test_warning "CSP config location not explicitly set" "Variable PROXY_CSP_CONFIG_FILE_LOCATION is empty" "OpenCloud"
    fi
fi

if [ "$COLLABORA_RUNNING" = true ]; then
    log_both "Checking Collabora environment..."
    
    ALL_ENV=$(docker exec "${COLLABORA_CONTAINER}" env 2>&1 | sort)
    log_file "Collabora full environment:"
    log_file "$ALL_ENV"
    
    ALIAS=$(docker exec "${COLLABORA_CONTAINER}" printenv aliasgroup1 2>/dev/null)
    if echo "$ALIAS" | grep -q "${WOPISERVER_DOMAIN}"; then
        test_passed "Collabora aliasgroup1 includes WOPI domain" "Value: $ALIAS" "Collabora"
    else
        test_failed "Collabora aliasgroup1 missing or incorrect" "Expected to contain: ${WOPISERVER_DOMAIN}\nActual value: ${ALIAS}" "Collabora" "true"
        add_recommendation "Set aliasgroup1=https://${WOPISERVER_DOMAIN}:443"
    fi
    
    EXTRA_PARAMS=$(docker exec "${COLLABORA_CONTAINER}" printenv extra_params 2>/dev/null)
    log_file "Collabora extra_params: $EXTRA_PARAMS"
    if echo "$EXTRA_PARAMS" | grep -q "ssl.enable=false"; then
        test_passed "SSL disabled in Collabora (correct for reverse proxy)" "ssl.enable=false found in extra_params" "Collabora"
    else
        test_warning "SSL settings unclear in Collabora" "extra_params: ${EXTRA_PARAMS}" "Collabora"
    fi
fi

if [ "$COLLABORATION_RUNNING" = true ]; then
    log_both "Checking Collaboration (WOPI) environment..."
    
    ALL_ENV=$(docker exec "${COLLABORATION_CONTAINER}" env 2>&1 | sort)
    log_file "Collaboration full environment:"
    log_file "$ALL_ENV"
    
    WOPI_SRC=$(docker exec "${COLLABORATION_CONTAINER}" printenv COLLABORATION_WOPI_SRC 2>/dev/null)
    if [ "$WOPI_SRC" = "https://${WOPISERVER_DOMAIN}" ]; then
        test_passed "COLLABORATION_WOPI_SRC correctly set" "Value: $WOPI_SRC" "WOPI Server"
    else
        test_failed "COLLABORATION_WOPI_SRC mismatch" "Expected: https://${WOPISERVER_DOMAIN}\nActual: ${WOPI_SRC}" "WOPI Server" "true"
        add_recommendation "Set COLLABORATION_WOPI_SRC=https://${WOPISERVER_DOMAIN}"
    fi
    
    APP_ADDR=$(docker exec "${COLLABORATION_CONTAINER}" printenv COLLABORATION_APP_ADDR 2>/dev/null)
    if [ "$APP_ADDR" = "https://${COLLABORA_DOMAIN}" ]; then
        test_passed "COLLABORATION_APP_ADDR correctly set" "Value: $APP_ADDR" "WOPI Server"
    else
        test_failed "COLLABORATION_APP_ADDR mismatch" "Expected: https://${COLLABORA_DOMAIN}\nActual: ${APP_ADDR}" "WOPI Server" "true"
        add_recommendation "Set COLLABORATION_APP_ADDR=https://${COLLABORA_DOMAIN}"
    fi
fi

################################################################################
# TEST 13: CONTAINER LOGS ANALYSIS
################################################################################

if [ "$EXTENDED_TESTS" = "true" ]; then
    print_section "Container Logs Analysis"
    
    if [ "$OPENCLOUD_RUNNING" = true ]; then
        log_both "Analyzing OpenCloud logs for errors..."
        FULL_LOGS=$(docker logs "${OPENCLOUD_CONTAINER}" --tail 100 2>&1)
        log_file "OpenCloud last 100 log lines:"
        log_file "$FULL_LOGS"
        
        ERROR_LOGS=$(echo "$FULL_LOGS" | grep -i "error\|fatal\|panic")
        ERROR_COUNT=$(echo "$ERROR_LOGS" | wc -l)
        
        if [ "$ERROR_COUNT" -eq 0 ] || [ -z "$ERROR_LOGS" ]; then
            test_passed "No recent errors in OpenCloud logs" "Checked last 100 lines" "OpenCloud"
        else
            test_warning "Found ${ERROR_COUNT} error messages in OpenCloud logs" "Recent errors:\n${ERROR_LOGS}" "OpenCloud"
            log_both "  Recent errors:"
            echo "$ERROR_LOGS" | tail -5 | while read line; do
                log_both "    $line"
            done
        fi
    fi
    
    if [ "$COLLABORA_RUNNING" = true ]; then
        log_both "Analyzing Collabora logs for errors..."
        FULL_LOGS=$(docker logs "${COLLABORA_CONTAINER}" --tail 100 2>&1)
        log_file "Collabora last 100 log lines:"
        log_file "$FULL_LOGS"
        
        ERROR_LOGS=$(echo "$FULL_LOGS" | grep -i "error\|fatal\|err:")
        ERROR_COUNT=$(echo "$ERROR_LOGS" | wc -l)
        
        if [ "$ERROR_COUNT" -eq 0 ] || [ -z "$ERROR_LOGS" ]; then
            test_passed "No recent errors in Collabora logs" "Checked last 100 lines" "Collabora"
        else
            test_warning "Found ${ERROR_COUNT} error messages in Collabora logs" "Recent errors:\n${ERROR_LOGS}" "Collabora"
            log_both "  Recent errors:"
            echo "$ERROR_LOGS" | tail -5 | while read line; do
                log_both "    $line"
            done
        fi
    fi
    
    if [ "$COLLABORATION_RUNNING" = true ]; then
        log_both "Analyzing Collaboration logs for errors..."
        FULL_LOGS=$(docker logs "${COLLABORATION_CONTAINER}" --tail 100 2>&1)
        log_file "Collaboration last 100 log lines:"
        log_file "$FULL_LOGS"
        
        ERROR_LOGS=$(echo "$FULL_LOGS" | grep -i "error\|fatal\|panic")
        ERROR_COUNT=$(echo "$ERROR_LOGS" | wc -l)
        
        if [ "$ERROR_COUNT" -eq 0 ] || [ -z "$ERROR_LOGS" ]; then
            test_passed "No recent errors in Collaboration logs" "Checked last 100 lines" "WOPI Server"
        else
            test_warning "Found ${ERROR_COUNT} error messages in Collaboration logs" "Recent errors:\n${ERROR_LOGS}" "WOPI Server"
            log_both "  Recent errors:"
            echo "$ERROR_LOGS" | tail -5 | while read line; do
                log_both "    $line"
            done
        fi
    fi
fi

################################################################################
# TEST 14: REVERSE PROXY CONFIGURATION
################################################################################

print_section "Reverse Proxy Configuration"

# Extract subdomain from domain (e.g., "opencloud" from "opencloud.yourdomain.com")
extract_subdomain() {
    echo "$1" | cut -d'.' -f1
}

OCIS_SUBDOMAIN=$(extract_subdomain "$OCIS_DOMAIN")
COLLABORA_SUBDOMAIN=$(extract_subdomain "$COLLABORA_DOMAIN")
WOPISERVER_SUBDOMAIN=$(extract_subdomain "$WOPISERVER_DOMAIN")

case "$PROXY_TYPE" in
    swag)
        PROXY_CONF_PATH="/mnt/user/appdata/swag/nginx/proxy-confs"
        if [ -d "$PROXY_CONF_PATH" ]; then
            test_passed "SWAG configuration directory found" "Path: $PROXY_CONF_PATH" "Reverse Proxy"
            
            log_file "SWAG proxy configuration files:"
            log_file "$(ls -la $PROXY_CONF_PATH 2>&1)"
            
            # Smart search for OpenCloud config using subdomain
            OPENCLOUD_CONF=$(find "${PROXY_CONF_PATH}" -type f -name "*.conf" -exec grep -l "server_name.*${OCIS_SUBDOMAIN}" {} \; 2>/dev/null | head -1)
            if [ -z "$OPENCLOUD_CONF" ]; then
                # Fallback to pattern matching
                OPENCLOUD_CONF=$(ls "${PROXY_CONF_PATH}"/*${OCIS_SUBDOMAIN}*.conf 2>/dev/null | head -1)
            fi
            
            if [ -n "$OPENCLOUD_CONF" ]; then
                test_passed "OpenCloud proxy config exists for ${OCIS_DOMAIN}" "File: $OPENCLOUD_CONF" "Reverse Proxy"
                log_file "OpenCloud proxy config contents:"
                log_file "$(cat $OPENCLOUD_CONF 2>&1)"
                
                # Check if it proxies to correct container/port
                if grep -q "upstream_app.*${OPENCLOUD_CONTAINER}\|proxy_pass.*:9200" "$OPENCLOUD_CONF"; then
                    test_passed "OpenCloud proxy targets correct backend" "Container: ${OPENCLOUD_CONTAINER}, Port: 9200" "Reverse Proxy"
                else
                    test_warning "OpenCloud proxy backend unclear" "Check proxy_pass directive in $OPENCLOUD_CONF" "Reverse Proxy"
                fi
            else
                test_failed "OpenCloud proxy config not found for ${OCIS_DOMAIN}" "Expected file with server_name containing '${OCIS_SUBDOMAIN}' in $PROXY_CONF_PATH" "Reverse Proxy" "true"
                add_recommendation "Create proxy config: ${PROXY_CONF_PATH}/${OCIS_SUBDOMAIN}.subdomain.conf"
            fi
            
            # Smart search for Collabora config using subdomain
            COLLABORA_CONF=$(find "${PROXY_CONF_PATH}" -type f -name "*.conf" -exec grep -l "server_name.*${COLLABORA_SUBDOMAIN}" {} \; 2>/dev/null | head -1)
            if [ -z "$COLLABORA_CONF" ]; then
                COLLABORA_CONF=$(ls "${PROXY_CONF_PATH}"/*${COLLABORA_SUBDOMAIN}*.conf 2>/dev/null | head -1)
            fi
            
            if [ -n "$COLLABORA_CONF" ]; then
                test_passed "Collabora proxy config exists for ${COLLABORA_DOMAIN}" "File: $COLLABORA_CONF" "Reverse Proxy"
                log_file "Collabora proxy config contents:"
                log_file "$(cat $COLLABORA_CONF 2>&1)"
                
                # Check WebSocket support
                if grep -q "websocket\|Upgrade.*\$http_upgrade" "$COLLABORA_CONF"; then
                    test_passed "Collabora proxy has WebSocket support" "Found WebSocket configuration" "Reverse Proxy"
                else
                    test_warning "Collabora proxy may be missing WebSocket support" "Check for WebSocket directives in $COLLABORA_CONF" "Reverse Proxy"
                fi
                
                # Check if it proxies to correct container/port
                if grep -q "upstream_app.*${COLLABORA_CONTAINER}\|proxy_pass.*:9980" "$COLLABORA_CONF"; then
                    test_passed "Collabora proxy targets correct backend" "Container: ${COLLABORA_CONTAINER}, Port: 9980" "Reverse Proxy"
                else
                    test_warning "Collabora proxy backend unclear" "Check proxy_pass directive in $COLLABORA_CONF" "Reverse Proxy"
                fi
            else
                test_failed "Collabora proxy config not found for ${COLLABORA_DOMAIN}" "Expected file with server_name containing '${COLLABORA_SUBDOMAIN}' in $PROXY_CONF_PATH" "Reverse Proxy" "true"
                add_recommendation "Create proxy config: ${PROXY_CONF_PATH}/${COLLABORA_SUBDOMAIN}.subdomain.conf"
            fi
            
            # Smart search for WOPI config using subdomain
            WOPI_CONF=$(find "${PROXY_CONF_PATH}" -type f -name "*.conf" -exec grep -l "server_name.*${WOPISERVER_SUBDOMAIN}" {} \; 2>/dev/null | head -1)
            if [ -z "$WOPI_CONF" ]; then
                WOPI_CONF=$(ls "${PROXY_CONF_PATH}"/*${WOPISERVER_SUBDOMAIN}*.conf 2>/dev/null | head -1)
            fi
            
            if [ -n "$WOPI_CONF" ]; then
                test_passed "WOPI proxy config exists for ${WOPISERVER_DOMAIN}" "File: $WOPI_CONF" "Reverse Proxy"
                log_file "WOPI proxy config contents:"
                log_file "$(cat $WOPI_CONF 2>&1)"
                
                # Check if it proxies to correct container/port
                if grep -q "upstream_app.*${COLLABORATION_CONTAINER}\|proxy_pass.*:9300" "$WOPI_CONF"; then
                    test_passed "WOPI proxy targets correct backend" "Container: ${COLLABORATION_CONTAINER}, Port: 9300" "Reverse Proxy"
                else
                    test_warning "WOPI proxy backend unclear" "Check proxy_pass directive in $WOPI_CONF" "Reverse Proxy"
                fi
            else
                test_failed "WOPI proxy config not found for ${WOPISERVER_DOMAIN}" "Expected file with server_name containing '${WOPISERVER_SUBDOMAIN}' in $PROXY_CONF_PATH" "Reverse Proxy" "true"
                add_recommendation "Create proxy config: ${PROXY_CONF_PATH}/${WOPISERVER_SUBDOMAIN}.subdomain.conf"
            fi
        else
            test_warning "SWAG configuration directory not found" "Expected path: ${PROXY_CONF_PATH}" "Reverse Proxy"
        fi
        ;;
    *)
        test_warning "Cannot auto-check ${PROXY_TYPE} configuration" "Manual verification required" "Reverse Proxy"
        log_both "  Please manually verify:"
        log_both "    - ${OCIS_DOMAIN} proxies to ${OPENCLOUD_CONTAINER}:9200"
        log_both "    - ${COLLABORA_DOMAIN} proxies to ${COLLABORA_CONTAINER}:9980 with WebSocket support"
        log_both "    - ${WOPISERVER_DOMAIN} proxies to ${COLLABORATION_CONTAINER}:9300"
        ;;
esac

################################################################################
# FINAL SUMMARY
################################################################################

log_both ""
print_header "COMPREHENSIVE DIAGNOSTIC SUMMARY"
log_both ""

# Calculate success rate
if [ $TOTAL_TESTS -gt 0 ]; then
    SUCCESS_RATE=$((PASSED_TESTS * 100 / TOTAL_TESTS))
else
    SUCCESS_RATE=0
fi

log_both "${CYAN}Overall Statistics:${NC}"
log_both "  ${GREEN}Passed:   ${PASSED_TESTS}/${TOTAL_TESTS}${NC}"
log_both "  ${RED}Failed:   ${FAILED_TESTS}/${TOTAL_TESTS}${NC}"
log_both "  ${YELLOW}Warnings: ${WARNING_TESTS}/${TOTAL_TESTS}${NC}"
log_both "  Success Rate: ${SUCCESS_RATE}%"
log_both ""

# Component breakdown
log_both "${CYAN}Results by Component:${NC}"
for component in "${!COMPONENT_TESTS[@]}"; do
    total=${COMPONENT_TESTS[$component]}
    passed=${COMPONENT_PASSED[$component]:-0}
    failed=${COMPONENT_FAILED[$component]:-0}
    warnings=${COMPONENT_WARNINGS[$component]:-0}
    
    # Color code based on component health
    if [ $failed -eq 0 ] && [ $warnings -le 1 ]; then
        STATUS="${GREEN}✓ HEALTHY${NC}"
    elif [ $failed -le 1 ]; then
        STATUS="${YELLOW}⚠ DEGRADED${NC}"
    else
        STATUS="${RED}✗ CRITICAL${NC}"
    fi
    
    log_both "  ${component}: ${STATUS}"
    log_both "    Tests: ${total} | Passed: ${GREEN}${passed}${NC} | Failed: ${RED}${failed}${NC} | Warnings: ${YELLOW}${warnings}${NC}"
done
log_both ""

# Critical failures section
if [ ${#FAILURES[@]} -gt 0 ]; then
    log_both "${RED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    log_both "${RED}CRITICAL FAILURES (${#FAILURES[@]}):${NC}"
    log_both "${RED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    for i in "${!FAILURES[@]}"; do
        FAILURE_TEXT="${FAILURES[$i]}"
        COMPONENT=$(echo "$FAILURE_TEXT" | cut -d':' -f1)
        MESSAGE=$(echo "$FAILURE_TEXT" | cut -d':' -f2-)
        
        log_both "${RED}$((i+1)). [${COMPONENT}]${MESSAGE}${NC}"
        
        # Find and display abbreviated error details
        for detail in "${DETAILED_ERRORS[@]}"; do
            if echo "$detail" | grep -q "^FAIL|${COMPONENT}|"; then
                ERROR_MSG=$(echo "$detail" | cut -d'|' -f4)
                if [ -n "$ERROR_MSG" ]; then
                    # Show first line of error only
                    FIRST_LINE=$(echo "$ERROR_MSG" | head -1)
                    log_both "   ${RED}→${NC} ${FIRST_LINE:0:150}"
                fi
            fi
        done
    done
    log_both ""
fi

# Warnings section
if [ ${#WARNINGS[@]} -gt 0 ]; then
    log_both "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    log_both "${YELLOW}WARNINGS (${#WARNINGS[@]}):${NC}"
    log_both "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    for i in "${!WARNINGS[@]}"; do
        WARNING_TEXT="${WARNINGS[$i]}"
        COMPONENT=$(echo "$WARNING_TEXT" | cut -d':' -f1)
        MESSAGE=$(echo "$WARNING_TEXT" | cut -d':' -f2-)
        
        log_both "${YELLOW}$((i+1)). [${COMPONENT}]${MESSAGE}${NC}"
    done
    log_both ""
fi

# Recommendations section
if [ ${#RECOMMENDATIONS[@]} -gt 0 ]; then
    log_both "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    log_both "${CYAN}RECOMMENDED ACTIONS (${#RECOMMENDATIONS[@]}):${NC}"
    log_both "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    for i in "${!RECOMMENDATIONS[@]}"; do
        log_both "  $((i+1)). ${RECOMMENDATIONS[$i]}"
    done
    log_both ""
fi

# Overall system assessment
log_both "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
log_both "${CYAN}SYSTEM HEALTH ASSESSMENT:${NC}"
log_both "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

# Determine what will work and what won't
OPENCLOUD_WORKS=true
COLLABORA_INTEGRATION_WORKS=true

# Check critical components
if [ "$CRITICAL_FAILURES" = "true" ]; then
    log_both ""
    log_both "${RED}⚠ CRITICAL ISSUES DETECTED${NC}"
    
    # Analyze what's broken
    if echo "${FAILURES[*]}" | grep -q "Network:"; then
        log_both "${RED}✗ Docker Network Issues${NC}"
        log_both "  → Containers cannot communicate"
        OPENCLOUD_WORKS=false
        COLLABORA_INTEGRATION_WORKS=false
    fi
    
    if echo "${FAILURES[*]}" | grep -q "OpenCloud.*container.*not"; then
        log_both "${RED}✗ OpenCloud Container Not Running${NC}"
        log_both "  → Primary service unavailable"
        OPENCLOUD_WORKS=false
        COLLABORA_INTEGRATION_WORKS=false
    fi
    
    if echo "${FAILURES[*]}" | grep -q "Collabora.*container.*not"; then
        log_both "${RED}✗ Collabora Container Not Running${NC}"
        log_both "  → Document editing unavailable"
        COLLABORA_INTEGRATION_WORKS=false
    fi
    
    if echo "${FAILURES[*]}" | grep -q "WOPI.*container.*not\|Collaboration.*container.*not"; then
        log_both "${RED}✗ WOPI Server Container Not Running${NC}"
        log_both "  → Document editing integration unavailable"
        COLLABORA_INTEGRATION_WORKS=false
    fi
    
    if echo "${FAILURES[*]}" | grep -q "CSP.*missing\|CSP.*NOT include"; then
        log_both "${RED}✗ CSP Configuration Issues${NC}"
        log_both "  → Collabora frames will be blocked by browser"
        COLLABORA_INTEGRATION_WORKS=false
    fi
    
    if echo "${FAILURES[*]}" | grep -q "Reverse Proxy.*domain not accessible"; then
        log_both "${RED}✗ Reverse Proxy Configuration Issues${NC}"
        log_both "  → Services not accessible from outside"
        OPENCLOUD_WORKS=false
        COLLABORA_INTEGRATION_WORKS=false
    fi
    
    if echo "${FAILURES[*]}" | grep -q "Connectivity.*CANNOT reach"; then
        log_both "${RED}✗ Container Connectivity Issues${NC}"
        log_both "  → Services cannot communicate"
        COLLABORA_INTEGRATION_WORKS=false
    fi
    
    if echo "${FAILURES[*]}" | grep -q "aliasgroup1\|COLLABORATION_WOPI_SRC\|COLLABORATION_APP_ADDR"; then
        log_both "${RED}✗ Container Environment Variable Issues${NC}"
        log_both "  → Incorrect service URLs configured"
        COLLABORA_INTEGRATION_WORKS=false
    fi
fi

log_both ""
log_both "${CYAN}Functionality Assessment:${NC}"

if [ "$OPENCLOUD_WORKS" = true ]; then
    log_both "${GREEN}✓ OpenCloud Platform: OPERATIONAL${NC}"
    log_both "  → Web interface accessible"
    log_both "  → File storage and sharing should work"
else
    log_both "${RED}✗ OpenCloud Platform: NOT OPERATIONAL${NC}"
    log_both "  → Core service unavailable"
    log_both "  → Fix critical failures above to restore service"
fi

log_both ""

if [ "$COLLABORA_INTEGRATION_WORKS" = true ]; then
    log_both "${GREEN}✓ Collabora Integration: OPERATIONAL${NC}"
    log_both "  → Document editing should work"
    log_both "  → Real-time collaboration enabled"
else
    log_both "${RED}✗ Collabora Integration: NOT OPERATIONAL${NC}"
    if [ "$OPENCLOUD_WORKS" = true ]; then
        log_both "  → OpenCloud works but document editing unavailable"
        log_both "  → Users can upload/download but cannot edit online"
    else
        log_both "  → Both OpenCloud and Collabora integration unavailable"
    fi
    log_both "  → Fix critical failures above to enable editing"
fi

log_both ""

# Final verdict
log_both "${CYAN}Overall System Status:${NC}"
if [ $FAILED_TESTS -eq 0 ] && [ $WARNING_TESTS -le 2 ]; then
    log_both "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    log_both "${GREEN}✓ SYSTEM FULLY OPERATIONAL${NC}"
    log_both "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    log_both "  All components healthy and properly configured"
    log_both "  OpenCloud + Collabora integration working as expected"
elif [ $FAILED_TESTS -le 3 ] && [ "$CRITICAL_FAILURES" = "false" ]; then
    log_both "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    log_both "${YELLOW}⚠ SYSTEM PARTIALLY OPERATIONAL${NC}"
    log_both "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    log_both "  Core functionality available with minor issues"
    log_both "  Address failures above for optimal performance"
else
    log_both "${RED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    log_both "${RED}✗ SYSTEM NOT OPERATIONAL${NC}"
    log_both "${RED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    log_both "  Critical components have failures"
    log_both "  Follow recommended actions above to restore service"
fi

log_both ""
log_both "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
log_both ""

log_both "Full diagnostic report saved to:"
log_both "  ${GREEN}${DIAGNOSTIC_FILE}${NC}"

if [ "$HIDE_SENSITIVE_DATA" = "true" ]; then
    log_both ""
    log_both "${YELLOW}⚠️  Privacy mode was enabled - this report is safe to share publicly${NC}"
fi

log_both ""
log_both "For further troubleshooting:"
log_both "  • Review full log file for detailed error messages"
log_both "  • Check container logs: ${CYAN}docker logs <container-name>${NC}"
log_both "  • Verify network: ${CYAN}docker network inspect ${NETWORK_NAME}${NC}"
log_both "  • OpenCloud documentation: ${CYAN}https://docs.opencloud.eu/${NC}"
log_both ""

# Final summary in log file
log_file ""
log_file "================================================================================"
log_file "DIAGNOSTIC SUMMARY"
log_file "================================================================================"
log_file "Total Tests: ${TOTAL_TESTS}"
log_file "Passed: ${PASSED_TESTS}"
log_file "Failed: ${FAILED_TESTS}"
log_file "Warnings: ${WARNING_TESTS}"
log_file "Success Rate: ${SUCCESS_RATE}%"
log_file ""
log_file "OpenCloud Platform: $([ "$OPENCLOUD_WORKS" = true ] && echo "OPERATIONAL" || echo "NOT OPERATIONAL")"
log_file "Collabora Integration: $([ "$COLLABORA_INTEGRATION_WORKS" = true ] && echo "OPERATIONAL" || echo "NOT OPERATIONAL")"
log_file ""
log_file "Privacy Mode: ${HIDE_SENSITIVE_DATA}"
log_file "Report generated at: $(date '+%Y-%m-%d %H:%M:%S %Z')"
log_file "================================================================================"

exit 0
