#!/bin/bash

# Configuration
TARGET_PORTS="21,22,23,445,3389,5900"
LOG_FILE="scan_results.log"
CONF_FILE="paused.conf"
RATE=1000

# Vulnerability Check Function
check_vuln() {
    local ip=$1
    local port=$2
    
    # Honeypot Filtering (Port 666 detection)
    if nmap -p 666 --open -Pn --host-timeout 800ms $ip | grep -q "open"; then
        return
    fi

    case $port in
        21) # FTP Anonymous Login
            nmap -p 21 --script ftp-anon -Pn $ip | grep -q "Allowed" && \
            echo "[VULN][FTP] Anonymous access enabled: $ip" >> $LOG_FILE ;;
        22) # SSH Banner Identification
            BANNER=$(timeout 3 nc -v -w 3 $ip 22 2>&1 | grep "SSH-")
            [ ! -z "$BANNER" ] && echo "[INFO][SSH] Banner ($ip): $BANNER" >> $LOG_FILE ;;
        23) # Telnet Unauthenticated Access
            (echo " "; sleep 1) | timeout 3 telnet $ip 23 2>&1 | grep -qi "Login\|Password" || \
            echo "[VULN][TELNET] No authentication required: $ip" >> $LOG_FILE ;;
        445) # SMB Guest Access
            nmap -p 445 --script smb-enum-shares -Pn $ip | grep -q "Anonymous\|Guest" && \
            echo "[VULN][SMB] Guest access enabled: $ip" >> $LOG_FILE ;;
        3389) # RDP System Info
            OS_INFO=$(nmap -p 3389 --script rdp-ntlm-info -Pn $ip | grep "Target_Name" | cut -d: -f2)
            [ ! -z "$OS_INFO" ] && echo "[INFO][RDP] Windows Target ($ip): $OS_INFO" >> $LOG_FILE ;;
        5900) # VNC Unauthenticated Access
            nmap -p 5900 --script vnc-info -Pn $ip | grep -q "None" && \
            echo "[VULN][VNC] Authentication disabled: $ip" >> $LOG_FILE ;;
    esac
}

echo "[*] Shodan-like Network Scanner initialized."
echo "[*] Target Ports: $TARGET_PORTS | Rate: $RATE pps"

# Usamos el formato simple de lista (-oL) que es más robusto para este bucle
if [ -f "$CONF_FILE" ]; then
    echo "[+] Resuming previous session..."
    sudo stdbuf -oL masscan --resume "$CONF_FILE" --rate $RATE -oL - 2>/dev/null | grep -a -v "^#" | while read -r status proto port ip time; do
        if [ "$status" == "open" ]; then
            [ "$port" == "666" ] && continue
            check_vuln $ip $port &
        fi
    done
else
    echo "[+] Starting new global scan..."
    sudo stdbuf -oL masscan 0.0.0.0/0 -p$TARGET_PORTS,666 --rate $RATE --exclude 255.255.255.255 -oL - 2>/dev/null | grep -a -v "^#" | while read -r status proto port ip time; do
        if [ "$status" == "open" ]; then
            [ "$port" == "666" ] && continue
            check_vuln $ip $port &
        fi
    done
fi
