#!/bin/bash
# WEB-FIND: Multithreaded Web Service Discovery
OUTPUT_FILE="webservers_found.txt"
WEB_PORTS=(80 443 8080 8443 8000)
PORTS_TO_SCAN=$(IFS=, ; echo "${WEB_PORTS[*]}")
scan_ip() {
    local ip="$1"
    if ping -c 1 -W 1 -i 0.05 "$ip" &>/dev/null; then
        nmap -Pn -n -T4 --max-retries 1 -p $PORTS_TO_SCAN --open -oG - "$ip" 2>/dev/null | while read -r nline; do
            if [[ $nline =~ Ports:\ (.*) ]]; then
                IFS=',' read -ra port_entries <<< "${BASH_REMATCH[1]}"
                for entry in "${port_entries[@]}"; do
                    if [[ $entry =~ ^([0-9]+)/open/([a-zA-Z]+) ]]; then
                        port="${BASH_REMATCH[1]}"
                        status=$(curl -s -k -o /dev/null -w "%{http_code}" --max-time 2 "http://$ip:$port/" || echo "000")
                        [[ "$status" == "000" ]] && status=$(curl -s -k -o /dev/null -w "%{http_code}" --max-time 2 "https://$ip:$port/" || echo "000")
                        if [[ "$status" =~ ^[1-5][0-9][0-9]$ ]]; then
                            echo "$ip:$port - HTTP $status" | tee -a "$OUTPUT_FILE"
                        fi
                    fi
                done
            fi
        done
    fi
}
trap "wait; exit" INT TERM
while true; do
    # Generamos el primer octeto por separado para validarlo
    octeto1=$((RANDOM%254+1))

    # Filtrado de rangos excluidos
    case $octeto1 in
        10|127|192)
            continue # Salta esta IP y genera otra
            ;;
    esac

    # Si pasa el filtro, generamos el resto de la IP
    ip="$octeto1.$((RANDOM%254+1)).$((RANDOM%254+1)).$((RANDOM%254+1))"
    
    scan_ip "$ip" &
    sleep 0.01
done