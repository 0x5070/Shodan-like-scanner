#!/bin/bash
# PRINTER-FIND: IoT/Printer Discovery
OUTPUT_FILE="impresoras_encontradas.txt"
WEB_PORTS=(631 9100 515)
PORTS_TO_SCAN=$(IFS=, ; echo "${WEB_PORTS[*]}")

scan_ip() {
    local ip="$1"
    if ping -c 1 -W 1 "$ip" &>/dev/null; then
        nmap -Pn -n -T4 -p $PORTS_TO_SCAN --open -oG - "$ip" 2>/dev/null | grep "/open/" && \
        echo "Found potential printer at $ip" | tee -a "$OUTPUT_FILE"
    fi
}

trap "wait; exit" INT TERM

echo "Escaneando... (Excluyendo 10.x.x.x, 127.x.x.x y 192.x.x.x.x)"

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