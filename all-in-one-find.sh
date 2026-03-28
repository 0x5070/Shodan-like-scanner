#!/usr/bin/env bash
# ============================================================
#  NetScan Pro — Escáner de vulnerabilidades de red
#  Uso: sudo ./netscan_pro.sh [--resume] [--rate N] [--target CIDR]
# ============================================================
set -euo pipefail
IFS=$'\n\t'

# --- CONFIGURACIÓN POR DEFECTO ---
readonly TARGET_PORTS="21,22,23,445,3389,3306,5432,27017"
readonly LOG_FILE="${LOG_FILE:-scan_results.log}"
readonly CONF_FILE="${CONF_FILE:-paused.conf}"
readonly RATE="${RATE:-10000}"
readonly TARGET_CIDR="${TARGET_CIDR:-0.0.0.0/0}"
readonly MAX_PARALLEL_CHECKS=50   # Máximo de análisis paralelos
readonly HONEYPOT_PORT=4444       # Puerto trampa (cambiado de 666 que es FP alto)
readonly NMAP_TIMEOUT="2s"

# --- COLORES ---
RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

# --- LOGGING ---
log()      { echo -e "${CYAN}[*]${RESET} $*"; }
log_ok()   { echo -e "${GREEN}[+]${RESET} $*"; }
log_warn() { echo -e "${YELLOW}[!]${RESET} $*"; }
log_err()  { echo -e "${RED}[ERR]${RESET} $*" >&2; }
log_vuln() { echo -e "${RED}${BOLD}[VULN]${RESET} $*"; }

write_log() {
    local level="$1"; shift
    printf '[%s][%s] %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$level" "$*" >> "$LOG_FILE"
}

# --- VERIFICACIÓN DE DEPENDENCIAS ---
check_deps() {
    local missing=()
    for cmd in masscan nmap nc timeout; do
        command -v "$cmd" &>/dev/null || missing+=("$cmd")
    done
    if (( ${#missing[@]} > 0 )); then
        log_err "Dependencias faltantes: ${missing[*]}"
        log_err "Instala con: sudo apt-get install -y ${missing[*]}"
        exit 1
    fi
}

# --- DETECCIÓN DE HONEYPOT ---
is_honeypot() {
    local ip="$1"
    # Un honeypot suele tener muchos puertos de servicio poco comunes abiertos
    # Verificamos el puerto trampa configurado
    nmap -p "$HONEYPOT_PORT" --open -Pn --host-timeout "$NMAP_TIMEOUT" "$ip" 2>/dev/null \
        | grep -q "open" && return 0
    return 1
}

# --- ANÁLISIS DE VULNERABILIDADES POR PROTOCOLO ---
check_ftp() {
    local ip="$1"
    local result
    result=$(nmap -p 21 --script ftp-anon -Pn --host-timeout 3s "$ip" 2>/dev/null)
    if echo "$result" | grep -q "Anonymous FTP login allowed"; then
        log_vuln "[FTP] Acceso anónimo habilitado: $ip"
        write_log "VULN" "FTP anonymous access: $ip"
    fi
}

check_ssh() {
    local ip="$1"
    local banner
    banner=$(timeout 3 nc -w 3 "$ip" 22 2>/dev/null | head -1 | grep "^SSH-" || true)
    if [[ -n "$banner" ]]; then
        # Alertar solo si la versión es antigua y potencialmente vulnerable
        local version
        version=$(echo "$banner" | grep -oP 'OpenSSH_\K[\d.]+' || true)
        log_ok "[SSH] Banner capturado en $ip: $banner"
        write_log "INFO" "SSH banner $ip: $banner"
        if [[ -n "$version" ]] && awk "BEGIN{exit !($version < 7.4)}"; then
            log_warn "[SSH] Versión posiblemente vulnerable ($version) en $ip"
            write_log "WARN" "SSH old version $version at $ip"
        fi
    fi
}

check_telnet() {
    local ip="$1"
    local output
    output=$(printf '\n' | timeout 4 telnet "$ip" 23 2>&1 || true)
    # Positivo: hay prompt de shell sin pedir credenciales
    if echo "$output" | grep -qiE '(Welcome|#\s*$|>\s*$|\$\s*$)' \
    && ! echo "$output" | grep -qiE '(login|password|user|acceso|autenticaci)'; then
        log_vuln "[TELNET] Sin autenticación requerida: $ip"
        write_log "VULN" "TELNET no auth: $ip"
    fi
}

check_smb() {
    local ip="$1"
    local result
    result=$(nmap -p 445 --script smb-enum-shares,smb-security-mode -Pn --host-timeout 5s "$ip" 2>/dev/null)
    if echo "$result" | grep -qiE '(Anonymous|Guest access|IPC\$)'; then
        log_vuln "[SMB] Acceso guest/anónimo detectado: $ip"
        write_log "VULN" "SMB guest access: $ip"
    fi
    # Detección adicional: SMBv1 habilitado
    if echo "$result" | grep -q "SMBv1 enabled"; then
        log_warn "[SMB] SMBv1 habilitado (EternalBlue risk): $ip"
        write_log "WARN" "SMBv1 enabled: $ip"
    fi
}

check_rdp() {
    local ip="$1"
    local result
    result=$(nmap -p 3389 --script rdp-ntlm-info,rdp-enum-encryption -Pn --host-timeout 5s "$ip" 2>/dev/null)
    local target_name
    target_name=$(echo "$result" | grep -i "Target_Name" | cut -d: -f2 | tr -d ' ' || true)
    [[ -n "$target_name" ]] && {
        log_ok "[RDP] Sistema Windows identificado ($ip): $target_name"
        write_log "INFO" "RDP target $ip: $target_name"
    }
    # NLA deshabilitado = mayor superficie de ataque
    if echo "$result" | grep -q "NLA: Disabled"; then
        log_warn "[RDP] NLA deshabilitado en $ip — autenticación de red no requerida"
        write_log "WARN" "RDP NLA disabled: $ip"
    fi
}

check_mysql() {
    local ip="$1"
    if nmap -p 3306 --script mysql-empty-password,mysql-info -Pn --host-timeout 5s "$ip" 2>/dev/null \
            | grep -qE "(root account has empty password|Anonymous access)"; then
        log_vuln "[MYSQL] Root sin contraseña o acceso anónimo: $ip"
        write_log "VULN" "MySQL no password: $ip"
    fi
}

check_postgres() {
    local ip="$1"
    # Intentar conexión como postgres sin password usando psql timeout
    if timeout 4 bash -c "echo '\q' | PGPASSWORD='' psql -h $ip -U postgres -w 2>&1" \
            | grep -qv "authentication failed"; then
        log_vuln "[POSTGRES] Acceso sin contraseña detectado: $ip"
        write_log "VULN" "PostgreSQL no auth: $ip"
    fi
}

check_mongodb() {
    local ip="$1"
    if nmap -p 27017 --script mongodb-databases,mongodb-info -Pn --host-timeout 5s "$ip" 2>/dev/null \
            | grep -qE "(databases|ok : 1)"; then
        log_vuln "[MONGODB] Sin autenticación — bases de datos expuestas: $ip"
        write_log "VULN" "MongoDB no auth: $ip"
    fi
}

# --- DESPACHADOR PRINCIPAL ---
check_vuln() {
    local ip="$1"
    local port="$2"

    # Verificar honeypot antes de cualquier análisis
    if is_honeypot "$ip"; then
        log_warn "Posible honeypot detectado, omitiendo $ip"
        write_log "SKIP" "Honeypot suspected: $ip"
        return 0
    fi

    case "$port" in
        21)    check_ftp      "$ip" ;;
        22)    check_ssh      "$ip" ;;
        23)    check_telnet   "$ip" ;;
        445)   check_smb      "$ip" ;;
        3389)  check_rdp      "$ip" ;;
        3306)  check_mysql    "$ip" ;;
        5432)  check_postgres "$ip" ;;
        27017) check_mongodb  "$ip" ;;
        *)     log_warn "Puerto $port no tiene análisis específico" ;;
    esac
}

# --- CONTROL DE PARALELISMO ---
# Semáforo básico con un directorio de locks
acquire_slot() {
    local slots_dir="/tmp/netscan_slots_$$"
    mkdir -p "$slots_dir"
    while (( $(ls "$slots_dir" | wc -l) >= MAX_PARALLEL_CHECKS )); do
        sleep 0.1
    done
    touch "$slots_dir/$$_$BASHPID"
}

release_slot() {
    rm -f "/tmp/netscan_slots_$$/$$_$BASHPID" 2>/dev/null || true
}

# --- AYUDA ---
usage() {
    cat <<EOF
${BOLD}NetScan Pro${RESET} — Escáner de vulnerabilidades de red

Uso: sudo $0 [opciones]

Opciones:
  --resume          Reanudar escaneo previo desde $CONF_FILE
  --rate N          Paquetes por segundo para masscan (por defecto: $RATE)
  --target CIDR     Red objetivo (por defecto: 0.0.0.0/0)
  --log FILE        Archivo de resultados (por defecto: $LOG_FILE)
  --help            Mostrar esta ayuda

Variables de entorno:
  RATE, LOG_FILE, CONF_FILE, TARGET_CIDR

Ejemplos:
  sudo $0 --target 192.168.1.0/24 --rate 5000
  sudo $0 --resume
EOF
    exit 0
}

# --- PARSEO DE ARGUMENTOS ---
RESUME=false
while [[ $# -gt 0 ]]; do
    case "$1" in
        --resume)         RESUME=true ;;
        --rate)           shift; RATE="$1" ;;
        --target)         shift; TARGET_CIDR="$1" ;;
        --log)            shift; LOG_FILE="$1" ;;
        --help|-h)        usage ;;
        *)                log_err "Argumento desconocido: $1"; usage ;;
    esac
    shift
done

# --- SEÑAL DE LIMPIEZA ---
cleanup() {
    log_warn "Señal recibida — limpiando procesos hijos..."
    rm -rf "/tmp/netscan_slots_$$" 2>/dev/null || true
    # masscan guarda estado automáticamente en paused.conf
    log "Estado guardado. Reanuda con: sudo $0 --resume"
    kill 0
}
trap cleanup INT TERM

# ============================================================
#  INICIO
# ============================================================
main() {
    check_deps

    if [[ "$EUID" -ne 0 ]]; then
        log_err "Este script requiere privilegios de root (sudo)"
        exit 1
    fi

    echo ""
    log "${BOLD}NetScan Pro iniciado${RESET}"
    log "Puertos objetivo : $TARGET_PORTS"
    log "Velocidad        : $RATE pps"
    log "Red objetivo     : $TARGET_CIDR"
    log "Log              : $LOG_FILE"
    echo "---"

    write_log "START" "Scan initiated — ports=$TARGET_PORTS rate=$RATE target=$TARGET_CIDR"

    local scan_cmd
    if [[ "$RESUME" == "true" && -f "$CONF_FILE" ]]; then
        log_ok "Reanudando sesión desde $CONF_FILE..."
        scan_cmd="masscan --resume $CONF_FILE --rate $RATE -oL -"
    else
        log_ok "Iniciando nuevo escaneo de $TARGET_CIDR..."
        scan_cmd="masscan $TARGET_CIDR -p${TARGET_PORTS},${HONEYPOT_PORT} \
            --rate $RATE \
            --exclude 255.255.255.255 \
            --banners \
            -oL -"
    fi

    # Pipeline principal: masscan → filtrar → analizar en paralelo
    stdbuf -oL $scan_cmd 2>/dev/null \
    | grep -av '^#' \
    | while IFS=' ' read -r status proto port ip _rest; do
        [[ "$status" != "open" ]] && continue
        [[ "$port" == "$HONEYPOT_PORT" ]] && continue

        log "[$(date '+%H:%M:%S')] Puerto $port abierto en $ip"

        # Análisis en background con control de paralelismo
        acquire_slot
        (
            check_vuln "$ip" "$port"
            release_slot
        ) &
    done

    # Esperar todos los jobs en background
    wait

    write_log "END" "Scan completed"
    echo "---"
    log_ok "Escaneo finalizado. Resultados en: ${BOLD}$LOG_FILE${RESET}"

    # Resumen rápido
    local vulns infos warns
    vulns=$(grep -c '\[VULN\]' "$LOG_FILE" 2>/dev/null || echo 0)
    warns=$(grep -c '\[WARN\]' "$LOG_FILE" 2>/dev/null || echo 0)
    infos=$(grep -c '\[INFO\]' "$LOG_FILE" 2>/dev/null || echo 0)

    echo ""
    echo -e "  ${RED}${BOLD}Vulnerabilidades: $vulns${RESET}"
    echo -e "  ${YELLOW}Advertencias    : $warns${RESET}"
    echo -e "  ${CYAN}Informacional   : $infos${RESET}"
    echo ""
}

main "$@"
