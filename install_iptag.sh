#!/usr/bin/env bash
# Instalação e atualização do sistema IP‑Tag para Proxmox VE 8/9
# Este script reproduz as funções do instalador que preparamos, mas
# em um único arquivo executável, facilitando a implantação. Execute
# como root no host Proxmox para instalar, atualizar, remover ou
# verificar o status do IP‑Tag.

set -Euo pipefail

# Verifica se estamos rodando como root
require_root() {
  if [[ "$EUID" -ne 0 ]]; then
    echo "Este script deve ser executado como root." >&2
    exit 1
  fi
}

# Checa a versão do Proxmox (opcional, pode ser comentado)
check_pve_version() {
  if ! command -v pveversion &>/dev/null; then
    echo "pveversion não encontrado. Este script deve ser executado em um host Proxmox." >&2
    exit 1
  fi
  local ver
  ver=$(pveversion 2>/dev/null || true)
  if [[ -z "$ver" || ! "$ver" =~ pve-manager/(8\.(0|1|2|3|4)|9\.[0-9]+) ]]; then
    echo "Versão do Proxmox não suportada. Requer PVE 8.0–8.4 ou 9.x." >&2
    exit 1
  fi
}

# Gera conteúdo do arquivo de configuração padrão
generate_config() {
  cat <<'EOF'
# Configuração padrão do IP‑Tag

# Blocos de rede permitidos. Somente IPs dentro destes CIDRs serão utilizados
# para gerar tags.
CIDR_LIST=(
  192.168.0.0/16
  10.0.0.0/8
  100.64.0.0/10
)

# Lista de bridges permitidas. Caso esteja vazia, todas são consideradas.
# Exemplo: ( vmbr0 vmbr1 )
BRIDGE_ALLOWLIST=( vmbr0 )

# Formato das tags numéricas quando usadas: full | last_octet | last_two_octets
TAG_FORMAT="last_two_octets"

# Modo das tags de IP. Pode ser:
#   fixed   – apenas a tag fixa (IP_FIXED_TAG)
#   numeric – apenas a tag numérica (formato acima)
#   both    – combina a tag fixa e a tag numérica
IP_TAG_MODE="fixed"

# Tag fixa que será sempre adicionada (quando modo != numeric)
IP_FIXED_TAG="ipaddr"

# Cores padrão para as tags (background e foreground). Serão aplicadas
# automaticamente via API do PVE (pvesh) se não existirem.
IP_COLOR_BG="0066FF"
IP_COLOR_FG="FFFFFF"

# Colorir também todas as tags numéricas detectadas? true/false
IP_COLORIZE_NUMERIC_TAGS=false

# Ajustes de cache e desempenho (em segundos)
VM_IP_CACHE_TTL=300
LXC_IP_CACHE_TTL=300
LXC_STATUS_CACHE_TTL=300
MAX_PARALLEL_VM_CHECKS=1
MAX_PARALLEL_LXC_CHECKS=2

# Caminho do arquivo de log. Se vazio, não grava em arquivo
LOG_FILE="/var/log/iptag.log"

# Ativa logs de depuração (DEBUG=true ou false)
DEBUG=false
EOF
}

# Gera o script principal (iptag) com suporte a IP_TAG_MODE
generate_iptag() {
  cat <<'EOF'
#!/usr/bin/env bash
set -Euo pipefail

# Caminhos e padrões
CONFIG_FILE="/opt/iptag/iptag.conf"
DEFAULT_TAG_FORMAT="full"

# Funções de logging com cores (colorir a saída)
RED=$'\033[0;31m'; GREEN=$'\033[0;32m'; BLUE=$'\033[0;34m'; CYAN=$'\033[0;36m'; GRAY=$'\033[0;37m'; NC=$'\033[0m'
log_success(){ echo -e "${GREEN}✓${NC} $*"; }
log_info()   { echo -e "${BLUE}ℹ${NC} $*"; }
log_same()   { echo -e "${GRAY}=${NC} $*"; }
log_change(){ echo -e "${CYAN}~${NC} $*"; }
file_log(){ [[ -n "${LOG_FILE:-}" ]] && printf '%s %s\n' "$(date +'%F %T')" "$*" >> "$LOG_FILE" || true; }
debug(){ [[ "${DEBUG:-false}" == "true" || "${DEBUG:-0}" == "1" ]] && echo "[DEBUG] $*" >&2; }

# Carrega configuração
[[ -f "$CONFIG_FILE" ]] && source "$CONFIG_FILE" || true
LOG_FILE=${LOG_FILE:-}
DEBUG=${DEBUG:-false}
declare -a CIDR_LIST BRIDGE_ALLOWLIST
IP_TAG_MODE=${IP_TAG_MODE:-fixed}
IP_FIXED_TAG=${IP_FIXED_TAG:-ipaddr}
IP_COLOR_BG=${IP_COLOR_BG:-0066FF}
IP_COLOR_FG=${IP_COLOR_FG:-FFFFFF}
IP_COLORIZE_NUMERIC_TAGS=${IP_COLORIZE_NUMERIC_TAGS:-false}

# Coletor para tags que precisam de cor
declare -Ag __COLOR_TAGS_SEEN=()
remember_color_tag(){ local t="${1:-}"; [[ -n "$t" ]] && __COLOR_TAGS_SEEN["$t"]=1; }

# Utilidades para validação de IP e CIDR
is_valid_ipv4(){ local ip=${1:-}; [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1; IFS='.' read -r a b c d <<<"$ip"; ((a<=255&&b<=255&&c<=255&&d<=255)); }
ip_like_numeric(){ [[ "${1:-}" =~ ^([0-9]+(\.[0-9]+){1,3}|[0-9]+(\.[0-9]+)*)$ ]]; }
ip_in_cidr(){ local ip="$1" cidr="$2"; local network prefix; IFS='/' read -r network prefix <<<"$cidr"; IFS='.' read -r a b c d <<<"$ip"; local ip_int=$(( (a<<24)+(b<<16)+(c<<8)+d )); IFS='.' read -r a b c d <<<"$network"; local net_int=$(( (a<<24)+(b<<16)+(c<<8)+d )); local mask=$(( 0xFFFFFFFF << (32 - prefix) & 0xFFFFFFFF )); (( (ip_int & mask) == (net_int & mask) )); }
ip_in_cidrs(){ local ip="$1"; shift || true; local -a cs=( "$@" ); for c in "${cs[@]}"; do ip_in_cidr "$ip" "$c" && return 0; done; return 1; }
format_ip_tag(){ local ip="$1" fmt="${TAG_FORMAT:-$DEFAULT_TAG_FORMAT}"; case "$fmt" in last_octet) echo "${ip##*.}" ;; last_two_octets) echo "${ip#*.*.}" ;; *) echo "$ip" ;; esac; }
bridge_allowed(){ local br="${1:-}"; [[ -z "$br" ]] && return 1; [[ "${#BRIDGE_ALLOWLIST[@]}" -eq 0 ]] && return 0; for b in "${BRIDGE_ALLOWLIST[@]}"; do [[ "$b" == "$br" ]] && return 0; done; return 1; }

# Busca IPs das VMs (QEMU)
get_vm_ips(){ local vmid="${1:-}"; [[ -n "$vmid" ]] || return 0
  local ips="" vm_cfg="/etc/pve/qemu-server/${vmid}.conf"
  [[ -f "$vm_cfg" ]] || return 0
  local status; status="$(qm status "$vmid" 2>/dev/null | awk '{print $2}')" || true
  [[ "$status" == "running" ]] || return 0
  local cache="/tmp/iptag_vm_${vmid}_cache" ttl="${VM_IP_CACHE_TTL:-60}"
  if [[ -f "$cache" ]] && (( $(date +%s) - $(stat -c %Y "$cache" 2>/dev/null || echo 0) < ttl )); then cat "$cache"; return 0; fi
  local brs macs
  brs=$(grep -E "^net[0-9]+:" "$vm_cfg" | grep -oE 'bridge=[^,]+' | cut -d= -f2 | xargs -n1 echo | sort -u) || true
  macs=$(grep -E "^net[0-9]+:" "$vm_cfg" | grep -oE "([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}") || true
  for br in $brs; do
    bridge_allowed "$br" || { debug "VM $vmid: ignorando bridge $br"; continue; }
    for mac in $macs; do
      local ip; ip=$(ip neighbor show dev "$br" 2>/dev/null | grep -i "$mac" | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | head -1) || true
      [[ -n "$ip" ]] && ips+="$ip "
    done
  done
  if [[ -z "$ips" ]]; then
    local qi
    qi=$(timeout 3 qm guest cmd "$vmid" network-get-interfaces 2>/dev/null | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | grep -v '^127\.0\.0\.1$' | head -4) || true
    for ip in $qi; do ips+="$ip "; done
  fi
  echo "${ips%% }" | tee "$cache" >/dev/null
}

# Busca IPs dos containers LXC
get_lxc_ips(){ local vmid="${1:-}"; [[ -n "$vmid" ]] || return 0
  local cfg="/etc/pve/lxc/${vmid}.conf"; local status="$(pct status "$vmid" 2>/dev/null | awk '{print $2}')" || true
  [[ "$status" == "running" ]] || return 0
  if [[ -f "$cfg" ]]; then
    local static_ip; static_ip=$(grep -E "^net[0-9]+:" "$cfg" | grep -oE 'ip=([0-9]{1,3}\.){3}[0-9]{1,3}' | cut -d= -f2 | head -1) || true
    [[ -n "$static_ip" ]] && { echo "$static_ip"; return 0; }
  fi
  local br mac; br=$(grep -Eo 'bridge=[^,]+' "$cfg" 2>/dev/null | head -1 | cut -d= -f2 || true)
  mac=$(grep -Eo 'hwaddr=([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}' "$cfg" 2>/dev/null | cut -d= -f2 || true)
  bridge_allowed "$br" || return 0
  if [[ -n "$br" && -n "$mac" ]]; then
    local ip; ip=$(ip neighbor show dev "$br" 2>/dev/null | grep -i "$mac" | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | head -1) || true
    [[ -n "$ip" ]] && { echo "$ip"; return 0; }
  fi
}

# Atualiza tags de uma VM ou LXC
update_tags(){
  local type="$1" id="$2" curr="" ips=""
  [[ -n "$id" ]] || { echo "same"; return 0; }
  if [[ "$type" == "lxc" ]]; then
    ips="$(get_lxc_ips "$id" || true)"
    curr="$(pct config "$id" 2>/dev/null | awk -F': ' '/^tags:/ {print $2}')"
  else
    ips="$(get_vm_ips "$id"  || true)"
    curr="$(qm  config "$id" 2>/dev/null | awk -F': ' '/^tags:/ {print $2}')"
  fi
  IFS=';' read -r -a cur_tags <<< "${curr:-}"
  local next=()
  # Remove tags numéricas/IP antigas
  for t in "${cur_tags[@]}"; do
    [[ -z "$t" ]] && continue
    if is_valid_ipv4 "$t" || ip_like_numeric "$t"; then
      continue
    fi
    next+=("$t")
  done
  # Inclui tag fixa se modo != numeric
  if [[ "$IP_TAG_MODE" != "numeric" && -n "$IP_FIXED_TAG" ]]; then
    local has_fixed=false
    for t in "${next[@]}"; do [[ "$t" == "$IP_FIXED_TAG" ]] && has_fixed=true; done
    $has_fixed || next+=("$IP_FIXED_TAG")
    remember_color_tag "$IP_FIXED_TAG"
  fi
  # Inclui tags numéricas se modo != fixed
  if [[ "$IP_TAG_MODE" != "fixed" ]]; then
    local new_ip_tags=()
    for ip in $ips; do
      is_valid_ipv4 "$ip" || continue
      ip_in_cidrs "$ip" "${CIDR_LIST[@]}" || continue
      new_ip_tags+=("$(format_ip_tag "$ip")")
    done
    next+=("${new_ip_tags[@]}")
    if [[ "$IP_COLORIZE_NUMERIC_TAGS" == "true" ]]; then
      for nt in "${new_ip_tags[@]}"; do ip_like_numeric "$nt" && remember_color_tag "$nt"; done
    fi
  fi
  local old_str="$(IFS=';'; echo "${cur_tags[*]}")"
  local new_str="$(IFS=';'; echo "${next[*]}")"
  if [[ "$old_str" != "$new_str" ]]; then
    if [[ "$type" == "lxc" ]]; then pct set "$id" -tags "$new_str" &>/dev/null || true
    else qm set "$id" -tags "$new_str" &>/dev/null || true; fi
    log_change "${type^^} ${CYAN}${id}${NC}: tags → [$new_str]"
    file_log "UPDATED ${type} ${id}: ${new_str}"
    echo "updated"
  else
    log_same "${type^^} ${GRAY}${id}${NC}: sem alterações"
    echo "same"
  fi
}

# Processa VMs/LXCs
process_type(){
  local type="$1"; shift || true
  local -a ids=( "$@" ); local updated=0 same=0
  for id in "${ids[@]}"; do
    [[ -n "$id" ]] || continue
    if [[ "$(update_tags "$type" "$id" || true)" == "updated" ]]; then ((updated++)); else ((same++)); fi
  done
  echo "$updated $same"
}

# Aplica cor às tags registradas
apply_color_map(){
  ((${#__COLOR_TAGS_SEEN[@]})) || return 0
  local cur map tag
  cur="$(pvesh get /cluster/options --output-format json 2>/dev/null | tr -d '\n' | sed -n 's/.*"tag-style":"color-map=\([^" ]*\)".*/\1/p')" || true
  map="$cur"
  for tag in "${!__COLOR_TAGS_SEEN[@]}"; do
    [[ -z "$tag" ]] && continue
    [[ -n "$map" ]] && echo "$map" | grep -qE "(^|,)$tag:" && continue
    map="${map:+$map,}${tag}:${IP_COLOR_BG}:${IP_COLOR_FG}"
  done
  [[ -n "$map" ]] && pvesh set /cluster/options --tag-style "color-map=${map}" >/dev/null 2>&1 || true
}

# Função principal
main(){
  log_info "Passagem única do IP-Tag (timer-based)"
  mapfile -t LXCS < <(pct list 2>/dev/null | awk 'NR>1{print $1}') || true
  mapfile -t VMS  < <(ls -1 /etc/pve/qemu-server/*.conf 2>/dev/null | sed 's#.*/\([0-9]\+\)\.conf#\1#' | sort -n) || true
  local lu=0 ls=0 vu=0 vs=0
  ((${#LXCS[@]})) && read lu ls < <(process_type "lxc" "${LXCS[@]}")
  ((${#VMS[@]}))  && read vu vs < <(process_type "vm"  "${VMS[@]}")
  apply_color_map
  log_success "OK. LXC: ${lu} atualizadas / ${ls} inalteradas | VM: ${vu} atualizadas / ${vs} inalteradas"
  file_log "SUMMARY LXC(updated=${lu},same=${ls}) VM(updated=${vu},same=${vs})"
  if [[ -d /var/lib/node_exporter/textfile_collector ]]; then
    cat > /var/lib/node_exporter/textfile_collector/iptag.prom <<METRICS
iptag_lxc_updated ${lu}
iptag_lxc_same ${ls}
iptag_vm_updated ${vu}
iptag_vm_same ${vs}
METRICS
  fi
  exit 0
}
main
EOF
}

# Gera o script iptag-run
generate_run() {
  cat <<'EOF'
#!/usr/bin/env bash
exec /opt/iptag/iptag
EOF
}

# Gera utilitário iptag-mode
generate_mode() {
  cat <<'EOF'
#!/usr/bin/env bash
set -Euo pipefail
# Script para alterar o modo de tags (fixed, numeric ou both) e opções de cor.
# Usa o arquivo de configuração em /opt/iptag/iptag.conf e executa iptag-run
CONF="/opt/iptag/iptag.conf"
RUN="/usr/local/bin/iptag-run"
usage() {
  cat <<USAGE
Uso: iptag-mode <fixed|numeric|both> [--bg HEX] [--fg HEX] [--colorize-numeric true|false]

Exemplos:
  iptag-mode fixed
  iptag-mode both --bg 0066FF --fg FFFFFF
  iptag-mode numeric --colorize-numeric true
USAGE
}
ensure_kv() {
  local k="$1" v="$2"
  if grep -qE "^[[:space:]]*${k}=" "$CONF"; then
    sed -i "s#^[[:space:]]*${k}=.*#${k}=${v}#g" "$CONF"
  else
    printf "%s=%s\n" "$k" "$v" >> "$CONF"
  fi
}
mode="${1:-}"; shift || true
[[ -f "$CONF" ]] || { echo "arquivo de config não encontrado: $CONF"; exit 1; }
case "$mode" in
  fixed|numeric|both) ;;
  ""|--help|-h) usage; exit 0 ;;
  *) echo "modo inválido: $mode"; usage; exit 1 ;;
esac
bg=""; fg=""; colorize=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --bg) bg="${2:-}"; shift 2 ;;
    --fg) fg="${2:-}"; shift 2 ;;
    --colorize-numeric) colorize="${2:-}"; shift 2 ;;
    *) echo "opção desconhecida: $1"; usage; exit 1 ;;
  esac
done
[[ -n "$bg" ]] && [[ "$bg" =~ ^[0-9A-Fa-f]{6}$ ]] || [[ -z "$bg" ]] || { echo "bg inválido: use HEX de 6 dígitos"; exit 1; }
[[ -n "$fg" ]] && [[ "$fg" =~ ^[0-9A-Fa-f]{6}$ ]] || [[ -z "$fg" ]] || { echo "fg inválido"; exit 1; }
[[ -n "$colorize" ]] && [[ "$colorize" =~ ^(true|false)$ ]] || [[ -z "$colorize" ]] || { echo "colorize-numeric deve ser true ou false"; exit 1; }
ensure_kv 'IP_TAG_MODE' "\"$mode\""
[[ -n "$bg" ]] && ensure_kv 'IP_COLOR_BG' "\"$bg\""
[[ -n "$fg" ]] && ensure_kv 'IP_COLOR_FG' "\"$fg\""
[[ -n "$colorize" ]] && ensure_kv 'IP_COLORIZE_NUMERIC_TAGS' "$colorize"
echo ">> IP_TAG_MODE=$mode aplicado."
[[ -n "$bg" ]] && echo ">> BG=$bg"
[[ -n "$fg" ]] && echo ">> FG=$fg"
[[ -n "$colorize" ]] && echo ">> IP_COLORIZE_NUMERIC_TAGS=$colorize"
if [[ -x "$RUN" ]]; then "$RUN" || true; else /opt/iptag/iptag || true; fi
EOF
}

# Gera utilitário iptag-color (altera cor sem tocar no modo)
generate_color() {
  cat <<'EOF'
#!/usr/bin/env bash
set -Euo pipefail
# Atualiza cores sem modificar o modo
CONF="/opt/iptag/iptag.conf"
RUN="/usr/local/bin/iptag-run"
usage(){ echo "Uso: iptag-color --bg HEX --fg HEX"; }
bg=""; fg=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --bg) bg="${2:-}"; shift 2 ;;
    --fg) fg="${2:-}"; shift 2 ;;
    *) usage; exit 1 ;;
  esac
done
[[ "$bg" =~ ^[0-9A-Fa-f]{6}$ ]] && [[ "$fg" =~ ^[0-9A-Fa-f]{6}$ ]] || { usage; exit 1; }
sed -i "s/^IP_COLOR_BG=.*/IP_COLOR_BG=\"${bg}\"/; s/^IP_COLOR_FG=.*/IP_COLOR_FG=\"${fg}\"/" "$CONF"
echo ">> cores atualizadas: BG=$bg FG=$fg"
if [[ -x "$RUN" ]]; then "$RUN" || true; else /opt/iptag/iptag || true; fi
EOF
}

# Gera a unidade systemd do serviço (oneshot)
generate_service() {
  cat <<'EOF'
[Unit]
Description=IP-Tag (oneshot) - atualiza tags de IP em VMs/LXCs
Wants=network-online.target
After=network-online.target

[Service]
Type=oneshot
ExecStart=/opt/iptag/iptag
User=root
Group=root
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=full
ProtectHome=read-only
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
LockPersonality=yes
RestrictRealtime=yes
CapabilityBoundingSet=CAP_NET_ADMIN CAP_SYS_ADMIN
AmbientCapabilities=CAP_NET_ADMIN CAP_SYS_ADMIN
EOF
}

# Gera a unidade systemd do timer
generate_timer() {
  cat <<'EOF'
[Unit]
Description=IP-Tag timer (executa periodicamente o serviço oneshot)

[Timer]
OnUnitActiveSec=3min
AccuracySec=30s
Persistent=true

[Install]
WantedBy=timers.target
EOF
}

# Gera configuração do logrotate
generate_logrotate() {
  cat <<'EOF'
/var/log/iptag.log {
    size 10M
    rotate 14
    missingok
    notifempty
    compress
    delaycompress
    create 0640 root adm
    copytruncate
}
EOF
}

# Instala arquivos e habilita timer
do_install() {
  mkdir -p /opt/iptag
  # Configuração: cria apenas se não existir
  if [[ ! -f /opt/iptag/iptag.conf ]]; then
    generate_config > /opt/iptag/iptag.conf
    echo "Configuração padrão criada em /opt/iptag/iptag.conf"
  else
    echo "Configuração existente encontrada; mantendo-a."
  fi
  # Scripts principais e utilitários
  generate_iptag > /opt/iptag/iptag
  chmod +x /opt/iptag/iptag
  generate_run > /usr/local/bin/iptag-run
  chmod +x /usr/local/bin/iptag-run
  generate_mode > /usr/local/bin/iptag-mode
  chmod +x /usr/local/bin/iptag-mode
  generate_color > /usr/local/bin/iptag-color
  chmod +x /usr/local/bin/iptag-color
  # Unidades systemd
  generate_service > /etc/systemd/system/iptag.service
  generate_timer > /etc/systemd/system/iptag.timer
  # Logrotate
  generate_logrotate > /etc/logrotate.d/iptag
  # Ativa
  systemctl daemon-reload
  systemctl enable --now iptag.timer
  # Primeira execução
  /usr/local/bin/iptag-run || true
  echo "Instalação concluída. Use 'iptag-mode' para alterar o modo de tags."
}

# Atualiza scripts (mantém config)
do_update() {
  echo "Atualizando scripts e unidades..."
  generate_iptag > /opt/iptag/iptag
  chmod +x /opt/iptag/iptag
  generate_run > /usr/local/bin/iptag-run
  chmod +x /usr/local/bin/iptag-run
  generate_mode > /usr/local/bin/iptag-mode
  chmod +x /usr/local/bin/iptag-mode
  generate_color > /usr/local/bin/iptag-color
  chmod +x /usr/local/bin/iptag-color
  generate_service > /etc/systemd/system/iptag.service
  generate_timer > /etc/systemd/system/iptag.timer
  generate_logrotate > /etc/logrotate.d/iptag
  systemctl daemon-reload
  systemctl restart iptag.timer
  # Passada única
  /usr/local/bin/iptag-run || true
  echo "Atualização concluída."
}

# Remove instalação
do_uninstall() {
  echo "Removendo IP‑Tag..."
  systemctl disable --now iptag.timer 2>/dev/null || true
  rm -f /etc/systemd/system/iptag.timer /etc/systemd/system/iptag.service
  systemctl daemon-reload
  rm -f /usr/local/bin/iptag-run /usr/local/bin/iptag-mode /usr/local/bin/iptag-color
  rm -rf /opt/iptag
  rm -f /etc/logrotate.d/iptag
  echo "IP‑Tag removido."
}

# Mostra status
do_status() {
  systemctl status --no-pager iptag.timer || true
  echo
  systemctl status --no-pager iptag.service || true
  echo
  if [[ -f /opt/iptag/iptag.conf ]]; then
    echo "Config: /opt/iptag/iptag.conf"
  fi
  if [[ -f /var/log/iptag.log ]]; then
    echo "Log: /var/log/iptag.log"
  fi
}

# Uso/ajuda
usage() {
  echo "Uso: $0 [--install | --update | --uninstall | --status]"
  echo "  --install    Instala o IP‑Tag e habilita o timer (padrão)"
  echo "  --update     Atualiza scripts/unidades mantendo a configuração existente"
  echo "  --uninstall  Remove instalação e desabilita timer"
  echo "  --status     Mostra status do serviço e timer"
  echo "  --help       Mostra esta ajuda"
}

main_script() {
  require_root
  check_pve_version
  local action="install"
  case "${1:-}" in
    --install) action="install" ;;
    --update)  action="update"  ;;
    --uninstall) action="uninstall" ;;
    --status)  action="status" ;;
    --help|-h) usage; exit 0 ;;
    "") action="install" ;;
    *) echo "Opção desconhecida: $1"; usage; exit 1 ;;
  esac
  case "$action" in
    install) do_install ;;
    update) do_update ;;
    uninstall) do_uninstall ;;
    status) do_status ;;
  esac
}
main_script "$@"