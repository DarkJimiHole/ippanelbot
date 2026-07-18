#!/usr/bin/env bash
set -Eeuo pipefail

APP_NAME="IPPanelBot"
SERVICE_NAME="ippanelbot"
SERVICE_USER="ippanelbot"
SERVICE_GROUP="ippanelbot"
APP_DIR="/opt/ippanelbot"
DATA_DIR="/var/lib/ippanelbot"
ENV_FILE="/etc/ippanelbot.env"
API_TARGETS_FILE="/etc/ippanelbot-api-targets.json"
SOURCE_FILE="/etc/ippanelbot.source"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
CTL_PATH="/usr/local/bin/boil"

DEFAULT_RAW_BASE="https://raw.githubusercontent.com/DarkJimiHole/ippanelbot/main"

if [ -f "$SOURCE_FILE" ]; then
  # shellcheck disable=SC1090
  . "$SOURCE_FILE"
fi

if [ -n "${IPPANELBOT_GITHUB_REPO:-}" ]; then
  IPPANELBOT_RAW_BASE="https://raw.githubusercontent.com/${IPPANELBOT_GITHUB_REPO}/${IPPANELBOT_BRANCH:-main}"
fi

RAW_BASE="${IPPANELBOT_RAW_BASE:-$DEFAULT_RAW_BASE}"

if [ -t 1 ]; then
  BLUE="\033[34m"
  YELLOW="\033[33m"
  GREEN="\033[32m"
  RED="\033[31m"
  DIM="\033[2m"
  RESET="\033[0m"
else
  BLUE=""
  YELLOW=""
  GREEN=""
  RED=""
  DIM=""
  RESET=""
fi

info() { printf "%b[INFO]%b %s\n" "$BLUE" "$RESET" "$*"; }
warn() { printf "%b[WARN]%b %s\n" "$YELLOW" "$RESET" "$*"; }
ok() { printf "%b[OK]%b %s\n" "$GREEN" "$RESET" "$*"; }
err() { printf "%b[ERR]%b %s\n" "$RED" "$RESET" "$*" >&2; }
die() { err "$*"; exit 1; }

usage() {
  cat <<EOF
${APP_NAME} 管理脚本

用法：
  sudo boil install
  sudo boil config
  sudo boil update
  sudo boil relay
  sudo boil start|stop|restart|status|logs
  sudo boil uninstall

GitHub 下载源：
  IPPANELBOT_RAW_BASE=${RAW_BASE}

示例：
  bash <(curl -Ls https://raw.githubusercontent.com/DarkJimiHole/ippanelbot/main/ippanelbot.sh)
  sudo IPPANELBOT_GITHUB_REPO=DarkJimiHole/ippanelbot bash ippanelbot.sh install
EOF
}

is_regular_script_file() {
  local src="${1:-}"
  [ -n "$src" ] || return 1
  [ -f "$src" ] || return 1
  case "$src" in
    /dev/fd/*|/proc/self/fd/*) return 1 ;;
    *) return 0 ;;
  esac
}

script_dir() {
  local src="${BASH_SOURCE[0]:-}"
  if is_regular_script_file "$src"; then
    cd -- "$(dirname -- "$src")" && pwd -P
  else
    pwd -P
  fi
}

SCRIPT_DIR="$(script_dir)"

require_root() {
  if [ "${EUID:-$(id -u)}" -ne 0 ]; then
    die "请使用 root 权限运行，例如：sudo $0 $*"
  fi
}

require_systemd() {
  command -v systemctl >/dev/null 2>&1 || die "需要 systemctl，当前系统不支持 systemd。"
}

is_placeholder_raw_base() {
  [ -z "$RAW_BASE" ] || [[ "$RAW_BASE" == *"YOUR_GITHUB_USERNAME"* ]]
}

require_download_base() {
  if is_placeholder_raw_base; then
    die "远程下载源未配置，请设置 IPPANELBOT_RAW_BASE 或 IPPANELBOT_GITHUB_REPO。"
  fi
}

shell_quote() {
  printf "'"
  printf "%s" "$1" | sed "s/'/'\\\\''/g"
  printf "'"
}

env_quote() {
  local value="$1"
  value="${value//\\/\\\\}"
  value="${value//\"/\\\"}"
  printf '"%s"' "$value"
}

write_source_file() {
  if is_placeholder_raw_base; then
    return 0
  fi

  local tmp
  tmp="$(mktemp)"
  {
    printf "IPPANELBOT_RAW_BASE="
    shell_quote "$RAW_BASE"
    printf "\n"
  } >"$tmp"
  install -m 600 -o root -g root "$tmp" "$SOURCE_FILE"
  rm -f "$tmp"
}

detect_os() {
  if [ -r /etc/os-release ]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    if [ "${ID:-}" != "debian" ]; then
      warn "此脚本面向 Debian 12，当前系统：${PRETTY_NAME:-unknown}。"
    elif [ "${VERSION_ID:-}" != "12" ]; then
      warn "此脚本主要在 Debian 12 测试，当前 Debian 版本：${VERSION_ID:-unknown}。"
    fi
  fi
}

install_dependencies() {
  if ! command -v apt-get >/dev/null 2>&1; then
    die "需要 apt-get。此安装脚本面向 Debian 12。"
  fi

  info "正在安装必要的系统组件..."
  export DEBIAN_FRONTEND=noninteractive
  apt-get update
  apt-get install -y python3 curl ca-certificates tzdata
  ok "系统组件已准备完成。"
}

ensure_user() {
  if ! getent group "$SERVICE_GROUP" >/dev/null 2>&1; then
    info "正在创建系统用户组 ${SERVICE_GROUP}..."
    groupadd --system "$SERVICE_GROUP"
    ok "系统用户组已创建。"
  fi

  if id "$SERVICE_USER" >/dev/null 2>&1; then
    ok "系统用户 ${SERVICE_USER} 已存在。"
    return 0
  fi

  info "正在创建系统用户 ${SERVICE_USER}..."
  useradd --system --gid "$SERVICE_GROUP" --home "$DATA_DIR" --shell /usr/sbin/nologin "$SERVICE_USER"
  ok "系统用户已创建。"
}

ensure_dirs() {
  install -d -m 755 -o root -g root "$APP_DIR"
  install -d -m 750 -o "$SERVICE_USER" -g "$SERVICE_GROUP" "$DATA_DIR"
}

find_local_file() {
  local rel="$1"
  local base
  for base in "$SCRIPT_DIR" "$SCRIPT_DIR/.." "$PWD"; do
    if [ -f "$base/$rel" ]; then
      readlink -f "$base/$rel"
      return 0
    fi
  done
  return 1
}

copy_or_download() {
  local rel="$1"
  local dest="$2"
  local mode="$3"
  local local_file tmp url

  if local_file="$(find_local_file "$rel")"; then
    install -m "$mode" -o root -g root "$local_file" "$dest"
    ok "已从本地文件安装 ${rel}。"
    return 0
  fi

  require_download_base
  command -v curl >/dev/null 2>&1 || die "远程下载需要 curl。"

  url="${RAW_BASE%/}/${rel}"
  tmp="$(mktemp)"
  info "正在下载 ${url}"
  curl -fsSL --retry 3 --connect-timeout 15 "$url" -o "$tmp"
  install -m "$mode" -o root -g root "$tmp" "$dest"
  rm -f "$tmp"
  ok "已从远程源安装 ${rel}。"
}

install_files() {
  ensure_dirs
  copy_or_download "bot.py" "$APP_DIR/bot.py" 755
  copy_or_download "pic.png" "$APP_DIR/pic.png" 644
}

install_manager() {
  local src current target
  src="${BASH_SOURCE[0]:-}"

  if is_regular_script_file "$src"; then
    current="$(readlink -f "$src" 2>/dev/null || printf "%s" "$src")"
    target="$(readlink -f "$CTL_PATH" 2>/dev/null || printf "%s" "$CTL_PATH")"
    if [ "$current" != "$target" ]; then
      install -m 755 -o root -g root "$src" "$CTL_PATH"
      ok "管理命令已安装：${CTL_PATH}"
    fi
    return 0
  fi

  copy_or_download "ippanelbot.sh" "$CTL_PATH" 755
  ok "管理命令已安装：${CTL_PATH}"
}

write_service() {
  local tmp
  tmp="$(mktemp)"
  cat >"$tmp" <<EOF
[Unit]
Description=IPPanelBot
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=${SERVICE_USER}
Group=${SERVICE_GROUP}
WorkingDirectory=${APP_DIR}
EnvironmentFile=${ENV_FILE}
ExecStart=/usr/bin/python3 ${APP_DIR}/bot.py
Restart=always
RestartSec=5
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full
ProtectHome=true
ReadWritePaths=${DATA_DIR}

[Install]
WantedBy=multi-user.target
EOF
  install -m 644 -o root -g root "$tmp" "$SERVICE_FILE"
  rm -f "$tmp"
  ok "systemd 服务已安装：${SERVICE_FILE}"
}

env_value() {
  local key="$1"
  local line value
  [ -f "$ENV_FILE" ] || return 0
  line="$(grep -E "^${key}=" "$ENV_FILE" | tail -n 1 || true)"
  [ -n "$line" ] || return 0
  value="${line#*=}"

  if [[ "$value" == \"*\" && "$value" == *\" ]]; then
    value="${value:1:${#value}-2}"
    value="${value//\\\"/\"}"
    value="${value//\\\\/\\}"
  elif [[ "$value" == \'*\' && "$value" == *\' ]]; then
    value="${value:1:${#value}-2}"
  fi
  printf "%s" "$value"
}

validate_no_newline() {
  local value="$1"
  if [[ "$value" == *$'\n'* || "$value" == *$'\r'* ]]; then
    return 1
  fi
  return 0
}

prompt_value() {
  local __var="$1"
  local label="$2"
  local default="${3:-}"
  local required="${4:-0}"
  local secret="${5:-0}"
  local value prompt_text

  while true; do
    if [ "$secret" = "1" ] && [ -n "$default" ]; then
      prompt_text="${label} [直接回车保持当前值]: "
    elif [ -n "$default" ]; then
      prompt_text="${label} [${default}]: "
    else
      prompt_text="${label}: "
    fi

    if [ "$secret" = "1" ]; then
      read -r -s -p "$prompt_text" value
      printf "\n"
    else
      read -r -p "$prompt_text" value
    fi

    value="${value:-$default}"
    if [ "$required" = "1" ] && [ -z "$value" ]; then
      warn "${label} 不能为空。"
      continue
    fi
    if ! validate_no_newline "$value"; then
      warn "${label} 不能包含换行。"
      continue
    fi
    printf -v "$__var" "%s" "$value"
    return 0
  done
}

prompt_int() {
  local __var="$1"
  local label="$2"
  local default="$3"
  local min="$4"
  local max="$5"
  local value

  while true; do
    read -r -p "${label} [${default}]: " value
    value="${value:-$default}"
    if [[ "$value" =~ ^[0-9]+$ ]] && [ "$value" -ge "$min" ] && [ "$value" -le "$max" ]; then
      printf -v "$__var" "%s" "$value"
      return 0
    fi
    warn "${label} 必须是 ${min}-${max} 之间的整数。"
  done
}

prompt_ttl() {
  local __var="$1"
  local label="$2"
  local default="$3"
  local ttl_value

  while true; do
    read -r -p "${label} [${default}]: " ttl_value
    ttl_value="${ttl_value:-$default}"
    if ! [[ "$ttl_value" =~ ^[0-9]+$ ]] || [ "$ttl_value" -lt 1 ] || [ "$ttl_value" -gt 86400 ]; then
      warn "${label} 必须是 1-86400 之间的整数。"
      continue
    fi
    if [ "$ttl_value" = "1" ] || [ "$ttl_value" -ge 60 ]; then
      printf -v "$__var" "%s" "$ttl_value"
      return 0
    fi
    warn "${label} 请输入 1 表示 Auto，或输入 60-86400 秒。"
  done
}

prompt_panel_mode() {
  local __var="$1"
  local current="${2:-legacy}"
  local default_choice=1 choice
  [ "$current" = "api" ] && default_choice=2
  while true; do
    printf "\n面板接入模式：\n"
    printf "  1) legacy - 原账号密码登录模式\n"
    printf "  2) api    - Bearer Token API 模式\n"
    read -r -p "请选择 [${default_choice}]: " choice
    choice="${choice:-$default_choice}"
    case "$choice" in
      1|legacy) printf -v "$__var" "%s" "legacy"; return 0 ;;
      2|api) printf -v "$__var" "%s" "api"; return 0 ;;
      *) warn "请选择 1 或 2。" ;;
    esac
  done
}

configure_api_targets_interactive() {
  local target_file="$1"
  local count rows_file json_file target_id target_name api_token index
  if [ -f "$target_file" ] && ! confirm "重新配置 API 机器和 Token？" n; then
    ok "已保留 API targets：${target_file}"
    return 0
  fi

  prompt_int count "API 机器数量" 1 1 50
  rows_file="$(mktemp)"
  json_file="$(mktemp)"
  chmod 600 "$rows_file" "$json_file"
  for ((index = 1; index <= count; index++)); do
    printf "\n配置第 %s/%s 台 API 机器。\n" "$index" "$count"
    while true; do
      prompt_value target_id "机器 ID（字母、数字、_、-，最多32字符）" "" 1 0
      if [[ "$target_id" =~ ^[A-Za-z0-9_-]{1,32}$ ]]; then
        break
      fi
      warn "机器 ID 格式不正确。"
    done
    prompt_value target_name "机器显示名称" "$target_id" 1 0
    prompt_value api_token "API Token" "" 1 1
    if [[ "$target_name" == *$'\t'* || "$api_token" == *$'\t'* ]]; then
      rm -f "$rows_file" "$json_file"
      die "机器名称和 Token 不能包含制表符。"
    fi
    printf "%s\t%s\t%s\n" "$target_id" "$target_name" "$api_token" >>"$rows_file"
  done

  if ! /usr/bin/python3 -c '
import csv, json, pathlib, sys
rows = []
seen = set()
with open(sys.argv[1], encoding="utf-8", newline="") as handle:
    for target_id, name, token in csv.reader(handle, delimiter="\t"):
        if target_id in seen:
            raise SystemExit(f"机器 ID 重复：{target_id}")
        seen.add(target_id)
        rows.append({"id": target_id, "name": name, "token": token})
pathlib.Path(sys.argv[2]).write_text(
    json.dumps(rows, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
)
' "$rows_file" "$json_file"; then
    rm -f "$rows_file" "$json_file"
    die "API targets 配置生成失败。"
  fi
  install -m 640 -o root -g "$SERVICE_GROUP" "$json_file" "$target_file"
  rm -f "$rows_file" "$json_file"
  ok "API targets 已保存：${target_file}"
}

detect_timezone() {
  local tz
  tz="$(timedatectl show -p Timezone --value 2>/dev/null || true)"
  if [ -n "$tz" ]; then
    printf "%s" "$tz"
  else
    printf "Asia/Shanghai"
  fi
}

validate_timezone() {
  local tz="$1"
  if [ "$tz" = "UTC" ] || [ -f "/usr/share/zoneinfo/$tz" ]; then
    return 0
  fi
  return 1
}

write_config_interactive() {
  local token chat_ids panel_mode base_url account password api_targets_file db_path
  local api_initial_delay api_poll_interval api_confirm_timeout
  local post_delay query_cache max_attempts retry_delay timezone poll_timeout panel_image log_level
  local ddns_enabled cloudflare_api_token cloudflare_zone_id ddns_ttl ddns_sync_after_change
  local relay_sync_enabled relay_sync_after_change
  local old_timezone

  old_timezone="$(env_value TIMEZONE)"
  [ -n "$old_timezone" ] || old_timezone="$(detect_timezone)"

  info "请输入 Bot 和面板配置。"
  prompt_value token "Telegram Bot Token" "$(env_value TELEGRAM_BOT_TOKEN)" 1 0
  prompt_value chat_ids "允许使用的 Telegram chat id，多个用英文逗号分隔" "$(env_value TELEGRAM_ALLOWED_CHAT_IDS)" 1 0
  panel_mode="$(env_value IPPANEL_MODE || true)"
  [ -n "$panel_mode" ] || panel_mode="legacy"
  prompt_panel_mode panel_mode "$panel_mode"
  base_url="$(env_value IPPANEL_BASE_URL || true)"
  [ -n "$base_url" ] || base_url="https://ippanel.boil.network"
  prompt_value base_url "IP 面板地址" "$base_url" 1 0
  account="$(env_value IPPANEL_ACCOUNT)"
  password="$(env_value IPPANEL_PASSWORD)"
  api_targets_file="$(env_value IPPANEL_API_TARGETS_FILE || true)"
  [ -n "$api_targets_file" ] || api_targets_file="$API_TARGETS_FILE"
  if [ "$panel_mode" = "legacy" ]; then
    prompt_value account "BoilCloud 面板账号" "$account" 1 0
    prompt_value password "BoilCloud 面板密码" "$password" 1 1
  else
    configure_api_targets_interactive "$api_targets_file"
  fi

  api_initial_delay="$(env_value API_CHANGE_INITIAL_DELAY_SECONDS || true)"
  [ -n "$api_initial_delay" ] || api_initial_delay=5
  api_poll_interval="$(env_value API_CHANGE_POLL_INTERVAL_SECONDS || true)"
  [ -n "$api_poll_interval" ] || api_poll_interval=30
  api_confirm_timeout="$(env_value API_CHANGE_CONFIRM_TIMEOUT_SECONDS || true)"
  [ -n "$api_confirm_timeout" ] || api_confirm_timeout=300
  if [ "$panel_mode" = "api" ]; then
    prompt_int api_initial_delay "API 换 IP 后首次查询等待秒数" "$api_initial_delay" 1 300
    prompt_int api_poll_interval "API 新 IP 确认轮询秒数" "$api_poll_interval" 5 300
    prompt_int api_confirm_timeout "API 新 IP 最长确认秒数" "$api_confirm_timeout" 30 3600
  fi

  db_path="$(env_value DB_PATH)"
  [ -n "$db_path" ] || db_path="${DATA_DIR}/ippanel_bot.sqlite3"

  post_delay="$(env_value POST_CHANGE_QUERY_DELAY_SECONDS || true)"
  [ -n "$post_delay" ] || post_delay=5
  query_cache="$(env_value QUERY_CACHE_SECONDS || true)"
  [ -n "$query_cache" ] || query_cache=60
  prompt_int query_cache "查询缓存秒数" "$query_cache" 0 300
  max_attempts="$(env_value CHANGE_MAX_ATTEMPTS || true)"
  [ -n "$max_attempts" ] || max_attempts=5
  retry_delay="$(env_value CHANGE_RETRY_DELAY_SECONDS || true)"
  [ -n "$retry_delay" ] || retry_delay=60
  if [ "$panel_mode" = "legacy" ]; then
    prompt_int post_delay "更换后等待查询秒数" "$post_delay" 1 60
    prompt_int max_attempts "更换失败重试次数" "$max_attempts" 1 20
    prompt_int retry_delay "更换失败重试间隔秒数" "$retry_delay" 1 3600
  fi

  while true; do
    prompt_value timezone "计划任务时区" "$old_timezone" 1 0
    if validate_timezone "$timezone"; then
      break
    fi
    warn "没有找到这个时区。示例：Asia/Shanghai、UTC、America/Los_Angeles。"
  done

  poll_timeout="$(env_value POLL_TIMEOUT_SECONDS || true)"
  [ -n "$poll_timeout" ] || poll_timeout=5
  prompt_int poll_timeout "Telegram 轮询等待秒数" "$poll_timeout" 1 60

  panel_image="$(env_value PANEL_IMAGE_PATH)"
  [ -n "$panel_image" ] || panel_image="pic.png"
  log_level="$(env_value LOG_LEVEL)"
  [ -n "$log_level" ] || log_level="INFO"

  ddns_enabled="$(env_value DDNS_ENABLED || true)"
  [ -n "$ddns_enabled" ] || ddns_enabled=0
  prompt_int ddns_enabled "启用 DDNS，0=关闭，1=开启" "$ddns_enabled" 0 1

  cloudflare_api_token="$(env_value CLOUDFLARE_API_TOKEN)"
  cloudflare_zone_id="$(env_value CLOUDFLARE_ZONE_ID)"
  ddns_ttl="$(env_value DDNS_TTL_SECONDS || true)"
  [ -n "$ddns_ttl" ] || ddns_ttl=60
  ddns_sync_after_change="$(env_value DDNS_SYNC_AFTER_CHANGE || true)"
  [ -n "$ddns_sync_after_change" ] || ddns_sync_after_change=1
  if [ "$ddns_enabled" = "1" ]; then
    prompt_value cloudflare_api_token "Cloudflare API Token" "$cloudflare_api_token" 1 1
    prompt_value cloudflare_zone_id "Cloudflare Zone ID" "$cloudflare_zone_id" 1 0
    prompt_ttl ddns_ttl "Cloudflare DNS TTL 秒数，1=Auto，60=1分钟" "$ddns_ttl"
    prompt_int ddns_sync_after_change "换 IP 成功后自动同步 DDNS，0=关闭，1=开启" "$ddns_sync_after_change" 0 1
  fi

  echo ""
  info "扩展组件：中转同步"
  info "项目地址：https://github.com/DarkJimiHole/ippanelreceiver"
  info "说明：配合安装在中转 VPS 上的 ippanelreceiver，在换 IP 成功后上报新 IP，并由 receiver 调用 easynftables 更新转发目标。"
  warn "该组件默认关闭。开启前请先在中转 VPS 安装并配置 ippanelreceiver。"
  relay_sync_enabled="$(env_value RELAY_SYNC_ENABLED || true)"
  [ -n "$relay_sync_enabled" ] || relay_sync_enabled=0
  prompt_int relay_sync_enabled "启用中转同步，0=关闭，1=开启" "$relay_sync_enabled" 0 1
  relay_sync_after_change="$(env_value RELAY_SYNC_AFTER_CHANGE || true)"
  [ -n "$relay_sync_after_change" ] || relay_sync_after_change=1
  if [ "$relay_sync_enabled" = "1" ]; then
    prompt_int relay_sync_after_change "换 IP 成功后自动上报中转同步，0=关闭，1=开启" "$relay_sync_after_change" 0 1
  fi

  local tmp
  tmp="$(mktemp)"
  {
    printf "TELEGRAM_BOT_TOKEN=%s\n" "$(env_quote "$token")"
    printf "TELEGRAM_ALLOWED_CHAT_IDS=%s\n" "$(env_quote "$chat_ids")"
    printf "\n"
    printf "IPPANEL_MODE=%s\n" "$(env_quote "$panel_mode")"
    printf "IPPANEL_BASE_URL=%s\n" "$(env_quote "$base_url")"
    printf "IPPANEL_ACCOUNT=%s\n" "$(env_quote "$account")"
    printf "IPPANEL_PASSWORD=%s\n" "$(env_quote "$password")"
    printf "IPPANEL_API_TARGETS_FILE=%s\n" "$(env_quote "$api_targets_file")"
    printf "API_CHANGE_INITIAL_DELAY_SECONDS=%s\n" "$(env_quote "$api_initial_delay")"
    printf "API_CHANGE_POLL_INTERVAL_SECONDS=%s\n" "$(env_quote "$api_poll_interval")"
    printf "API_CHANGE_CONFIRM_TIMEOUT_SECONDS=%s\n" "$(env_quote "$api_confirm_timeout")"
    printf "\n"
    printf "DB_PATH=%s\n" "$(env_quote "$db_path")"
    printf "POST_CHANGE_QUERY_DELAY_SECONDS=%s\n" "$(env_quote "$post_delay")"
    printf "QUERY_CACHE_SECONDS=%s\n" "$(env_quote "$query_cache")"
    printf "CHANGE_MAX_ATTEMPTS=%s\n" "$(env_quote "$max_attempts")"
    printf "CHANGE_RETRY_DELAY_SECONDS=%s\n" "$(env_quote "$retry_delay")"
    printf "TIMEZONE=%s\n" "$(env_quote "$timezone")"
    printf "POLL_TIMEOUT_SECONDS=%s\n" "$(env_quote "$poll_timeout")"
    printf "PANEL_IMAGE_PATH=%s\n" "$(env_quote "$panel_image")"
    printf "LOG_LEVEL=%s\n" "$(env_quote "$log_level")"
    printf "\n"
    printf "DDNS_ENABLED=%s\n" "$(env_quote "$ddns_enabled")"
    printf "CLOUDFLARE_API_TOKEN=%s\n" "$(env_quote "$cloudflare_api_token")"
    printf "CLOUDFLARE_ZONE_ID=%s\n" "$(env_quote "$cloudflare_zone_id")"
    printf "DDNS_TTL_SECONDS=%s\n" "$(env_quote "$ddns_ttl")"
    printf "DDNS_SYNC_AFTER_CHANGE=%s\n" "$(env_quote "$ddns_sync_after_change")"
    printf "\n"
    printf "RELAY_SYNC_ENABLED=%s\n" "$(env_quote "$relay_sync_enabled")"
    printf "RELAY_SYNC_AFTER_CHANGE=%s\n" "$(env_quote "$relay_sync_after_change")"
  } >"$tmp"

  install -m 600 -o root -g root "$tmp" "$ENV_FILE"
  rm -f "$tmp"
  ok "配置已保存：${ENV_FILE}"
}

confirm() {
  local prompt="$1"
  local default="${2:-n}"
  local answer suffix
  if [ "$default" = "y" ]; then
    suffix="[Y/n]"
  else
    suffix="[y/N]"
  fi
  read -r -p "${prompt} ${suffix}: " answer
  answer="${answer:-$default}"
  case "$answer" in
    y|Y|yes|YES|是|确认) return 0 ;;
    *) return 1 ;;
  esac
}

is_installed() {
  [ -f "$SERVICE_FILE" ] && [ -f "$APP_DIR/bot.py" ] && [ -f "$ENV_FILE" ]
}

has_managed_files() {
  [ -e "$SERVICE_FILE" ] || [ -d "$APP_DIR" ] || [ -d "$DATA_DIR" ] || \
    [ -f "$ENV_FILE" ] || [ -f "$API_TARGETS_FILE" ] || [ -f "$SOURCE_FILE" ] || \
    [ -e "$CTL_PATH" ] || \
    id "$SERVICE_USER" >/dev/null 2>&1 || getent group "$SERVICE_GROUP" >/dev/null 2>&1
}

require_installed() {
  if ! is_installed; then
    die "${APP_NAME} 尚未安装，请先运行：sudo boil install"
  fi
}

menu_require_installed() {
  if ! is_installed; then
    warn "${APP_NAME} 尚未安装，请先选择 1 进行安装。"
    return 1
  fi
  return 0
}

run_install() {
  require_root "$@"
  require_systemd
  detect_os
  install_dependencies
  ensure_user
  install_files
  install_manager
  write_source_file
  write_config_interactive
  write_service
  systemctl daemon-reload
  systemctl enable --now "$SERVICE_NAME"
  ok "${APP_NAME} 已安装并正在运行。"
  info "查看状态：sudo boil status"
}

run_config() {
  require_root "$@"
  require_installed
  write_config_interactive
  if systemctl list-unit-files "$SERVICE_NAME.service" >/dev/null 2>&1; then
    if confirm "Restart ${SERVICE_NAME} now?" y; then
      systemctl restart "$SERVICE_NAME"
      ok "服务已重启。"
    fi
  fi
}

run_update() {
  require_root "$@"
  require_systemd
  require_installed
  command -v curl >/dev/null 2>&1 || install_dependencies
  ensure_user
  install_files
  install_manager
  write_source_file
  write_service
  systemctl daemon-reload
  if systemctl is-enabled "$SERVICE_NAME" >/dev/null 2>&1; then
    systemctl restart "$SERVICE_NAME"
    ok "已更新并重启 ${SERVICE_NAME}。"
  else
    ok "文件已更新，服务当前未设置开机启动。"
  fi
}

safe_remove_file() {
  local path="$1"
  local expected="$2"
  local resolved
  resolved="$(readlink -m "$path")"
  if [ "$resolved" != "$expected" ]; then
    die "拒绝删除非预期文件路径：${path}"
  fi
  if [ -e "$resolved" ] || [ -L "$resolved" ]; then
    rm -f -- "$resolved"
    ok "已删除 ${resolved}"
  fi
}

safe_remove_dir() {
  local path="$1"
  local expected="$2"
  local resolved
  resolved="$(readlink -m "$path")"
  if [ "$resolved" != "$expected" ]; then
    die "拒绝删除非预期目录路径：${path}"
  fi
  if [ -d "$resolved" ]; then
    rm -rf --one-file-system -- "$resolved"
    ok "已删除 ${resolved}"
  fi
}

remove_user_group() {
  local home shell gid members
  if id "$SERVICE_USER" >/dev/null 2>&1; then
    home="$(getent passwd "$SERVICE_USER" | cut -d: -f6)"
    shell="$(getent passwd "$SERVICE_USER" | cut -d: -f7)"
    if [ "$home" = "$DATA_DIR" ] && [ "$shell" = "/usr/sbin/nologin" ]; then
      userdel "$SERVICE_USER" || warn "无法删除用户 ${SERVICE_USER}。"
      ok "已删除用户 ${SERVICE_USER}。"
    else
      warn "用户 ${SERVICE_USER} 看起来不是此脚本创建的，已跳过删除。"
    fi
  fi

  if getent group "$SERVICE_GROUP" >/dev/null 2>&1; then
    gid="$(getent group "$SERVICE_GROUP" | cut -d: -f3)"
    members="$(getent group "$SERVICE_GROUP" | cut -d: -f4)"
    if [ -z "$members" ] && ! getent passwd | awk -F: -v gid="$gid" '$4 == gid { found=1 } END { exit found ? 0 : 1 }'; then
      groupdel "$SERVICE_GROUP" || warn "无法删除用户组 ${SERVICE_GROUP}。"
      ok "已删除用户组 ${SERVICE_GROUP}。"
    else
      warn "用户组 ${SERVICE_GROUP} 仍在使用，已跳过删除。"
    fi
  fi
}

run_uninstall() {
  require_root "$@"
  require_systemd
  if ! has_managed_files; then
    warn "${APP_NAME} 尚未安装，无需卸载。"
    return 0
  fi
  warn "即将卸载 ${APP_NAME}，包括服务、配置、程序文件和 SQLite 数据。"
  warn "只会删除这些路径：${APP_DIR}、${DATA_DIR}、${ENV_FILE}、${API_TARGETS_FILE}、${SOURCE_FILE}、${SERVICE_FILE}、${CTL_PATH}。"

  systemctl disable --now "$SERVICE_NAME" >/dev/null 2>&1 || true
  safe_remove_file "$SERVICE_FILE" "$SERVICE_FILE"
  systemctl daemon-reload
  systemctl reset-failed "$SERVICE_NAME" >/dev/null 2>&1 || true
  safe_remove_file "$ENV_FILE" "$ENV_FILE"
  safe_remove_file "$API_TARGETS_FILE" "$API_TARGETS_FILE"
  safe_remove_file "$SOURCE_FILE" "$SOURCE_FILE"
  safe_remove_dir "$APP_DIR" "$APP_DIR"
  safe_remove_dir "$DATA_DIR" "$DATA_DIR"
  remove_user_group
  safe_remove_file "$CTL_PATH" "$CTL_PATH"
  ok "${APP_NAME} 已完全卸载。"
}

run_status() {
  require_systemd
  require_installed
  systemctl status "$SERVICE_NAME" --no-pager
}

run_logs() {
  require_systemd
  require_installed
  journalctl -u "$SERVICE_NAME" -f
}

run_bot_cli() {
  require_root "$@"
  require_installed
  BOT_ENV_FILE="$ENV_FILE" /usr/bin/python3 "$APP_DIR/bot.py" "$@"
  chown -R "$SERVICE_USER:$SERVICE_GROUP" "$DATA_DIR" >/dev/null 2>&1 || true
}

run_relay_config() {
  require_root "$@"
  require_installed
  info "扩展组件：中转同步"
  info "项目地址：https://github.com/DarkJimiHole/ippanelreceiver"
  info "说明：配合安装在中转 VPS 上的 ippanelreceiver，在换 IP 成功后上报新 IP，并由 receiver 调用 easynftables 更新转发目标。"
  if [ "$(env_value RELAY_SYNC_ENABLED || true)" != "1" ]; then
    warn "当前未开启中转同步。请先运行 sudo boil config，将“启用中转同步”设置为 1。"
    return 1
  fi
  while true; do
    printf "\n%b中转同步管理%b\n" "$GREEN" "$RESET"
    printf "  1) 查看绑定\n"
    printf "  2) 添加绑定\n"
    printf "  3) 修改绑定\n"
    printf "  4) 删除绑定\n"
    printf "  0) 返回\n"
    read -r -p "请选择: " relay_choice
    case "$relay_choice" in
      1) run_bot_cli relay-list ;;
      2) run_bot_cli relay ;;
      3) run_bot_cli relay-edit ;;
      4) run_bot_cli relay-delete ;;
      0) return 0 ;;
      *) warn "无效选项。" ;;
    esac
  done
}

run_service_action() {
  local action="$1"
  require_root "$@"
  require_systemd
  require_installed
  systemctl "$action" "$SERVICE_NAME"
  ok "服务操作完成：${action} ${SERVICE_NAME}"
}

run_menu() {
  while true; do
    printf "\n%b%s 管理菜单%b\n" "$GREEN" "$APP_NAME" "$RESET"
    if is_installed; then
      printf "%b当前状态：已安装%b\n" "$DIM" "$RESET"
    else
      printf "%b当前状态：未安装%b\n" "$DIM" "$RESET"
    fi
    printf "  1) 安装\n"
    printf "  2) 修改配置\n"
    printf "  3) 更新文件\n"
    printf "  4) 启动\n"
    printf "  5) 停止\n"
    printf "  6) 重启\n"
    printf "  7) 查看状态\n"
    printf "  8) 查看日志\n"
    printf "  9) 配置中转同步\n"
    printf " 10) 卸载\n"
    printf "  0) 退出\n"
    read -r -p "请选择: " choice
    case "$choice" in
      1) run_install ;;
      2) menu_require_installed && run_config ;;
      3) menu_require_installed && run_update ;;
      4) menu_require_installed && run_service_action start ;;
      5) menu_require_installed && run_service_action stop ;;
      6) menu_require_installed && run_service_action restart ;;
      7) menu_require_installed && run_status ;;
      8) menu_require_installed && run_logs ;;
      9) menu_require_installed && run_relay_config ;;
      10) run_uninstall ;;
      0) exit 0 ;;
      *) warn "无效选项。" ;;
    esac
  done
}

main() {
  local cmd="${1:-menu}"
  shift || true
  case "$cmd" in
    install) run_install "$@" ;;
    config|configure|modify) run_config "$@" ;;
    update|upgrade) run_update "$@" ;;
    relay) run_relay_config "$@" ;;
    start|stop|restart) run_service_action "$cmd" "$@" ;;
    status) run_status "$@" ;;
    logs|log) run_logs "$@" ;;
    uninstall|remove) run_uninstall "$@" ;;
    menu) run_menu "$@" ;;
    help|-h|--help) usage ;;
    *) usage; die "未知命令：${cmd}" ;;
  esac
}

main "$@"
