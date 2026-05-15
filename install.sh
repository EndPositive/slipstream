#!/usr/bin/env bash
set -euo pipefail

TAG="latest"
NON_INTERACTIVE=0

usage() {
  echo "Usage: ./install.sh [--tag <tag>] [--non-interactive]"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --tag)
      TAG="${2:-}"; shift 2 ;;
    --non-interactive)
      NON_INTERACTIVE=1; shift ;;
    -h|--help)
      usage; exit 0 ;;
    *)
      echo "Unknown arg: $1"; usage; exit 1 ;;
  esac
done

section() {
  echo ""
  echo "==== $1 ===="
}

fail() {
  echo "" >&2
  echo "ERROR: $1" >&2
  exit 1
}

have_cmd() {
  command -v "$1" >/dev/null 2>&1
}

can_sudo() {
  sudo -n true >/dev/null 2>&1
}

require_cmd() {
  local name="$1"; local hint="$2"
  if ! have_cmd "$name"; then
    fail "$name not found. $hint"
  fi
}

read_required() {
  local prompt="$1"
  local v=""
  while true; do
    read -r -p "$prompt" v
    if [[ -n "${v// }" ]]; then
      echo "$v"
      return
    fi
    echo "Value is required."
  done
}

read_default() {
  local prompt="$1"; local def="$2"
  local v=""
  read -r -p "$prompt (default: $def) " v
  if [[ -z "${v// }" ]]; then
    echo "$def"
  else
    echo "$v"
  fi
}

read_yes_no() {
  local prompt="$1"; local def="$2" # def: y|n
  local suffix=""
  if [[ "$def" == "y" ]]; then suffix="Y/n"; else suffix="y/N"; fi
  local v=""
  while true; do
    read -r -p "$prompt [$suffix] " v
    v="${v,,}"
    if [[ -z "${v// }" ]]; then
      [[ "$def" == "y" ]] && echo "y" || echo "n"
      return
    fi
    case "$v" in
      y|yes) echo "y"; return ;;
      n|no) echo "n"; return ;;
    esac
    echo "Please answer yes or no."
  done
}

read_int() {
  local prompt="$1"; local def="$2"; local min="$3"; local max="$4"
  local v=""
  while true; do
    read -r -p "$prompt (default: $def) " v
    if [[ -z "${v// }" ]]; then
      echo "$def"; return
    fi
    if [[ "$v" =~ ^[0-9]+$ ]] && (( v >= min && v <= max )); then
      echo "$v"; return
    fi
    echo "Enter a valid number between $min and $max."
  done
}

detect_os() {
  local u
  u="$(uname -s 2>/dev/null || echo unknown)"
  case "${u,,}" in
    linux) echo "linux" ;;
    darwin) echo "macos" ;;
    msys*|mingw*|cygwin*) echo "windows" ;;
    *) echo "unknown" ;;
  esac
}

is_root() {
  [[ "${EUID:-$(id -u)}" -eq 0 ]]
}

sudo_prefix() {
  if is_root; then
    echo ""
  else
    echo "sudo"
  fi
}

ensure_linux_server_service_prereqs() {
  if ! have_cmd systemctl; then
    fail "systemctl not found. This script can only install a persistent service on systemd-based Linux."
  fi
  if ! have_cmd setcap; then
    if have_cmd apt-get; then
      local ans="y"
      if [[ "$NON_INTERACTIVE" -eq 0 ]]; then
        ans="$(read_yes_no "Install libcap2-bin (setcap) to allow binding to port 53 without running as root?" y)"
      fi
      if [[ "$ans" == "y" ]]; then
        $(sudo_prefix) apt-get update
        $(sudo_prefix) apt-get install -y libcap2-bin
      fi
    fi
  fi
}

ensure_sshd_if_requested() {
  if have_cmd sshd; then
    return
  fi
  if ! have_cmd apt-get; then
    echo "sshd not found and this script can auto-install it only on apt-based distros."
    echo "Install an SSH server manually if you want to forward to SSH."
    return
  fi
  local ans="y"
  if [[ "$NON_INTERACTIVE" -eq 0 ]]; then
    ans="$(read_yes_no "Install and enable openssh-server on this host?" y)"
  fi
  [[ "$ans" == "y" ]] || return

  $(sudo_prefix) apt-get update
  $(sudo_prefix) apt-get install -y openssh-server
  $(sudo_prefix) systemctl enable --now ssh
}

server_target_wizard() {
  local choice="ssh"
  while true; do
    if [[ "$NON_INTERACTIVE" -eq 1 ]]; then
      choice="ssh"
    else
      read -r -p "Select target service to forward to: ssh | custom " choice
      choice="${choice,,}"
    fi

    if [[ "$choice" == "ssh" ]]; then
      ensure_sshd_if_requested
      echo "127.0.0.1:22"
      return
    fi

    if [[ "$choice" != "custom" ]]; then
      echo "Invalid choice. Please enter 'ssh' or 'custom'." >&2
      [[ "$NON_INTERACTIVE" -eq 1 ]] && return 1
      continue
    fi

    local target
    while true; do
      if [[ "$NON_INTERACTIVE" -eq 1 ]]; then
        target="127.0.0.1:5201"
      else
        target="$(read_default "Target TCP address (host:port)" "127.0.0.1:5201")"
        target="${target// /}"
      fi

      if [[ "$target" =~ ^\[?[A-Za-z0-9:.%-]+\]?:[0-9]+$ ]]; then
        echo "$target"
        return
      fi

      echo "Invalid target format. Use host:port (examples: 127.0.0.1:22 or 10.0.0.5:5201)." >&2
      [[ "$NON_INTERACTIVE" -eq 1 ]] && return 1
    done
  done
}

install_systemd_slipstream_server() {
  local server_bin="$1"
  local domain="$2"
  local target_address="$3"
  local dns_port="$4"
  local use_ipv6="$5" # 0|1

  ensure_linux_server_service_prereqs

  local svc_user="slipstream"
  local svc_group="slipstream"
  local install_dir="/opt/slipstream"
  local certs_dir="$install_dir/certs"
  local unit_path="/etc/systemd/system/slipstream-server.service"

  $(sudo_prefix) mkdir -p "$install_dir"
  $(sudo_prefix) mkdir -p "$certs_dir"

  if ! id -u "$svc_user" >/dev/null 2>&1; then
    $(sudo_prefix) useradd --system --home "$install_dir" --shell /usr/sbin/nologin "$svc_user" || true
  fi

  $(sudo_prefix) cp "$server_bin" "$install_dir/slipstream-server"
  $(sudo_prefix) chmod 0755 "$install_dir/slipstream-server"

  if [[ -d "$CERTS_PATH" ]]; then
    $(sudo_prefix) cp "$CERTS_PATH/cert.pem" "$certs_dir/cert.pem"
    $(sudo_prefix) cp "$CERTS_PATH/key.pem" "$certs_dir/key.pem"
    $(sudo_prefix) chmod 0644 "$certs_dir/cert.pem"
    $(sudo_prefix) chmod 0600 "$certs_dir/key.pem"
  fi

  $(sudo_prefix) chown -R "$svc_user:$svc_group" "$install_dir" || true

  if have_cmd setcap; then
    $(sudo_prefix) setcap 'cap_net_bind_service=+ep' "$install_dir/slipstream-server" || true
  fi

  local ipv6_arg=""
  if [[ "$use_ipv6" -eq 1 ]]; then
    ipv6_arg=" --dns-listen-ipv6"
  fi

  local cert_args=""
  if [[ -f "$certs_dir/cert.pem" && -f "$certs_dir/key.pem" ]]; then
    cert_args=" --cert=$certs_dir/cert.pem --key=$certs_dir/key.pem"
  fi

  $(sudo_prefix) bash -c "cat > '$unit_path' <<EOF
[Unit]
Description=Slipstream Server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$svc_user
Group=$svc_group
WorkingDirectory=$install_dir
ExecStart=$install_dir/slipstream-server --dns-listen-port=$dns_port --domain=$domain --target-address=$target_address$ipv6_arg$cert_args
Restart=on-failure
RestartSec=2
NoNewPrivileges=true
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
EOF"

  $(sudo_prefix) systemctl daemon-reload
  $(sudo_prefix) systemctl enable --now slipstream-server.service

  echo ""
  echo "Service installed: slipstream-server.service"
  echo "Status: systemctl status slipstream-server.service"
  echo "Logs: journalctl -u slipstream-server.service -f"
}

print_dns_guidance() {
  local domain="$1"
  echo ""
  echo "DNS configuration guidance (general):"
  echo "- Add NS record for '$domain' pointing to a nameserver hostname you control (example: ns.$domain)."
  echo "- Add A/AAAA record for that nameserver hostname pointing to this server's public IP."
  echo "Example zone records:"
  echo "  @   IN  NS  ns.$domain."
  echo "  ns  IN  A   <SERVER_PUBLIC_IP>"
}

is_git_repo() {
  git rev-parse --is-inside-work-tree >/dev/null 2>&1
}

port_in_use() {
  local proto="$1" # tcp|udp
  local port="$2"
  if have_cmd ss; then
    if [[ "$proto" == "tcp" ]]; then
      ss -ltn "sport = :$port" 2>/dev/null | awk 'NR>1 {exit 0} END {exit 1}' && return 0 || return 1
    else
      ss -lun "sport = :$port" 2>/dev/null | awk 'NR>1 {exit 0} END {exit 1}' && return 0 || return 1
    fi
  fi
  if have_cmd lsof; then
    lsof -nP -i"$proto":$port >/dev/null 2>&1 && return 0 || return 1
  fi
  return 1
}

ensure_submodules() {
  if ! is_git_repo; then
    echo "Not a git repository; cannot auto-initialize submodules."
    echo "If you downloaded a zip/tarball, please clone with --recurse-submodules instead."
    return
  fi

  require_cmd git "Install git to manage submodules."

  local need_init=0
  for p in "subprojects/picoquic" "extern/SPCDNS" "extern/lua-resty-base-encoding" "extern/quick_arg_parser"; do
    if [[ ! -d "$REPO_ROOT/$p" ]]; then
      need_init=1
    fi
  done

  if git submodule status --recursive 2>/dev/null | grep -qE '^-' ; then
    need_init=1
  fi

  if [[ "$need_init" -eq 0 ]]; then
    return
  fi

  local ans="y"
  if [[ "$NON_INTERACTIVE" -eq 0 ]]; then
    ans="$(read_yes_no "Project submodules are missing. Initialize/update submodules now?" y)"
  fi
  [[ "$ans" == "y" ]] || fail "Submodules missing. Run: git submodule update --init --recursive"

  git submodule update --init --recursive
}

docker_ok() {
  docker info >/dev/null 2>&1
}

ensure_docker() {
  require_cmd docker "Install Docker and ensure it's in PATH."
  if ! docker_ok; then
    fail "Docker daemon is not reachable. Start Docker then re-run."
  fi
}

download_file() {
  local url="$1"
  local out="$2"

  if have_cmd curl; then
    curl -fsSL "$url" -o "$out" || return 1
    return 0
  fi
  if have_cmd wget; then
    wget -qO "$out" "$url" || return 1
    return 0
  fi
  fail "Neither curl nor wget is available to download binaries. Install curl or wget."
}

download_windows_client_only() {
  local version_tag="$1"  # e.g. v0.0.1
  local win_arch="$2"     # e.g. windows-x86_64.exe

  local base="https://github.com/EndPositive/slipstream/releases/download/${version_tag}"
  local client_win_default="${base}/slipstream-client-${version_tag}-${win_arch}"
  local client_win_url="$client_win_default"

  section "Client (Windows) binary"
  echo "Default URL is based on GitHub releases pattern."
  echo "If your release assets use a different naming, paste the correct URL."

  mkdir -p "$REPO_ROOT/bin"

  while true; do
    if [[ "$NON_INTERACTIVE" -eq 0 ]]; then
      client_win_url="$(read_default "Client (Windows) binary URL" "$client_win_default")"
    else
      client_win_url="$client_win_default"
    fi

    echo "Downloading client (Windows) from: $client_win_url"
    if download_file "$client_win_url" "$REPO_ROOT/bin/slipstream-client.exe"; then
      chmod +x "$REPO_ROOT/bin/slipstream-client.exe" || true
      echo "Windows client downloaded to: $REPO_ROOT/bin/slipstream-client.exe"
      return 0
    fi

    echo "Download failed (URL may be wrong or the asset does not exist)." >&2
    if [[ "$NON_INTERACTIVE" -eq 1 ]]; then
      return 1
    fi

    skip="$(read_yes_no "Skip downloading Windows client and continue?" n)"
    if [[ "$skip" == "y" ]]; then
      echo "Skipping Windows client."
      return 0
    fi
  done
}

download_binaries() {
  local version_tag="$1" # e.g. v0.0.1
  local linux_arch="$2"  # e.g. linux-x86_64
  local win_arch="$3"    # e.g. windows-x86_64.exe

  local base="https://github.com/EndPositive/slipstream/releases/download/${version_tag}"
  local client_linux_default="${base}/slipstream-client-${version_tag}-${linux_arch}"
  local client_win_default="${base}/slipstream-client-${version_tag}-${win_arch}"
  local server_default="${base}/slipstream-server-${version_tag}-${linux_arch}"

  section "Download binaries"
  echo "Default URLs are based on GitHub releases pattern."
  echo "If your release assets use a different naming, paste the correct URLs."

  local client_linux_url="$client_linux_default"
  local client_win_url="$client_win_default"
  local server_url="$server_default"

  if [[ "$NON_INTERACTIVE" -eq 0 ]]; then
    if [[ "$MODE" == "client" || "$MODE" == "both" ]]; then
      if [[ "$CLIENT_PLATFORMS" == "linux" || "$CLIENT_PLATFORMS" == "both" ]]; then
        client_linux_url="$(read_default "Client (Linux) binary URL" "$client_linux_default")"
      fi
      if [[ "$CLIENT_PLATFORMS" == "windows" || "$CLIENT_PLATFORMS" == "both" ]]; then
        client_win_url="$(read_default "Client (Windows) binary URL" "$client_win_default")"
      fi
    fi
    if [[ "$MODE" == "server" || "$MODE" == "both" ]]; then
      server_url="$(read_default "Server binary URL" "$server_default")"
    fi
  fi

  mkdir -p "$REPO_ROOT/bin"

  if [[ "$MODE" == "client" || "$MODE" == "both" ]]; then
    if [[ "$CLIENT_PLATFORMS" == "linux" || "$CLIENT_PLATFORMS" == "both" ]]; then
      echo "Downloading client (Linux) from: $client_linux_url"
      download_file "$client_linux_url" "$REPO_ROOT/bin/slipstream-client"
      chmod +x "$REPO_ROOT/bin/slipstream-client"
    fi
    if [[ "$CLIENT_PLATFORMS" == "windows" || "$CLIENT_PLATFORMS" == "both" ]]; then
      echo "Downloading client (Windows) from: $client_win_url"
      download_file "$client_win_url" "$REPO_ROOT/bin/slipstream-client.exe"
      chmod +x "$REPO_ROOT/bin/slipstream-client.exe" || true
    fi
  fi
  if [[ "$MODE" == "server" || "$MODE" == "both" ]]; then
    echo "Downloading server from: $server_url"
    download_file "$server_url" "$REPO_ROOT/bin/slipstream-server"
    chmod +x "$REPO_ROOT/bin/slipstream-server"
  fi

  echo ""
  echo "Downloaded binaries to: $REPO_ROOT/bin"
}

ensure_linux_build_prereqs() {
  if have_cmd meson && have_cmd cmake && have_cmd git && have_cmd pkg-config && have_cmd ninja && have_cmd python3; then
    return
  fi

  if ! have_cmd apt-get; then
    echo "This script can auto-install build deps only on apt-based distros (Debian/Ubuntu)."
    echo "Required tools: python3-pip cmake git pkg-config libssl-dev ninja-build clang (or gcc/g++) and meson."
    return
  fi

  local ans="y"
  if [[ "$NON_INTERACTIVE" -eq 0 ]]; then
    ans="$(read_yes_no "Install Linux build prerequisites using apt-get?" y)"
  fi
  [[ "$ans" == "y" ]] || fail "Build prerequisites missing. Install them and re-run."

  require_cmd sudo "sudo is required to install packages."
  sudo apt-get update
  sudo apt-get install -y python3 python3-pip cmake git pkg-config libssl-dev ninja-build clang gcc g++

  if ! have_cmd meson; then
    python3 -m pip install --user meson
    export PATH="$HOME/.local/bin:$PATH"
  fi
}

local_build() {
  local build_type="$1" # debug|release
  local opt_static="$2" # 0|1
  local opt_loglib="$3" # 0|1
  shift 3
  local targets=("$@")
  ensure_submodules
  ensure_linux_build_prereqs
  local build_dir="build"
  if [[ "$build_type" == "release" ]]; then build_dir="build-release"; fi

  local setup_args=()
  if [[ "$build_type" == "release" ]]; then
    setup_args+=(--buildtype=release -Db_lto=true --warnlevel=0)
  fi
  if [[ "$opt_static" -eq 1 ]]; then
    setup_args+=(-Ddefault_library=static)
  fi
  if [[ "$opt_loglib" -eq 1 ]]; then
    setup_args+=(-Dbuild_loglib=true)
  fi

  if [[ -d "$build_dir" ]]; then
    meson setup --reconfigure "${setup_args[@]}" "$build_dir"
  else
    meson setup "${setup_args[@]}" "$build_dir"
  fi
  if [[ "${#targets[@]}" -gt 0 ]]; then
    meson compile -C "$build_dir" "${targets[@]}"
  else
    meson compile -C "$build_dir"
  fi

  echo "Built binaries are in: $build_dir"
}

section "Choose install/run mode"
MODE="server"
if [[ "$NON_INTERACTIVE" -eq 1 ]]; then
  MODE="server"
else
  while true; do
    read -r -p "Select mode: server | client | both " MODE
    MODE="${MODE,,}"
    [[ "$MODE" == "server" || "$MODE" == "client" || "$MODE" == "both" ]] && break
    echo "Invalid mode."
  done
fi

CLIENT_PLATFORMS="linux"
if [[ "$MODE" == "client" || "$MODE" == "both" ]]; then
  section "Client platform(s)"
  if [[ "$NON_INTERACTIVE" -eq 1 ]]; then
    CLIENT_PLATFORMS="linux"
  else
    while true; do
      read -r -p "Select client platform(s): linux | windows | both " CLIENT_PLATFORMS
      CLIENT_PLATFORMS="${CLIENT_PLATFORMS,,}"
      [[ "$CLIENT_PLATFORMS" == "linux" || "$CLIENT_PLATFORMS" == "windows" || "$CLIENT_PLATFORMS" == "both" ]] && break
      echo "Invalid choice."
    done
  fi
fi

section "Slipstream Easy Installer"
HOST_OS="$(detect_os)"
echo "Detected OS: $HOST_OS"

INSTALL_METHOD="docker"
section "Choose installation method"
if [[ "$HOST_OS" == "windows" ]]; then
  INSTALL_METHOD="docker"
  echo "Windows detected. Run this script inside WSL or Git Bash."
elif [[ "$HOST_OS" == "linux" ]]; then
  if [[ "$NON_INTERACTIVE" -eq 1 ]]; then
    INSTALL_METHOD="docker"
  else
    while true; do
      read -r -p "Select install method: docker | local-build | download-binaries " INSTALL_METHOD
      INSTALL_METHOD="${INSTALL_METHOD,,}"
      [[ "$INSTALL_METHOD" == "docker" || "$INSTALL_METHOD" == "local-build" || "$INSTALL_METHOD" == "download-binaries" ]] && break
      echo "Invalid install method."
    done
  fi
else
  echo "Unsupported OS for automated setup: $HOST_OS"
  echo "You can still use Docker or build manually."
  INSTALL_METHOD="docker"
fi

section "Common configuration"
DOMAIN="test.com"
if [[ "$NON_INTERACTIVE" -eq 1 ]]; then
  DOMAIN="test.com"
else
  DOMAIN="$(read_required "Domain (e.g., test.com): ")"
fi

SERVER_IMAGE="ghcr.io/endpositive/slipstream-server:$TAG"
CLIENT_IMAGE="ghcr.io/endpositive/slipstream-client:$TAG"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CERTS_PATH="$REPO_ROOT/certs"

if [[ "$INSTALL_METHOD" == "local-build" ]]; then
  section "Local build"
  [[ "$HOST_OS" == "linux" ]] || fail "Local build is supported by this script only on Linux."

  BUILD_TYPE="release"
  if [[ "$NON_INTERACTIVE" -eq 0 ]]; then
    BUILD_TYPE="$(read_default "Build type (debug|release)" release)"
    BUILD_TYPE="${BUILD_TYPE,,}"
    [[ "$BUILD_TYPE" == "debug" || "$BUILD_TYPE" == "release" ]] || BUILD_TYPE="release"
  fi

  OPT_STATIC=0
  OPT_LOGLIB=0
  if [[ "$NON_INTERACTIVE" -eq 0 ]]; then
    static_ans="$(read_yes_no "Enable static linking (Meson: -Ddefault_library=static)?" n)"
    [[ "$static_ans" == "y" ]] && OPT_STATIC=1
    log_ans="$(read_yes_no "Enable picoquic logging library (Meson: -Dbuild_loglib=true)?" n)"
    [[ "$log_ans" == "y" ]] && OPT_LOGLIB=1
  fi

  NEED_LINUX_BUILD=1
  if [[ "$MODE" == "client" ]] && [[ "$CLIENT_PLATFORMS" == "windows" ]]; then
    NEED_LINUX_BUILD=0
  fi

  BUILD_DIR="build"
  [[ "$BUILD_TYPE" == "release" ]] && BUILD_DIR="build-release"

  if [[ "$NEED_LINUX_BUILD" -eq 1 ]]; then
    BUILD_TARGETS=()
    if [[ "$MODE" == "server" || "$MODE" == "both" ]]; then
      BUILD_TARGETS+=("slipstream-server")
    fi
    if [[ "$MODE" == "client" || "$MODE" == "both" ]]; then
      if [[ "$CLIENT_PLATFORMS" == "linux" || "$CLIENT_PLATFORMS" == "both" ]]; then
        BUILD_TARGETS+=("slipstream-client")
      fi
    fi
    local_build "$BUILD_TYPE" "$OPT_STATIC" "$OPT_LOGLIB" "${BUILD_TARGETS[@]}"
  else
    echo "Skipping Linux build: only Windows client was requested."
  fi

  if [[ "$MODE" == "server" || "$MODE" == "both" ]]; then
    section "Server setup"
    DNS_LISTEN_PORT=53
    if [[ "$NON_INTERACTIVE" -eq 0 ]]; then
      DNS_LISTEN_PORT="$(read_int "DNS listen port (recommended 53)" 53 1 65535)"
    fi
    if port_in_use udp "$DNS_LISTEN_PORT"; then
      echo "Warning: UDP port $DNS_LISTEN_PORT appears to be in use on the host."
    fi
    TARGET_ADDRESS="$(server_target_wizard)"
    echo "Selected target-address: $TARGET_ADDRESS"

    do_service="y"
    if [[ "$NON_INTERACTIVE" -eq 0 ]]; then
      do_service="$(read_yes_no "Install and start slipstream-server as a systemd service?" y)"
    fi
    if [[ "$do_service" == "y" ]]; then
      install_systemd_slipstream_server "$REPO_ROOT/$BUILD_DIR/slipstream-server" "$DOMAIN" "$TARGET_ADDRESS" "$DNS_LISTEN_PORT" 0
      print_dns_guidance "$DOMAIN"
    else
      echo "You can run manually:"
      echo "  ./$BUILD_DIR/slipstream-server --dns-listen-port=$DNS_LISTEN_PORT --domain=$DOMAIN --target-address=$TARGET_ADDRESS"
      print_dns_guidance "$DOMAIN"
    fi
  fi

  if [[ "$MODE" == "client" || "$MODE" == "both" ]]; then
    echo ""
    if [[ "$CLIENT_PLATFORMS" == "linux" || "$CLIENT_PLATFORMS" == "both" ]]; then
      if [[ "$NEED_LINUX_BUILD" -eq 1 ]]; then
        echo "Client (Linux) binary built at: ./$BUILD_DIR/slipstream-client"
        echo "Usage: ./$BUILD_DIR/slipstream-client --domain=$DOMAIN --resolver=<resolver-ip:port>"
      else
        echo "Client (Linux) was not built (Windows-only selection)."
      fi
    fi

    if [[ "$CLIENT_PLATFORMS" == "windows" || "$CLIENT_PLATFORMS" == "both" ]]; then
      REL_TAG="v0.0.1"
      WIN_ARCH="windows-x86_64.exe"
      if [[ "$NON_INTERACTIVE" -eq 0 ]]; then
        REL_TAG="$(read_default "Release tag for Windows client (e.g., v0.0.1)" "$REL_TAG")"
        WIN_ARCH="$(read_default "Windows asset suffix (e.g., windows-x86_64.exe)" "$WIN_ARCH")"
      fi
      download_windows_client_only "$REL_TAG" "$WIN_ARCH"
    fi
  fi

  echo ""
  echo "Done."
  exit 0
fi

if [[ "$INSTALL_METHOD" == "download-binaries" ]]; then
  [[ "$HOST_OS" == "linux" ]] || fail "download-binaries is supported by this script only on Linux."

  REL_TAG="v0.0.1"
  LINUX_ARCH="linux-x86_64"
  WIN_ARCH="windows-x86_64.exe"
  if [[ "$NON_INTERACTIVE" -eq 0 ]]; then
    REL_TAG="$(read_default "Release tag (e.g., v0.0.1)" "$REL_TAG")"
    LINUX_ARCH="$(read_default "Linux asset suffix (e.g., linux-x86_64)" "$LINUX_ARCH")"
    if [[ "$MODE" == "client" || "$MODE" == "both" ]]; then
      if [[ "$CLIENT_PLATFORMS" == "windows" || "$CLIENT_PLATFORMS" == "both" ]]; then
        WIN_ARCH="$(read_default "Windows asset suffix (e.g., windows-x86_64.exe)" "$WIN_ARCH")"
      fi
    fi
  fi

  download_binaries "$REL_TAG" "$LINUX_ARCH" "$WIN_ARCH"

  if [[ "$MODE" == "server" || "$MODE" == "both" ]]; then
    section "Server setup"
    DNS_LISTEN_PORT=53
    if [[ "$NON_INTERACTIVE" -eq 0 ]]; then
      DNS_LISTEN_PORT="$(read_int "DNS listen port (recommended 53)" 53 1 65535)"
    fi
    if port_in_use udp "$DNS_LISTEN_PORT"; then
      echo "Warning: UDP port $DNS_LISTEN_PORT appears to be in use on the host."
    fi
    TARGET_ADDRESS="$(server_target_wizard)"
    echo "Selected target-address: $TARGET_ADDRESS"

    do_service="y"
    if [[ "$NON_INTERACTIVE" -eq 0 ]]; then
      do_service="$(read_yes_no "Install and start slipstream-server as a systemd service?" y)"
    fi
    if [[ "$do_service" == "y" ]]; then
      install_systemd_slipstream_server "$REPO_ROOT/bin/slipstream-server" "$DOMAIN" "$TARGET_ADDRESS" "$DNS_LISTEN_PORT" 0
      print_dns_guidance "$DOMAIN"
    else
      echo "You can run manually:"
      echo "  $REPO_ROOT/bin/slipstream-server --dns-listen-port=$DNS_LISTEN_PORT --domain=$DOMAIN --target-address=$TARGET_ADDRESS"
      print_dns_guidance "$DOMAIN"
    fi
  fi

  if [[ "$MODE" == "client" || "$MODE" == "both" ]]; then
    echo ""
    if [[ "$CLIENT_PLATFORMS" == "linux" || "$CLIENT_PLATFORMS" == "both" ]]; then
      echo "Client (Linux) binary at: $REPO_ROOT/bin/slipstream-client"
      echo "Usage: $REPO_ROOT/bin/slipstream-client --domain=$DOMAIN --resolver=<resolver-ip:port>"
    fi
    if [[ "$CLIENT_PLATFORMS" == "windows" || "$CLIENT_PLATFORMS" == "both" ]]; then
      echo "Client (Windows) binary at: $REPO_ROOT/bin/slipstream-client.exe"
    fi
  fi

  echo ""
  echo "Done."
  exit 0
fi

section "Pull images"
ensure_docker

if [[ "$MODE" == "server" || "$MODE" == "both" ]]; then
  echo "Pulling $SERVER_IMAGE"
  docker pull "$SERVER_IMAGE"
fi

if [[ "$MODE" == "client" || "$MODE" == "both" ]]; then
  echo "Pulling $CLIENT_IMAGE"
  docker pull "$CLIENT_IMAGE"
fi

SERVER_ARGS=()
SERVER_PORTS=()
USE_CUSTOM_CERTS=0

CLIENT_ARGS=()
CLIENT_PORTS=()

if [[ "$MODE" == "server" || "$MODE" == "both" ]]; then
  section "Server configuration"

  DNS_LISTEN_PORT=53
  if [[ "$NON_INTERACTIVE" -eq 1 ]]; then
    DNS_LISTEN_PORT=53
  else
    DNS_LISTEN_PORT="$(read_int "DNS listen port (host and container)" 53 1 65535)"
    if [[ "$DNS_LISTEN_PORT" -eq 53 ]]; then
      echo "Note: binding to port 53 may require root and may conflict with local DNS services."
      cont="$(read_yes_no "Continue with port 53?" y)"
      if [[ "$cont" != "y" ]]; then
        DNS_LISTEN_PORT="$(read_int "DNS listen port" 8853 1 65535)"
      fi
    fi
  fi

  if port_in_use udp "$DNS_LISTEN_PORT"; then
    echo "Warning: UDP port $DNS_LISTEN_PORT appears to be in use on the host."
  fi
  if port_in_use tcp "$DNS_LISTEN_PORT"; then
    echo "Warning: TCP port $DNS_LISTEN_PORT appears to be in use on the host."
  fi

  LISTEN_IPV6=0
  if [[ "$NON_INTERACTIVE" -eq 0 ]]; then
    ipv6_ans="$(read_yes_no "Listen on IPv6?" n)"
    [[ "$ipv6_ans" == "y" ]] && LISTEN_IPV6=1
  fi

  TARGET_ADDRESS="127.0.0.1:5201"
  if [[ "$NON_INTERACTIVE" -eq 0 ]]; then
    TARGET_ADDRESS="$(read_default "Target TCP address to forward to (host:port)" "127.0.0.1:5201")"
  fi

  if [[ -d "$CERTS_PATH" ]]; then
    if [[ "$NON_INTERACTIVE" -eq 1 ]]; then
      USE_CUSTOM_CERTS=1
    else
      cert_ans="$(read_yes_no "Mount ./certs into container and use certs/cert.pem + certs/key.pem?" y)"
      [[ "$cert_ans" == "y" ]] && USE_CUSTOM_CERTS=1
    fi
  else
    echo "certs/ directory not found at: $CERTS_PATH"
    echo "Server will use container defaults (may fail if certs are required)."
  fi

  SERVER_ARGS+=("--domain=$DOMAIN")
  SERVER_ARGS+=("--target-address=$TARGET_ADDRESS")
  SERVER_ARGS+=("--dns-listen-port=$DNS_LISTEN_PORT")
  [[ "$LISTEN_IPV6" -eq 1 ]] && SERVER_ARGS+=("--dns-listen-ipv6")

  if [[ "$USE_CUSTOM_CERTS" -eq 1 ]]; then
    SERVER_ARGS+=("--cert=certs/cert.pem")
    SERVER_ARGS+=("--key=certs/key.pem")
  fi

  SERVER_PORTS+=("$DNS_LISTEN_PORT:$DNS_LISTEN_PORT")
fi

if [[ "$MODE" == "client" || "$MODE" == "both" ]]; then
  section "Client configuration"

  TCP_LISTEN_PORT=5201
  if [[ "$NON_INTERACTIVE" -eq 0 ]]; then
    TCP_LISTEN_PORT="$(read_int "TCP listen port on client (host and container)" 5201 1 65535)"
  fi

  RESOLVERS=()
  if [[ "$NON_INTERACTIVE" -eq 1 ]]; then
    RESOLVERS+=("1.1.1.1:53")
  else
    echo "Resolver address(es). Examples: 1.1.1.1, 8.8.8.8:53, 127.0.0.1:8853, [2001:db8::1]:53"
    while true; do
      r=""
      read -r -p "Enter resolver (leave empty to finish): " r
      if [[ -z "${r// }" ]]; then
        if [[ "${#RESOLVERS[@]}" -ge 1 ]]; then
          break
        fi
        echo "At least one resolver is required."
        continue
      fi
      RESOLVERS+=("$r")
      more="$(read_yes_no "Add another resolver?" n)"
      [[ "$more" == "y" ]] || break
    done
  fi

  [[ "${#RESOLVERS[@]}" -ge 1 ]] || fail "At least one resolver is required for client (--resolver)."

  CC="dcubic"
  GSO=0
  KEEP_ALIVE=400

  if [[ "$NON_INTERACTIVE" -eq 0 ]]; then
    CC="$(read_default "Congestion control (bbr|dcubic)" dcubic)"
    CC="${CC,,}"
    [[ "$CC" == "bbr" || "$CC" == "dcubic" ]] || CC="dcubic"

    gso_ans="$(read_yes_no "Enable GSO?" n)"
    [[ "$gso_ans" == "y" ]] && GSO=1

    KEEP_ALIVE="$(read_int "Keep alive interval (0 disables)" 400 0 1000000)"
  fi

  CLIENT_ARGS+=("--domain=$DOMAIN")
  CLIENT_ARGS+=("--tcp-listen-port=$TCP_LISTEN_PORT")
  CLIENT_ARGS+=("--congestion-control=$CC")
  CLIENT_ARGS+=("--keep-alive-interval=$KEEP_ALIVE")
  [[ "$GSO" -eq 1 ]] && CLIENT_ARGS+=("--gso")

  for r in "${RESOLVERS[@]}"; do
    CLIENT_ARGS+=("--resolver=$r")
  done

  CLIENT_PORTS+=("$TCP_LISTEN_PORT:$TCP_LISTEN_PORT")
fi

section "Run containers"
STARTED=()

if [[ "$MODE" == "server" || "$MODE" == "both" ]]; then
  SERVER_CMD=(docker run --rm --name slipstream-server)

  PUBLISH_TCP_DNS=0
  if [[ "$NON_INTERACTIVE" -eq 0 ]]; then
    tcp_dns_ans="$(read_yes_no "Also publish DNS over TCP on the same port?" n)"
    [[ "$tcp_dns_ans" == "y" ]] && PUBLISH_TCP_DNS=1
  fi

  for p in "${SERVER_PORTS[@]}"; do
    SERVER_CMD+=(-p "$p/udp")
    [[ "$PUBLISH_TCP_DNS" -eq 1 ]] && SERVER_CMD+=(-p "$p/tcp")
  done
  if [[ "$USE_CUSTOM_CERTS" -eq 1 ]]; then
    SERVER_CMD+=(-v "$CERTS_PATH:/usr/src/app/certs:ro")
  fi
  SERVER_CMD+=("$SERVER_IMAGE")
  SERVER_CMD+=("${SERVER_ARGS[@]}")

  echo "Server command:"
  printf ' %q' "${SERVER_CMD[@]}"; echo

  if [[ "$NON_INTERACTIVE" -eq 0 ]]; then
    run_now="$(read_yes_no "Start server now?" y)"
    if [[ "$run_now" == "y" ]]; then
      "${SERVER_CMD[@]}"
      STARTED+=("server")
    fi
  fi
fi

if [[ "$MODE" == "client" || "$MODE" == "both" ]]; then
  CLIENT_CMD=(docker run --rm --name slipstream-client)
  for p in "${CLIENT_PORTS[@]}"; do CLIENT_CMD+=(-p "$p"); done
  CLIENT_CMD+=("$CLIENT_IMAGE")
  CLIENT_CMD+=("${CLIENT_ARGS[@]}")

  echo "Client command:"
  printf ' %q' "${CLIENT_CMD[@]}"; echo

  if [[ "$NON_INTERACTIVE" -eq 0 ]]; then
    run_now="$(read_yes_no "Start client now?" y)"
    if [[ "$run_now" == "y" ]]; then
      "${CLIENT_CMD[@]}"
      STARTED+=("client")
    fi
  fi
fi

section "Result"
echo "Selected mode: $MODE"
echo "Domain: $DOMAIN"
echo "Image tag: $TAG"
if [[ "${#STARTED[@]}" -gt 0 ]]; then
  echo "Started: ${STARTED[*]}"
else
  echo "Nothing was started automatically. Use the commands shown above to run."
fi

echo ""
echo "Done."
