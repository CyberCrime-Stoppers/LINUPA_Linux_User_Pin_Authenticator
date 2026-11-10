#! /bin/bash

#!/usr/bin/env bash
#===============================================================================
#  LINUPA.sh - Linux Fingerprint Reader & Driver Finder
#  Part of the CyberCrime-Stoppers toolset (L3DPS.sh)

#
#  Purpose:
#    1) Detect fingerprint readers/hardware on this Linux machine
#       (USB IDs, kernel drivers, loaded modules)
#    2) Check which fingerprint drivers exist on your personal domain
#    3) Optionally download + verify (sha256) a matching driver package
#
#  Author: Scott Dev (CyberCrime-Stoppers)
#  License: GPL-3.0-or-later
#===============================================================================

#-------------------------------------------------------------------------------
# CONFIG - EDIT THESE
#-------------------------------------------------------------------------------
# Your personal domain hosting LINUPA driver packages.
# Layout expected on the server (adjust DRIVER_PATH if you store elsewhere):
#   https://ld-sos.unixinbox.com/linupa/drivers/<distro>/<pkg-name>.<ext>
#   https://ld-sos.unixinbox.com/linupa/drivers/<distro>/SHA256SUMS
DOWNLOAD_DOMAIN="verified-drivers.unixinbox.com"        # Verification and trusted drivers
DRIVER_PATH="/linupa/drivers"   # path relative to domain
VERIFY_CHECKSUMS="yes"      # yes/no - verify SHA256SUMS after download
DOWNLOAD_DIR="$HOME/linupa-downloads"
LOG_FILE="$HOME/.local/share/linupa/linupa.log"

#-------------------------------------------------------------------------------
# Constants / helpers
#-------------------------------------------------------------------------------
readonly SCRIPT_NAME="$(basename "${BASH_SOURCE[0]}")"
readonly VERSION="0.1.0"

log()   { printf '[INFO] linupa: %s\n' "$*" | tee -a "$LOG_FILE" >&2; }
warn()  { printf '[WARN] linupa: %s\n' "$*" | tee -a "$LOG_FILE" >&2; }
err()   { printf '[ERROR] linupa: %s\n' "$*" | tee -a "$LOG_FILE" >&2; }
die()   { err "$*"; exit 1; }

usage() {
  cat <<EOF
LINUPA v$VERSION - Linux Fingerprint Reader & Driver Finder

Usage:
  $SCRIPT_NAME [OPTIONS]

Options:
  -h, --help        Show this help message
  -s, --scan        Scan for fingerprint readers (default if no option given)
  -c, --check       Check available drivers on DOWNLOAD_DOMAIN
  -d, --download    Download matching driver package from DOWNLOAD_DOMAIN
  -a, --all         Do scan + check + interactive download prompt
  -j, --json        Output scan results in JSON (for piping into PDUA later)
  -q, --quiet       Suppress [INFO] logs, only show results

Examples:
  $SCRIPT_NAME              # quick hardware scan
  $SCRIPT_NAME --all        # full flow: scan, check domain, offer download
  $SCRIPT_NAME -j           # machine-readable scan output
EOF
}

#-------------------------------------------------------------------------------
# Dependency check
#-------------------------------------------------------------------------------
need_tool() {
  if ! command -v "$1" &>/dev/null; then
    warn "Missing tool: '$1' - $2"
    MISSING_TOOLS+=("$1")
    return 1
  fi
  return 0
}

MISSING_TOOLS=()
check_deps() {
  need_tool lsusb   "install: usbutils (needed for USB device detection)"
  need_tool lspci   "install: pciutils (optional, PCI device detection)"
  need_tool modprobe "install: kmod (kernel module checks)"
  need_tool curl    "install: curl (domain connectivity check)"

  if [ ${#MISSING_TOOLS[@]} -gt 0 ]; then
    warn "Some features will be skipped due to missing tools."
  fi
}

#-------------------------------------------------------------------------------
# Step 1: Hardware detection
#-------------------------------------------------------------------------------

# Known fingerprint reader vendors (Linux community reference list)
# source: libfprint / fprint.freedesktop.org supported-devices data
KNOWN_VENDORS=(
  "0483:"  # STMicroelectronics (many OEM sensors)
  "06cb:"  # Synaptics
  "138a:"  # Validity Sensors
  "1c7a:"  # LighTuning (EgisTec)
  "045e:"  # Microsoft (some USB sensors)
  "0bda:"  # Realtek
  "10a5:"  # Bluestaron / Biomini style
  "1b55:"  # Protouch
  "2508:"  # FocalTech style IDs seen on laptops
  "3423:"  # Goodix vendor block
  "27c6:"  # Shenzhen Goodix Technology
  "1a40:"  # Terminus hubs (sometimes includes sensors)
  "147e:"  # Upek
  "08ff:"  # AuthenTec
  "04f3:"  # Elan Microelectronics
)

# Return 0 if arg matches any known vendor prefix
is_known_fingerprint_vendor() {
  local vid_lower="${1,,}"
  for v in "${KNOWN_VENDORS[@]}"; do
    if [[ "$vid_lower" == "${v,,}"* ]]; then
      return 0
    fi
  done
  return 1
}

scan_usb_readers() {
  log "Scanning USB bus for fingerprint readers..."
  local found=()

  if ! command -v lsusb &>/dev/null; then
    warn "lsusb not available, skipping USB scan."
    echo "$found"
    return
  fi

  while IFS= read -r line; do
    # typical lsusb line:  "Bus 001 Device 003: ID 06cb:009a Synaptics, Inc."
    local id vendor_desc
    id=$(echo "$line" | awk '{print $6}')
    vendor_desc=$(echo "$line" | cut -d':' -f3- | sed 's/^ //')
    [ -z "$id" ] && continue

    local vid="${id%%:*}"

    # Heuristic 1: known biometric vendor prefixes
    if is_known_fingerprint_vendor "$vid"; then
      found+=("$id|$vendor_desc|known-vendor")
    fi
  done < <(lsusb 2>/dev/null)

  printf '%s\n' "${found[@]}"
}

scan_pci_candidates() {
  log "Scanning PCI bus for biometric-class devices (rare)..."

  if ! command -v lspci &>/dev/null; then
    warn "lspci not available, skipping PCI scan."
    return
  fi

  # Look for anything explicitly labelled biometric
  lspci 2>/dev/null | grep -iE 'biometric|finger' || true
}

get_udev_driver_for_devnode() {
  # Query udev to see which kernel driver a sysfs path is bound to
  local devpath="$1"
  [ -z "$devpath" ] && return 1
  udevadm info --query=all --path="$devpath" 2>/dev/null | grep '^E: DRIVER=' | head -n1
}

list_libfprint_devices() {
  # Try to query libfprint's supported device list via fprintd-list (best effort)
  if command -v fprintd-list &>/dev/null; then
    log "Querying fprintd for enrolled/known devices..."
    fprintd-list "$USER" 2>/dev/null || true
  else
    warn "fprintd-list not found - install 'fprintd' and 'libfprint' for full driver support."
  fi
}

check_kernel_modules() {
  log "Checking for loaded fingerprint-related kernel modules..."
  local mods=(
    "fingerprint"
    "uinput"
    "hid_sensor_custom"
    "elan_i2c"
    "wacom_i2c"
  )
  for m in "${mods[@]}"; do
    if lsmod 2>/dev/null | grep -qw "^${m}"; then
      log "Loaded kernel module: $m"
    fi
  done
}

#-------------------------------------------------------------------------------
# Step 2: Domain check
#-------------------------------------------------------------------------------
build_base_url() {
  [ -n "$DOWNLOAD_DOMAIN" ] || return 1
  # Trim trailing slash on domain, ensure DRIVER_PATH starts with /
  local base="${DOWNLOAD_DOMAIN%/}"
  local path="${DRIVER_PATH#/}"
  printf '%s/%s' "$base" "$path"
}

check_domain_drivers() {
  local base_url
  base_url=$(build_base_url) || die "DOWNLOAD_DOMAIN is not set - edit the CONFIG block at top of $SCRIPT_NAME"

  log "Checking domain for driver index: $base_url"
  if ! curl -fsSL --head --max-time 10 "$base_url/" >/dev/null 2>&1; then
    warn "Could not reach $base_url - check domain, DNS, or firewall (Portmaster/UFW rules?)."
    return 1
  fi

  # If an index.html or SHA256SUMS is served, show available driver files
  local sums_url="$base_url/SHA256SUMS"
  log "Fetching checksum index: $sums_url"
  local sums_content
  if sums_content=$(curl -fsSL --max-time 15 "$sums_url" 2>/dev/null); then
    log "Found SHA256SUMS, listing available driver packages:"
    echo "---- SHA256SUMS ----"
    echo "$sums_content"
    echo "--------------------"
  else
    warn "No SHA256SUMS at $sums_url"
  fi
}

#-------------------------------------------------------------------------------
# Step 3: Download + verify
#-------------------------------------------------------------------------------
verify_checksums() {
  local file="$1"
  local dir
  dir="$(dirname "$file")"
  local sums_file="$dir/SHA256SUMS"

  if [ ! -f "$sums_file" ]; then
    warn "No SHA256SUMS found next to $file - skipping verification (VERIFY_CHECKSUMS=$VERIFY_CHECKSUMS)"
    return 0
  fi
  log "Verifying $(basename "$file") against SHA256SUMS..."
  if (cd "$dir" && sha256sum --check --strict "$(basename "$sums_file")"); then
    log "Checksum OK."
    return 0
  else
    err "Checksum MISMATCH for $(basename "$file") - do NOT trust this binary."
    return 1
  fi
}

download_driver() {
  local pkg_name="$1"
  local base_url
  base_url=$(build_base_url) || die "DOWNLOAD_DOMAIN is not set."

  local distro="generic"
  if command -v lsb_release &>/dev/null; then
    distro=$(lsb_release -is | tr '[:upper:]' '[:lower:]')
  elif [ -f /etc/os-release ]; then
    distro=$(. /etc/os-release; echo "$ID")
  fi

  local url="$base_url/$distro/$pkg_name"
  mkdir -p "$DOWNLOAD_DIR"

  log "Downloading $url -> $DOWNLOAD_DIR/"
  if ! curl -fSL --max-time 300 -o "$DOWNLOAD_DIR/$(basename "$pkg_name")" "$url"; then
    err "Download failed: $url"
    return 1
  fi

  # Fetch checksum index for verification
  if [ "$VERIFY_CHECKSUMS" = "yes" ]; then
    curl -fsSL --max-time 15 -o "$DOWNLOAD_DIR/SHA256SUMS" "$base_url/$distro/SHA256SUMS" 2>/dev/null \
      || warn "Could not fetch SHA256SUMS - install verification will be skipped."
    verify_checksums "$DOWNLOAD_DIR/$(basename "$pkg_name")" || return 1
  fi

  log "Driver package saved to: $DOWNLOAD_DIR/$(basename "$pkg_name")"
  log "Install manually (dpkg -i / rpm -U / make install) depending on package format."
}

#-------------------------------------------------------------------------------
# Step 4: Combined flow
#-------------------------------------------------------------------------------
run_full_flow() {
  echo "==============================================="
  echo " LINUPA - Linux Fingerprint Reader & Driver"
  echo " v$VERSION - CyberCrime-Stoppers"
  echo "==============================================="

  check_deps

  echo
  echo "--- [1/4] Hardware Scan ---"
  local readers=()
  mapfile -t readers < <(scan_usb_readers)

  if [ ${#readers[@]} -eq 0 ]; then
    warn "No known fingerprint reader detected over USB."
    echo "Tips:"
    echo "  * Run 'lsusb' manually to view all USB devices"
    echo "  * Some laptop sensors hide behind hubs or use I2C, try 'lspci'"
    echo "  * Sensor may be disabled in BIOS/UEFI"
  else
    echo "Detected possible fingerprint reader(s):"
    for r in "${readers[@]}"; do
      IFS='|' read -r id desc tag <<<"$r"
      echo "  [$tag] USB $id - $desc"
    done
  fi

  echo
  scan_pci_candidates
  echo
  check_kernel_modules
  echo
  list_libfprint_devices

  echo
  echo "--- [2/4] Domain Check ---"
  if [ -n "$DOWNLOAD_DOMAIN" ]; then
    check_domain_drivers || true
  else
    warn "DOWNLOAD_DOMAIN not configured in $SCRIPT_NAME - edit CONFIG block at top."
  fi

  echo
  echo "--- [3/4] Summary ---"
  if [ ${#readers[@]} -gt 0 ]; then
    echo "Fingerprint hardware found: ${#readers[@]}"
    if [ -n "$DOWNLOAD_DOMAIN" ]; then
      echo "Domain: $DOWNLOAD_DOMAIN$DRIVER_PATH"
    fi
  else
    echo "No fingerprint hardware detected - nothing to install."
  fi

  echo
  echo "--- [4/4] Optional Download ---"
  if [ -n "$DOWNLOAD_DOMAIN" ] && [ ${#readers[@]} -gt 0 ]; then
    IFS='|' read -r vid pid _ <<<"${readers[0]}"
    echo "Reader vendor ID: $vid  Product ID: $pid"
    read -rp "Enter a driver package filename from SHA256SUMS to download (blank to skip): " pkg
    if [ -n "$pkg" ]; then
      download_driver "$pkg"
    else
      log "Skipping download."
    fi
  fi

  log "LINUPA scan complete. Log saved to $LOG_FILE"
}

#-------------------------------------------------------------------------------
# Argument parsing
#-------------------------------------------------------------------------------
QUIET=false
JSON_MODE=false
ACTION="scan"

while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help)     usage; exit 0 ;;
    -s|--scan)     ACTION="scan" ;;
    -c|--check)    ACTION="check" ;;
    -d|--download) ACTION="download" ;;
    -a|--all)      ACTION="all" ;;
    -j|--json)     JSON_MODE=true ;;
    -q|--quiet)    QUIET=true ;;
    *)             err "Unknown option: $1"; usage; exit 1 ;;
  esac
  shift
done

mkdir -p "$(dirname "$LOG_FILE")"
touch "$LOG_FILE"

case "$ACTION" in
  scan)
    check_deps
    if [ "$JSON_MODE" = "true" ]; then
      # emit minimal JSON - easy for PDUA to consume later
      echo "{\"tool\":\"linupa\",\"version\":\"$VERSION\",\"readers\":["
      first=true
      while IFS= read -r line; do
        [ -z "$line" ] && continue
        IFS='|' read -r id desc tag <<<"$line"
        $first && first=false || echo ","
        printf '{"usb_id":"%s","description":"%s","match":"%s"}' "$id" "$desc" "$tag"
      done < <(scan_usb_readers)
      echo "]}"
    else
      scan_usb_readers
      scan_pci_candidates
      check_kernel_modules
      list_libfprint_devices
    fi
    ;;
  check)   check_domain_drivers ;;
  download)
    read -rp "Driver package filename to download: " pkg
    [ -n "$pkg" ] && download_driver "$pkg" || die "No package given."
    ;;
  all)     run_full_flow ;;
esac


