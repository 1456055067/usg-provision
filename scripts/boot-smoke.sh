#!/usr/bin/env bash
# M1 boot smoke harness (plan WU-11, section 10.5): QEMU x86-64 + OVMF
# network-boots the test payload from the real usgp-relay binary.
#
# Usage:
#   scripts/boot-smoke.sh build                       # as the normal user
#   sudo -E scripts/boot-smoke.sh all                 # Linux, as root
#   scripts/boot-smoke.sh <preflight|payload-disk|S1..S8|all> [more ...]
#
# `build` (never as root) builds the release relay and cli (FIPS build), the
# netlab tools (release) and both payload builds, and stages the payloads in
# target/boot-smoke/stage/. Every other subcommand only uses those artifacts.
#
# Linux needs root. The harness builds one bridge namespace (usgp-lab) and
# one namespace per role (usgp-relay, usgp-site, usgp-router, usgp-probe);
# see testing/boot-smoke/topology.md. Services run as uid 65534 through
# setpriv with only the ambient capabilities net_bind_service and net_raw;
# QEMU runs as $SUDO_USER (or USGP_QEMU_USER) on taps owned by that user.
# KVM is used when that user can open /dev/kvm, TCG otherwise.
#
# Darwin runs only `payload-disk` (Homebrew OVMF, QEMU fat: disk). Every
# network scenario prints NOT RUN with the plan section 0 reasons.
#
# Result rules: each scenario prints PASS, FAIL or NOT RUN with evidence
# lines. A missing prerequisite, or firmware without a PXE stack, is NOT RUN,
# never PASS or FAIL. Exit status: 0 every requested scenario passed; 1 any
# FAIL (or a preflight FAIL); 77 nothing failed but something was NOT RUN;
# 2 usage error. Callers must treat 77 as NOT RUN, never as PASS.
#
# Environment (all optional):
#   USGP_OVMF_CODE, USGP_OVMF_VARS          normal firmware (Ubuntu ovmf
#                                           defaults; Homebrew on Darwin)
#   USGP_OVMF_SB_CODE, USGP_OVMF_SB_VARS    Secure Boot firmware, keys enrolled
#   USGP_RELAY_BIN, USGP_CLI_BIN            default target/release/...
#   USGP_NETLAB_BIN_DIR                     default target/testing/netlab/release
#   USGP_PAYLOAD_EFI, USGP_DISK_EFI         default target/boot-smoke/stage/...
#   USGP_BOOT_SMOKE_OUT                     evidence directory (default
#                                           target/boot-smoke/run-<UTC time>)
#   USGP_QEMU_USER                          user for QEMU (default $SUDO_USER)
#   USGP_ACCEL                              kvm or tcg (default: detect)
#   USGP_BOOT_DEADLINE                      seconds per boot (120 KVM, 300 TCG)
#   USGP_FALLTHROUGH_DEADLINE               seconds for a boot that must fall
#                                           through to the disk (S6, S7;
#                                           default 2 x boot deadline + 180)
#   USGP_PREFLIGHT_DEADLINE                 PXE check seconds (60 KVM, 150 TCG)
#   USGP_SB_REFUSAL_PATTERN                 optional extended regex; a serial
#                                           line matching it also counts as
#                                           the firmware's refusal in S5
#
# COMPLIANCE MAPPING:
# - NIST 800-53: SA-11 (Developer Testing and Evaluation), CA-2, SI-7, SC-5,
#   SC-7, CM-7, AC-6 (services run unprivileged)
# - SPEC: specs/boot-network.md#REQ-BOOT-001..006, 010..012, 020..022,
#   030, 031, 034, 040..042, 044, 050, 051, 060, 070 (scenarios S1 to S8)
# - specs/standards/uefi-boot-manager.md §5, uefi-secure-boot.md §5 (S5:
#   a refused image makes the boot manager move on to the next option)
set -uo pipefail
umask 022

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root" || exit 2

EXIT_NOT_RUN=77
MARK_NET="USGP-M1-PAYLOAD-OK"
MARK_DISK="USGP-M1-DISK-FALLBACK-OK"
PAYLOAD_NAME="usgp-test-payload.efi"
HOST_OS="$(uname -s)"
TARGET_DIR="${CARGO_TARGET_DIR:-$root/target}"
STAGE_DIR="$root/target/boot-smoke/stage"

RELAY_BIN="${USGP_RELAY_BIN:-$TARGET_DIR/release/usgp-relay}"
CLI_BIN="${USGP_CLI_BIN:-$TARGET_DIR/release/usgp-cli}"
NETLAB_DIR="${USGP_NETLAB_BIN_DIR:-$root/target/testing/netlab/release}"
PAYLOAD_EFI="${USGP_PAYLOAD_EFI:-$STAGE_DIR/$PAYLOAD_NAME}"
DISK_EFI="${USGP_DISK_EFI:-$STAGE_DIR/disk-fallback.efi}"

# Lab topology (testing/boot-smoke/topology.md).
NS_LAB=usgp-lab
NS_RELAY=usgp-relay
NS_SITE=usgp-site
NS_ROUTER=usgp-router
NS_PROBE=usgp-probe
NAMESPACES=("$NS_LAB" "$NS_RELAY" "$NS_SITE" "$NS_ROUTER" "$NS_PROBE")
RELAY_ADDR=10.20.1.2
SITE_ADDR=10.20.1.3
ROUTER_A=10.20.1.1
ROUTER_B=10.20.2.1
PROBE_ADDR=10.20.1.9
UNCONF_RELAY_ADDR=10.20.9.2
UNCONF_PROBE_ADDR=10.20.9.9
# The relay's event detail is a JSON string inside the JSON line, so its
# quotes appear escaped. This token matches only the yiaddr detail field.
YIADDR0='yiaddr\":\"0.0.0.0'

# Relay limits written into the lab config; S4 dhcp-rate bounds use them.
LIM_CLIENT_BURST=8
LIM_CLIENT_REFILL_MS=2000
RECHECK_SECS=5
RELOAD_SECS=2
SUMMARY_SECS=60 # usgp-relay SUMMARY_INTERVAL (fixed, not configurable)

# State.
OUT=""
LAB=""
CLEANED=0
PIDS=()
RES_IDS=()
RES_STATUS=()
RES_REASON=()
EVID=()
SC_FAIL=0
PREFLIGHT_STATUS="" # OK | NOT RUN | FAIL
PREFLIGHT_REASON=""
PREFLIGHT_DEADLINE=0
OVMF_CODE=""
OVMF_VARS=""
OVMF_SB_CODE=""
OVMF_SB_VARS=""
BG_PID=""
SB_REASON=""
RELAY_PID=""
RELAY_STARTTIME=""
DHCPD_PID=""
AGENT_PID=""
CONTENT_BROKEN=""
ACCEL=""
BASE_DEADLINE=0
LONG_DEADLINE=0
FALL_DEADLINE=0
QEMU_USER=""
QEMU_UID=""
QEMU_GID=""
VM_PID=""
VM_SERIAL=""
FIN_PATH=""
RELAY_LOG=""
DHCPD_LOG=""
AGENT_LOG=""
DROP=(setpriv --reuid=65534 --regid=65534 --clear-groups
  "--inh-caps=-all,+net_bind_service,+net_raw"
  "--ambient-caps=-all,+net_bind_service,+net_raw"
  "--bounding-set=-all,+net_bind_service,+net_raw"
  --no-new-privs)
P_REL=(--iface p0 --local "$PROBE_ADDR" --server "$RELAY_ADDR")
# Fall-through guests (S5, S6, S7) run with the firmware's IPv6 network
# stack switched off through this fw_cfg item, so after IPv4 PXE the only
# network option left on a NIC is IPv4 HTTP boot and the next NIC or the
# disk follows. Checked against Ubuntu 24.04 ovmf 2024.02-2ubuntu0.10
# (OVMF_CODE_4M.fd and OVMF_CODE_4M.secboot.fd, the hashes recorded in
# environment.txt): the item name is in the firmware, and a guest started
# with it tries PXEv4, HTTPv4, then the disk instead of PXEv4, PXEv6,
# HTTPv4, HTTPv6, then the disk (each failed network option costs about
# 60 s of firmware timeouts). Firmware without the item ignores it; the
# fall-through deadline still covers the full sequence.
FW_IPV6_OFF="name=opt/org.tianocore/IPv6Support,string=no"
# OVMF serial line for a failed IPv4 PXE boot option.
PXE4_FAIL_RE='failed to load Boot[0-9A-Fa-f]+ "UEFI PXEv4'

usage() {
  sed -n '2,8p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
}

# ------------------------------------------------------------ utilities --

# Matching rule: `grep -q` never reads from a pipe in this script. Under
# `set -o pipefail`, grep exiting on the first match can kill the producer
# with SIGPIPE and turn a match into a failure; outputs are captured first
# and matched through here-strings instead.

say() { printf '%s\n' "$*"; }
progress() { printf 'boot-smoke: %s\n' "$*" >&2; }
now() { date +%s; }

lines() {
  if [ -f "$1" ]; then
    wc -l < "$1" | tr -d ' '
  else
    echo 0
  fi
}

# Lines of file $1 after the first $2 lines.
since() {
  [ -f "$1" ] || return 0
  tail -n +"$(($2 + 1))" "$1"
}

sha256_of() {
  if command -v sha256sum > /dev/null 2>&1; then
    sha256sum "$1" | cut -d ' ' -f 1
  else
    shasum -a 256 "$1" | cut -d ' ' -f 1
  fi
}

serial_has() {
  [ -f "$1" ] && grep -a -q -F -- "$2" "$1"
}

# Keeps only stdin lines containing every fixed-string token; status 1 if
# nothing is left.
filter_tokens() {
  local data
  data="$(cat)"
  local t
  for t in "$@"; do
    data="$(printf '%s\n' "$data" | grep -F -- "$t")"
  done
  [ -n "$data" ] || return 1
  printf '%s\n' "$data"
}

# Relay JSON lines (after line $1) whose event is $2 and that contain every
# further token. Prints the lines; status 1 if none.
relay_find() {
  local off="$1" ev="$2"
  shift 2
  # serde_json writes compact JSON: "event":"<name>".
  since "$RELAY_LOG" "$off" | grep -F -- "\"event\":\"$ev\"" | filter_tokens "$@"
}

# Lease address lab-dhcpd ACKed to MAC $2 after line $1 (empty if none).
dhcpd_lease_ip() {
  since "$DHCPD_LOG" "$1" | grep -F 'event=ack' | grep -F "chaddr=$2" | tail -n 1 |
    sed -n 's/.* yiaddr=\([0-9.]*\).*/\1/p'
}

# A DISCOVER from MAC $2 with the UEFI x86-64 PXE vendor class, after line $1.
dhcpd_pxe_discover() {
  since "$DHCPD_LOG" "$1" | grep -F 'event=discover' | grep -F "chaddr=$2" |
    grep -F 'PXEClient:Arch:00007' | sed -n 1p | grep .
}

short() {
  local s="$1"
  if [ "${#s}" -gt 320 ]; then
    printf '%s...' "${s:0:320}"
  else
    printf '%s' "$s"
  fi
}

# ------------------------------------------------------------- results --

evidence() { EVID+=("$*"); }

# note <status> <description>: a pass condition; status 0 means it held.
note() {
  local st="$1"
  shift
  if [ "$st" -eq 0 ]; then
    evidence "ok: $*"
  else
    evidence "FAILED: $*"
    SC_FAIL=1
  fi
}

# note_absent <status> <description>: a pass condition that holds when the
# check it follows found nothing (non-zero status).
note_absent() {
  local st="$1"
  shift
  if [ "$st" -eq 0 ]; then
    note 1 "$@"
  else
    note 0 "$@"
  fi
}

begin() {
  EVID=()
  SC_FAIL=0
  progress "running $1"
}

record() {
  local id="$1" status="$2" reason="$3" e
  RES_IDS+=("$id")
  RES_STATUS+=("$status")
  RES_REASON+=("$reason")
  say "[$id] $status: $reason"
  for e in ${EVID[@]+"${EVID[@]}"}; do
    say "    evidence: $e"
  done
  if [ -n "$OUT" ] && [ -d "$OUT" ]; then
    {
      say "[$id] $status: $reason"
      for e in ${EVID[@]+"${EVID[@]}"}; do
        say "    evidence: $e"
      done
    } >> "$OUT/results.txt"
  fi
  EVID=()
  SC_FAIL=0
}

finish() {
  local id="$1" what="$2"
  if [ "$SC_FAIL" -eq 0 ]; then
    record "$id" PASS "$what"
  else
    record "$id" FAIL "$what"
  fi
}

result_of() {
  local i=0
  while [ "$i" -lt "${#RES_IDS[@]}" ]; do
    if [ "${RES_IDS[$i]}" = "$1" ]; then
      printf '%s' "${RES_STATUS[$i]}"
      return 0
    fi
    i=$((i + 1))
  done
  return 1
}

summary() {
  local pass=0 fail=0 notrun=0 i=0
  say ""
  say "boot-smoke summary (host $HOST_OS${ACCEL:+, accel $ACCEL}${OUT:+, evidence $OUT}):"
  if [ -n "$PREFLIGHT_STATUS" ]; then
    say "  preflight     $PREFLIGHT_STATUS${PREFLIGHT_REASON:+ ($PREFLIGHT_REASON)}"
  fi
  while [ "$i" -lt "${#RES_IDS[@]}" ]; do
    printf '  %-13s %-8s %s\n' "${RES_IDS[$i]}" "${RES_STATUS[$i]}" "${RES_REASON[$i]}"
    case "${RES_STATUS[$i]}" in
      PASS) pass=$((pass + 1)) ;;
      FAIL) fail=$((fail + 1)) ;;
      *) notrun=$((notrun + 1)) ;;
    esac
    i=$((i + 1))
  done
  say "  totals: pass=$pass fail=$fail not_run=$notrun"
  if [ -n "$OUT" ] && [ -d "$OUT" ]; then
    {
      say "pass=$pass fail=$fail not_run=$notrun"
      say "preflight=$PREFLIGHT_STATUS"
    } > "$OUT/summary.txt"
  fi
  if [ "$fail" -gt 0 ] || [ "$PREFLIGHT_STATUS" = FAIL ]; then
    return 1
  fi
  if [ "$notrun" -gt 0 ] || [ "$pass" -eq 0 ]; then
    return "$EXIT_NOT_RUN"
  fi
  return 0
}

# ------------------------------------------------------------- cleanup --

stop_pid() {
  local pid="$1" n=0
  [ -n "$pid" ] || return 0
  kill -TERM "$pid" 2> /dev/null || return 0
  while kill -0 "$pid" 2> /dev/null && [ "$n" -lt 10 ]; do
    sleep 0.5
    n=$((n + 1))
  done
  kill -KILL "$pid" 2> /dev/null || true
  wait "$pid" 2> /dev/null || true
}

cleanup() {
  [ "$CLEANED" -eq 1 ] && return 0
  CLEANED=1
  local pid
  for pid in ${PIDS[@]+"${PIDS[@]}"}; do
    kill -TERM "$pid" 2> /dev/null || true
  done
  sleep 1
  for pid in ${PIDS[@]+"${PIDS[@]}"}; do
    kill -KILL "$pid" 2> /dev/null || true
  done
  if [ "$HOST_OS" = Linux ] && [ "$(id -u)" -eq 0 ]; then
    local ns
    for ns in "${NAMESPACES[@]}"; do
      if grep -q -w -- "$ns" <<< "$(ip netns list 2> /dev/null)"; then
        ip netns pids "$ns" 2> /dev/null | xargs -r kill -KILL 2> /dev/null || true
        ip netns delete "$ns" 2> /dev/null || true
      fi
    done
  fi
  if [ -n "$LAB" ] && [ -d "$LAB" ]; then
    if [ -d "$LAB/vm" ] && [ -n "$OUT" ] && [ -d "$OUT" ]; then
      mkdir -p "$OUT/vm"
      cp -p "$LAB"/vm/*.qemu.log "$OUT/vm/" 2> /dev/null || true
    fi
    case "$LAB" in
      */usgp-boot-smoke.*) rm -rf -- "$LAB" ;;
    esac
  fi
  if [ -n "$OUT" ] && [ -d "$OUT" ] && [ "$(id -u)" -eq 0 ] && [ -n "${SUDO_USER:-}" ]; then
    chown -R "$SUDO_USER" "$OUT" 2> /dev/null || true
  fi
}

trap 'cleanup' EXIT
trap 'progress "interrupted"; cleanup; exit 130' INT
trap 'progress "terminated"; cleanup; exit 143' TERM

# --------------------------------------------------------------- build --

do_build() {
  if [ "$(id -u)" -eq 0 ]; then
    say "boot-smoke: run 'build' as the normal user, not root (root-owned build output)" >&2
    return 2
  fi
  set -e
  mkdir -p "$STAGE_DIR"
  if [ "$HOST_OS" = Linux ]; then
    progress "building usgp-relay and usgp-cli (release, FIPS)"
    cargo build --release --locked -p usgp-relay -p usgp-cli
    progress "building netlab tools (release)"
    (cd testing/netlab && env -u CARGO_TARGET_DIR cargo build --release --locked)
  fi
  local efi="$root/target/testing/uefi-payload/x86_64-unknown-uefi/release/$PAYLOAD_NAME"
  progress "building payload ($MARK_NET)"
  (cd testing/uefi-payload && env -u CARGO_TARGET_DIR -u USGP_PAYLOAD_MARKER cargo build --release --locked)
  cp "$efi" "$STAGE_DIR/$PAYLOAD_NAME"
  progress "building payload ($MARK_DISK)"
  (cd testing/uefi-payload && env -u CARGO_TARGET_DIR USGP_PAYLOAD_MARKER="$MARK_DISK" cargo build --release --locked)
  cp "$efi" "$STAGE_DIR/disk-fallback.efi"
  set +e
  say "staged: $STAGE_DIR/$PAYLOAD_NAME sha256=$(sha256_of "$STAGE_DIR/$PAYLOAD_NAME")"
  say "staged: $STAGE_DIR/disk-fallback.efi sha256=$(sha256_of "$STAGE_DIR/disk-fallback.efi")"
  return 0
}

# ------------------------------------------------------------ firmware --

firmware_defaults() {
  if [ "$HOST_OS" = Darwin ]; then
    local qemu share=""
    qemu="$(command -v qemu-system-x86_64 2> /dev/null || true)"
    if [ -n "$qemu" ]; then
      share="$(cd "$(dirname "$qemu")/../share/qemu" 2> /dev/null && pwd)"
    fi
    OVMF_CODE="${USGP_OVMF_CODE:-$share/edk2-x86_64-code.fd}"
    OVMF_VARS="${USGP_OVMF_VARS:-$share/edk2-i386-vars.fd}"
  else
    OVMF_CODE="${USGP_OVMF_CODE:-/usr/share/OVMF/OVMF_CODE_4M.fd}"
    OVMF_VARS="${USGP_OVMF_VARS:-/usr/share/OVMF/OVMF_VARS_4M.fd}"
  fi
  OVMF_SB_CODE="${USGP_OVMF_SB_CODE:-/usr/share/OVMF/OVMF_CODE_4M.secboot.fd}"
  OVMF_SB_VARS="${USGP_OVMF_SB_VARS:-/usr/share/OVMF/OVMF_VARS_4M.ms.fd}"
}

# Resolves the unprivileged user QEMU runs as (Linux root only).
resolve_qemu_user() {
  QEMU_USER="${USGP_QEMU_USER:-${SUDO_USER:-nobody}}"
  [ "$QEMU_USER" = root ] && QEMU_USER=nobody
  if ! QEMU_UID="$(id -u "$QEMU_USER" 2> /dev/null)" || ! QEMU_GID="$(id -g "$QEMU_USER" 2> /dev/null)"; then
    QEMU_UID=""
    QEMU_GID=""
    return 1
  fi
  return 0
}

# Picks KVM or TCG and the deadlines. The /dev/kvm access check runs as the
# QEMU user when one is set (Linux root), otherwise as the current user.
pick_accel() {
  local can_kvm=1
  if [ "$HOST_OS" = Linux ] && [ -e /dev/kvm ]; then
    if [ -n "$QEMU_UID" ]; then
      setpriv --reuid="$QEMU_UID" --regid="$QEMU_GID" --init-groups \
        sh -c '[ -r /dev/kvm ] && [ -w /dev/kvm ]' && can_kvm=0
    else
      [ -r /dev/kvm ] && [ -w /dev/kvm ] && can_kvm=0
    fi
  fi
  case "${USGP_ACCEL:-}" in
    kvm | tcg) ACCEL="$USGP_ACCEL" ;;
    *) if [ "$can_kvm" -eq 0 ]; then ACCEL=kvm; else ACCEL=tcg; fi ;;
  esac
  local base=300 pre=150
  if [ "$ACCEL" = kvm ]; then
    base=120
    pre=60
  fi
  BASE_DEADLINE="${USGP_BOOT_DEADLINE:-$base}"
  PREFLIGHT_DEADLINE="${USGP_PREFLIGHT_DEADLINE:-$pre}"
  LONG_DEADLINE=$((BASE_DEADLINE * 2))
  # Firmware network timeouts, not CPU speed, dominate a fall-through
  # boot: about 60 s per failed network boot option, four options per NIC
  # if the IPv6 switch above is not honoured.
  FALL_DEADLINE="${USGP_FALLTHROUGH_DEADLINE:-$((LONG_DEADLINE + 180))}"
}

# ------------------------------------------------------------------ VMs --

# vm_start <label> <normal|secure> <none|disk> [--ipv4-only] <tap=mac> [<tap=mac>]
# Starts QEMU in the background; sets VM_PID and VM_SERIAL. --ipv4-only
# passes FW_IPV6_OFF to the firmware (fall-through scenarios).
vm_start() {
  local label="$1" fw="$2" disk="$3" v4only=0
  shift 3
  if [ "${1:-}" = --ipv4-only ]; then
    v4only=1
    shift
  fi
  local code vars machine
  if [ "$fw" = secure ]; then
    code="$OVMF_SB_CODE"
    vars="$OVMF_SB_VARS"
  else
    code="$OVMF_CODE"
    vars="$OVMF_VARS"
  fi
  mkdir -p "$LAB/vm"
  local vcopy="$LAB/vm/$label.vars.fd"
  VM_SERIAL="$LAB/vm/$label.serial"
  cp "$vars" "$vcopy" || return 1
  : > "$VM_SERIAL"
  if [ -n "$QEMU_UID" ]; then
    chown "$QEMU_UID:$QEMU_GID" "$LAB/vm" "$vcopy" "$VM_SERIAL" || return 1
  fi
  local args=(-machine q35 -m 512 -display none -no-reboot
    -serial "file:$VM_SERIAL" -accel "$ACCEL")
  if [ "$fw" = secure ]; then
    args=(-machine "q35,smm=on" -global "driver=cfi.pflash01,property=secure,value=on"
      -m 512 -display none -no-reboot -serial "file:$VM_SERIAL" -accel "$ACCEL")
  fi
  args+=(-drive "if=pflash,format=raw,unit=0,readonly=on,file=$code"
    -drive "if=pflash,format=raw,unit=1,file=$vcopy")
  local fwopt=""
  if [ "$v4only" -eq 1 ]; then
    args+=(-fw_cfg "$FW_IPV6_OFF")
    fwopt=" fw_cfg=$FW_IPV6_OFF"
  fi
  local idx=1 nic tap mac
  if [ "$#" -eq 0 ]; then
    args+=(-nic none)
  fi
  for nic in "$@"; do
    tap="${nic%%=*}"
    mac="${nic#*=}"
    args+=(-netdev "tap,id=n$idx,ifname=$tap,script=no,downscript=no"
      -device "virtio-net-pci,netdev=n$idx,romfile=,mac=$mac,bootindex=$idx")
    idx=$((idx + 1))
  done
  if [ "$disk" != none ]; then
    args+=(-drive "file=fat:ro:$disk,format=raw,if=none,id=d0,readonly=on"
      -device "virtio-blk-pci,drive=d0,bootindex=$idx")
  fi
  machine="${args[1]}"
  local qlog="$LAB/vm/$label.qemu.log" pre=()
  if [ -n "$QEMU_UID" ]; then
    # Linux root: drop to the QEMU user; NICs need the bridge namespace,
    # where the taps live.
    pre=(setpriv --reuid="$QEMU_UID" --regid="$QEMU_GID" --init-groups)
    if [ "$#" -gt 0 ]; then
      pre=(ip netns exec "$NS_LAB" "${pre[@]}")
    fi
  fi
  ${pre[@]+"${pre[@]}"} qemu-system-x86_64 "${args[@]}" > "$qlog" 2>&1 &
  VM_PID=$!
  PIDS+=("$VM_PID")
  evidence "qemu $label: pid=$VM_PID machine=$machine accel=$ACCEL firmware=$fw nics=$* disk=$disk$fwopt"
  return 0
}

# Waits until a marker appears (then a 2 s grace), the VM exits, or the
# deadline passes. $1 pid, $2 serial, $3 seconds, then markers.
vm_wait() {
  local pid="$1" serial="$2" secs="$3"
  shift 3
  local dl m
  dl=$(($(now) + secs))
  while kill -0 "$pid" 2> /dev/null && [ "$(now)" -lt "$dl" ]; do
    for m in "$@"; do
      if serial_has "$serial" "$m"; then
        sleep 2
        return 0
      fi
    done
    sleep 1
  done
  return 0
}

# Stops a VM (in this shell, so it is reaped) and copies its serial log into
# the evidence directory. Sets FIN_PATH to the evidence copy.
vm_finish() {
  local pid="$1" label="$2" serial="$3"
  stop_pid "$pid"
  mkdir -p "$OUT/serial"
  FIN_PATH="$OUT/serial/$label.log"
  cp "$serial" "$FIN_PATH" 2> /dev/null || : > "$FIN_PATH"
  cp "$LAB/vm/$label.qemu.log" "$OUT/serial/$label.qemu.log" 2> /dev/null || true
}

# ------------------------------------------------------- payload-disk --

run_payload_disk() {
  begin payload-disk
  local miss=""
  command -v qemu-system-x86_64 > /dev/null 2>&1 || miss="$miss qemu-system-x86_64"
  [ -f "$OVMF_CODE" ] || miss="$miss firmware:$OVMF_CODE"
  [ -f "$OVMF_VARS" ] || miss="$miss vars:$OVMF_VARS"
  [ -f "$PAYLOAD_EFI" ] || miss="$miss payload:$PAYLOAD_EFI (run scripts/boot-smoke.sh build)"
  if [ -n "$miss" ]; then
    record payload-disk "NOT RUN" "missing prerequisite:$miss"
    return
  fi
  mkdir -p "$LAB/pdisk/EFI/BOOT"
  cp "$PAYLOAD_EFI" "$LAB/pdisk/EFI/BOOT/BOOTX64.EFI"
  evidence "payload $PAYLOAD_EFI sha256=$(sha256_of "$PAYLOAD_EFI")"
  evidence "firmware $OVMF_CODE sha256=$(sha256_of "$OVMF_CODE")"
  vm_start payload-disk normal "$LAB/pdisk" || {
    record payload-disk FAIL "QEMU did not start"
    return
  }
  local pid="$VM_PID" serial="$VM_SERIAL" st=0 dl
  dl=$(($(now) + BASE_DEADLINE))
  while kill -0 "$pid" 2> /dev/null && [ "$(now)" -lt "$dl" ]; do
    sleep 1
  done
  if kill -0 "$pid" 2> /dev/null; then
    st=124
  else
    wait "$pid"
    st=$?
  fi
  local path
  vm_finish "$pid" payload-disk "$serial"
  path="$FIN_PATH"
  serial_has "$path" "$MARK_NET"
  note $? "serial $path contains $MARK_NET"
  [ "$st" -eq 0 ]
  note $? "QEMU exited through the payload's shutdown (status $st; 124 = deadline ${BASE_DEADLINE}s)"
  finish payload-disk "payload prints its marker and shuts down (disk boot; proves the payload only)"
}

# ----------------------------------------------------------- preflight --

darwin_reason="Darwin host: usgp-relay binds with Linux SO_BINDTODEVICE only (UnsupportedPlatform), no root network namespaces, and the installed OVMF has no network stack and no enrolled Secure Boot keys (plan section 0)"

# Static checks that need no network. Sets PREFLIGHT_STATUS/REASON.
preflight_static() {
  if [ "$HOST_OS" != Linux ]; then
    PREFLIGHT_STATUS="NOT RUN"
    PREFLIGHT_REASON="$darwin_reason"
    [ "$HOST_OS" = Darwin ] || PREFLIGHT_REASON="unsupported host OS $HOST_OS (Linux only)"
    return 1
  fi
  if [ "$(id -u)" -ne 0 ]; then
    PREFLIGHT_STATUS="NOT RUN"
    PREFLIGHT_REASON="not root (run: sudo -E scripts/boot-smoke.sh ...)"
    return 1
  fi
  local miss="" c
  for c in ip setpriv ss sysctl qemu-system-x86_64 dd od cmp xargs; do
    command -v "$c" > /dev/null 2>&1 || miss="$miss $c"
  done
  [ -f "$OVMF_CODE" ] || miss="$miss firmware:$OVMF_CODE"
  [ -f "$OVMF_VARS" ] || miss="$miss vars:$OVMF_VARS"
  [ -x "$RELAY_BIN" ] || miss="$miss relay:$RELAY_BIN"
  [ -x "$CLI_BIN" ] || miss="$miss cli:$CLI_BIN"
  for c in lab-dhcpd lab-relay-agent lab-probe; do
    [ -x "$NETLAB_DIR/$c" ] || miss="$miss $NETLAB_DIR/$c"
  done
  [ -f "$PAYLOAD_EFI" ] || miss="$miss payload:$PAYLOAD_EFI"
  [ -f "$DISK_EFI" ] || miss="$miss disk-payload:$DISK_EFI"
  if [ -n "$miss" ]; then
    PREFLIGHT_STATUS="NOT RUN"
    PREFLIGHT_REASON="missing prerequisite:$miss (run scripts/boot-smoke.sh build as the normal user)"
    return 1
  fi
  if cmp -s "$PAYLOAD_EFI" "$DISK_EFI"; then
    PREFLIGHT_STATUS="NOT RUN"
    PREFLIGHT_REASON="network and disk payloads are identical; rebuild with scripts/boot-smoke.sh build"
    return 1
  fi
  if ! resolve_qemu_user; then
    PREFLIGHT_STATUS="NOT RUN"
    PREFLIGHT_REASON="QEMU user $QEMU_USER does not exist"
    return 1
  fi
  "$RELAY_BIN" --self-check > /dev/null 2>&1
  local st=$?
  if [ "$st" -ne 0 ]; then
    PREFLIGHT_STATUS=FAIL
    PREFLIGHT_REASON="usgp-relay --self-check exited $st (FIPS mode not active)"
    return 1
  fi
  if [ ! -f "$OVMF_SB_CODE" ] || [ ! -f "$OVMF_SB_VARS" ]; then
    SB_REASON="Secure Boot firmware missing ($OVMF_SB_CODE, $OVMF_SB_VARS)"
  fi
  return 0
}

# ------------------------------------------------------------ topology --

topo() {
  if ! "$@" >> "$OUT/topology.log" 2>&1; then
    PREFLIGHT_REASON="lab topology setup failed: $*"
    return 1
  fi
}

# veth <ns> <ifname> <bridge> <addr/prefix|-> : one leg from <ns> to <bridge>.
veth() {
  local ns="$1" ifn="$2" br="$3" addr="$4" peer="v$2"
  topo ip -n "$NS_LAB" link add "$peer" type veth peer name "$ifn" netns "$ns" || return 1
  topo ip -n "$NS_LAB" link set "$peer" master "$br" up || return 1
  if [ "$addr" != - ]; then
    topo ip -n "$ns" addr add "$addr" dev "$ifn" || return 1
  fi
  topo ip -n "$ns" link set "$ifn" up
}

setup_topology() {
  local ns br tap
  for ns in "${NAMESPACES[@]}"; do
    topo ip netns add "$ns" || return 1
    topo ip -n "$ns" link set lo up || return 1
    topo ip netns exec "$ns" sysctl -q -w net.ipv4.conf.all.rp_filter=0 net.ipv4.conf.default.rp_filter=0 || return 1
  done
  for br in br-a br-b br-x; do
    topo ip -n "$NS_LAB" link add "$br" type bridge stp_state 0 || return 1
    topo ip -n "$NS_LAB" link set "$br" up || return 1
  done
  veth "$NS_RELAY" relay0 br-a "$RELAY_ADDR/24" || return 1
  veth "$NS_RELAY" relay9 br-x "$UNCONF_RELAY_ADDR/24" || return 1
  veth "$NS_SITE" dhcp0 br-a "$SITE_ADDR/24" || return 1
  veth "$NS_ROUTER" rtA br-a "$ROUTER_A/24" || return 1
  veth "$NS_ROUTER" rtB br-b "$ROUTER_B/24" || return 1
  veth "$NS_PROBE" p0 br-a "$PROBE_ADDR/24" || return 1
  veth "$NS_PROBE" px br-x "$UNCONF_PROBE_ADDR/24" || return 1
  topo ip netns exec "$NS_ROUTER" sysctl -q -w net.ipv4.ip_forward=1 || return 1
  topo ip -n "$NS_RELAY" route add 10.20.2.0/24 via "$ROUTER_A" dev relay0 || return 1
  topo ip -n "$NS_SITE" route add 10.20.2.0/24 via "$ROUTER_A" dev dhcp0 || return 1
  topo ip -n "$NS_PROBE" route add 10.20.2.0/24 via "$ROUTER_A" dev p0 || return 1
  for tap in tapA:br-a tapA2:br-a tapB:br-b; do
    topo ip -n "$NS_LAB" tuntap add dev "${tap%%:*}" mode tap user "$QEMU_UID" || return 1
    topo ip -n "$NS_LAB" link set "${tap%%:*}" master "${tap#*:}" up || return 1
  done
  {
    for ns in "${NAMESPACES[@]}"; do
      echo "== $ns"
      ip -n "$ns" -br addr
      ip -n "$ns" route
    done
  } > "$OUT/topology.txt" 2>&1
  return 0
}

# Stages binaries, boot root, manifest (via usgp-cli) and configs in $LAB.
stage_lab() {
  mkdir -p "$LAB/bin" "$LAB/etc" "$LAB/boot" "$LAB/disk/EFI/BOOT" "$LAB/vm" "$OUT/config"
  chmod 0755 "$LAB" "$LAB/bin" "$LAB/etc" "$LAB/boot" "$LAB/disk" "$LAB/vm"
  install -m 0755 "$RELAY_BIN" "$LAB/bin/usgp-relay" || return 1
  install -m 0755 "$NETLAB_DIR/lab-dhcpd" "$NETLAB_DIR/lab-relay-agent" "$NETLAB_DIR/lab-probe" "$LAB/bin/" || return 1
  install -m 0644 "$PAYLOAD_EFI" "$LAB/boot/$PAYLOAD_NAME" || return 1
  cp "$PAYLOAD_EFI" "$LAB/payload.orig" || return 1
  install -m 0644 "$DISK_EFI" "$LAB/disk/EFI/BOOT/BOOTX64.EFI" || return 1
  chmod -R a+rX "$LAB/disk"
  if ! "$CLI_BIN" boot-manifest create --root "$LAB/boot" --out "$LAB/etc/boot-manifest.toml" \
    "$PAYLOAD_NAME" > "$OUT/config/cli-create.log" 2>&1; then
    PREFLIGHT_REASON="usgp-cli boot-manifest create failed (see $OUT/config/cli-create.log)"
    return 1
  fi
  "$CLI_BIN" boot-manifest verify --root "$LAB/boot" --manifest "$LAB/etc/boot-manifest.toml" \
    > "$OUT/config/cli-verify.log" 2>&1 || {
    PREFLIGHT_REASON="usgp-cli boot-manifest verify failed (see $OUT/config/cli-verify.log)"
    return 1
  }
  printf 'schema_version = 1\n' > "$LAB/etc/suppress.toml"
  cat > "$LAB/etc/relay.toml" << EOF
# Boot smoke lab configuration (generated by scripts/boot-smoke.sh). Limits
# are the project defaults (OPEN-BOOT-L1); recheck and reload intervals are
# shortened for the lab, within their configured ranges.
schema_version = 1

[[interface]]
name = "relay0"
address = "$RELAY_ADDR"

[boot]
manifest = "$LAB/etc/boot-manifest.toml"
root = "$LAB/boot"
uefi_x64_program = "$PAYLOAD_NAME"

[limits]
dhcp_client_burst = $LIM_CLIENT_BURST
dhcp_client_refill_ms = $LIM_CLIENT_REFILL_MS

[content]
recheck_interval_secs = $RECHECK_SECS

[suppression]
file = "$LAB/etc/suppress.toml"
reload_interval_secs = $RELOAD_SECS

[log]
level = "info"
node_name = "boot-smoke-relay"
EOF
  chmod 0644 "$LAB/etc/"*
  cp "$LAB/etc/relay.toml" "$LAB/etc/boot-manifest.toml" "$OUT/config/"
  return 0
}

# ------------------------------------------------------------ services --

# start_bg <ns> <log> <cmd...>: background process in <ns>; sets BG_PID.
start_bg() {
  local ns="$1" log="$2"
  shift 2
  ip netns exec "$ns" "$@" >> "$log" 2>&1 &
  BG_PID=$!
  PIDS+=("$BG_PID")
}

wait_log() { # <file> <offset> <fixed string> <secs> <pid>
  local dl
  dl=$(($(now) + $4))
  while [ "$(now)" -lt "$dl" ]; do
    grep -q -F -- "$3" <<< "$(since "$1" "$2")" && return 0
    kill -0 "$5" 2> /dev/null || return 1
    sleep 0.5
  done
  return 1
}

start_dhcpd() {
  local off
  off="$(lines "$DHCPD_LOG")"
  start_bg "$NS_SITE" "$DHCPD_LOG" "${DROP[@]}" "$LAB/bin/lab-dhcpd" \
    --listen "dhcp0=$SITE_ADDR" \
    --pool "10.20.1.0/24,10.20.1.100-10.20.1.199,$ROUTER_A" \
    --pool "10.20.2.0/24,10.20.2.100-10.20.2.199,$ROUTER_B"
  DHCPD_PID="$BG_PID"
  wait_log "$DHCPD_LOG" "$off" "event=ready" 15 "$DHCPD_PID"
}

start_agent() {
  start_bg "$NS_ROUTER" "$AGENT_LOG" "${DROP[@]}" "$LAB/bin/lab-relay-agent" \
    --client-iface rtB --client-addr "$ROUTER_B" --server-iface rtA --own-addr "$ROUTER_A" \
    --server "$SITE_ADDR" --server "$RELAY_ADDR"
  AGENT_PID="$BG_PID"
  wait_log "$AGENT_LOG" 0 "event=ready" 15 "$AGENT_PID"
}

start_relay() {
  start_bg "$NS_RELAY" "$RELAY_LOG" "${DROP[@]}" "$LAB/bin/usgp-relay" --config "$LAB/etc/relay.toml"
  RELAY_PID="$BG_PID"
  local dl
  dl=$(($(now) + 30))
  while [ "$(now)" -lt "$dl" ]; do
    if relay_find 0 relay.start > /dev/null; then
      RELAY_STARTTIME="$(awk '{print $22}' "/proc/$RELAY_PID/stat" 2> /dev/null)"
      return 0
    fi
    kill -0 "$RELAY_PID" 2> /dev/null || return 1
    sleep 0.5
  done
  return 1
}

relay_same() {
  [ -n "$RELAY_PID" ] && kill -0 "$RELAY_PID" 2> /dev/null &&
    [ "$(awk '{print $22}' "/proc/$RELAY_PID/stat" 2> /dev/null)" = "$RELAY_STARTTIME" ]
}

check_config_as_relay_user() {
  "${DROP[@]}" "$LAB/bin/usgp-relay" --check-config "$LAB/etc/relay.toml" > "$OUT/config/check-config-$1.log" 2>&1
}

# probe <log name> <lab-probe args...>: runs lab-probe in usgp-probe as the
# unprivileged user; adds its summary and any failing checks as evidence.
probe() {
  local name="$1"
  shift
  local log="$OUT/probe/$name.log"
  mkdir -p "$OUT/probe"
  ip netns exec "$NS_PROBE" "${DROP[@]}" "$LAB/bin/lab-probe" "$@" > "$log" 2>&1
  local st=$?
  local l
  while IFS= read -r l; do
    evidence "probe $name: $(short "$l")"
  done < <(grep -E 'result=FAIL|^lab-probe summary' "$log")
  note "$st" "lab-probe $1 (exit $st, log $log)"
  return "$st"
}

# Writes the suppression file atomically and waits for the relay to load it.
set_suppression() {
  local content="$1" off
  off="$(lines "$RELAY_LOG")"
  printf '%s' "$content" > "$LAB/etc/suppress.toml.new"
  chmod 0644 "$LAB/etc/suppress.toml.new"
  mv -f "$LAB/etc/suppress.toml.new" "$LAB/etc/suppress.toml"
  local dl
  dl=$(($(now) + RELOAD_SECS * 5 + 5))
  while [ "$(now)" -lt "$dl" ]; do
    relay_find "$off" suppression.loaded > /dev/null && return 0
    sleep 0.5
  done
  return 1
}

# Brings the lab up: topology, staging, site DHCP, relay agent, firmware
# PXE check, relay. Sets PREFLIGHT_STATUS.
lab_up() {
  if [ -z "$OUT" ]; then
    OUT="${USGP_BOOT_SMOKE_OUT:-$root/target/boot-smoke/run-$(date -u +%Y%m%dT%H%M%SZ)}"
  fi
  mkdir -p "$OUT"
  RELAY_LOG="$OUT/relay.log"
  DHCPD_LOG="$OUT/lab-dhcpd.log"
  AGENT_LOG="$OUT/lab-relay-agent.log"
  : > "$RELAY_LOG"
  : > "$DHCPD_LOG"
  : > "$AGENT_LOG"
  {
    uname -a
    qemu-system-x86_64 --version | sed -n 1p
    echo "accel=$ACCEL qemu_user=$QEMU_USER"
    for f in "$OVMF_CODE" "$OVMF_VARS" "$OVMF_SB_CODE" "$OVMF_SB_VARS" "$RELAY_BIN" "$CLI_BIN" \
      "$NETLAB_DIR/lab-dhcpd" "$NETLAB_DIR/lab-relay-agent" "$NETLAB_DIR/lab-probe" "$PAYLOAD_EFI" "$DISK_EFI"; do
      [ -f "$f" ] && echo "sha256 $(sha256_of "$f") $f"
    done
  } > "$OUT/environment.txt" 2>&1
  # Remove leftovers of an interrupted earlier run (our names only).
  local ns
  for ns in "${NAMESPACES[@]}"; do
    if grep -q -w -- "$ns" <<< "$(ip netns list 2> /dev/null)"; then
      ip netns pids "$ns" 2> /dev/null | xargs -r kill -KILL 2> /dev/null || true
      ip netns delete "$ns" 2> /dev/null || true
    fi
  done
  setup_topology || {
    PREFLIGHT_STATUS="NOT RUN"
    return 1
  }
  stage_lab || {
    PREFLIGHT_STATUS=FAIL
    return 1
  }
  start_dhcpd || {
    PREFLIGHT_STATUS="NOT RUN"
    PREFLIGHT_REASON="lab-dhcpd did not start (see $DHCPD_LOG)"
    return 1
  }
  start_agent || {
    PREFLIGHT_STATUS="NOT RUN"
    PREFLIGHT_REASON="lab-relay-agent did not start (see $AGENT_LOG)"
    return 1
  }
  # Firmware network check: the normal firmware must send a UEFI x86-64 PXE
  # DISCOVER (relay not running yet).
  local mac=52:54:00:00:01:00 off pid serial dl seen=1
  off="$(lines "$DHCPD_LOG")"
  EVID=()
  vm_start preflight normal none "tapA=$mac" || {
    PREFLIGHT_STATUS="NOT RUN"
    PREFLIGHT_REASON="QEMU did not start"
    return 1
  }
  pid="$VM_PID"
  serial="$VM_SERIAL"
  dl=$(($(now) + PREFLIGHT_DEADLINE))
  while kill -0 "$pid" 2> /dev/null && [ "$(now)" -lt "$dl" ]; do
    if dhcpd_pxe_discover "$off" "$mac" > /dev/null; then
      seen=0
      break
    fi
    sleep 1
  done
  vm_finish "$pid" preflight "$serial"
  EVID=()
  if [ "$seen" -ne 0 ]; then
    PREFLIGHT_STATUS="NOT RUN"
    PREFLIGHT_REASON="firmware has no PXE stack: no DISCOVER with PXEClient:Arch:00007 from $mac within ${PREFLIGHT_DEADLINE}s ($OVMF_CODE)"
    return 1
  fi
  check_config_as_relay_user start
  local st=$?
  if [ "$st" -ne 0 ]; then
    PREFLIGHT_STATUS=FAIL
    PREFLIGHT_REASON="usgp-relay --check-config exited $st before start (see $OUT/config/check-config-start.log)"
    return 1
  fi
  if ! start_relay; then
    PREFLIGHT_STATUS=FAIL
    PREFLIGHT_REASON="usgp-relay did not start (no relay.start event; see $RELAY_LOG)"
    return 1
  fi
  PREFLIGHT_STATUS=OK
  PREFLIGHT_REASON="firmware PXE DISCOVER seen; relay pid $RELAY_PID up as uid 65534; accel $ACCEL"
  return 0
}

lab_down() {
  [ -n "$RELAY_PID" ] || return 0
  kill -TERM "$RELAY_PID" 2> /dev/null || return 0
  wait "$RELAY_PID" 2> /dev/null
  local st=$?
  if relay_find 0 relay.stop > /dev/null; then
    progress "relay stopped (exit $st, relay.stop logged)"
  else
    progress "relay stopped (exit $st, no relay.stop event)"
  fi
  RELAY_PID=""
}

# ----------------------------------------------------------- scenarios --

# Common checks for a network boot that should succeed. $1 relay offset,
# $2 dhcpd offset, $3 MAC, $4 serial path.
check_net_boot() {
  local roff="$1" doff="$2" mac="$3" serial="$4" line ip
  serial_has "$serial" "$MARK_NET"
  note $? "serial $serial contains $MARK_NET"
  line="$(relay_find "$roff" dhcp.offer.sent "$mac" "$YIADDR0" | sed -n 1p)"
  note $? "relay dhcp.offer.sent for $mac with yiaddr 0.0.0.0"
  [ -n "$line" ] && evidence "relay: $(short "$line")"
  ip="$(dhcpd_lease_ip "$doff" "$mac")"
  [ -n "$ip" ]
  note $? "site lab-dhcpd leased ${ip:-nothing} to $mac (the address comes from site DHCP)"
  if [ -n "$ip" ]; then
    line="$(relay_find "$roff" tftp.transfer.completed "$PAYLOAD_NAME" "$ip:" | sed -n 1p)"
    note $? "relay tftp.transfer.completed $PAYLOAD_NAME to $ip"
    [ -n "$line" ] && evidence "relay: $(short "$line")"
  fi
}

net_ready() { # <id>: NOT RUN guard for scenarios that need a healthy lab
  if [ "$PREFLIGHT_STATUS" != OK ]; then
    record "$1" "NOT RUN" "preflight: ${PREFLIGHT_REASON:-not run}"
    return 1
  fi
  if [ -n "$CONTENT_BROKEN" ]; then
    record "$1" "NOT RUN" "$CONTENT_BROKEN"
    return 1
  fi
  if ! relay_same; then
    record "$1" FAIL "relay process $RELAY_PID is gone or was restarted"
    return 1
  fi
  return 0
}

s1() {
  net_ready S1 || return
  begin S1
  local mac=52:54:00:00:01:01 roff doff path
  roff="$(lines "$RELAY_LOG")"
  doff="$(lines "$DHCPD_LOG")"
  vm_start s1 normal none "tapA=$mac" || {
    record S1 FAIL "QEMU did not start"
    return
  }
  local pid="$VM_PID" serial="$VM_SERIAL"
  vm_wait "$pid" "$serial" "$BASE_DEADLINE" "$MARK_NET"
  vm_finish "$pid" s1 "$serial"
  path="$FIN_PATH"
  check_net_boot "$roff" "$doff" "$mac" "$path"
  finish S1 "same-segment UEFI PXE boot from usgp-relay (exit 1a)"
}

s2() {
  net_ready S2 || return
  begin S2
  local mac=52:54:00:00:02:01 roff doff aoff path line
  roff="$(lines "$RELAY_LOG")"
  doff="$(lines "$DHCPD_LOG")"
  aoff="$(lines "$AGENT_LOG")"
  vm_start s2 normal none "tapB=$mac" || {
    record S2 FAIL "QEMU did not start"
    return
  }
  local pid="$VM_PID" serial="$VM_SERIAL"
  vm_wait "$pid" "$serial" "$BASE_DEADLINE" "$MARK_NET"
  vm_finish "$pid" s2 "$serial"
  path="$FIN_PATH"
  check_net_boot "$roff" "$doff" "$mac" "$path"
  line="$(relay_find "$roff" dhcp.offer.sent "$mac" relay_agent "$ROUTER_B:67" | sed -n 1p)"
  note $? "relay offer for $mac sent to giaddr $ROUTER_B:67 (destination relay_agent)"
  line="$(since "$AGENT_LOG" "$aoff" | grep -F 'event=reply' | grep -F "from=$RELAY_ADDR:" |
    grep -F "chaddr=$mac" | grep -F 'opt82=ok' | sed -n 1p)"
  note $? "lab-relay-agent got the relay's reply for $mac with option 82 unchanged (opt82=ok)"
  [ -n "$line" ] && evidence "agent: $(short "$line")"
  finish S2 "cross-subnet boot through a DHCP relay agent (exit 1b)"
}

s3() {
  net_ready S3 || return
  if [ "$(result_of S1)" != PASS ]; then
    record S3 "NOT RUN" "needs S1 PASS in the same run (S1: $(result_of S1 || echo not run))"
    return
  fi
  begin S3
  local f="$LAB/boot/$PAYLOAD_NAME" size off byte flipped roff path line st
  size="$(wc -c < "$f" | tr -d ' ')"
  off=$((size / 2))
  byte="$(od -A n -t u1 -j "$off" -N 1 "$f" | tr -d ' ')"
  flipped=$(((byte + 1) % 256))
  roff="$(lines "$RELAY_LOG")"
  printf '%b' "$(printf '\\0%03o' "$flipped")" | dd of="$f" bs=1 seek="$off" conv=notrunc 2> /dev/null
  evidence "changed byte $off of $PAYLOAD_NAME from $byte to $flipped in the boot root (relay not restarted); sha256 now $(sha256_of "$f")"
  local mac=52:54:00:00:01:03
  vm_start s3 normal none "tapA=$mac" || {
    record S3 FAIL "QEMU did not start"
    cp "$LAB/payload.orig" "$f"
    return
  }
  local pid="$VM_PID" serial="$VM_SERIAL" dl seen_at=""
  dl=$(($(now) + BASE_DEADLINE))
  while kill -0 "$pid" 2> /dev/null && [ "$(now)" -lt "$dl" ]; do
    serial_has "$serial" "$MARK_NET" && break
    if [ -z "$seen_at" ] && relay_find "$roff" relay.state.changed running_missing_content > /dev/null; then
      seen_at="$(now)"
    fi
    # Let the guest retry for 15 s after the state change, then stop.
    if [ -n "$seen_at" ] && [ "$(now)" -ge $((seen_at + 15)) ]; then
      break
    fi
    sleep 1
  done
  vm_finish "$pid" s3 "$serial"
  path="$FIN_PATH"
  serial_has "$path" "$MARK_NET"
  note_absent $? "no $MARK_NET in $path"
  line="$(relay_find "$roff" boot.file.integrity_failed "$PAYLOAD_NAME" | sed -n 1p)"
  note $? "relay boot.file.integrity_failed for $PAYLOAD_NAME"
  [ -n "$line" ] && evidence "relay: $(short "$line")"
  line="$(relay_find "$roff" relay.state.changed | grep -E '(^|[^a-z_])to[^a-z_]+running_missing_content' | sed -n 1p)"
  note $? "relay state changed to running_missing_content"
  [ -n "$line" ] && evidence "relay: $(short "$line")"
  probe s3-no-offer dhcp-offer "${P_REL[@]}" --expect-none --seed 31 > /dev/null
  check_config_as_relay_user tampered
  st=$?
  [ "$st" -eq 3 ]
  note $? "usgp-relay --check-config exits 3 (missing content); got $st"
  # The drop summary is emitted every SUMMARY_SECS.
  local sdl found=1
  sdl=$(($(now) + SUMMARY_SECS + 15))
  while [ "$(now)" -lt "$sdl" ]; do
    if line="$(relay_find "$roff" dhcp.drop.summary missing_content | sed -n 1p)"; then
      found=0
      break
    fi
    sleep 1
  done
  note "$found" "relay dhcp.drop.summary counts missing_content (offers stopped)"
  [ -n "$line" ] && [ "$found" -eq 0 ] && evidence "relay: $(short "$line")"
  # Restore and wait for the periodic re-check to recover.
  local roff2 rdl rec=1
  roff2="$(lines "$RELAY_LOG")"
  cp "$LAB/payload.orig" "$f"
  rdl=$(($(now) + RECHECK_SECS * 4 + 10))
  while [ "$(now)" -lt "$rdl" ]; do
    if grep -q -E '(^|[^a-z_])to[^a-z_]+running([^_a-z]|$)' <<< "$(relay_find "$roff2" relay.state.changed)"; then
      rec=0
      break
    fi
    sleep 1
  done
  note "$rec" "after restoring the file the relay returned to state running (re-check, no restart)"
  [ "$rec" -eq 0 ] || CONTENT_BROKEN="relay did not recover after S3 restored the payload"
  relay_same
  note $? "relay pid $RELAY_PID unchanged"
  finish S3 "one changed byte makes the relay refuse to serve (exit 2, SI-7)"
}

s4() {
  net_ready S4 || return
  begin S4
  local roff vlog x line
  roff="$(lines "$RELAY_LOG")"
  probe offer-67 dhcp-offer "${P_REL[@]}" --expect-file "$PAYLOAD_NAME" --seed 41 > /dev/null
  probe offer-4011 dhcp-offer "${P_REL[@]}" --port 4011 --expect-file "$PAYLOAD_NAME" --seed 42 > /dev/null
  probe vectors dhcp-vectors "${P_REL[@]}" --expect-file "$PAYLOAD_NAME" --seed 43 > /dev/null
  vlog="$OUT/probe/vectors.log"
  for x in opt60-non-pxe arch-0-bios; do
    line="$(grep -F -- "check=vector:$x result=" "$vlog" | sed -n 1p)"
    grep -q 'result=PASS' <<< "$line"
    note $? "vector $x got no reply: $(short "$line")"
  done
  # The giaddr-* vectors' replies would go to that giaddr, which the probe
  # cannot observe; the relay log must show no reply for their xids.
  local n=0
  while IFS= read -r x; do
    [ -n "$x" ] || continue
    n=$((n + 1))
    if relay_find "$roff" dhcp.offer.sent "$x" > /dev/null || relay_find "$roff" dhcp.ack.sent "$x" > /dev/null; then
      note 1 "relay replied to unobservable vector xid $x"
    fi
  done < <(grep -E 'check=vector:giaddr-' "$vlog" | sed -n 's/.* xid=\(0x[0-9a-f]*\).*/\1/p')
  [ "$n" -eq 4 ]
  note $? "relay log shows no offer or ack for the $n giaddr-* vector xids (4 expected)"
  probe random dhcp-random "${P_REL[@]}" --count 10000 --seed 44 --expect-file "$PAYLOAD_NAME" > /dev/null
  local secs=10 wait_ms=500 max
  max=$((LIM_CLIENT_BURST + (secs * 1000 + wait_ms) / LIM_CLIENT_REFILL_MS))
  evidence "dhcp-rate bound: burst $LIM_CLIENT_BURST + ($secs s + ${wait_ms} ms) / $LIM_CLIENT_REFILL_MS ms = $max replies"
  probe rate dhcp-rate "${P_REL[@]}" --per-sec 50 --secs "$secs" --wait-ms "$wait_ms" \
    --min-replies "$LIM_CLIENT_BURST" --max-replies "$max" --seed 45 > /dev/null
  probe unconfigured dhcp-offer --mode direct --iface px --server "$UNCONF_RELAY_ADDR" --expect-none --seed 46 > /dev/null
  probe tftp-wrq tftp-wrq --server "$RELAY_ADDR" --iface p0 --file x > /dev/null
  probe tftp-traversal tftp-traversal --server "$RELAY_ADDR" --iface p0 > /dev/null
  probe tftp-subnet-bcast tftp-rrq --server 10.20.1.255 --iface p0 --file "$PAYLOAD_NAME" --expect none > /dev/null
  probe tftp-bcast tftp-rrq --server 255.255.255.255 --iface p0 --file "$PAYLOAD_NAME" --expect none > /dev/null
  probe tftp-ok tftp-rrq --server "$RELAY_ADDR" --iface p0 --file "$PAYLOAD_NAME" --expect ok \
    --blksize 1468 --tsize --compare "$LAB/boot/$PAYLOAD_NAME" > /dev/null
  # Binding: every relay socket is tied to relay0 (exit 4).
  local ss_out="$OUT/probe/ss-ulpn.txt" mine bad
  ip netns exec "$NS_RELAY" ss -H -ulpn > "$ss_out" 2>&1
  mine="$(grep -F "pid=$RELAY_PID," "$ss_out")"
  for x in "0.0.0.0%relay0:67" "$RELAY_ADDR%relay0:4011" "$RELAY_ADDR%relay0:69"; do
    grep -q -x -F -- "$x" <<< "$(printf '%s\n' "$mine" | awk '{print $4}')"
    note $? "relay socket bound at $x"
  done
  bad="$(printf '%s\n' "$mine" | awk 'NF {print $4}' | grep -v -F '%relay0:')"
  [ -z "$bad" ]
  note $? "no relay socket outside relay0 (${bad:-none}; see $ss_out)"
  [ -n "$mine" ] && evidence "ss: $(printf '%s' "$mine" | awk '{print $4}' | tr '\n' ' ')"
  relay_same
  note $? "relay pid $RELAY_PID unchanged after all probes (no panic, no restart)"
  finish S4 "binding, malformed input, rate limit, no address, TFTP refusals (exit 4)"
}

s5() {
  net_ready S5 || return
  if [ -n "$SB_REASON" ]; then
    record S5 "NOT RUN" "$SB_REASON"
    return
  fi
  if [ "$(result_of S1)" != PASS ]; then
    record S5 "NOT RUN" "needs the S1 positive control to PASS in the same run"
    return
  fi
  begin S5
  local mac1=52:54:00:00:01:05 mac2=52:54:00:00:01:15 roff doff path
  roff="$(lines "$RELAY_LOG")"
  doff="$(lines "$DHCPD_LOG")"
  evidence "firmware $OVMF_SB_CODE sha256=$(sha256_of "$OVMF_SB_CODE"); vars $OVMF_SB_VARS sha256=$(sha256_of "$OVMF_SB_VARS")"
  vm_start s5 secure none --ipv4-only "tapA=$mac1" "tapA2=$mac2" || {
    record S5 FAIL "QEMU did not start"
    return
  }
  local pid="$VM_PID" serial="$VM_SERIAL" dl stop_at="" pxe=1 done_tx=1 fall=1 pat=1 marker=1
  local ip1="" doff_tx="" line_tx="" line_fall="" line_pat=""
  dl=$(($(now) + LONG_DEADLINE))
  while kill -0 "$pid" 2> /dev/null && [ "$(now)" -lt "$dl" ]; do
    if serial_has "$serial" "$MARK_NET"; then
      marker=0
      break
    fi
    [ "$pxe" -ne 0 ] && dhcpd_pxe_discover "$doff" "$mac1" > /dev/null && pxe=0
    if [ "$done_tx" -ne 0 ]; then
      ip1="$(dhcpd_lease_ip "$doff" "$mac1")"
      if [ -n "$ip1" ] && line_tx="$(relay_find "$roff" tftp.transfer.completed "$PAYLOAD_NAME" "$ip1:" | sed -n 1p)"; then
        done_tx=0
        doff_tx="$(lines "$DHCPD_LOG")"
      fi
    fi
    # Refusal: after the complete download the boot manager moves on to the
    # next boot option (uefi-secure-boot.md §5), seen as a new DISCOVER.
    if [ "$done_tx" -eq 0 ] && [ "$fall" -ne 0 ]; then
      if line_fall="$(since "$DHCPD_LOG" "$doff_tx" | grep -F 'event=discover' |
        grep -E "chaddr=($mac1|$mac2)" | sed -n 1p | grep .)"; then
        fall=0
      fi
    fi
    if [ "$done_tx" -eq 0 ] && [ "$pat" -ne 0 ] && [ -n "${USGP_SB_REFUSAL_PATTERN:-}" ]; then
      line_pat="$(grep -a -E -- "$USGP_SB_REFUSAL_PATTERN" "$serial" | sed -n 1p)" && [ -n "$line_pat" ] && pat=0
    fi
    if [ -z "$stop_at" ] && { [ "$fall" -eq 0 ] || [ "$pat" -eq 0 ]; }; then
      stop_at=$(($(now) + 10)) # keep watching for a late marker
    fi
    if [ -n "$stop_at" ] && [ "$(now)" -ge "$stop_at" ]; then
      break
    fi
    sleep 1
  done
  vm_finish "$pid" s5 "$serial"
  path="$FIN_PATH"
  serial_has "$path" "$MARK_NET" && marker=0
  evidence "serial: $path"
  if [ "$marker" -eq 0 ]; then
    record S5 FAIL "Secure Boot not enforced (vars not enrolled?): $MARK_NET appeared in $path"
    return
  fi
  if [ "$pxe" -ne 0 ]; then
    record S5 "NOT RUN" "Secure Boot firmware has no PXE stack: no DISCOVER with PXEClient:Arch:00007 from $mac1 within ${LONG_DEADLINE}s"
    return
  fi
  note "$done_tx" "relay delivered the verified payload to the Secure Boot guest (tftp.transfer.completed to ${ip1:-no lease})"
  [ -n "$line_tx" ] && evidence "relay: $(short "$line_tx")"
  evidence "ok: no $MARK_NET in $path within the deadline"
  local refused
  if refused="$(first_match "$path" -E "$PXE4_FAIL_RE")"; then
    evidence "serial: $(short "${refused#*:}")"
  fi
  if [ "$fall" -eq 0 ]; then
    evidence "ok: firmware refused the image: boot manager moved to the next boot option after the download: $(short "$line_fall")"
  elif [ "$pat" -eq 0 ]; then
    evidence "ok: firmware refusal on serial (USGP_SB_REFUSAL_PATTERN): $(short "$line_pat")"
  else
    note 1 "firmware refusal observed (no fall-through DISCOVER from $mac1/$mac2 after the download and no USGP_SB_REFUSAL_PATTERN match)"
  fi
  finish S5 "unsigned payload refused by Secure Boot firmware; relay does not weaken it (exit 5)"
}

# first_match <file> <-E|-F> <pattern>: "<line number>:<line>" of the first
# matching line (carriage returns removed); status 1 if none.
first_match() {
  [ -f "$1" ] || return 1
  grep -a -n -m 1 "$2" -- "$3" "$1" | tr -d '\r' | grep .
}

# Network boot expected to fall through to the disk payload. Positive
# evidence of the fall-through: the firmware reports that the IPv4 PXE boot
# option failed, and only after that does the disk payload print its
# marker (uefi-boot-manager.md §5: on failure the boot manager tries the
# next boot option).
check_fallback() {
  local serial="$1" pxe="" disk="" e16 st=1
  serial_has "$serial" "$MARK_DISK"
  note $? "serial $serial contains $MARK_DISK (disk fallback ran)"
  serial_has "$serial" "$MARK_NET"
  note_absent $? "no $MARK_NET in $serial"
  pxe="$(first_match "$serial" -E "$PXE4_FAIL_RE")"
  disk="$(first_match "$serial" -F "$MARK_DISK")"
  if [ -n "$pxe" ] && [ -n "$disk" ] && [ "${pxe%%:*}" -lt "${disk%%:*}" ]; then
    st=0
  fi
  note "$st" "serial shows the IPv4 PXE boot option failed (line ${pxe%%:*}) before $MARK_DISK (line ${disk%%:*})"
  [ -n "$pxe" ] && evidence "serial: $(short "${pxe#*:}")"
  if e16="$(first_match "$serial" -F "PXE-E16")"; then
    evidence "serial: $(short "${e16#*:}")"
  fi
  # Informational: whether the firmware honoured FW_IPV6_OFF.
  if grep -a -q -E 'UEFI (PXEv6|HTTPv6)' "$serial" 2> /dev/null; then
    evidence "note: firmware still tried IPv6 boot options (fw_cfg IPv6Support not honoured)"
  else
    evidence "note: no IPv6 boot option tried (fw_cfg IPv6Support honoured)"
  fi
}

s6() {
  net_ready S6 || return
  begin S6
  local mac=52:54:00:00:01:06 roff path line pid serial
  set_suppression "$(printf 'schema_version = 1\n\n[[device]]\nmac = "%s"\nnote = "boot smoke S6"\n' "$mac")"
  note $? "relay loaded a suppression list naming $mac (suppression.loaded)"
  roff="$(lines "$RELAY_LOG")"
  vm_start s6-suppressed normal "$LAB/disk" --ipv4-only "tapA=$mac" || {
    record S6 FAIL "QEMU did not start"
    return
  }
  pid="$VM_PID"
  serial="$VM_SERIAL"
  vm_wait "$pid" "$serial" "$FALL_DEADLINE" "$MARK_NET" "$MARK_DISK"
  vm_finish "$pid" s6-suppressed "$serial"
  path="$FIN_PATH"
  check_fallback "$path"
  line="$(relay_find "$roff" dhcp.suppressed "$mac" | sed -n 1p)"
  note $? "relay dhcp.suppressed for $mac"
  [ -n "$line" ] && evidence "relay: $(short "$line")"
  relay_find "$roff" dhcp.offer.sent "$mac" > /dev/null
  note_absent $? "relay sent no offer to $mac while suppressed"
  set_suppression "$(printf 'schema_version = 1\n')"
  note $? "relay loaded the list with the entry removed (suppression.loaded, reload ${RELOAD_SECS}s)"
  local doff
  roff="$(lines "$RELAY_LOG")"
  doff="$(lines "$DHCPD_LOG")"
  vm_start s6-lifted normal "$LAB/disk" --ipv4-only "tapA=$mac" || {
    record S6 FAIL "QEMU did not start (second boot)"
    return
  }
  pid="$VM_PID"
  serial="$VM_SERIAL"
  vm_wait "$pid" "$serial" "$BASE_DEADLINE" "$MARK_NET" "$MARK_DISK"
  vm_finish "$pid" s6-lifted "$serial"
  path="$FIN_PATH"
  check_net_boot "$roff" "$doff" "$mac" "$path"
  relay_same
  note $? "relay pid $RELAY_PID unchanged (suppression applied without restart)"
  finish S6 "per-device suppression and fall-through to disk (REQ-BOOT-050, 051, 060)"
}

s7() {
  net_ready S7 || return
  begin S7
  local mac=52:54:00:00:01:07 roff path line n bad pid serial
  stop_pid "$DHCPD_PID"
  evidence "lab-dhcpd (pid $DHCPD_PID) stopped: no site DHCP on segment A"
  roff="$(lines "$RELAY_LOG")"
  vm_start s7 normal "$LAB/disk" --ipv4-only "tapA=$mac" || {
    record S7 FAIL "QEMU did not start"
    start_dhcpd
    return
  }
  pid="$VM_PID"
  serial="$VM_SERIAL"
  vm_wait "$pid" "$serial" "$FALL_DEADLINE" "$MARK_NET" "$MARK_DISK"
  vm_finish "$pid" s7 "$serial"
  path="$FIN_PATH"
  check_fallback "$path"
  n="$(relay_find "$roff" dhcp.offer.sent "$mac" | grep -c .)"
  bad="$(relay_find "$roff" dhcp.offer.sent "$mac" | grep -c -v -F -- "$YIADDR0")"
  [ "${n:-0}" -ge 1 ] && [ "${bad:-0}" -eq 0 ]
  note $? "relay answered $mac ($n offers) and every offer carried yiaddr 0.0.0.0 (no address from the relay)"
  line="$(relay_find "$roff" dhcp.offer.sent "$mac" | sed -n 1p)"
  [ -n "$line" ] && evidence "relay: $(short "$line")"
  start_dhcpd
  note $? "lab-dhcpd restarted"
  finish S7 "site DHCP down: no address, device falls through (REQ-BOOT-012)"
}

s8() {
  net_ready S8 || return
  begin S8
  local roff loop_pid dl started=1
  roff="$(lines "$RELAY_LOG")"
  mkdir -p "$OUT/probe"
  (
    while :; do
      ip netns exec "$NS_PROBE" "${DROP[@]}" "$LAB/bin/lab-probe" tftp-stall --server "$RELAY_ADDR" \
        --iface p0 --file "$PAYLOAD_NAME" --hold-secs 20 >> "$OUT/probe/stall.log" 2>&1
    done
  ) &
  loop_pid=$!
  PIDS+=("$loop_pid")
  dl=$(($(now) + 20))
  while [ "$(now)" -lt "$dl" ]; do
    if relay_find "$roff" tftp.transfer.started "$PROBE_ADDR:" > /dev/null; then
      started=0
      break
    fi
    sleep 0.5
  done
  note "$started" "stalled transfer to $PROBE_ADDR started (lab-probe tftp-stall, never ACKs)"
  local ma=52:54:00:00:01:08 mb=52:54:00:00:02:08 pa pb sa sb
  vm_start s8-a normal none "tapA=$ma" || note 1 "QEMU A started"
  pa="$VM_PID"
  sa="$VM_SERIAL"
  vm_start s8-b normal none "tapB=$mb" || note 1 "QEMU B started"
  pb="$VM_PID"
  sb="$VM_SERIAL"
  dl=$(($(now) + BASE_DEADLINE))
  while [ "$(now)" -lt "$dl" ]; do
    serial_has "$sa" "$MARK_NET" && serial_has "$sb" "$MARK_NET" && break
    sleep 1
  done
  sleep 2
  local path_a path_b
  vm_finish "$pa" s8-a "$sa"
  path_a="$FIN_PATH"
  vm_finish "$pb" s8-b "$sb"
  path_b="$FIN_PATH"
  kill -TERM "$loop_pid" 2> /dev/null
  wait "$loop_pid" 2> /dev/null
  ip netns pids "$NS_PROBE" 2> /dev/null | xargs -r kill -TERM 2> /dev/null
  serial_has "$path_a" "$MARK_NET"
  note $? "guest A (segment A) printed $MARK_NET: $path_a"
  serial_has "$path_b" "$MARK_NET"
  note $? "guest B (segment B, relayed) printed $MARK_NET: $path_b"
  evidence "stall starts: $(grep -c -F 'check=tftp-stall' "$OUT/probe/stall.log" 2> /dev/null) (log $OUT/probe/stall.log)"
  relay_same
  note $? "relay pid $RELAY_PID unchanged"
  finish S8 "two concurrent boots while a client stalls (REQ-BOOT-034)"
}

# ---------------------------------------------------------------- main --

run_preflight_only() {
  firmware_defaults
  if ! preflight_static; then
    say "[preflight] $PREFLIGHT_STATUS: $PREFLIGHT_REASON"
    [ "$PREFLIGHT_STATUS" = FAIL ] && return 1
    return "$EXIT_NOT_RUN"
  fi
  pick_accel
  # Always under /tmp (root-owned, sticky), never $TMPDIR: `sudo -E` keeps
  # the caller's TMPDIR, and a user-owned ancestor fails the relay's
  # trusted-path check (exit 78) since no --admin-uid is passed.
  LAB="$(mktemp -d /tmp/usgp-boot-smoke.XXXXXX)" || return 1
  chmod 0755 "$LAB"
  lab_up
  say "[preflight] $PREFLIGHT_STATUS: $PREFLIGHT_REASON"
  [ -n "$SB_REASON" ] && say "[preflight] S5 NOT RUN: $SB_REASON"
  lab_down
  case "$PREFLIGHT_STATUS" in
    OK) return 0 ;;
    FAIL) return 1 ;;
    *) return "$EXIT_NOT_RUN" ;;
  esac
}

main() {
  [ "$#" -ge 1 ] || {
    usage >&2
    return 2
  }
  case "$1" in
    -h | --help)
      usage
      return 0
      ;;
    build)
      [ "$#" -eq 1 ] || {
        usage >&2
        return 2
      }
      do_build
      return $?
      ;;
    preflight)
      [ "$#" -eq 1 ] || {
        usage >&2
        return 2
      }
      run_preflight_only
      return $?
      ;;
  esac
  local want=() a disk=0 s
  for a in "$@"; do
    case "$a" in
      all) want+=(S1 S2 S3 S4 S5 S6 S7 S8) disk=1 ;;
      payload-disk) disk=1 ;;
      S1 | S2 | S3 | S4 | S5 | S6 | S7 | S8) want+=("$a") ;;
      *)
        say "boot-smoke: unknown scenario '$a'" >&2
        usage >&2
        return 2
        ;;
    esac
  done
  # S3 and S5 need S1 in the same run (S5 uses it as the positive control).
  local need_s1=0 have_s1=0 ordered=()
  for s in ${want[@]+"${want[@]}"}; do
    case "$s" in
      S1) have_s1=1 ;;
      S3 | S5) need_s1=1 ;;
    esac
  done
  if [ "$need_s1" -eq 1 ] && [ "$have_s1" -eq 0 ]; then
    want=(S1 ${want[@]+"${want[@]}"})
  fi
  for s in S1 S2 S3 S4 S5 S6 S7 S8; do
    case " ${want[*]-} " in *" $s "*) ordered+=("$s") ;; esac
  done

  firmware_defaults
  # Always under /tmp (root-owned, sticky), never $TMPDIR: `sudo -E` keeps
  # the caller's TMPDIR, and a user-owned ancestor fails the relay's
  # trusted-path check (exit 78) since no --admin-uid is passed.
  LAB="$(mktemp -d /tmp/usgp-boot-smoke.XXXXXX)" || return 1
  chmod 0755 "$LAB"
  local pf=0
  preflight_static || pf=1
  # Under root, QEMU always runs as the unprivileged QEMU user.
  if [ "$HOST_OS" = Linux ] && [ "$(id -u)" -eq 0 ] && [ -z "$QEMU_UID" ]; then
    resolve_qemu_user || true
  fi
  pick_accel
  if [ "$disk" -eq 1 ]; then
    if [ -z "$OUT" ]; then
      OUT="${USGP_BOOT_SMOKE_OUT:-$root/target/boot-smoke/run-$(date -u +%Y%m%dT%H%M%SZ)}"
      mkdir -p "$OUT"
    fi
    # Needs no network or root: Darwin and Linux non-root run it as the
    # current user.
    run_payload_disk
  fi
  if [ "${#ordered[@]}" -gt 0 ]; then
    if [ "$pf" -eq 0 ]; then
      lab_up || true
      progress "preflight: $PREFLIGHT_STATUS ${PREFLIGHT_REASON}"
    fi
    for s in "${ordered[@]}"; do
      case "$s" in
        S1) s1 ;;
        S2) s2 ;;
        S3) s3 ;;
        S4) s4 ;;
        S5) s5 ;;
        S6) s6 ;;
        S7) s7 ;;
        S8) s8 ;;
      esac
    done
    lab_down
  fi
  summary
}

main "$@"
status=$?
cleanup
exit "$status"
