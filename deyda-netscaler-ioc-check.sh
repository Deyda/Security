#!/bin/sh
#
# Deyda Consulting | NetScaler ADC Defensive Triage
# Script:  deyda-netscaler-ioc-check.sh
# Version: 9.61
# Sample-specific checks below additionally use the operator-supplied 380d56
# analysis screenshot and follow-up description (2026-10-02), not independently verified. No partial hash
# is used. Paths/ports alone are CHECK; matching behavior requires investigation.
# New operator-reported lead (2026-10-02): pyrlnk.cc and its subdomains as
# attempted payload delivery destinations; independently unverified, time-sensitive.
# Changes: tighten real nsaaad lifecycle matching; exclude LDAP username payloads
# and monitoring command echoes; bound reboot keywords to avoid powerbi noise.
# Explicit upstream firewall blocking reminder for 213.209.159.55;
# exclude authentication payload text from nsaaad crash classification;
# broaden restart-limit patterns and add bounded pyrlnk.cc log counts;
# align result groups with their own headings; initialize install marker
# before core checks; deduplicate CVE messages and baseline context; saved SAML
# configurations; authentication-service crash triage; SAML workaround inventory;
# tagged User-Agent payloads; multi-signal login injection; unusual HTTP responses;
# open-file and /flash privileged-file inventories. No mitigation is applied.
# Additional leads: operator-supplied Gotham advisory/checker package (2026-10-02).
# Its observations are scoped to inspected systems, not universal patch guarantees.
#
# Publisher
#   Deyda Consulting GmbH
#   Website: https://www.deyda-consulting.de
#   Author: Manuel Winkel
#   Security Readiness:
#   https://www.deyda-consulting.de/expertise/netscaler-security-readiness/
#
# References
#   NetScaler CVE checklist (DE):
#   https://www.deyda.net/index.php/de/2026/08/28/netscaler-cve-checkliste-updates-sicherheitspruefung-und-incident-response/
#   NetScaler CVE checklist (EN):
#   https://www.deyda.net/index.php/en/2026/08/28/netscaler-cve-checklist-updates-security-assessment-and-incident-response/
#   Public detection research: https://pitscaler.com/netscaler-detection/
#   Public IoCs: https://pitscaler.com/netscaler-iocs/
#   Remediation/timeline: https://pitscaler.com/netscaler-remediation/
#   https://pitscaler.com/netscaler-timeline/
#   CERT-EU (CVE-2026-88771 log-chain analysis):
#   https://cert.europa.eu/blog/taking-execute-logging-a-bit-too-literally-cve-2026-88771
#   Unit 42 (CVE-2026-88771/88772 indicators, updated 2026-09-30):
#   https://unit42.paloaltonetworks.com/netscaler-zero-days-exploited/
#   TENEX active exploitation observations (2026-10-01):
#   https://tenex.ai/blog/what-tenex-observed-inside-active-exploitation-of-netscaler-zero-day/
#   Citrix incident response: CTX694799
#
# Operation
#   Read-only. Run from the ADC shell. No interactive prompts are used.
#   No configuration changes, restarts, or cleanup are performed.
#   Matches are investigative leads, not proof of compromise or attribution.
#   Missing or undetected values stay UNKNOWN and produce CHECK results;
#   the scan continues.
#
# Parameters (in this exact order)
#   1. FIRMWARE_VERSION
#      Version/build from "show ns version", e.g. 14.1-73.37.nc.
#      If omitted, the script prefers the running kernel path and live
#      nsconmsg; saved loader/config files are fallback sources.
#   2. ENHANCED_ISN
#      ENABLED or DISABLED (or the full CLI output).
#      If omitted, /nsconfig/ns.conf is used; absent means DISABLED.
#   Install-time marker
#      On an ADC, the script reads the modification time of
#      /var/nsinstall/installns_state. Confirm it against change records.
#      Exported-config mode has no install-time marker.
#   No third positional parameter is used.
#
# Usage
#   Automatic detection:
#     sh /path/to/deyda-netscaler-ioc-check.sh
#   Explicit version and Enhanced ISN state:
#     sh /path/to/deyda-netscaler-ioc-check.sh 14.1-73.37.nc ENABLED
#   Exported ns.conf (configuration checks only):
#     sh /path/to/deyda-netscaler-ioc-check.sh \
#       --config /path/to/ns.conf 14.1-73.37.nc ENABLED
#
# Optional approved configuration baseline (same deployment, before suspected activity):
#   DEYDA_CONFIG_BASELINE=/path/to/approved-ns.conf sh /path/to/deyda-netscaler-ioc-check.sh
#   Compares account names, rights/policy bindings, and authentication/EPA statements.
#   User passwords are omitted. Saved configuration is not assumed to be live.
# Optional trusted same-build hash for the existing NetScaler customsnmpd component:
#   DEYDA_CUSTOMSNMPD_REFERENCE_SHA256=<64-hex-SHA256> sh /path/to/deyda-netscaler-ioc-check.sh
#   Obtain the reference from a trusted, identical firmware build; never infer it from an
#   appliance under investigation. Internal /var/python/bin and /var/configd_devno values
#   below come from one clean 14.1-73.37 appliance and are not Citrix-published checksums.
#
# Status labels: [OK] no match in scanned scope; [ACTION] investigate indicator;
# [CHECK] manual validation required or scan coverage incomplete.
# Report output: /var/tmp/deyda-netscaler-ioc-check_<host>_<time>.txt
#
PATH=/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin
export PATH
umask 077
HOST=$(hostname 2>/dev/null || echo unknown-host)
NOW=$(date '+%Y-%m-%d_%H%M%S' 2>/dev/null || echo unknown-time)
OUT="/var/tmp/deyda-netscaler-ioc-check_${HOST}_${NOW}.txt"
CONFIG=/nsconfig/ns.conf
RUNNING_ON_ADC=YES

# Prefer an explicitly supplied version. Otherwise, on an ADC prefer the booted
# kernel path, then live nsconmsg, then the active boot loader configuration.
# The saved ns.conf header is only a last fallback because it can be stale after upgrade.
CURRENT_INPUT=${1-}
ISN_INPUT=${2-}
VERSION_SOURCE='not determined'
CONFIG_VERSION_LINE=''
CONFIG_VERSION=''
RUNTIME_FAMILY=''
ISN_CONFIG_STATE=NOT_EXPLICITLY_SET
ISN_SOURCE='not supplied'
if [ -n "$ISN_INPUT" ]; then ISN_SOURCE='operator-supplied value'; fi
if [ "${1-}" = '--config' ]; then
    CONFIG=${2-}
    CURRENT_INPUT=${3-}
    ISN_INPUT=${4-}
    RUNNING_ON_ADC=NO
elif [ -n "${1-}" ] && [ -r "${1-}" ] && [ -f "${1-}" ]; then
    CONFIG=$1
    CURRENT_INPUT=''
    ISN_INPUT=${2-}
    RUNNING_ON_ADC=NO
fi
if [ -r "$CONFIG" ]; then
    CONFIG_VERSION_LINE=$(head -n 5 "$CONFIG" 2>/dev/null | grep -iE '^#NS[0-9]+\.[0-9]+ Build' | head -1)
    CONFIG_VERSION=$(printf '%s\n' "$CONFIG_VERSION_LINE" | sed -E -n 's/.*NS([0-9]+\.[0-9]+) Build ([0-9]+\.[0-9]+).*/\1-\2/p')
fi
if [ -n "$CURRENT_INPUT" ]; then
    VERSION_SOURCE='operator-supplied version'
else
    if [ "$RUNNING_ON_ADC" = YES ]; then
        RUNTIME_FAMILY=$(uname -r 2>/dev/null | sed -nE 's/.*NETSCALER-([0-9]+\.[0-9]+).*/\1/p')
        BOOT_KERNEL=$(sysctl -n kern.bootfile 2>/dev/null)
        BOOT_VERSION=$(printf '%s\n' "$BOOT_KERNEL" | sed -nE 's/.*ns-([0-9]+\.[0-9]+)-([0-9]+\.[0-9]+).*/\1-\2/p')
        if [ -n "$BOOT_VERSION" ]; then
            CURRENT_INPUT=$BOOT_VERSION
            VERSION_SOURCE="running kernel path ($BOOT_KERNEL)"
        fi
        if [ -z "$CURRENT_INPUT" ] && command -v nsconmsg >/dev/null 2>&1; then
            LIVE_VERSION_LINE=$(nsconmsg -K /var/nslog/newnslog -d setime 2>/dev/null | grep -iE 'NS[0-9]+\.[0-9]+ Build' | head -1)
            LIVE_VERSION=$(printf '%s\n' "$LIVE_VERSION_LINE" | sed -E -n 's/.*NS([0-9]+\.[0-9]+) Build ([0-9]+\.[0-9]+).*/\1-\2/p')
            LIVE_FAMILY=$(printf '%s\n' "$LIVE_VERSION" | sed -nE 's/^([0-9]+\.[0-9]+)-.*/\1/p')
            if [ -n "$LIVE_VERSION" ] && { [ -z "$RUNTIME_FAMILY" ] || [ "$LIVE_FAMILY" = "$RUNTIME_FAMILY" ]; }; then
                CURRENT_INPUT=$LIVE_VERSION
                VERSION_SOURCE='live nsconmsg output'
            fi
        fi
    fi
    if [ -z "$CURRENT_INPUT" ]; then
        LOADER_KERNEL=$(grep -hE '^[[:space:]]*kernel[[:space:]]*=' /flash/boot/loader.conf /flash/boot/loader.conf.local 2>/dev/null | tail -1)
        LOADER_VERSION=$(printf '%s\n' "$LOADER_KERNEL" | sed -nE 's/.*ns-([0-9]+\.[0-9]+)-([0-9]+\.[0-9]+).*/\1-\2/p')
        LOADER_FAMILY=$(printf '%s\n' "$LOADER_VERSION" | sed -nE 's/^([0-9]+\.[0-9]+)-.*/\1/p')
        if [ -n "$LOADER_VERSION" ] && { [ -z "$RUNTIME_FAMILY" ] || [ "$LOADER_FAMILY" = "$RUNTIME_FAMILY" ]; }; then
            CURRENT_INPUT=$LOADER_VERSION
            VERSION_SOURCE='boot loader configuration (configured kernel; not proof of the currently booted kernel)'
        fi
    fi
    if [ -z "$CURRENT_INPUT" ] && [ -n "$RUNTIME_FAMILY" ]; then
        CURRENT_INPUT=$RUNTIME_FAMILY
        VERSION_SOURCE='running kernel release family only; build number unavailable'
    fi
    if [ -z "$CURRENT_INPUT" ] && [ -n "$CONFIG_VERSION" ]; then
            if [ "$RUNNING_ON_ADC" != YES ] || [ -z "$RUNTIME_FAMILY" ] || [ "${CONFIG_VERSION%%-*}" = "$RUNTIME_FAMILY" ]; then
                CURRENT_INPUT=$CONFIG_VERSION
                VERSION_SOURCE="saved configuration header ($CONFIG; fallback only)"
            else
                CURRENT_INPUT=$RUNTIME_FAMILY
                VERSION_SOURCE='running kernel release family only; saved config header disagrees and build is unavailable'
            fi
    fi
fi

# Read Enhanced ISN from the saved ns.conf by default. An explicit CLI value
# supplied as an argument takes precedence when checking unsaved runtime changes.
if [ -r "$CONFIG" ]; then
    if grep -E -i -q '^[[:space:]]*set ns tcpParam .*-[eE]nhancedISNGeneration[[:space:]]+ENABLED' "$CONFIG"; then ISN_CONFIG_STATE=ENABLED
    elif grep -E -i -q '^[[:space:]]*set ns tcpParam .*-[eE]nhancedISNGeneration[[:space:]]+DISABLED' "$CONFIG"; then ISN_CONFIG_STATE=DISABLED
    else ISN_CONFIG_STATE=DISABLED_DEFAULT
    fi
fi
if [ -z "$ISN_INPUT" ]; then
    if [ "$ISN_CONFIG_STATE" = ENABLED ] || [ "$ISN_CONFIG_STATE" = DISABLED ]; then
        ISN_INPUT=$ISN_CONFIG_STATE
        ISN_SOURCE="saved configuration ($CONFIG)"
    elif [ "$ISN_CONFIG_STATE" = DISABLED_DEFAULT ]; then
        ISN_INPUT=DISABLED
        ISN_SOURCE='saved configuration default (directive absent; Citrix default is DISABLED)'
    fi
fi
ISN_NORMALIZED=$(printf '%s\n' "$ISN_INPUT" | tr '[:lower:]' '[:upper:]')
ISN_STATE=UNKNOWN
case "$ISN_NORMALIZED" in
    ENABLED|*'ENHANCED ISN GENERATION:'*ENABLED*) ISN_STATE=ENABLED ;;
    DISABLED|*'ENHANCED ISN GENERATION:'*DISABLED*) ISN_STATE=DISABLED ;;
esac

# Preserve terminal streams, save a plain-text report, then display it with colored statuses.
exec 3>&1 4>&2
SCAN_STARTED=$(date +%s)

progress() {
    _progress_now=$(date +%s)
    printf '  [%s elapsed] %s\n' "$(format_duration "$((_progress_now - SCAN_STARTED))")" "$1" >&3
}

# Preserve raw report bytes for evidence. Only the terminal rendering is sanitized;
# remove attacker-controlled ANSI/OSC/control sequences before adding status colors.
safe_display() {
    if command -v perl >/dev/null 2>&1; then
        perl -pe 's/[\x00-\x08\x0b-\x1f\x7f]/./g' "$@"
    else
        LC_ALL=C tr -d '\000-\010\013-\037\177' < "$1"
    fi
}

format_duration() {
    _duration_seconds=$1
    if [ "$_duration_seconds" -lt 60 ]; then
        printf '%ss' "$_duration_seconds"
    elif [ "$_duration_seconds" -lt 3600 ]; then
        printf '%sm %ss' "$((_duration_seconds / 60))" "$((_duration_seconds % 60))"
    else
        printf '%sh %sm' "$((_duration_seconds / 3600))" "$(((_duration_seconds % 3600) / 60))"
    fi
}

LOG_EST_FILES=0
LOG_EST_BYTES=0
if [ "$RUNNING_ON_ADC" = YES ]; then
    # These non-overlapping globs cover local text-log families searched below.
    for _log_file in /var/log/httpaccess* /var/log/httperror* /var/log/ns.log* \
        /var/log/messages* /var/log/notice.log* /var/log/nsvpn.log* /var/log/sh.log* /var/log/bash.log* /var/log/audit.log* \
        /var/log/named* /var/log/dns* /var/log/boot.log; do
        [ -f "$_log_file" ] && [ -r "$_log_file" ] || continue
        _log_size=$(ls -lnL "$_log_file" 2>/dev/null | awk 'NR==1 && $1 ~ /^-/ {print $5}')
        case "$_log_size" in ''|*[!0-9]*) continue ;; esac
        LOG_EST_FILES=$((LOG_EST_FILES + 1))
        LOG_EST_BYTES=$((LOG_EST_BYTES + _log_size))
    done
    LOG_EST_MB=$(((LOG_EST_BYTES + 1048575) / 1048576))
    if [ "$LOG_EST_FILES" -gt 0 ]; then
        # Selected logs are searched repeatedly. This is a rough range based on
        # 12-24 sequential passes at 10 MiB/s plus startup overhead.
        LOG_EST_MIN_SECONDS=$(((LOG_EST_BYTES * 12 + 10485759) / 10485760 + 8))
        LOG_EST_MAX_SECONDS=$(((LOG_EST_BYTES * 24 + 10485759) / 10485760 + 15))
        LOG_EST_TIME="$(format_duration "$LOG_EST_MIN_SECONDS")–$(format_duration "$LOG_EST_MAX_SECONDS")"
    else
        LOG_EST_TIME='unavailable (no readable candidate log files)'
    fi
    printf '\nDeyda NetScaler IOC check pre-scan estimate\n' >&3
    printf '  Readable candidate log files: %s\n' "$LOG_EST_FILES" >&3
    printf '  Total on-disk size: about %s MiB (compressed files included)\n' "$LOG_EST_MB" >&3
    printf '  Estimated run time: %s\n' "$LOG_EST_TIME" >&3
    printf '  Rough estimate; compression, storage speed, and appliance load affect actual time.\n' >&3
    printf '  While the check runs, take a break or catch up on the latest articles at deyda.net.\n' >&3
    printf '  Starting read-only checks now...\n\n' >&3
else
    LOG_EST_MB=0
    LOG_EST_TIME='not applicable (exported configuration mode skips appliance logs)'
    printf '\nDeyda NetScaler IOC check: exported configuration mode; appliance log checks are skipped. Starting configuration checks...\n\n' >&3
fi

exec > "$OUT" 2>&1

section() { progress "$1"; printf '\n===== %s =====\n' "$1"; }
subsection() { printf '\n--- %s ---\n' "$1"; }
status() { printf '\n[%s] %s\n' "$1" "$2"; }
sha256_of() {
    _hash_path=$1
    if command -v sha256 >/dev/null 2>&1; then
        sha256 "$_hash_path" 2>/dev/null | sed -nE 's/.*([[:xdigit:]]{64}).*/\1/p' | head -1 | tr 'A-F' 'a-f'
    elif command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$_hash_path" 2>/dev/null | awk '{print tolower($1)}'
    fi
}
check_1417337_reference() {
    REFERENCE_MATCH=UNKNOWN
    _ref_path=$1
    _ref_hash=$2
    [ "${CURRENT_INPUT-}" = '14.1-73.37.nc' ] || [ "${CURRENT_INPUT-}" = '14.1-73.37' ] || return 0
    _actual_hash=$(sha256_of "$_ref_path")
    if [ -n "$_actual_hash" ]; then
        printf 'SHA-256 observed:  %s\n' "$_actual_hash"
        printf 'SHA-256 reference: %s\n' "$_ref_hash"
    fi
    if [ -z "$_actual_hash" ]; then
        status CHECK "Could not calculate SHA-256 for $_ref_path against the internal 14.1-73.37 sample."
    elif [ "$_actual_hash" = "$_ref_hash" ]; then
        REFERENCE_MATCH=YES
        status OK "$_ref_path SHA-256 matches the internal 14.1-73.37 reference from one clean appliance; this is not a Citrix-published checksum."
    else
        status CHECK "$_ref_path SHA-256 differs from the internal one-appliance 14.1-73.37 reference; compare edition, configuration, and a trusted peer before treating it as anomalous."
    fi
}
reference_suid_1417337() {
    case "$1" in
        /var/nslog/nslog.nextfile) check_nslog_nextfile_state "$1" ;;
        /var/run/nsprofmgmt.pid) check_nsprofmgmt_pid "$1" ;;
        /var/configd_devno) check_1417337_reference "$1" '5b76771117eacc288a42de079a719402e26528e997cfa82241c4d7a842eba5d2' ;;
    esac
}
check_nsprofmgmt_pid() {
    _pid_file=$1
    _pid=$(tr -d '[:space:]' < "$_pid_file" 2>/dev/null)
    _pid_meta=$(ls -ln "$_pid_file" 2>/dev/null | awk 'NR==1{print $1 ":" $3 ":" $4}')
    if [ -z "$_pid" ] || ! printf '%s\n' "$_pid" | grep -E -q '^[0-9]+$'; then
        status CHECK "$_pid_file does not contain a numeric PID; preserve and inspect the file."
        return
    fi
    # NetScaler's FreeBSD ps output is reliable in the traditional auxww form;
    # avoid comma-separated -o formatting, which is not parsed consistently here.
    _pid_process=$(ps auxww 2>/dev/null | awk -v target="$_pid" '$2 == target {print}')
    if [ -n "$_pid_process" ] && printf '%s\n' "$_pid_process" | grep -E -q '/netscaler/nsprofmgmt([[:space:]]|$)'; then
        status OK "$_pid_file contains PID $_pid and it resolves to the expected /netscaler/nsprofmgmt process. PID-file hashes are not compared because the PID changes at runtime."
        printf 'Matched process: %s\n' "$_pid_process"
    elif [ -n "$_pid_process" ]; then
        status CHECK "$_pid_file contains PID $_pid, but that PID belongs to a different process; investigate the mismatch:"
        printf '%s\n' "$_pid_process"
    else
        status CHECK "$_pid_file contains PID $_pid, but no matching live process was found; check for a stale PID file or stopped service."
    fi
    if [ "$_pid_meta" = '---x--S---:0:0' ]; then
        status OK 'nsprofmgmt.pid mode and numeric owner/group match the internal 14.1-73.37 sample; size, timestamp, and hash are intentionally not compared.'
    else
        status CHECK "nsprofmgmt.pid mode/owner/group differ from the internal sample (observed ${_pid_meta:-unavailable}); validate against a trusted same-build peer."
    fi
}
check_nslog_nextfile_state() {
    _state_file=$1
    _next_value=$(tr -d '[:space:]' < "$_state_file" 2>/dev/null)
    _state_meta=$(ls -ln "$_state_file" 2>/dev/null | awk 'NR==1{print $1 ":" $3 ":" $4}')
    if [ -n "$_next_value" ] && printf '%s\n' "$_next_value" | grep -E -q '^[0-9]+$'; then
        status OK "$_state_file contains a numeric next-file value. Its content can change with log rotation, so the one-appliance SHA-256 is not used as a fixed baseline."
    else
        status CHECK "$_state_file does not contain the expected numeric next-file value; preserve and inspect the content."
        printf 'Observed content: %s\n' "${_next_value:-<empty>}"
    fi
    if [ "$_state_meta" = '-rwS--x---:0:0' ]; then
        status OK 'nslog.nextfile mode and numeric owner/group match the internal 14.1-73.37 sample; size, timestamp, and hash are intentionally not compared.'
    else
        status CHECK "nslog.nextfile mode/owner/group differ from the internal sample (observed ${_state_meta:-unavailable}); validate against a trusted same-build peer."
    fi
}
FW_PATCHED=UNKNOWN

printf 'Deyda Consulting NetScaler IOC and CVE triage report\n'
printf 'Host: %s\nTime: %s\nScript version: 9.61\n\n' "$HOST" "$NOW"
printf 'Prepared by: Deyda Consulting GmbH\nAuthor: Manuel Winkel\nWebsite: https://www.deyda-consulting.de\n\n'
printf 'Related articles\n  DE: https://www.deyda.net/index.php/de/2026/08/28/netscaler-cve-checkliste-updates-sicherheitspruefung-und-incident-response/\n'
printf '  EN: https://www.deyda.net/index.php/en/2026/08/28/netscaler-cve-checklist-updates-security-assessment-and-incident-response/\n\n'
printf 'Additional research: https://pitscaler.com/netscaler-detection/ (independent snapshot; coverage changes over time)\n'
printf 'Mode: read-only; no configuration changes, restarts, or cleanup performed\n'
printf 'Report: %s\n' "$OUT"
if [ "$RUNNING_ON_ADC" = YES ]; then
    printf 'Pre-scan estimate: %s readable candidate log files, about %s MiB on disk; estimated run time %s (rough estimate)\n' "$LOG_EST_FILES" "$LOG_EST_MB" "$LOG_EST_TIME"
else
    printf 'Pre-scan estimate: %s\n' "$LOG_EST_TIME"
fi
printf 'Status definitions are provided once in the section \"How to read this report\" below.\n\n'
printf 'Build input/source: %s / %s\n' "${CURRENT_INPUT:-not supplied}" "$VERSION_SOURCE"
if [ "$RUNNING_ON_ADC" = YES ] && [ -n "$CONFIG_VERSION" ] && [ -n "$RUNTIME_FAMILY" ] && [ "${CONFIG_VERSION%%-*}" != "$RUNTIME_FAMILY" ]; then
    status CHECK "Saved ns.conf header reports $CONFIG_VERSION, but the running kernel release identifies $RUNTIME_FAMILY. The running-kernel source takes precedence; treat the saved header as stale until verified."
elif [ "$RUNNING_ON_ADC" = YES ] && [ -n "$CONFIG_VERSION" ] && [ -n "$CURRENT_INPUT" ] && [ "$CONFIG_VERSION" != "$CURRENT_INPUT" ] && [ "$VERSION_SOURCE" != 'operator-supplied version' ] && [ "$CURRENT_INPUT" = *-* ]; then
    status CHECK "Saved ns.conf header reports $CONFIG_VERSION while the running build source reports $CURRENT_INPUT. The saved header may be stale after upgrade."
fi
printf 'Enhanced ISN: assessed=%s (source: %s); saved-config=%s (%s)\n' \
    "$ISN_STATE" "$ISN_SOURCE" "$ISN_CONFIG_STATE" "$CONFIG"

section 'How to read this report'
cat <<'READ_GUIDE'
[OK] means the selected pattern was not found in the source and time range the check scanned. It is not a clean bill of health.
[CHECK] means the output needs human validation, usually against an approved change, a trusted same-build baseline, or a wider evidence source.
[ACTION] means a higher-priority indicator matched. Preserve the relevant evidence and correlate it before cleanup, restart, or rebuild. It is not automatic proof that the appliance was compromised.

Read the report in this order: firmware/CVE applicability; host integrity and persistence; web configuration and files; log coverage and attack indicators; then the final next-action list.
READ_GUIDE

section '1. Platform and uptime'
if [ "$RUNNING_ON_ADC" = YES ]; then
    uname -a 2>&1
    uptime 2>&1
    printf '\n--- System time, timezone, and NTP context ---\n'
    date 2>&1
    date '+Timezone: %Z (UTC offset %z)' 2>&1
    sysctl kern.boottime 2>&1
    if command -v ntpq >/dev/null 2>&1; then
        ntpq -pn 2>&1 | head -20
    else
        status CHECK 'ntpq is unavailable; verify configured NTP peers and synchronization using the supported NetScaler method.'
    fi
    for f in /etc/ntp.conf /etc/ntp.drift /nsconfig/ntp.conf; do
        if [ -r "$f" ]; then ls -l "$f" 2>&1; grep -E -i -n '^(server|pool|peer|restrict)[[:space:]]' "$f" 2>/dev/null | head -20; fi
    done
    status CHECK 'Compare displayed system time, timezone, NTP state, and boot time with remote log sources and the incident timeline.'
else
    status CHECK "Offline configuration mode: host checks and live ADC state are not available; config file is $CONFIG."
fi

section '2. Firmware and CVE applicability'
subsection 'Purpose and follow-up'
printf '%s\n' 'Purpose: compare the detected build with the bulletin threshold and inventory saved-config preconditions.'
printf '%s\n' 'If below threshold: schedule the fixed build. If at/above threshold: treat matching config lines as historical-exposure context, then review the pre-update logs and file evidence.'
cat <<'NOTE'
Citrix fixed-build thresholds stated in the bulletin:
  Standard 14.1: 14.1-73.37 or later
  Standard 13.1: 13.1-64.23 or later
  14.1 FIPS: 14.1-73.37 FIPS or later
  13.1 FIPS/NDcPP: 13.1-37.279 or later
CVE-2026-88771: all deployments below the fixed build are affected; no config precondition.
Citrix reports observed exploitation of CVE-2026-88771 and CVE-2026-88772.
  88771: unauthenticated remote code execution (RCE).
  88772: DTLS-related memory overflow; may lead to RCE or denial of service (DoS).
  88773: HTTP request smuggling.
  88774: possible policy bypass involving HTTP URL-based expressions.
  88775-88777: memory overflows that may cause unexpected behavior or DoS in specified configurations.
  88778: TCP Initial Sequence Number (ISN) prediction.
NOTE
if [ -n "$CURRENT_INPUT" ]; then
    FW_FAMILY=$(printf '%s\n' "$CURRENT_INPUT" | sed -E -n 's/.*(14\.1|13\.1)[^0-9]*([0-9]+\.[0-9]+).*/\1/p' | head -1)
    FW_BUILD=$(printf '%s\n' "$CURRENT_INPUT" | sed -E -n 's/.*(14\.1|13\.1)[^0-9]*([0-9]+\.[0-9]+).*/\2/p' | head -1)
    if [ -n "$FW_FAMILY" ] && [ -n "$FW_BUILD" ]; then
        FW_MAJOR=$(printf '%s' "$FW_BUILD" | cut -d. -f1)
        FW_MINOR=$(printf '%s' "$FW_BUILD" | cut -d. -f2)
        REQUIRED_BUILD=''
        if [ "$FW_FAMILY" = '14.1' ]; then
            REQUIRED_BUILD='73.37'
        elif [ "$FW_FAMILY" = '13.1' ] && { [ "$FW_MAJOR" = '37' ] || printf '%s\n' "$CURRENT_INPUT" | grep -E -i -q 'FIPS|NDcPP'; }; then
            REQUIRED_BUILD='37.279'
        elif [ "$FW_FAMILY" = '13.1' ]; then
            REQUIRED_BUILD='64.23'
        fi
        if [ -n "$REQUIRED_BUILD" ]; then
            REQ_MAJOR=$(printf '%s' "$REQUIRED_BUILD" | cut -d. -f1)
            REQ_MINOR=$(printf '%s' "$REQUIRED_BUILD" | cut -d. -f2)
            printf '\nFirmware comparison: detected %s build %s; required fixed build is %s-%s or later.\n' "$FW_FAMILY" "$FW_BUILD" "$FW_FAMILY" "$REQUIRED_BUILD"
            if [ "$FW_MAJOR" -gt "$REQ_MAJOR" ] || { [ "$FW_MAJOR" -eq "$REQ_MAJOR" ] && [ "$FW_MINOR" -ge "$REQ_MINOR" ]; }; then
                FW_PATCHED=YES
                status OK 'Detected/supplied firmware build meets or exceeds the fixed-build threshold in the bulletin.'
            else
                FW_PATCHED=NO
                status ACTION 'Detected/supplied firmware build is below the fixed-build threshold; update urgently.'
            fi
        else
            status CHECK "Could not select a fixed-build threshold for detected family $FW_FAMILY."
        fi
    else
        if [ "$CURRENT_INPUT" = '14.1' ] || [ "$CURRENT_INPUT" = '13.1' ]; then
            status CHECK "Running release family $CURRENT_INPUT was identified, but the build number is unavailable. Do not assess the fixed-build threshold from a conflicting saved config; verify with show ns version."
        else
            status CHECK 'Version input was not recognized. Paste the version/build from show ns version, e.g. 14.1-73.37.nc.'
        fi
    fi
else
    status CHECK 'Firmware comparison skipped; rerun with the version from show ns version as argument, e.g. sh deyda-netscaler-ioc-check.sh 14.1-73.37.nc.'
fi
printf '\nCVE configuration matches below show feature/precondition clues from the configuration file.\n'
printf 'If the entered build meets the fixed threshold, these matches do not mean the patched appliance remains vulnerable; they may matter when assessing exposure before the update.\n'

if [ -r "$CONFIG" ]; then
    printf '\nSaved configuration reviewed: %s\n' "$CONFIG"
    printf 'This is not necessarily the running configuration; compare with the ADC CLI output.\n'

    scan_config() {
        label=$1
        pattern=$2
        hit_status=$3
        miss_status=$4
        printf '\n--- %s ---\n' "$label"
        matches=$(grep -E -i -n "$pattern" "$CONFIG" 2>/dev/null | head -100)
        if [ -n "$matches" ]; then
            if [ "$FW_PATCHED" = YES ]; then
                status OK 'This CVE precondition appears in saved config, but the entered build meets the fixed threshold; no CVE-driven config change is indicated.'
            elif [ "$FW_PATCHED" = NO ]; then
                status "$hit_status" 'Potentially relevant precondition on a below-threshold build; review and update urgently.'
            else
                status CHECK 'Potentially relevant precondition found, but the firmware version was not verified.'
            fi
            echo "$matches"
        else
            status "$miss_status" 'No matching lines found in the saved configuration.'
        fi
    }

    subsection 'CVE-2026-88772: DTLS enabled on Gateway or DTLS virtual server'
    vpn_lines=$(grep -E -i '^add vpn vserver ' "$CONFIG" 2>/dev/null)
    dtls_lines=$(grep -E -i '^add [^#]*vserver .* DTLS([[:space:]]|$)' "$CONFIG" 2>/dev/null)
    if [ -n "$vpn_lines" ]; then
        printf '%s\n' "$vpn_lines" | while IFS= read -r line; do
            if printf '%s\n' "$line" | grep -E -i -q -- '-dtls[[:space:]]+OFF'; then
                status OK 'Saved VPN vServer explicitly shows -dtls OFF:'
            elif printf '%s\n' "$line" | grep -E -i -q -- '-state[[:space:]]+DISABLED'; then
                status OK 'Saved VPN vServer is explicitly disabled:'
            elif [ "$FW_PATCHED" = YES ]; then
                status OK 'DTLS may be enabled by default, but the entered firmware meets the fixed threshold for this CVE:'
            elif [ "$FW_PATCHED" = NO ]; then
                status ACTION 'VPN vServer lacks -dtls OFF and is not explicitly disabled on a below-threshold build:'
            else
                status CHECK 'VPN vServer lacks -dtls OFF; confirm DTLS state and firmware version:'
            fi
            echo "$line"
        done
    else
        status OK 'No VPN vServer lines found in the saved configuration.'
    fi
    if [ -n "$dtls_lines" ]; then
        printf '%s\n' "$dtls_lines" | while IFS= read -r line; do
            if printf '%s\n' "$line" | grep -E -i -q -- '-state[[:space:]]+DISABLED'; then
                status OK 'DTLS-typed vServer is explicitly disabled in saved config:'
            elif [ "$FW_PATCHED" = YES ]; then
                status OK 'DTLS-typed vServer is configured, but the entered firmware meets the fixed threshold for this CVE:'
            elif [ "$FW_PATCHED" = NO ]; then
                status ACTION 'DTLS-typed vServer is not explicitly disabled on a below-threshold build:'
            else
                status CHECK 'DTLS-typed vServer found; verify live state and firmware version:'
            fi
            echo "$line"
        done
    else
        status OK 'No vServer explicitly typed as DTLS found in the saved configuration.'
    fi
    if [ "$FW_PATCHED" = YES ]; then status OK 'For this bulletin, saved-config preconditions are remediated by the entered fixed build; verify live state only if investigating the pre-update exposure window.'; elif [ "$FW_PATCHED" = NO ]; then status CHECK 'Confirm DTLS state in running configuration; saved config may be stale and build is below threshold.'; else status CHECK 'Confirm DTLS state in running configuration and provide the firmware build; saved config may be stale.'; fi

    subsection 'CVE-2026-88773: HTTP configuration enabled'
    scan_config 'HTTP or SSL LB/CS/VPN/AAA virtual servers' '^[[:space:]]*add (lb|cs|vpn|authentication) vserver .* (HTTP|SSL)([[:space:]]|$)' ACTION OK
    if [ "$FW_PATCHED" != YES ]; then
        status CHECK 'HTTP/SSL vServers can be relevant to this CVE on an unverified or below-threshold build. Confirm active state in the running configuration.'
    fi

    subsection 'CVE-2026-88774: HTTP URL-based policy expressions'
    printf '\n--- Common URL expression strings (partial text search) ---\n'
    URL_EXPRESSION_MATCHES=$(grep -E -i -n 'HTTP\.REQ\.URL|HTTP\.URL|HTTP\.REQ\.HOSTNAME' "$CONFIG" 2>/dev/null | head -100)
    if [ -n "$URL_EXPRESSION_MATCHES" ]; then
        echo "$URL_EXPRESSION_MATCHES"
        if [ "$FW_PATCHED" = YES ]; then
            status OK 'The build meets the fixed threshold; these partial URL-expression matches are configuration inventory, not a remaining CVE finding.'
        else
            status CHECK 'This partial search found URL expressions; the bulletin does not provide a complete matcher. Review applicable policy expressions and running configuration.'
        fi
    else
        status OK 'No common URL expression strings found in the saved configuration; this partial search does not cover every possible expression.'
    fi

    subsection 'CVE-2026-88775: Gateway or AAA virtual server'
    scan_config 'VPN or authentication virtual servers' '^[[:space:]]*add (vpn|authentication) vserver ' ACTION OK
    if [ "$FW_PATCHED" != YES ]; then
        status CHECK 'Confirm whether matching Gateway/AAA vServers are active if the build is unverified or below threshold.'
    fi

    subsection 'CVE-2026-88776: Oracle load-balancing virtual server'
    scan_config 'Oracle LB virtual servers' '^[[:space:]]*add lb vserver .* ORACLE([[:space:]]|$)' ACTION OK
    if [ "$FW_PATCHED" != YES ]; then status CHECK 'Confirm any Oracle LB match is active if the build is unverified or below threshold.'; fi

    subsection 'CVE-2026-88777: non-HTTP L7 / FTP / RTSP / DNS64 / NAT64 patterns'
    scan_config 'FTP vServers, services, and monitors' '^[[:space:]]*add (lb|cs) vserver .* FTP([[:space:]]|$)|^[[:space:]]*add service .* FTP([[:space:]]|$)|^[[:space:]]*add lb monitor .* FTP(-EXTENDED)?([[:space:]]|$)' ACTION OK
    scan_config 'LSN groups and enabled FTP/RTSP ALG settings' '^[[:space:]]*add lsn group |^[[:space:]]*set lsn group .*-(ftp|rtspalg)[[:space:]]+ENABLED' ACTION OK
    scan_config 'DNS64 and NAT64 configuration' '^[[:space:]]*add lb vserver .* DNS .* -dns64 ENABLED|^[[:space:]]*add dns policy64 |^[[:space:]]*add nat64 ' ACTION OK
    if [ "$FW_PATCHED" = YES ]; then
        status OK 'The entered build meets the fixed threshold; the matches above are configuration inventory, not an indication that a CVE-driven change remains necessary.'
    else
        status CHECK 'LSN groups may use FTP ALG by default; confirm per-group settings and whether DNS64 policy objects are bound to an active DNS vServer. Matches are clues, not proof of exposure.'
    fi

    subsection 'CVE-2026-88778: Enhanced ISN Generation and supported vServer types'
    ISN_VSERVER_LINES=$(grep -E -i '^[[:space:]]*add (lb|cs|vpn|authentication|gslb|cr) vserver .* (HTTP|SSL|SSL_BRIDGE|TCP|SSL_TCP|FTP|NNTP|RTSP|RDP|DNS_TCP|DOT|SIP_TCP|SIP_SSL|DIAMETER|SSL_DIAMETER|MYSQL|MSSQL|ORACLE|SMPP|MQTT|MQTT_TLS|MONGO|MONGO_TLS|PROXY|SSL_PROXY|USER_TCP|USER_SSL_TCP)([[:space:]]|$)' "$CONFIG" 2>/dev/null | head -100)
    if [ -n "$ISN_VSERVER_LINES" ]; then
        printf '%s\n' "$ISN_VSERVER_LINES"
        case "$ISN_STATE" in
            ENABLED) status OK 'Enhanced ISN Generation is ENABLED; the CVE-2026-88778 precondition is not met for these saved-config vServer types.' ;;
            DISABLED) status ACTION 'A listed vServer type is present and Enhanced ISN Generation was reported DISABLED; enable it. This requirement applies even when the firmware meets the fixed-build threshold.' ;;
            *) status CHECK 'A listed vServer type is present, but the live Enhanced ISN Generation state was not supplied. Run show ns tcpparam | grep "Enhanced ISN Generation" and rerun with ENABLED or DISABLED.' ;;
        esac
    else
        status OK 'No Citrix-listed vServer type found in the saved configuration; verify running configuration and confirm TCP configuration applicability.'
    fi
    printf 'ISN state used for this assessment: %s%s\n' "$ISN_STATE" "$( [ "$ISN_STATE" = UNKNOWN ] && printf ' (not verified)' )"
    if [ "$ISN_CONFIG_STATE" = NOT_EXPLICITLY_SET ] && [ "$ISN_STATE" = UNKNOWN ]; then
        status CHECK "Saved config $CONFIG is unavailable or unreadable, and no CLI value was supplied; Enhanced ISN state remains unverified."
    fi
    printf 'vServer search source: %s; Enhanced ISN assessment source: %s\n' "$CONFIG" "$ISN_SOURCE"
else
    status CHECK "Saved config $CONFIG is unavailable; perform all CVE precondition checks against the running configuration."
fi

# Access-control inventory intentionally omits user passwords and password hashes.
# Configuration comparison is deployment-specific, not a firmware hash baseline.
access_control_inventory() {
    awk '
    function user_name(s, i,c,q,escaped,result) {
        match(tolower(s), /^[[:space:]]*add[[:space:]]+system[[:space:]]+user[[:space:]]+/); s=substr(s,RLENGTH+1)
        q=substr(s,1,1); result=""; escaped=0
        if (q != "\"") { sub(/[[:space:]].*$/, "", s); return s }
        for(i=1;i<=length(s);i++) {
            c=substr(s,i,1); result=result c
            if(i>1 && c==q && !escaped) return result
            if(c=="\\" && !escaped) escaped=1; else escaped=0
        }
        return "[unparsed name]"
    }
    {
        raw=$0; low=tolower(raw)
        if(low ~ /^[[:space:]]*add[[:space:]]+system[[:space:]]+user[[:space:]]+/) {
            print "add system user " user_name(raw) " [credentials omitted]"; next
        }
        if(low ~ /^[[:space:]]*(add|set)[[:space:]]+system[[:space:]]+cmdpolicy[[:space:]]+/ ||
           low ~ /^[[:space:]]*add[[:space:]]+system[[:space:]]+group[[:space:]]+/ ||
           low ~ /^[[:space:]]*bind[[:space:]]+system[[:space:]]+(user|group)[[:space:]]+/ ||
           low ~ /^[[:space:]]*(add|set)[[:space:]]+authentication[[:space:]]+(epaaction|policy)[[:space:]]+/ ||
           low ~ /^[[:space:]]*bind[[:space:]]+authentication[[:space:]]+(vserver|policylabel)[[:space:]]+/ ||
           low ~ /^[[:space:]]*(add|set)[[:space:]]+vpn[[:space:]]+sessionpolicy[[:space:]]+/ ||
           low ~ /^[[:space:]]*bind[[:space:]]+vpn[[:space:]]+vserver[[:space:]].*-policy[[:space:]]+/) {
            sub(/^[[:space:]]+/, "", raw); sub(/[[:space:]]+$/, "", raw); print raw
        }
    }' "$1" | sort -u
}
subsection 'Administrative accounts and EPA configuration integrity'
printf '%s\n' 'Purpose: review administrative persistence and authentication-policy changes, including extra accounts, privilege bindings, EPA default groups, and removed bindings. NO_AUTH is a group name, not proof of authentication bypass. Saved-config inventory cannot establish when or by whom a change occurred.'
ACCESS_BASELINE=${DEYDA_CONFIG_BASELINE-}
if [ -r "$CONFIG" ]; then
    ACCESS_CURRENT=$(access_control_inventory "$CONFIG")
    if [ -n "$ACCESS_CURRENT" ]; then
        printf '%s\n' 'Selected administrative and authentication inventory (user credentials omitted; policies and bindings are not necessarily EPA-related):'
        printf '%s\n' "$ACCESS_CURRENT" | head -120
        printf '%s\n' 'Inventory display is limited to 120 lines; optional baseline comparison uses all selected lines.'
    else
        status OK 'No selected administrative-account or authentication-policy statements found in the saved configuration; defaults and live configuration are outside this inventory.'
    fi
    if [ -n "$ACCESS_BASELINE" ]; then
        if [ "$ACCESS_BASELINE" = "$CONFIG" ]; then
            status CHECK 'The supplied access-control baseline is the scanned configuration itself; supply an independent, approved pre-incident backup.'
        elif [ -f "$ACCESS_BASELINE" ] && [ -r "$ACCESS_BASELINE" ]; then
            ACCESS_BEFORE=$(access_control_inventory "$ACCESS_BASELINE")
            ACCESS_DIFF=$( {
                printf '%s\n' "$ACCESS_BEFORE"
                printf '%s\n' '__DEYDA_ACCESS_BASELINE_END__'
                printf '%s\n' "$ACCESS_CURRENT"
            } | awk '
                $0=="__DEYDA_ACCESS_BASELINE_END__" {current=1; next}
                NF && !current {before[$0]=1; next}
                NF && current {after[$0]=1}
                END {
                    for(line in after) if(!(line in before)) print "ADDED/CHANGED: " line
                    for(line in before) if(!(line in after)) print "REMOVED/CHANGED: " line
                }' | sort)
            if [ -n "$ACCESS_DIFF" ]; then
                status CHECK "Selected access-control statements differ from approved baseline $ACCESS_BASELINE. Verify authorization, effective policy flow, and timestamps; differences alone do not establish compromise:"
                printf '%s\n' "$ACCESS_DIFF" | head -120
            else
                status OK "All selected access-control statements match baseline $ACCESS_BASELINE. Password values are excluded; verify the baseline predates suspected activity and belongs to this deployment."
            fi
        else
            status CHECK "Access-control baseline $ACCESS_BASELINE is not a readable regular file."
        fi
    else
        status CHECK 'No approved configuration baseline supplied. New accounts and removed EPA bindings cannot be established automatically. Use DEYDA_CONFIG_BASELINE=/path/to/approved-ns.conf when starting this script; compare running configuration separately.'
    fi
else
    status CHECK 'Saved configuration is unreadable; administrative-account and EPA configuration inventory could not run.'
fi


subsection 'SAML request workaround: saved policy and binding inventory'
# Inventory only. A name match cannot verify the vendor workaround or live coverage.
if [ -r "$CONFIG" ]; then
    SAML_ACTIONS=$(grep -Ei '^[[:space:]]*add[[:space:]]+authentication[[:space:]]+samlAction[[:space:]]' "$CONFIG" 2>/dev/null | wc -l | tr -d ' ')
    printf 'Saved SAML action count: %s\n' "$SAML_ACTIONS"
    SAML_OTHER_CONFIG=$(grep -Ei '^[[:space:]]*(add[[:space:]]+authentication[[:space:]]+samlIdPProfile[[:space:]]|(add|set)[[:space:]]+vpn[[:space:]]+sessionAction[[:space:]].*-samlSSO[[:space:]]+ENABLED)' "$CONFIG" 2>/dev/null | wc -l | tr -d ' ')
    if [ "$SAML_ACTIONS" -eq 0 ] && [ "$SAML_OTHER_CONFIG" -eq 0 ] && ! grep -Eiq '^[[:space:]]*add[[:space:]]+responder[[:space:]]+policy[[:space:]]+pol_samlauth_prefixlist_block[[:space:]]' "$CONFIG"; then
        status OK 'No SAML authentication actions, selected SAML IdP/SSO settings, or named workaround policy found in saved configuration; the SAML workaround warning is not applicable in this scanned scope. Unsaved live changes are outside coverage.'
    else
    SAML_WARNING_LEVEL=CHECK
    if [ "$SAML_ACTIONS" -gt 0 ]; then SAML_WARNING_LEVEL=ACTION; fi
    SAML_WORKAROUND_PRESENT=NO
    if grep -Eiq '^[[:space:]]*add[[:space:]]+responder[[:space:]]+policy[[:space:]]+pol_samlauth_prefixlist_block[[:space:]]' "$CONFIG"; then
        SAML_WORKAROUND_PRESENT=YES
        SAML_POLICY_SHAPE=$(grep -Ei '^[[:space:]]*add[[:space:]]+responder[[:space:]]+policy[[:space:]]+pol_samlauth_prefixlist_block[[:space:]]' "$CONFIG" |
            grep -Ei '/cgi/samlauth' | grep -Ei 'PrefixList' | grep -Ei 'B64DECODE' | grep -Ei '[[:space:]]DROP([[:space:]]|$)' | wc -l | tr -d ' ')
        if [ "$SAML_POLICY_SHAPE" -gt 0 ]; then
            status CHECK 'The named SAML workaround policy includes selected path/PrefixList/decode/DROP markers. This is not an exact expression validation: compare the full expression and action with current Citrix Support instructions, then test legitimate SAML sign-ins.'
        else
            status "$SAML_WARNING_LEVEL" 'WARNING: The named SAML workaround policy exists but lacks one or more selected expression/action markers. Its name alone does not establish protection; compare the actual policy with Citrix Support instructions.'
        fi
    else
        status "$SAML_WARNING_LEVEL" 'WARNING: pol_samlauth_prefixlist_block is missing from saved configuration. If SAML is used, verify and implement the current approved Citrix Support workaround, including its required bindings. Another policy name or unsaved mitigation must be checked manually; no change was made by this script.'
    fi
    SAML_WORKAROUND_BINDINGS=$(awk '
    {line=tolower($0)}
    line ~ /^[ \t]*bind (vpn|authentication) vserver / && line ~ /-type[ \t]+aaa_request([ \t]|$)/ && line !~ /-state[ \t]+disabled([ \t]|$)/ {
        for(i=1;i<NF;i++) if(tolower($i)=="-policy" || tolower($i)=="-policyname") {
            name=$(i+1); gsub(/"/,"",name); if(name=="pol_samlauth_prefixlist_block") n++
        }
    }
    END{print n+0}' "$CONFIG")
    printf 'Named Gateway/AAA AAA_REQUEST binding count: %s\n' "$SAML_WORKAROUND_BINDINGS"
    if [ "$SAML_WORKAROUND_PRESENT" = YES ] && [ "$SAML_WORKAROUND_BINDINGS" -eq 0 ]; then
        status "$SAML_WARNING_LEVEL" 'WARNING: The workaround policy exists, but no enabled named AAA_REQUEST binding was found on a Gateway/AAA vServer. Creating a policy or binding it globally alone does not establish request-path coverage. Verify every relevant SAML frontend and bind according to current Citrix Support instructions.'
    elif [ "$SAML_WORKAROUND_PRESENT" = YES ] && [ "$SAML_WORKAROUND_BINDINGS" -gt 0 ]; then
        status OK 'The named workaround policy and at least one Gateway/AAA AAA_REQUEST binding are present in saved configuration. This confirms presence only; expression correctness, priority and complete live SAML flow coverage still require validation.'
    fi
    # Standard whitespace-delimited object names. Quoted names need manual review.
    awk '
    BEGIN {IGNORECASE=0}
    { line=tolower($0) }
    line ~ /^[ \t]*add (vpn|authentication) vserver / {kind=$2; name=$4; keys[kind SUBSEP name]=1}
    line ~ /^[ \t]*bind (vpn|authentication) vserver / && line ~ /-type[ \t]+aaa_request([ \t]|$)/ && line !~ /-state[ \t]+disabled([ \t]|$)/ {
        for(i=1;i<NF;i++) if(tolower($i)=="-policy" || tolower($i)=="-policyname") {
            policy=$(i+1); gsub(/"/,"",policy); if(policy=="pol_samlauth_prefixlist_block") bound[$2 SUBSEP $4]=1
        }
    }
    END {for(k in keys) {split(k,a,SUBSEP); if (a[2] ~ /"/) print "[CHECK] Quoted vServer name requires manual SAML binding review: " a[1] " " a[2]; else if(bound[k]) print "[CHECK] Named AAA_REQUEST binding found for " a[1] " vServer " a[2] "; validate priority, expression, flow and live configuration."; else print "[CHECK] No named AAA_REQUEST workaround binding found for " a[1] " vServer " a[2] "; determine whether this vServer handles SAML and needs the approved workaround."}}
    ' "$CONFIG"
    status CHECK 'This is saved-config inventory only. Other policy names, disabled objects, authentication profiles, frontend AAA mappings and unsaved changes require live review. A global binding alone is not counted as Gateway/AAA request coverage.'
    fi
else
    status CHECK 'Saved configuration unreadable; SAML workaround inventory unavailable.'
fi

if [ "$RUNNING_ON_ADC" = YES ]; then
section '3. Host integrity and persistence'
subsection 'Purpose and follow-up'
printf '%s\n' 'Purpose: review reboot/core history, install timing, startup/persistence locations, user-owned processes, shell permissions, and selected SUID/SGID files.'
printf '%s\n' 'For each [CHECK]: compare path, owner, mode, hash, and timestamp with a trusted appliance on the same build; correlate with installns_state, change records, and HA peer evidence. Preserve unexpected files before changing them.'
printf '\n--- Firmware installation directory / possible review window ---\n'
if [ -d /var/nsinstall ]; then
    ls -lt /var/nsinstall 2>/dev/null | head -8
    INSTALL_STATE_FILE=/var/nsinstall/installns_state
    INSTALL_EPOCH=''
    if [ -r "$INSTALL_STATE_FILE" ]; then
        if command -v perl >/dev/null 2>&1; then
            INSTALL_EPOCH=$(perl -e '@s=stat($ARGV[0]); print $s[9] if @s' "$INSTALL_STATE_FILE" 2>/dev/null)
        elif stat -f %m "$INSTALL_STATE_FILE" >/dev/null 2>&1; then
            INSTALL_EPOCH=$(stat -f %m "$INSTALL_STATE_FILE" 2>/dev/null)
        elif stat -c %Y "$INSTALL_STATE_FILE" >/dev/null 2>&1; then
            INSTALL_EPOCH=$(stat -c %Y "$INSTALL_STATE_FILE" 2>/dev/null)
        fi
    fi
    if [ -n "$INSTALL_EPOCH" ]; then
        INSTALL_TIME=$(date -r "$INSTALL_EPOCH" '+%Y-%m-%d %H:%M:%S %Z' 2>/dev/null)
        [ -n "$INSTALL_TIME" ] || INSTALL_TIME=$(perl -MPOSIX -e 'print strftime("%Y-%m-%d %H:%M:%S %Z", localtime($ARGV[0]))' "$INSTALL_EPOCH" 2>/dev/null)
        printf 'Install-time marker: %s\nFile: %s\n' "${INSTALL_TIME:-epoch $INSTALL_EPOCH (date formatting unavailable)}" "$INSTALL_STATE_FILE"
        status CHECK 'The marker is the file modification time, not independent proof of a completed firmware installation; verify it against change records and appliance version/boot history.'
    else
        status CHECK "$INSTALL_STATE_FILE is absent, unreadable, or its modification time could not be read; no install time was inferred."
    fi
else
    status CHECK '/var/nsinstall is unavailable; no install-time marker could be read.'
fi

subsection 'Recent reboot / shutdown history'
if command -v last >/dev/null 2>&1; then
    last -n 80 2>&1 | head -80
    status CHECK 'Correlate any unexpected reboot/cold-start time with HTTP access logs; no reboot entry is not proof that none occurred.'
else
    status CHECK 'The last command is unavailable; review system event and reboot history manually.'
fi



printf '\n--- Recent core/crash files (last 14 days) ---\n'
CRASH_DIRS_FOUND=0
for d in /var/core /var/crash; do [ -d "$d" ] && CRASH_DIRS_FOUND=$((CRASH_DIRS_FOUND + 1)); done
RECENT_CRASHES=$(find /var/core /var/crash -type f ! -name bounds -mtime -14 -print 2>/dev/null | head -100)
if [ -n "$RECENT_CRASHES" ]; then
    status CHECK 'Recent core/crash dump files found (excluding the bounds index); correlate with appliance events and preserve before cleanup:'
    echo "$RECENT_CRASHES"
elif [ "$CRASH_DIRS_FOUND" -eq 0 ]; then
    status OK 'No recent core/crash dump files found in the checked paths; /var/core/bounds is excluded because it is an index file.'
else
    status OK 'No core/crash files modified within the last 14 days found in the checked directories.'
fi
if [ -r "${INSTALL_STATE_FILE-}" ]; then
    POST_INSTALL_CORES=$(find /var/core /var/crash -type f ! -name bounds -newer "$INSTALL_STATE_FILE" -print 2>/dev/null | head -100)
    if [ -n "$POST_INSTALL_CORES" ]; then
        status CHECK 'Core/crash files newer than installns_state were found; correlate with DTLS/NSPPE events and preserve before cleanup:'
        printf '%s\n' "$POST_INSTALL_CORES"
    else
        status OK 'No core/crash files newer than installns_state were found in /var/core or /var/crash.'
    fi
else
    status CHECK 'Core/crash recency could not be compared with the install marker; the recent-14-day check above is the only automated time window.'
fi


printf '\n--- Possible temporary callhome artifacts ---\n'
CALLHOME_FILES=$(find /var/tmp -type f -name 'callhome_tmps*' -print 2>/dev/null | head -50)
if [ -n "$CALLHOME_FILES" ]; then
    status CHECK 'callhome_tmps* files found; verify whether they are expected for this appliance and preserve unexpected files:'
    echo "$CALLHOME_FILES"
else
    status OK 'No callhome_tmps* files found under /var/tmp.'
fi

printf '\n--- Security-relevant files modified since the install marker ---\n'
INSTALL_SCOPE_DIRS_FOUND=0
INSTALL_SCOPE_HITS=''
for d in /var/vpn /var/netscaler/logon /var/python /netscaler/ns_gui /var/nsproflog /var/netscaler/gui /netscaler/portal; do
    [ -d "$d" ] || continue
    INSTALL_SCOPE_DIRS_FOUND=$((INSTALL_SCOPE_DIRS_FOUND + 1))
    if [ -r "${INSTALL_STATE_FILE-}" ]; then
        newer=$(find "$d" -type f -newer "$INSTALL_STATE_FILE" -print 2>/dev/null | head -100)
        if [ -n "$newer" ]; then INSTALL_SCOPE_HITS="${INSTALL_SCOPE_HITS}${INSTALL_SCOPE_HITS:+
--- $d ---
}$newer"; fi
    fi
done
if [ -n "$INSTALL_SCOPE_HITS" ]; then
    status CHECK 'Files newer than /var/nsinstall/installns_state were found in the selected security-relevant trees. The list is capped at 100 per tree; upgrades and approved changes commonly modify files, so validate each against the change window and same-build baseline:'
    printf '%s\n' "$INSTALL_SCOPE_HITS"
elif [ -r "${INSTALL_STATE_FILE-}" ] && [ "$INSTALL_SCOPE_DIRS_FOUND" -gt 0 ]; then
    status OK 'No files newer than the installns_state marker were found in the selected security-relevant trees; this is limited to those paths and filesystem timestamps.'
elif [ "$INSTALL_SCOPE_DIRS_FOUND" -eq 0 ]; then
    status CHECK 'None of the selected security-relevant trees exists; post-install file-change coverage is unavailable.'
else
    status CHECK 'No readable installns_state marker is available; the post-install file-change search could not run.'
fi

subsection 'Reported persistence account in saved configuration'
PERSISTENCE_ACCOUNT_CONFIG=''
for f in /nsconfig/ns.conf /flash/nsconfig/ns.conf /nsconfig/ns.conf.default; do
    [ -r "$f" ] || continue
    if grep -E -i -q '^[[:space:]]*add[[:space:]]+system[[:space:]]+user[[:space:]]+sec_monitor([[:space:]]|$)' "$f" 2>/dev/null; then PERSISTENCE_ACCOUNT_CONFIG="$f"; fi
done
if [ -n "$PERSISTENCE_ACCOUNT_CONFIG" ]; then
    status CHECK 'The account name sec_monitor appears in a saved configuration. This name was reported in public incident research but may be locally legitimate; verify its owner, creation time, group bindings, and approval without exposing credential fields.'
else
    status OK 'No saved-config system-user entry named sec_monitor found in the checked configuration files. This does not cover transient/live-only accounts or other names.'
fi
subsection 'Administrative persistence payloads and temporary configuration exports'
for f in /var/tmp/c1.txt /var/tmp/c2.txt /var/tmp/labels.txt; do
    if [ -e "$f" ]; then
        status CHECK "Observed payload-associated filename exists: $f. This generic name alone is not an IOC. Preserve and inspect origin, timestamp, owner, and content; configuration exports can contain secrets and are not printed here."
        ls -ldn "$f" 2>&1
        printf 'SHA-256: %s\n' "$(sha256_of "$f")"
    else
        status OK "No $f artifact found."
    fi
done
ACCESS_PAYLOAD_CANDIDATES=$(find /var/tmp /tmp /nsconfig /flash/nsconfig -type f -size -1024k -print 2>/dev/null | head -501)
ACCESS_PAYLOAD_COUNT=$(printf '%s\n' "$ACCESS_PAYLOAD_CANDIDATES" | awk 'NF {n++} END {print n+0}')
ACCESS_PAYLOAD_HITS=0
printf '%s\n' 'Payload search: up to 500 readable regular files below 1 MiB in /var/tmp, /tmp, /nsconfig, and /flash/nsconfig; own generated reports excluded. Larger files, unreadable files, and other paths are outside coverage.'
while IFS= read -r f; do
    [ -n "$f" ] && [ -r "$f" ] || continue
    case "$f" in /var/tmp/deyda-netscaler-ioc-check_*.txt) continue ;; esac
    if grep -E -i -q 'add[[:space:]]+system[[:space:]]+user[[:space:]]' "$f" 2>/dev/null &&
       grep -E -i -q 'bind[[:space:]]+system[[:space:]]+user[[:space:]]' "$f" 2>/dev/null &&
       grep -E -i -q 'set[[:space:]]+authentication[[:space:]]+epaAction.*-defaultEPAGroup[[:space:]]+NO_AUTH' "$f" 2>/dev/null &&
       grep -E -i -q 'unbind[[:space:]]+(authentication[[:space:]]+(vserver|policylabel)|vpn[[:space:]]+vserver)' "$f" 2>/dev/null &&
       grep -E -i -q 'save[[:space:]]+ns[[:space:]]+config' "$f" 2>/dev/null; then
        ACCESS_PAYLOAD_HITS=$((ACCESS_PAYLOAD_HITS + 1))
        status ACTION "Combined administrative-persistence payload pattern found in $f: user creation/binding, EPA NO_AUTH change, policy unbinding, and config save. Preserve and verify whether this is an approved tool; file content is evidence of a payload, not proof of execution."
        ls -ldn "$f" 2>&1
        printf 'SHA-256: %s\n' "$(sha256_of "$f")"
    fi
done <<ACCESS_PAYLOAD_EOF
$(printf '%s\n' "$ACCESS_PAYLOAD_CANDIDATES" | head -500)
ACCESS_PAYLOAD_EOF
if [ "$ACCESS_PAYLOAD_HITS" -eq 0 ]; then
    status OK 'No combined account/EPA modification payload signature found in the bounded candidate-file search.'
fi
if [ "$ACCESS_PAYLOAD_COUNT" -gt 500 ]; then
    status CHECK 'Administrative-payload file search reached its 500-file limit; this partial scan does not cover all files in the selected directories.'
fi

subsection 'Targeted Perl implant and payload staging checks'
progress 'Host integrity: targeted Perl implant and payload staging checks'
NSMON_PATH_FOUND=0
for f in /var/tmp/.nsmon /var/tmp/.nsmon/nsmon.pl /var/tmp/.nsmon/.cfg /var/tmp/.nsmon/.state; do
    [ -e "$f" ] || continue
    NSMON_PATH_FOUND=1
    ls -ldn "$f" 2>/dev/null
    if [ -f "$f" ]; then printf 'SHA-256: %s\n' "$(sha256_of "$f")"; fi
done
if [ "$NSMON_PATH_FOUND" -eq 1 ]; then
    status CHECK 'nsmon-associated paths exist. Preserve them and compare content, owner, and origin; filenames alone do not prove an implant ran.'
else
    status OK 'No selected /var/tmp/.nsmon paths found.'
fi
NSMON_PS=$(ps auxww 2>/dev/null)
if [ -z "$NSMON_PS" ]; then
    status CHECK 'Process inventory unavailable for the targeted nsmon check.'
else
    NSMON_RUNNING=$(printf '%s\n' "$NSMON_PS" | awk '/nsmon[.]pl|\/var\/tmp\/[.]nsmon\// && !/awk|grep|deyda-netscaler-ioc-check/ {print}')
    if [ -n "$NSMON_RUNNING" ]; then
        status ACTION 'A process command line refers to nsmon.pl or the .nsmon implant path. Preserve process/socket evidence and verify authorization; normal nsmonitor names are excluded:'
        printf '%s\n' "$NSMON_RUNNING" | head -20
    else
        status OK 'No selected nsmon.pl/.nsmon process command line found in the current snapshot.'
    fi
fi
NSMON_CRON=$(grep -nE 'nsmon[.]pl|/var/tmp/[.]nsmon/' /etc/crontab /nsconfig/crontab /flash/nsconfig/crontab /var/cron/tabs/* 2>/dev/null)
if [ -n "$NSMON_CRON" ]; then
    status ACTION 'Cron content refers to an nsmon-associated script/path. Preserve the tab and referenced file, and verify the scheduled command against approved administration:'
    printf '%s\n' "$NSMON_CRON" | head -30
else
    status OK 'No nsmon-associated script/path reference found in readable system or spool crontab files. General cron coverage is reported below.'
fi
if command -v sockstat >/dev/null 2>&1; then
    NSMON_SOCKET_SNAPSHOT=$(sockstat -4 -l 2>/dev/null)
    if [ -n "$NSMON_SOCKET_SNAPSHOT" ]; then
        NSMON_LISTENERS=$(printf '%s\n' "$NSMON_SOCKET_SNAPSHOT" | awk '$2 ~ /^perl/ && $6 ~ /:41[0-9][0-9][0-9]$/ {print}')
        if [ -n "$NSMON_LISTENERS" ]; then
            status CHECK 'Perl is listening on TCP 41000-41999, a reported implant port range. The port alone is not proof; correlate PID, executable, command line, cron, and .nsmon files:'
            printf '%s\n' "$NSMON_LISTENERS"
        else
            status OK 'No Perl TCP listener in the selected 41000-41999 range found in the IPv4 snapshot.'
        fi
    else
        status CHECK 'sockstat returned no usable listener inventory; targeted Perl-listener coverage is unavailable.'
    fi
else
    status CHECK 'sockstat is unavailable; the targeted Perl-listener check could not run.'
fi
for f in /v /tmp/v /var/tmp/v; do
    [ -f "$f" ] || continue
    status CHECK "Payload-associated generic path $f exists. Name alone is insufficient; preserve and inspect content and related download/execution logs."
    ls -ln "$f" 2>/dev/null
    printf 'SHA-256: %s\n' "$(sha256_of "$f")"
done

subsection 'Reported .slap/.ux persistence and tunnel indicators'
progress 'Host integrity: reported .slap/.ux persistence and tunnel indicators'
printf '%s\n' 'Source: operator-supplied 380d56 sample-analysis screenshot and follow-up description; independently unverified. No incomplete hash is used. Names/ports are leads, not automatic proof of compromise.'
SLAP_ARTIFACTS_FOUND=0
for f in /nsconfig/.slap /flash/nsconfig/.slap /nsconfig/.slap/agent.pl /nsconfig/.slap/bridge.pl /nsconfig/.slap/boot.sh /flash/nsconfig/.slap/agent.pl /flash/nsconfig/.slap/bridge.pl /flash/nsconfig/.slap/boot.sh /var/tmp/.ux /var/tmp/.ux/slapshot.py /var/tmp/.ux/whipd.py /var/tmp/.ux/whippid.py /etc/httpd.conf.slap.bak; do
    [ -e "$f" ] || continue
    SLAP_ARTIFACTS_FOUND=1
    status CHECK "Sample-associated path $f exists. Preserve and validate content, origin, metadata, and matching persistence/socket evidence. Name alone is insufficient."
    ls -ldn "$f" 2>/dev/null
    if [ -f "$f" ] && [ -r "$f" ]; then
        printf 'SHA-256 observed: %s\n' "$(sha256_of "$f")"
        # Require multiple behavior markers in the SAME file. Do not print cookies,
        # tokens, private keys or full source; no discovered code is ever executed.
        if grep -qiE 'X[-_]Cmd|HTTP_X_CMD' "$f" &&
           grep -qiE 'b64decode|decode_base64|base64_decode' "$f" &&
           grep -qiE 'subprocess|os[.]system|shell_exec|passthru|exec[[:space:]]*\(' "$f"; then
            status ACTION "Combined command-header, Base64-decoder and execution-code markers found in $f. This is stronger than a filename match; preserve for offline analysis. It does not establish when the file ran."
        fi
    fi
done
[ "$SLAP_ARTIFACTS_FOUND" -eq 1 ] || status OK 'No selected .slap/.ux persistence/tunnel paths or httpd.conf.slap.bak found.'
SLAP_STAGING_FILES=$(find /var/tmp -maxdepth 1 \( -name '.s2loot' -o -name '.slap-*' \) -print 2>/dev/null | head -50)
if [ -n "$SLAP_STAGING_FILES" ]; then
    status CHECK 'Reported .s2loot staging directory or .slap-* artifact found under /var/tmp. Preserve metadata and inspect offline; filenames alone do not establish that data was uploaded. Contents may contain configuration secrets and are not printed:'
    while IFS= read -r f; do
        ls -ldn "$f" 2>/dev/null
        [ -f "$f" ] && printf 'SHA-256: %s\n' "$(sha256_of "$f")"
    done <<EOF_SLAP_STAGING
$SLAP_STAGING_FILES
EOF_SLAP_STAGING
else
    status OK 'No selected /var/tmp/.s2loot or /var/tmp/.slap-* path found. Deleted staging artifacts are outside filesystem coverage.'
fi
SLAP_BACKUP_FILES=$(find /nsconfig/.slap /flash/nsconfig/.slap -type f -print 2>/dev/null | head -50)
if [ -n "$SLAP_BACKUP_FILES" ]; then
    status CHECK 'Files exist in reported persistent .slap backup directories. A saved webshell can be restored by boot/cron even after a served copy is removed. Preserve and compare; only metadata/hashes are printed (maximum 50 files):'
    while IFS= read -r f; do
        ls -ln "$f" 2>/dev/null
        printf 'SHA-256: %s\n' "$(sha256_of "$f")"
    done <<EOF_SLAP_BACKUPS
$SLAP_BACKUP_FILES
EOF_SLAP_BACKUPS
fi
SLAP_PERSISTENCE=$(grep -nE '/(flash/)?nsconfig/[.]slap/|/var/tmp/[.]ux/(slapshot|whipd|whippid)[.]py|httpd[.]conf[.]slap[.]bak' \
    /nsconfig/rc.netscaler /flash/nsconfig/rc.netscaler /nsconfig/nsafter.sh /etc/monitrc /etc/crontab /nsconfig/crontab /flash/nsconfig/crontab /var/cron/tabs/* 2>/dev/null | head -40)
if [ -n "$SLAP_PERSISTENCE" ]; then
    status ACTION 'Startup/monitoring/cron content refers to sample-associated hidden payload paths. Preserve the configuration and referenced files; verify authorization and correlate execution events:'
    printf '%s\n' "$SLAP_PERSISTENCE"
else
    status OK 'No selected hidden .slap/.ux payload-path reference found in readable candidate startup/monitoring/cron files. General coverage is reported below.'
fi
SLAP_PROCESS_SNAPSHOT=$(ps auxww 2>/dev/null)
if [ -n "$SLAP_PROCESS_SNAPSHOT" ]; then
    SLAP_PROCESSES=$(printf '%s\n' "$SLAP_PROCESS_SNAPSHOT" | awk '/\/(flash\/)?nsconfig\/[.]slap\/|\/var\/tmp\/[.]ux\/(slapshot|whipd|whippid)[.]py/ && !/awk|grep|deyda-netscaler-ioc-check/ {print}')
    if [ -n "$SLAP_PROCESSES" ]; then
        status ACTION 'Current process command line refers to a sample-associated hidden payload path. Preserve PID/executable/socket evidence and investigate; command-line identity alone does not authenticate the binary:'
        printf '%s\n' "$SLAP_PROCESSES" | head -20
    else
        status OK 'No selected .slap/.ux payload path found in the current process command lines.'
    fi
else
    status CHECK 'Process inventory unavailable for the reported .slap/.ux tunnel checks.'
fi
if command -v sockstat >/dev/null 2>&1; then
    SLAP_SOCKETS=$(sockstat -4 -l 2>/dev/null)
    if [ -n "$SLAP_SOCKETS" ]; then
        SLAP_PORTS=$(printf '%s\n' "$SLAP_SOCKETS" | awk '$5 == "tcp4" && $6 ~ /:(9909|9910)$/ {print}')
        if [ -n "$SLAP_PORTS" ]; then
            status CHECK 'TCP listener on sample-reported port 9909 or 9910 found. Ports may be legitimate; correlate owner/PID, bind address, executable and .slap/.ux files:'
            printf '%s\n' "$SLAP_PORTS"
        else
            status OK 'No IPv4 TCP listener on selected sample-reported ports 9909/9910 found in the current snapshot.'
        fi
    else
        status CHECK 'No usable IPv4 listener snapshot returned for the 9909/9910 check.'
    fi
else
    status CHECK 'sockstat unavailable; sample-reported tunnel ports were not assessed.'
fi

subsection 'Cron and startup persistence'
printf '%s\n' 'Inventory scheduled tasks and startup files. Existing entries are not automatically suspicious; validate ownership, commands, timestamps, and purpose against an approved same-build baseline.'

printf '\n--- /etc/crontab ---\n'
if [ -r /etc/crontab ]; then
    CRON_LINES=$(grep -v '^[[:space:]]*#' /etc/crontab 2>/dev/null | grep -v '^[[:space:]]*$')
    if [ -z "$CRON_LINES" ]; then
        status OK '/etc/crontab is readable and contains no active entries.'
    elif [ "${CURRENT_INPUT-}" = '14.1-73.37.nc' ] || [ "${CURRENT_INPUT-}" = '14.1-73.37' ]; then
        CRON_UNRECOGNIZED=''
        while IFS= read -r CRON_LINE; do
            CRON_NORMALIZED=$(printf '%s\n' "$CRON_LINE" | sed 's/[[:space:]][[:space:]]*/ /g; s/^ //; s/ $//')
            case "$CRON_NORMALIZED" in
                '0 * * * * root newsyslog'|\
                '0 0 * * * root purge_tickets.sh'|\
                '1,31 0-5 * * * root adjkerntz -a'|\
                '*/30 * * * * root curl http://localhost -o /dev/null 2>&1 > /dev/null'|\
                '0 */12 * * * root /netscaler/adss-licexp.sh'|\
                '0 * * * * root /netscaler/ns_cleanup.sh'|\
                '* * * * * root lockf -t 0 -k -s /tmp/.nsfsyncd_lock /netscaler/nsfsyncd -p'|\
                '55 0-23 * * * root nslog.sh dozip'|\
                '28 0-23 * * * root nslog.sh dozip'|\
                'SHELL=/bin/sh'|\
                'PATH=/netscaler:/etc:/bin:/sbin:/usr/bin:/usr/sbin'|\
                'HOME=/var/log') ;;
                *) CRON_UNRECOGNIZED="${CRON_UNRECOGNIZED}${CRON_UNRECOGNIZED:+\n}$CRON_LINE" ;;
            esac
        done <<CRON_EOF
$CRON_LINES
CRON_EOF
        if [ -n "$CRON_UNRECOGNIZED" ]; then
            status CHECK 'Unrecognized /etc/crontab entries differ from the internal 14.1-73.37 sample; validate schedule and command. The comparison covers one appliance, not a Citrix-published universal baseline:'
            printf '%b\n' "$CRON_UNRECOGNIZED"
        else
            status OK 'All /etc/crontab entries match recognized NetScaler defaults in the internal 14.1-73.37 sample, including cron environment settings and the nslog.sh dozip schedule. This is a single-appliance reference, not a Citrix-published universal baseline.'
        fi
    else
        status CHECK 'Non-comment entries are present in /etc/crontab; validate each scheduled command against a trusted same-build baseline:'
        printf '%s\n' "$CRON_LINES"
    fi
elif [ -e /etc/crontab ]; then
    status CHECK '/etc/crontab exists but is unreadable; cron-file content was not assessed.'
else
    status OK '/etc/crontab is absent on this appliance.'
fi

if command -v crontab >/dev/null 2>&1; then
    for CRON_USER in root nsroot nobody; do
        printf '\n--- crontab for %s ---\n' "$CRON_USER"
        CRON_OUTPUT=$(crontab -u "$CRON_USER" -l 2>&1)
        CRON_RC=$?
        CRON_ACTIVE=$(printf '%s\n' "$CRON_OUTPUT" | grep -v '^[[:space:]]*#' | grep -v '^[[:space:]]*$' | grep -v "^crontab: no crontab for ${CRON_USER}$")
        if [ "$CRON_RC" -eq 0 ]; then
            if [ -n "$CRON_ACTIVE" ]; then status CHECK "Crontab entries exist for $CRON_USER; validate each scheduled command:"; printf '%s\n' "$CRON_ACTIVE"; else status OK "No active crontab entries found for $CRON_USER."; fi
        elif printf '%s\n' "$CRON_OUTPUT" | grep -q "no crontab for ${CRON_USER}"; then
            status OK "No crontab is defined for $CRON_USER."
        else
            status CHECK "Could not read the $CRON_USER crontab (exit $CRON_RC); review manually:"; printf '%s\n' "$CRON_OUTPUT"
        fi
    done
else
    status CHECK 'crontab utility is unavailable; per-user crontabs could not be enumerated.'
fi

printf '\n--- /var/cron/tabs inventory ---\n'
if [ -d /var/cron/tabs ]; then
    printf '%s\n' 'This enumerates every regular per-user crontab file, including users beyond root, nsroot, and nobody checked above. Filenames identify the account; active entries are shown for manual validation.'
    CRON_TAB_LIST=$(ls -la /var/cron/tabs 2>&1)
    printf '%s\n' "$CRON_TAB_LIST"
    CRON_TAB_FILES=$(find /var/cron/tabs -type f -print 2>/dev/null)
    if [ -n "$CRON_TAB_FILES" ]; then
        for f in $CRON_TAB_FILES; do
            ls -l "$f" 2>&1
            CRON_TAB_ACTIVE=$(grep -v '^[[:space:]]*#' "$f" 2>/dev/null | grep -v '^[[:space:]]*$')
            if [ -n "$CRON_TAB_ACTIVE" ]; then
                status CHECK "Active lines are present in $f; validate the owner, schedule, command, and purpose against the approved baseline:"
                printf '%s\n' "$CRON_TAB_ACTIVE"
            else
                status OK "$f contains no active non-comment lines."
            fi
        done
    else
        status OK 'No regular files were found in /var/cron/tabs.'
    fi
else
    status OK '/var/cron/tabs directory is absent on this appliance.'
fi

printf '\n--- Startup and monitoring persistence files ---\n'
PERSIST_FILES_FOUND=0
PERSIST_READABLE=0
RCN_PRIMARY_HASH=''
for f in /nsconfig/rc.netscaler /nsconfig/nsafter.sh /flash/nsconfig/rc.netscaler /etc/monitrc; do
    if [ -e "$f" ]; then
        PERSIST_FILES_FOUND=$((PERSIST_FILES_FOUND + 1))
        printf '\n    File: %s\n' "$f"
        ls -la "$f" 2>&1
        case "$f" in
            /nsconfig/rc.netscaler)
                RCN_PRIMARY_HASH=$(sha256_of "$f")
                check_1417337_reference "$f" '7f65ac090000fda7fed9fb56b2d4e7678181f4f9fac71961e4336fdfa7cbf738'
                ;;
            /flash/nsconfig/rc.netscaler)
                RCN_SECONDARY_HASH=$(sha256_of "$f")
                if [ -n "$RCN_PRIMARY_HASH" ] && [ "$RCN_PRIMARY_HASH" = "$RCN_SECONDARY_HASH" ]; then
                    status OK '/flash/nsconfig/rc.netscaler has the same SHA-256 content as /nsconfig/rc.netscaler; the baseline comparison is reported once.'
                else
                    check_1417337_reference "$f" '7f65ac090000fda7fed9fb56b2d4e7678181f4f9fac71961e4336fdfa7cbf738'
                fi
                ;;
            /etc/monitrc)
                check_1417337_reference "$f" 'ab1aae7ba469c122ae16a992da9ddc4b12f81301b0b05d8eba2b379a06d56e54'
                ;;
        esac
        if [ -r "$f" ] && [ -f "$f" ]; then
            PERSIST_READABLE=$((PERSIST_READABLE + 1))
            PERSIST_HITS=$(grep -E -i -n 'curl|wget|fetch[[:space:]]|base64[.](b64|b85)decode|python[0-9.]*[[:space:]]+-c|chmod[[:space:]].*([+]s|[2467][0-7]{3})|/var/tmp/|/tmp/|\.ctxs\.receiver|receiver[.]min|php_flag[[:space:]]+engine[[:space:]]+on|kill[[:space:]]+-9|nohup' "$f" 2>/dev/null)
            if [ -n "$PERSIST_HITS" ]; then
                status CHECK "Selected command or persistence patterns found in $f; review in context and compare with the approved baseline:"
                printf '%s\n' "$PERSIST_HITS" | head -40
            else
                status OK "No selected high-signal command patterns found in $f; file contents still require baseline review."
            fi
        else
            status CHECK "$f exists but is not readable as a regular file; content was not inspected."
        fi
    else
        printf '\n%s: absent\n' "$f"
    fi
done
if [ "$PERSIST_FILES_FOUND" -eq 0 ]; then
    status OK 'None of the listed startup/monitoring persistence files exists.'
else
    status CHECK "$PERSIST_FILES_FOUND listed startup/monitoring file(s) exist ($PERSIST_READABLE readable); existence is inventory, not evidence of compromise. Compare content, owner, mode, and timestamps with the same-build baseline."
fi

printf '\n--- Python references in rc.netscaler ---\n'
if [ -r /flash/nsconfig/rc.netscaler ]; then
    RCN_PYTHON=$(grep -E -i -n 'python' /flash/nsconfig/rc.netscaler 2>/dev/null)
    if [ -n "$RCN_PYTHON" ]; then status CHECK 'Python reference(s) found in rc.netscaler; compare with the approved startup configuration:'; echo "$RCN_PYTHON"; else status OK 'No Python references found in rc.netscaler.'; fi
else
    status CHECK '/flash/nsconfig/rc.netscaler is absent or unreadable; this persistence check could not run.'
fi

printf '\n--- Additional startup/configuration obfuscation indicators ---\n'
CONFIG_IOC_FILES_FOUND=0
CONFIG_IOC_HITS=''
for f in /flash/nsconfig/rc.netscaler /nsconfig/ns.conf /etc/rc /etc/rc.conf.defaults; do
    [ -r "$f" ] || continue
    CONFIG_IOC_FILES_FOUND=$((CONFIG_IOC_FILES_FOUND + 1))
    FILE_HITS=$(grep -E -i -n 'python3[[:space:]]+-c|base64[.](b64|b85)decode|zlib[.]decompress|apachectl[[:space:]]+graceful|php_flag[[:space:]]+engine[[:space:]]+off|fnoc[.]dptth|php[.]xedni|relacsten|hs/pmt/rav/|tnioPnogoL|gifnocsn' "$f" 2>/dev/null)
    if [ -n "$FILE_HITS" ]; then CONFIG_IOC_HITS="${CONFIG_IOC_HITS}${CONFIG_IOC_HITS:+
--- $f ---
}$FILE_HITS"; fi
done
if [ -n "$CONFIG_IOC_HITS" ]; then
    status CHECK 'Legacy NetScaler compromise-hunting strings found in startup/configuration files; compare with the same-build baseline. Matches are clues, not proof of compromise:'
    printf '%s\n' "$CONFIG_IOC_HITS" | head -80
elif [ "$CONFIG_IOC_FILES_FOUND" -eq 0 ]; then
    status CHECK 'No readable candidate startup/configuration files were available for this targeted string check.'
else
    status OK "No selected Python one-liners, decoder, zlib, PHP activation, or legacy obfuscation strings found in $CONFIG_IOC_FILES_FOUND candidate startup/configuration file(s)."
fi

printf '\n--- Processes running as nobody other than httpd ---\n'
NOBODY_PROCESSES=$(ps auxww 2>/dev/null | grep '^nobody' | grep -v '/bin/httpd' | grep -v '[g]rep' | head -50)
if [ -n "$NOBODY_PROCESSES" ]; then status CHECK 'Processes owned by nobody found; distinguish expected services from unexpected processes:'; echo "$NOBODY_PROCESSES"; else status OK 'No non-httpd processes owned by nobody were returned by ps.'; fi

printf '\n--- Perl/Python processes and process resource snapshot ---\n'
SCRIPT_PROCESSES=$(ps auxww 2>/dev/null | grep -E '[p]erl|[p]ython')
if [ -n "$SCRIPT_PROCESSES" ]; then
    status CHECK 'Perl/Python processes are present; validate executable path, owner, start time, command line, and hash against expected NetScaler functions:'
    printf '%s\n' "$SCRIPT_PROCESSES" | head -50
else
    status OK 'No Perl/Python process command lines were returned by ps.'
fi
PROCESS_SNAPSHOT=$(ps auxww 2>/dev/null | sort -nr -k3 | head -21)
if [ -n "$PROCESS_SNAPSHOT" ]; then
    status CHECK 'Review this process snapshot, ordered by the displayed CPU column, for unknown processes, sustained high CPU, miners, proxies, or tunnels; one point-in-time sample does not establish persistence or sustained load:'
    printf '%s\n' "$PROCESS_SNAPSHOT"
else
    status CHECK 'Could not collect a process snapshot with ps.'
fi

printf '\n--- HA configuration and synchronization process ---\n'
if [ -r "$CONFIG" ]; then
    HA_PEER_LINES=$(grep -E -i '^[[:space:]]*add[[:space:]]+ha[[:space:]]+node[[:space:]]+[0-9]+[[:space:]]+' "$CONFIG" 2>/dev/null)
    if [ -n "$HA_PEER_LINES" ]; then
        HA_CONFIG_STATE=YES
        status OK "Saved configuration contains one or more HA peer definitions in $CONFIG:"
        printf '%s\n' "$HA_PEER_LINES"
    else
        HA_CONFIG_STATE=NO
        status OK "No 'add ha node' peer definition was found in saved config $CONFIG; this file indicates no saved HA pair configuration."
    fi
else
    HA_CONFIG_STATE=UNKNOWN
    status CHECK "Cannot read $CONFIG; HA role cannot be inferred from saved configuration."
fi

HA_PROCESS=$(ps auxww 2>/dev/null | grep '[n]sfsyncd')
if [ "$HA_CONFIG_STATE" = YES ]; then
    if [ -n "$HA_PROCESS" ]; then
        status OK 'An HA peer is configured in saved ns.conf and nsfsyncd is running.'
        printf '%s\n' "$HA_PROCESS"
    else
        status CHECK 'An HA peer is configured in saved ns.conf, but nsfsyncd was not returned by ps; validate live HA status and peer connectivity.'
    fi
elif [ "$HA_CONFIG_STATE" = NO ]; then
    status OK 'No saved HA peer is configured; nsfsyncd process presence/absence is not used as a health finding for this appliance.'
    [ -n "$HA_PROCESS" ] && printf '%s\n' "$HA_PROCESS"
else
    status CHECK 'HA process state cannot be interpreted because the saved configuration was unavailable.'
    [ -n "$HA_PROCESS" ] && printf '%s\n' "$HA_PROCESS"
fi

HA_LOG_HITS=$(zgrep -E -i -n 'nsfsyncd|(^|[^[:alnum:]_])HA[[:space:]_-]+(sync|synchronization|state|fail|error)|(^|[^[:alnum:]_])(sync|synchronization)[[:space:]_-]+(HA|peer)' /var/log/ns.log* /var/log/messages* /var/log/notice.log* /var/log/nsvpn.log* 2>/dev/null | tail -60)
if [ "$HA_CONFIG_STATE" = YES ]; then
    if [ -n "$HA_LOG_HITS" ]; then
        status CHECK 'HA/synchronization-related log lines found; distinguish routine state changes from failures and compare both nodes:'
        printf '%s\n' "$HA_LOG_HITS"
    else
        status OK 'No selected HA synchronization patterns found in retained ns.log/messages files; this covers retained local logs only.'
    fi
elif [ "$HA_CONFIG_STATE" = NO ]; then
    status OK 'HA peer-log correlation is not applicable according to the saved configuration.'
elif [ -n "$HA_LOG_HITS" ]; then
    status CHECK 'HA/synchronization-related log lines found, but HA configuration could not be read; correlate manually:'
    printf '%s\n' "$HA_LOG_HITS"
else
    status CHECK 'HA log coverage cannot be interpreted because the saved configuration was unavailable.'
fi

subsection 'Shell binaries and privilege-escalation artifacts'
if [ -e /bin/sh ]; then
    ls -l /bin/sh 2>&1
    ls -ln /bin/sh 2>&1
    if command -v file >/dev/null 2>&1; then file /bin/sh 2>&1; else status CHECK 'file utility is unavailable; compare the SHA-256 hash and metadata with a trusted appliance on the same build.'; fi
    if command -v stat >/dev/null 2>&1; then stat /bin/sh 2>&1; else printf 'Metadata source: ls/hash (stat unavailable).\n'; fi
    SHELL_HASH=''
    if command -v sha256 >/dev/null 2>&1; then
        SHA_OUTPUT=$(sha256 /bin/sh 2>&1)
        printf '%s\n' "$SHA_OUTPUT"
        SHELL_HASH=$(printf '%s\n' "$SHA_OUTPUT" | sed -nE 's/.*([[:xdigit:]]{64}).*/\1/p' | head -1 | tr 'A-F' 'a-f')
    elif command -v sha256sum >/dev/null 2>&1; then
        SHA_OUTPUT=$(sha256sum /bin/sh 2>&1)
        printf '%s\n' "$SHA_OUTPUT"
        SHELL_HASH=$(printf '%s\n' "$SHA_OUTPUT" | awk '{print tolower($1)}')
    fi
    if [ "${CURRENT_INPUT-}" = '14.1-73.37.nc' ] || [ "${CURRENT_INPUT-}" = '14.1-73.37' ]; then
        if [ "$SHELL_HASH" = '2c1310d7c4d7dfb1ef47b137be1eb572cc743cc609898ae38320963cc0578665' ]; then
            status OK '/bin/sh SHA-256 matches the internal reference recorded for NetScaler 14.1-73.37; this is not a vendor-published checksum.'
        elif [ -n "$SHELL_HASH" ]; then
            status CHECK '/bin/sh SHA-256 differs from the internal 14.1-73.37 reference; compare platform/edition and a trusted appliance before treating it as anomalous. The reference is not vendor-published.'
        else
            status CHECK 'Could not calculate /bin/sh SHA-256 for comparison with the internal 14.1-73.37 reference.'
        fi
    fi
    ls -ld /bin /bin/sh 2>&1
    SHELL_META=$(ls -ln /bin/sh 2>/dev/null | awk 'NR==1{print $1 ":" $3 ":" $4 ":" $5}')
    if { [ "${CURRENT_INPUT-}" = '14.1-73.37.nc' ] || [ "${CURRENT_INPUT-}" = '14.1-73.37' ]; } && [ "$SHELL_META" = '-r-xr-xr-x:0:0:165368' ]; then
        status OK '/bin/sh mode, numeric owner/group, and size match the internal clean-sample reference for 14.1-73.37; timestamps are host-specific and are not compared. This is not a vendor-published baseline.'
    else
        status CHECK "Compare /bin/sh mode, owner, group, size, timestamp, and hash with a trusted same-build reference; observed metadata: ${SHELL_META:-unavailable}. The internal reference is from one clean 14.1-73.37 appliance, not a vendor-published universal baseline."
    fi
else
    status ACTION '/bin/sh was not found at the expected path; verify platform paths and investigate.'
fi

printf '\nSetuid/setgid mode check:\n'
SHELL_MODE=$(ls -l /bin/sh 2>/dev/null | awk 'NR==1{print $1}')
case "$SHELL_MODE" in
    *[sS]*) status ACTION "/bin/sh has a setuid/setgid permission marker ($SHELL_MODE); preserve evidence and compare with a trusted baseline." ;;
    '') status CHECK 'Could not read /bin/sh mode.' ;;
    *) status OK "/bin/sh has no setuid/setgid permission marker ($SHELL_MODE); still compare owner, mode, timestamp, and hash with a same-build baseline." ;;
esac



subsection 'Privileged-file inventory under /flash'
if [ -d /flash ] && [ -r /flash ]; then
    FLASH_PRIVILEGED=$(find /flash -type f -user root \( -perm -4000 -o -perm -2000 \) -print 2>/dev/null | head -100)
    if [ -n "$FLASH_PRIVILEGED" ]; then
        status CHECK 'Root-owned SUID/SGID files found under /flash (up to 100). No universal clean baseline is configured here; compare path, contents, owner, mode and hash with an approved same-build peer:'
        while IFS= read -r f; do
            [ -f "$f" ] || continue
            ls -ldn "$f" 2>&1
            if command -v sha256 >/dev/null 2>&1; then sha256 "$f"; elif command -v sha256sum >/dev/null 2>&1; then sha256sum "$f"; fi
            case "${f##*/}" in sh|bash|csh|tcsh|ksh|zsh)
                status ACTION "A shell-named file under /flash has privileged mode bits: $f. Preserve and investigate; the name alone does not identify its contents." ;;
            esac
        done <<EOF_FLASH_PRIVILEGED
$FLASH_PRIVILEGED
EOF_FLASH_PRIVILEGED
    else
        status OK 'No root-owned SUID/SGID files returned by the /flash inventory. Filesystem traversal errors are not assessed by this result.'
    fi
else
    status CHECK '/flash absent or unreadable; privileged-file inventory unavailable.'
fi

subsection 'Packet Engine open web and callhome files'
if command -v lsof >/dev/null 2>&1; then
    PPE_OPEN_FILES=$(lsof -nP -c NSPPE -c nsppe 2>/dev/null)
    if [ -n "$PPE_OPEN_FILES" ]; then
        PPE_OPEN_MATCHES=$(printf '%s\n' "$PPE_OPEN_FILES" | grep -Ei '/var/netscaler/|callhome' | head -30)
        if [ -n "$PPE_OPEN_MATCHES" ]; then
            status CHECK 'NSPPE open-file inventory includes web/callhome paths. This can be legitimate; correlate process identity, open descriptor, path and nearby events rather than treating an open file as command execution:'
            printf '%s\n' "$PPE_OPEN_MATCHES"
        else
            status OK 'No selected web/callhome path found in the available NSPPE lsof snapshot.'
        fi
    else
        status CHECK 'lsof returned no usable NSPPE process inventory; open-file coverage could not be established.'
    fi
else
    status CHECK 'lsof unavailable; NSPPE open web/callhome files were not assessed. Use an approved offline/support collection if needed.'
fi

printf '\n--- SUID/SGID persistence indicators under /var ---\n'
TMP_SETUID_SHELL=/var/tmp/sh
if [ -e "$TMP_SETUID_SHELL" ]; then
    ls -l "$TMP_SETUID_SHELL" 2>&1
    if [ -u "$TMP_SETUID_SHELL" ]; then
        status ACTION '/var/tmp/sh exists with the setuid bit; preserve it and investigate as a possible privilege-persistence artifact.'
    else
        status CHECK '/var/tmp/sh exists but is not setuid; verify why a shell binary is present in this temporary directory.'
    fi
else
    status OK 'No /var/tmp/sh file found.'
fi
ROOT_SUID_GID=$(find /var -type f -user root \( -perm -4000 -o -perm -2000 \) -print 2>/dev/null | head -100)
if [ -n "$ROOT_SUID_GID" ]; then
    while IFS= read -r f; do
        [ -n "$f" ] || continue
        ls -ldn "$f" 2>&1
        if command -v file >/dev/null 2>&1; then file "$f" 2>&1; fi
        if command -v sha256 >/dev/null 2>&1; then sha256 "$f" 2>&1; elif command -v sha256sum >/dev/null 2>&1; then sha256sum "$f" 2>&1; else status CHECK "No SHA-256 utility available for $f."; fi
        case "$f" in
            /var/nslog/nslog.nextfile|/var/run/nsprofmgmt.pid|/var/configd_devno) reference_suid_1417337 "$f" ;;
            *) status CHECK "No internal reference hash is configured for $f; compare with a trusted same-build appliance." ;;
        esac
    done <<SUID_FILES_EOF
$ROOT_SUID_GID
SUID_FILES_EOF
else
    status OK 'No root-owned SUID/SGID files were returned under /var.'
fi
if [ -r "${INSTALL_STATE_FILE-}" ]; then
    RECENT_SUID_GID=$(find /var -type f -newer "$INSTALL_STATE_FILE" -user root \( -perm -4000 -o -perm -2000 \) -print 2>/dev/null | head -100)
    if [ -n "$RECENT_SUID_GID" ]; then
        RECENT_SUID_UNKNOWN=''
        RECENT_SUID_KNOWN=''
        while IFS= read -r f; do
            [ -n "$f" ] || continue
            case "$f" in
                /var/nslog/nslog.nextfile|/var/run/nsprofmgmt.pid|/var/configd_devno)
                    RECENT_SUID_KNOWN="${RECENT_SUID_KNOWN}${f}\n"
                    ;;
                *)
                    RECENT_SUID_UNKNOWN="${RECENT_SUID_UNKNOWN}${f}\n"
                    ;;
            esac
        done <<RECENT_SUID_EOF
$RECENT_SUID_GID
RECENT_SUID_EOF
        if [ -n "$RECENT_SUID_KNOWN" ]; then
            printf '%b' "$RECENT_SUID_KNOWN" | while IFS= read -r f; do
                [ -n "$f" ] || continue
                _expected=''
                case "$f" in
                    /var/nslog/nslog.nextfile|/var/run/nsprofmgmt.pid) continue ;;
                    /var/configd_devno) _expected='5b76771117eacc288a42de079a719402e26528e997cfa82241c4d7a842eba5d2' ;;
                esac
                _observed=$(sha256_of "$f")
                if { [ "$CURRENT_INPUT" = '14.1-73.37' ] || [ "$CURRENT_INPUT" = '14.1-73.37.nc' ]; } && [ -n "$_observed" ] && [ "$_observed" = "$_expected" ]; then
                    status OK "$f is newer than installns_state but matches the internal 14.1-73.37 reference; recency alone is not suspicious. Reference is from one clean appliance, not Citrix."
                else
                    ls -ldn "$f" 2>&1
                    status CHECK "$f is newer than installns_state and does not match the internal reference (or the firmware is not 14.1-73.37); validate runtime changes and compare with another clean same-build appliance."
                fi
            done
        fi
        if [ -n "$RECENT_SUID_UNKNOWN" ]; then
            status ACTION 'Unclassified root-owned SUID/SGID files newer than installns_state were found under /var. Preserve and investigate; confirm the timestamp is not an approved upgrade or maintenance change:'
            printf '%b' "$RECENT_SUID_UNKNOWN" | while IFS= read -r f; do [ -n "$f" ] && ls -ldn "$f" 2>&1; done
        fi
    else
        status OK 'No root-owned SUID/SGID files newer than installns_state were found under /var.'
    fi
else
    status CHECK 'SUID/SGID recency could not be compared with the install marker; the full /var inventory above still requires baseline review.'
fi


subsection 'Vendor Python files and customsnmpd integrity baseline'
CUSTOMSNMPD_FILE=/var/python/bin/customsnmpd
if [ -f "$CUSTOMSNMPD_FILE" ]; then
    CUSTOMSNMPD_HASH=$(sha256_of "$CUSTOMSNMPD_FILE")
    if [ "$CUSTOMSNMPD_HASH" = 'e9fe43968c6c0955300e3bc4d7fb0b05a18570b4733aaf4f5c6f7f09be5a242c' ]; then
        status ACTION 'The /var/python/bin/customsnmpd SHA-256 matches a sample reported in public incident research. Preserve the file and investigate the appliance and connected systems.'
        printf 'SHA-256: %s  %s\n' "$CUSTOMSNMPD_HASH" "$CUSTOMSNMPD_FILE"
    elif [ -n "$CUSTOMSNMPD_HASH" ]; then
        printf 'SHA-256: %s  %s\n' "$CUSTOMSNMPD_HASH" "$CUSTOMSNMPD_FILE"
        if printf '%s' "${DEYDA_CUSTOMSNMPD_REFERENCE_SHA256-}" | grep -E -i -q '^[0-9a-f]{64}$'; then
            if [ "$(printf '%s' "$DEYDA_CUSTOMSNMPD_REFERENCE_SHA256" | tr 'A-F' 'a-f')" = "$CUSTOMSNMPD_HASH" ]; then
                status OK '/var/python/bin/customsnmpd matches the operator-supplied trusted same-build SHA-256 reference. This is a local reference, not a vendor checksum.'
            else
                status CHECK '/var/python/bin/customsnmpd differs from the operator-supplied trusted same-build SHA-256 reference. Preserve it and verify the baseline source and approved changes.'
                printf 'Trusted reference: %s\n' "$DEYDA_CUSTOMSNMPD_REFERENCE_SHA256"
            fi
        elif { [ "${CURRENT_INPUT-}" = '14.1-73.37.nc' ] || [ "${CURRENT_INPUT-}" = '14.1-73.37' ]; } && [ "$CUSTOMSNMPD_HASH" = '1dd0887ff21b18b0eb78a336e76d4dc3bb6f4fc645e9d864414a2958cb1637fe' ]; then
            status OK '/var/python/bin/customsnmpd matches the internal clean-appliance 14.1-73.37 SHA-256 reference; this is not a Citrix-published checksum.'
        elif { [ "${CURRENT_INPUT-}" = '14.1-73.37.nc' ] || [ "${CURRENT_INPUT-}" = '14.1-73.37' ]; }; then
            status CHECK '/var/python/bin/customsnmpd differs from the internal one-appliance 14.1-73.37 reference. Compare edition, approved changes, and another trusted same-build node.'
            printf 'Internal clean reference: %s\n' '1dd0887ff21b18b0eb78a336e76d4dc3bb6f4fc645e9d864414a2958cb1637fe'
        else
            status CHECK '/var/python/bin/customsnmpd does not match the selected public malicious-sample hash, but no valid trusted same-build hash was supplied; integrity remains unverified.'
        fi
    else
        status CHECK 'Could not calculate SHA-256 for /var/python/bin/customsnmpd.'
    fi
else
    status OK 'No /var/python/bin/customsnmpd file found.'
fi
if [ "${CURRENT_INPUT-}" = '14.1-73.37.nc' ] || [ "${CURRENT_INPUT-}" = '14.1-73.37' ]; then
    PYTHON_REFERENCE_NAMES='fixup_pubsub_v1_keywords.py CreateCluster.py MyFirstNitroApplication.py get_config.py jp.py rm_config.py set_config.py stat_config.py'
    PYTHON_REFERENCE_COUNT=0
    PYTHON_REFERENCE_MISMATCHES=0
    for name in $PYTHON_REFERENCE_NAMES; do
        PYTHON_REFERENCE_COUNT=$((PYTHON_REFERENCE_COUNT + 1))
        f="/var/python/bin/$name"
        case "$name" in
            fixup_pubsub_v1_keywords.py) PYTHON_EXPECTED='c1f44da36acb747f43906abf2c2cdde86f436473c631f603ed7aa0386a996170' ;;
            CreateCluster.py) PYTHON_EXPECTED='d425f646c717e85e3d799b21eb4bc7032997e8f91afa45a183dd63db6e17e2bf' ;;
            MyFirstNitroApplication.py) PYTHON_EXPECTED='edf3a5c3ca3621ecd1c4690f57e044ea066ac4c16b3f19914c567e2543c3bdfb' ;;
            get_config.py) PYTHON_EXPECTED='b681ae3666300014287c2bf7ff286792dc40934cf0ae504325ccfc80b4beb5d9' ;;
            jp.py) PYTHON_EXPECTED='3e473aaa397c21c6d35219a218da7a627e24079714e211228a7c522f5b01b306' ;;
            rm_config.py) PYTHON_EXPECTED='597311c15a0570933688320c7f79dd51992ad0503d04e01a75f319d31d524209' ;;
            set_config.py) PYTHON_EXPECTED='61df56aef3b63bae9436a449afc8c13a02ff202a411357f3d819ac8f0c685971' ;;
            stat_config.py) PYTHON_EXPECTED='c03a8b059878d685fabd3c3d166965e46cbf9163f6ec9c88cb11eda9d46e2b58' ;;
        esac
        if [ ! -f "$f" ]; then
            status CHECK "$f is absent but exists in the internal clean 14.1-73.37 reference; verify whether the component is expected on this appliance."
            PYTHON_REFERENCE_MISMATCHES=$((PYTHON_REFERENCE_MISMATCHES + 1))
            continue
        fi
        PYTHON_OBSERVED=$(sha256_of "$f")
        if [ -n "$PYTHON_OBSERVED" ] && [ "$PYTHON_OBSERVED" = "$PYTHON_EXPECTED" ]; then
            status OK "$f matches the internal clean 14.1-73.37 SHA-256 reference. This is not a Citrix-published checksum."
        else
            status CHECK "$f differs from the internal clean 14.1-73.37 reference or could not be hashed; validate approved changes and compare with another trusted same-build appliance."
            printf 'Observed: %s\nExpected: %s\n' "${PYTHON_OBSERVED:-unavailable}" "$PYTHON_EXPECTED"
            PYTHON_REFERENCE_MISMATCHES=$((PYTHON_REFERENCE_MISMATCHES + 1))
        fi
    done
    UNKNOWN_PYTHON_FILES=''
    for f in /var/python/bin/*.py; do
        [ -f "$f" ] || continue
        case "${f##*/}" in
            fixup_pubsub_v1_keywords.py|CreateCluster.py|MyFirstNitroApplication.py|get_config.py|jp.py|rm_config.py|set_config.py|stat_config.py) ;;
            *) UNKNOWN_PYTHON_FILES="${UNKNOWN_PYTHON_FILES}${UNKNOWN_PYTHON_FILES:+
}$f" ;;
        esac
    done
    if [ -n "$UNKNOWN_PYTHON_FILES" ]; then
        status CHECK 'Additional Python files exist in /var/python/bin outside the supplied clean-reference set; review each against the installed build and approved changes:'
        printf '%s\n' "$UNKNOWN_PYTHON_FILES"
        printf '%s\n' "$UNKNOWN_PYTHON_FILES" | while IFS= read -r f; do ls -ln "$f" 2>/dev/null; printf 'SHA-256: %s\n' "$(sha256_of "$f")"; done
    elif [ "$PYTHON_REFERENCE_MISMATCHES" -eq 0 ]; then
        status OK "All $PYTHON_REFERENCE_COUNT referenced Python files under /var/python/bin match the internal clean 14.1-73.37 hashes; no additional .py files were found."
    fi
fi
subsection 'configd state-file metadata baseline'
if { [ "${CURRENT_INPUT-}" = '14.1-73.37.nc' ] || [ "${CURRENT_INPUT-}" = '14.1-73.37' ]; }; then
    if [ -f /var/configd_devno ]; then
        CONFIGD_DEVNO_META=$(ls -ln /var/configd_devno 2>/dev/null | awk 'NR==1{print $1 ":" $3 ":" $4 ":" $5}')
        if [ "$CONFIGD_DEVNO_META" = '-rwxr-Sr--:0:0:129' ]; then
            status OK '/var/configd_devno mode, numeric owner/group, and size match the internal clean 14.1-73.37 sample.'
        else
            status CHECK "/var/configd_devno metadata differs from the internal clean sample (-rwxr-Sr--:0:0:129); observed: ${CONFIGD_DEVNO_META:-unavailable}. Compare with another trusted same-build appliance."
        fi
    else
        status CHECK '/var/configd_devno is absent on this appliance, but was present on the internal 14.1-73.37 reference; verify whether it is expected here and compare with a trusted peer.'
    fi
fi
section '4. Web configuration and served-file integrity'
subsection 'Purpose and follow-up'
printf '%s\n' 'Purpose: inspect httpd.conf indicators, web-facing files, known webshell/payload markers, custom language files, and recent file changes.'
printf '%s\n' 'For each [CHECK]: validate the exact file and timestamp against the firmware install/change window, compare hashes with a trusted same-build node, and inspect suspicious content from a preserved copy. A normal vendor package or upgrade timestamp can explain a match.'
printf '%s\n' 'Request-path hits are not automatically malicious: check the request date, source address, method, response, and whether the requested path is a normal NetScaler resource. Prior-year scanner noise should stay classified as historical unless correlated evidence says otherwise.'
subsection 'httpd.conf metadata and indicators'
FOUND_HTTPD=0
for f in /etc/httpd.conf /nsconfig/httpd.conf /netscaler/httpd.conf; do
    if [ -e "$f" ]; then
        FOUND_HTTPD=1
        printf '\n    Log/file: %s\n' "$f"
        ls -l "$f" 2>&1
        REFERENCE_MATCH=UNKNOWN
        case "$f" in
            /etc/httpd.conf) check_1417337_reference "$f" '3f5c9e7dae71498e524dbf41168fe81fc7864551c36b8f26e5a695ba1af17918' ;;
        esac
        if command -v stat >/dev/null 2>&1; then stat "$f" 2>&1; else printf 'Metadata source: ls/hash (stat unavailable).\n'; fi
        if find "$f" -mtime -14 -print 2>/dev/null | grep -q .; then
            if [ "$REFERENCE_MATCH" = YES ]; then
                printf 'Timestamp context: modified within 14 days; current contents match the internal reference. Time alone is not a content-integrity finding.\n'
            else
                status CHECK 'Modification time is within 14 days and no matching content baseline was established; compare with approved changes and a trusted peer.'
            fi
        else
            printf 'Timestamp context: not modified within 14 days; file age alone does not establish integrity.\n'
        fi
        if [ -r "$f" ]; then
            hits=$(grep -E -i -n 'b64decode|base64|LogonPoint/custom|/bin/sh|/\.ctxs|receiver[.]min|^[[:space:]]*(Alias|AliasMatch)[[:space:]].*(receiver|\.ctxs)|^[[:space:]]*(php_flag|php_admin_flag)[[:space:]]+engine[[:space:]]+on|^[[:space:]]*php_engine[[:space:]]+on|^[[:space:]]*(AddHandler|SetHandler)[[:space:]].*php' "$f" 2>/dev/null)
            MANDIANT_HTTPD_HITS=$(grep -E -i -n '^[[:space:]]*(AddType|AddHandler|SetHandler)[[:space:]].*application/x-httpd-php.*[.](deb|sig|rpm|tgz|html)([[:space:]]|$)|^[[:space:]]*AliasMatch[[:space:]].*/vpn/(media|theme|images)/.*(/vpn/scripts/linux|/gui/vpn/scripts/linux|/ns_gui/vpn/scripts/linux)|^[[:space:]]*Alias(Match)?[[:space:]].*LogonUISimple[.]html[.]style[.]min[.]css.*[.]local_journal' "$f" 2>/dev/null)
            if [ -n "$MANDIANT_HTTPD_HITS" ]; then status ACTION 'Non-standard PHP handler or VPN web-path alias matching publicly reported persistence patterns found; preserve httpd.conf and compare with a trusted same-build baseline:'; echo "$MANDIANT_HTTPD_HITS"; fi
            if [ -n "$hits" ]; then status CHECK 'Potential webshell alias, PHP-enabling directive, encoded-command, or payload-related configuration indicator found; compare with a trusted same-build baseline and preserve unexpected changes:'; echo "$hits"; else status OK 'No selected webshell aliases, PHP-enabling directives, encoded-command, or payload indicators found. Standard NetScaler PHP mappings and php_flag engine off are not treated as indicators by themselves.'; fi
        else
            status CHECK "$f exists but is not readable; indicator search could not be performed."
        fi
        if [ "$REFERENCE_MATCH" != YES ]; then status CHECK 'No matching content baseline was established for this file; compare with a trusted same-build peer or File Integrity Monitoring.'; fi
    fi
done
[ "$FOUND_HTTPD" -eq 1 ] || status CHECK 'No known httpd.conf path found; verify the correct path for this ADC build.'

printf '\n--- NetScaler webshell aliases and PHP configuration indicators ---\n'
HTTPD_CANDIDATES_FOUND=0
for f in /etc/httpd.conf /nsconfig/httpd.conf /netscaler/httpd.conf; do [ -r "$f" ] && HTTPD_CANDIDATES_FOUND=1; done
RECEIVER_ALIAS_HITS=$(grep -nE -i 'receiver([.]v2)?[.]min([.][a-f0-9]+)?[.]css|Alias(Match)?[[:space:]].*/[.]ctxs([[:space:]]|$)|LogonUISimple[.]html[.]style[.]min[.]css|[.]local_journal' /etc/httpd.conf /nsconfig/httpd.conf /netscaler/httpd.conf 2>/dev/null)
if [ -n "$RECEIVER_ALIAS_HITS" ]; then
    status ACTION 'NetScaler webshell alias indicator found in httpd.conf; preserve the file and investigate the referenced target and timestamps:'
    printf '%s\n' "$RECEIVER_ALIAS_HITS"
elif [ "$HTTPD_CANDIDATES_FOUND" -eq 0 ]; then
    status CHECK 'No readable candidate httpd.conf file found; the webshell-alias check could not run.'
else
    status OK 'No selected receiver.min.css/receiver.v2.min.<hex>.css, .ctxs, or LogonUISimple/.local_journal alias patterns found in candidate httpd.conf files.'
fi
subsection 'Reported receiver variants and PHP handling of .deb files'
SLAP_WEB_FOUND=0
for f in /var/netscaler/logon/LogonPoint/custom/.slap.receiver /var/netscaler/logon/LogonPoint/custom/.ctxs.receiver /var/netscaler/logon/LogonPoint/custom/receiver.deb; do
    [ -f "$f" ] || continue
    SLAP_WEB_FOUND=1
    status CHECK "Reported receiver artifact $f exists. Preserve metadata/hash and inspect content; filename alone is not proof. A fake HTTP 404 does not establish harmlessness."
    ls -ln "$f" 2>/dev/null
    printf 'SHA-256 observed: %s\n' "$(sha256_of "$f")"
    if [ -r "$f" ] && grep -qiE '<\?[[:space:]]*php' "$f" &&
       grep -qiE 'CsrfToken|HTTP_X_CMD|X-Cmd' "$f" &&
       grep -qiE 'eval[[:space:]]*\(|shell_exec|passthru|system[[:space:]]*\(|proc_open' "$f"; then
        status ACTION "PHP plus command/cookie interface and execution-code markers found in $f. Preserve and investigate as a strong webshell-content lead; execution is not established by this content match."
    fi
done
[ "$SLAP_WEB_FOUND" -eq 1 ] || status OK 'No selected .slap.receiver/.ctxs.receiver/receiver.deb file found in LogonPoint/custom.'
COOKIE_COMMAND_CANDIDATES=$(find /var/netscaler/logon/LogonPoint/custom /var/vpn /nsconfig/.slap /flash/nsconfig/.slap -type f -size -2048k \
    ! -name 'deyda-netscaler-ioc-check*.sh' ! -name 'deyda-netscaler-ioc-check*.txt' \
    -exec grep -lF 'CsrfToken2' {} + 2>/dev/null | head -30)
COOKIE_COMMAND_FOUND=0
while IFS= read -r f; do
    [ -r "$f" ] || continue
    if grep -qiE '<\?[[:space:]]*php' "$f" &&
       grep -qF '$_COOKIE' "$f" &&
       grep -qiE 'shell_exec|passthru|proc_open|system[[:space:]]*\(|eval[[:space:]]*\(' "$f"; then
        COOKIE_COMMAND_FOUND=1
        status ACTION "PHP cookie-command webshell-content pattern found in $f: CsrfToken2, cookie access and execution code coexist. Preserve for offline analysis; this does not establish execution. Cookie/token values and source content are omitted."
        ls -ln "$f" 2>/dev/null
        printf 'SHA-256: %s\n' "$(sha256_of "$f")"
    fi
done <<EOF_COOKIE_COMMAND
$COOKIE_COMMAND_CANDIDATES
EOF_COOKIE_COMMAND
if [ "$COOKIE_COMMAND_FOUND" -eq 0 ]; then
    status OK 'No combined CsrfToken2/PHP/cookie/command-execution content pattern found in readable candidate files below 2 MiB in selected web and .slap backup paths. Other names/paths/formats remain outside coverage.'
fi
printf '%s\n' 'Coverage: ordinary HTTP access logs normally omit Cookie and X-Cmd values. A missing token in those logs or an HTTP 404 response does not rule out cookie-command execution.'
DEB_PHP_HANDLERS=$(grep -nE -i '^[[:space:]]*(AddType|AddHandler)[[:space:]]+[^#]*php[^#]*[[:space:]][.]deb([[:space:]]|$)' /etc/httpd.conf /nsconfig/httpd.conf /netscaler/httpd.conf 2>/dev/null)
if [ -n "$DEB_PHP_HANDLERS" ]; then
    status ACTION 'Active-looking Apache directive associates .deb with PHP. Preserve configuration and review directive scope, Files/FilesMatch blocks and mapped files against a trusted baseline:'
    printf '%s\n' "$DEB_PHP_HANDLERS"
elif [ "$HTTPD_CANDIDATES_FOUND" -eq 1 ]; then
    status OK 'No selected active-looking AddType/AddHandler PHP-to-.deb directive found. Other extensions and scoped SetHandler constructs are covered only by the broader configuration checks.'
else
    status CHECK 'No readable httpd.conf candidate for the PHP-to-.deb directive check.'
fi
WEB_CUSTOM_DIRS_FOUND=0
for d in /var/netscaler/logon/LogonPoint/custom /var/vpn /var/netscaler; do [ -d "$d" ] && WEB_CUSTOM_DIRS_FOUND=1; done
UNEXPECTED_PHP_XHTML=$(find /var/netscaler -type f \( -name '*.php' -o -name '*.xhtml' \) ! -path '/var/netscaler/gui/admin_ui/*' ! -path '/var/netscaler/websocketd/*' -print 2>/dev/null | head -100)
if [ -n "$UNEXPECTED_PHP_XHTML" ]; then
    status CHECK 'PHP/XHTML files found outside the known admin_ui and websocketd paths; review each against this appliance build and approved customizations:'
    WEB_CONTENT_HITS=''
    for f in $UNEXPECTED_PHP_XHTML; do
        ls -l "$f" 2>&1
        FILE_CONTENT_HITS=$(grep -nE -i 'base64_decode[[:space:]]*\(|eval[[:space:]]*\(|passthru[[:space:]]*\(|shell_exec[[:space:]]*\(|system[[:space:]]*\(|proc_open[[:space:]]*\(|NSC_TASS|CsrfToken' "$f" 2>/dev/null)
        if [ -n "$FILE_CONTENT_HITS" ]; then WEB_CONTENT_HITS="${WEB_CONTENT_HITS}${WEB_CONTENT_HITS:+
--- $f ---
}$FILE_CONTENT_HITS"; fi
    done
    if [ -n "$WEB_CONTENT_HITS" ]; then
        status CHECK 'Webshell-like PHP content patterns found. These signatures are heuristic; inspect the file and compare it with a trusted same-build copy:'
        printf '%s\n' "$WEB_CONTENT_HITS" | head -80
    fi
elif [ -d /var/netscaler ]; then
    status OK 'No PHP/XHTML files found under /var/netscaler outside the known admin_ui and websocketd paths.'
else
    status CHECK '/var/netscaler is absent; the broad PHP/XHTML inventory could not run.'
fi
subsection 'VPN script staging and WHIPSHOT/SLAPSHOT artifacts'
STAGING_PATHS_FOUND=0
STAGING_FILES=''
for d in /var/netscaler/gui/vpn/scripts/linux /netscaler/ns_gui/vpn/scripts/linux /netscaler/gui/vpns/scripts/vista /netscaler/gui/vpns/scripts/mac /netscaler/ns_gui/vpns/scripts/vista /netscaler/ns_gui/vpns/scripts/mac; do
    [ -d "$d" ] || continue
    STAGING_PATHS_FOUND=1
    files=$(find "$d" -type f \( -name '*.sig' -o -name '*.deb' -o -name '*.php' -o -name 'nginstaller*' -o -name 'nsgclient*' -o -name 'e6ee7c85*' \) -print 2>/dev/null | head -100)
    if [ -n "$files" ]; then STAGING_FILES="${STAGING_FILES}${STAGING_FILES:+
}$files"; fi
done
if [ -n "$STAGING_FILES" ]; then
    printf '%s\n' "$STAGING_FILES"
    STAGING_REVIEW_UNKNOWN=0
    STAGING_REFERENCE_MATCHES=0
    STAGING_REFERENCE_MISMATCHES=0
    STAGING_CANDIDATE_PATHS=$(printf '%s\n' "$STAGING_FILES" | awk '/^\// {print}' | sort -u)
    for f in $STAGING_CANDIDATE_PATHS; do
        [ -f "$f" ] || continue
        ls -l "$f" 2>/dev/null
        EXPECTED_HASH=''
        case "$f" in
            /var/netscaler/gui/vpn/scripts/linux/nsgclient18_64.deb|/netscaler/ns_gui/vpn/scripts/linux/nsgclient18_64.deb)
                EXPECTED_HASH='c802dc70e762245150a2741816a4b9b299fb8762ace8f56868ba2f66ae2b1b10' ;;
            /var/netscaler/gui/vpn/scripts/linux/nsginstaller64.deb|/netscaler/ns_gui/vpn/scripts/linux/nsginstaller64.deb)
                EXPECTED_HASH='56d3095495c6847738404a6f076e43484887675be4776ea73aa6ad11472c09b3' ;;
            *) STAGING_REVIEW_UNKNOWN=1 ;;
        esac
        if [ -n "$EXPECTED_HASH" ]; then
            ACTUAL_HASH=$(sha256_of "$f")
            if [ -n "$ACTUAL_HASH" ]; then
                printf 'SHA-256 observed:  %s\n' "$ACTUAL_HASH"
                printf 'SHA-256 reference: %s\n' "$EXPECTED_HASH"
                if { [ "${CURRENT_INPUT-}" = '14.1-73.37.nc' ] || [ "${CURRENT_INPUT-}" = '14.1-73.37' ]; } && [ "$ACTUAL_HASH" = "$EXPECTED_HASH" ]; then
                    status OK "$f matches the internal single-appliance 14.1-73.37 SHA-256 reference."
                    STAGING_REFERENCE_MATCHES=$((STAGING_REFERENCE_MATCHES + 1))
                else
                    status CHECK "$f does not match the usable internal baseline (or the entered build is outside its scope); inspect before disposition."
                    STAGING_REFERENCE_MISMATCHES=$((STAGING_REFERENCE_MISMATCHES + 1))
                fi
            else
                status CHECK "Could not calculate SHA-256 for $f."
                STAGING_REFERENCE_MISMATCHES=$((STAGING_REFERENCE_MISMATCHES + 1))
            fi
        fi
        if grep -qE -i 'HTTP_NSC_(LDAP|CLIENTTYPE)|HTTP_X_UX(_[0-9]+)?|UXD_IDLE_EXIT|base64_decode[[:space:]]*\(|eval[[:space:]]*\(|shell_exec[[:space:]]*\(|<\?php|nsginstaller|nsgclient' "$f" 2>/dev/null; then
            status ACTION "Webshell/tunneler behavior strings found in $f; preserve it and investigate as a potential compromise artifact."
        fi
    done
    if [ "$STAGING_REVIEW_UNKNOWN" -eq 0 ] && [ "$STAGING_REFERENCE_MISMATCHES" -eq 0 ] && [ "$STAGING_REFERENCE_MATCHES" -eq "$(printf '%s\n' "$STAGING_CANDIDATE_PATHS" | wc -l | tr -d ' ')" ] && [ "$STAGING_REFERENCE_MATCHES" -gt 0 ]; then
        status OK 'Every VPN staging file found matches a known package hash in the internal 14.1-73.37 reference set; presence alone is expected on this reference build. The hashes are not Citrix-published.'
    else
        status CHECK 'VPN staging inventory includes an unknown, unverified, or hash-mismatching file; validate it against a trusted same-build baseline.'
    fi
elif [ "$STAGING_PATHS_FOUND" -eq 0 ]; then
    status OK 'No reported VPN script staging files found; none of the candidate staging directories exists on this build. Confirm the path map if this build is expected to use one of them.'
else
    status OK 'No .sig/.deb/.php files found in the reported VPN script staging paths.'
fi
UXD_ARTIFACT_FOUND=0
for f in /tmp/.uxdport /tmp/.uxdlock /var/tmp/.uxdport /var/tmp/.uxdlock; do
    if [ -e "$f" ]; then UXD_ARTIFACT_FOUND=1; ls -l "$f" 2>&1; case "$f" in *uxdport) printf 'Recorded loopback port: '; head -c 128 "$f" 2>/dev/null; printf '\n' ;; esac; fi
done
if [ "$UXD_ARTIFACT_FOUND" -eq 1 ]; then
    status ACTION 'SLAPSHOT-related .uxdport/.uxdlock artifact found. Record the port and process/socket state, preserve evidence, and investigate; do not delete the files.'
    if command -v sockstat >/dev/null 2>&1; then sockstat -4 -l 2>&1 | head -60; fi
    ps auxww 2>/dev/null | grep -E '[p]ython.*(UXD_IDLE_EXIT|base64|127[.]0[.]0[.]1)' | head -20
else
    status OK 'No .uxdport/.uxdlock artifacts found in /tmp or /var/tmp.'
fi
subsection 'Additional publicly reported persistence and staging artifacts'
PITSCALER_ARTIFACTS=$( { find /var/netscaler /var/vpn /var/python /tmp -type f \( -name '.local_journal' -o -name 'xua.html' -o -name 'update_result_*.tgz' -o -name 'customsnmpd' -o -name 'nsg64.deb' -o -name '1.py' \) -print 2>/dev/null; find /var/tmp/.nsmon -type f \( -name '.cfg' -o -name '.state' \) -print 2>/dev/null; } | head -100)
if [ -n "$PITSCALER_ARTIFACTS" ]; then
    while IFS= read -r f; do
        [ -f "$f" ] || continue
        if [ "$f" = /var/python/bin/customsnmpd ]; then
            printf '\nInventory: %s — hash classification is reported under Host integrity / Vendor Python files and customsnmpd integrity baseline.\n' "$f"
        else
            status CHECK "Reported artifact name found: $f. A name alone is not proof; verify content, owner, timestamp and same-build hash."
            ls -ln "$f" 2>/dev/null
        fi
    done <<EOF_REPORTED_ARTIFACTS
$PITSCALER_ARTIFACTS
EOF_REPORTED_ARTIFACTS
else
    status OK 'No selected .local_journal, xua.html, update_result_*.tgz, customsnmpd, .nsmon state, nsg64.deb, or 1.py artifact names found in the searched directories.'
fi
progress 'Web and payload integrity: Platypus bootstrap content'
# Find by content, not token/hash; no token or file content is printed.
# Quoted find -exec avoids shell evaluation and xargs splitting of spaced paths.
PLATYPUS_BOOTSTRAPS=$(find /tmp /var/tmp /netscaler.local /var/core -type f -size -1024k \
    ! -name 'deyda-netscaler-ioc-check*.txt' ! -name 'deyda-netscaler-ioc-check*.sh' \
    -exec grep -lE 'Platypus agent bootstrap|PLATYPUS_INGRESS_CA|AGENT_TOKEN[[:space:]]*=[[:space:]]*.[pP][lL][tT]_' {} + 2>/dev/null | head -30)
if [ -n "$PLATYPUS_BOOTSTRAPS" ]; then
    status ACTION 'Distinctive Platypus-bootstrap content matched in selected files below 1 MiB. This indicates a staged script, not proof of execution. Preserve and inspect offline; enrollment token values are omitted:'
    while IFS= read -r f; do
        [ -f "$f" ] || continue
        ls -ln "$f" 2>/dev/null
        printf 'SHA-256: %s\n' "$(sha256_of "$f")"
    done <<EOF_BOOTSTRAPS
$PLATYPUS_BOOTSTRAPS
EOF_BOOTSTRAPS
else
    status OK 'No selected Platypus-bootstrap content found in readable candidate files below 1 MiB in /tmp, /var/tmp, /netscaler.local, or /var/core. Other paths and larger files are outside this check.'
fi
PLATYPUS_CACHE_DIR=/var/core/.ns-cache
if [ -d "$PLATYPUS_CACHE_DIR" ]; then
    PLATYPUS_CACHE_FILES=$(find "$PLATYPUS_CACHE_DIR" -type f -print 2>/dev/null | head -100)
    if [ -n "$PLATYPUS_CACHE_FILES" ]; then
        status CHECK 'Files exist under /var/core/.ns-cache, a path TENEX associated with Platypus working data and enrollment credentials. The path alone is not proof; preserve files and validate against a clean same-build appliance. File contents, especially private keys, are not printed:'
        printf '%s\n' "$PLATYPUS_CACHE_FILES" | while IFS= read -r f; do ls -ln "$f" 2>/dev/null; done
    else
        status OK '/var/core/.ns-cache exists but contains no files in the scanned tree.'
    fi
else
    status OK 'No /var/core/.ns-cache directory found in the scanned filesystem.'
fi
PLATYPUS_SCRIPT_FILES=$(find /netscaler.local -type f -name 'ns_*.pl' -print 2>/dev/null | head -100)
if [ -n "$PLATYPUS_SCRIPT_FILES" ]; then
    PLATYPUS_SCRIPT_REPORT=''
    PLATYPUS_SCRIPT_STRONG=0
    while IFS= read -r f; do
        [ -f "$f" ] || continue
        PLATYPUS_SCRIPT_REPORT="${PLATYPUS_SCRIPT_REPORT}${PLATYPUS_SCRIPT_REPORT:+
}$f"
        PLATYPUS_SCRIPT_META=$(ls -ln "$f" 2>/dev/null)
        [ -n "$PLATYPUS_SCRIPT_META" ] && PLATYPUS_SCRIPT_REPORT="${PLATYPUS_SCRIPT_REPORT}
$PLATYPUS_SCRIPT_META"
        if grep -qE -i 'platypus://server/default|platypus-ingress|platypus-mesh[.]tcp' "$f" 2>/dev/null; then
            PLATYPUS_SCRIPT_STRONG=1
            PLATYPUS_SCRIPT_REPORT="${PLATYPUS_SCRIPT_REPORT}
SHA-256 $(sha256_of "$f")  $f"
        fi
    done <<EOF_PLATYPUS_FILES
$PLATYPUS_SCRIPT_FILES
EOF_PLATYPUS_FILES
    if [ "$PLATYPUS_SCRIPT_STRONG" -eq 1 ]; then
        status ACTION 'A NetScaler-named Perl file in /netscaler.local contains a distinctive Platypus marker. Preserve and investigate; this is stronger than a filename-only match:'
        printf '%s\n' "$PLATYPUS_SCRIPT_REPORT"
    else
        status CHECK 'NetScaler-named Perl files found under /netscaler.local. Names may mimic stock files; verify each against a trusted same-build baseline:'
        printf '%s\n' "$PLATYPUS_SCRIPT_REPORT"
    fi
else
    status OK 'No ns_*.pl files found under /netscaler.local. This only covers the scanned path.'
fi
subsection 'PHP and webshell content in customization trees'
MISPLACED_PHP=$(grep -rlE '<\?[[:space:]]*php|passthru[[:space:]]*\(|NSC_TASS|CsrfToken' /var/netscaler/logon/LogonPoint/custom /var/vpn 2>/dev/null)
if [ -n "$MISPLACED_PHP" ]; then
    status ACTION 'PHP/webshell-like code found in Gateway customization paths where it is unexpected; inspect contents and preserve evidence:'
    printf '%s\n' "$MISPLACED_PHP"
elif [ ! -d /var/netscaler/logon/LogonPoint/custom ] && [ ! -d /var/vpn ]; then
    status CHECK 'Neither target customization directory exists; misplaced-PHP content coverage is unknown.'
else
    status OK 'No selected PHP/webshell signatures found in LogonPoint/custom or /var/vpn.'
fi

printf '\n--- Sensitive configuration/key copies in web and temporary paths ---\n'
SENSITIVE_COPY_FILES=$(find /var/vpn /var/netscaler/logon /var/netscaler/gui /netscaler/ns_gui /tmp /var/tmp -type f \( -name 'ns.conf' -o -name '.F1.key' -o -name '.F2.key' \) -print 2>/dev/null | head -100)
if [ -n "$SENSITIVE_COPY_FILES" ]; then
    status CHECK 'Files named ns.conf, .F1.key, or .F2.key were found in web-facing or temporary trees. Verify whether these are expected copies and preserve unexpected files:'
    printf '%s\n' "$SENSITIVE_COPY_FILES"
    printf '%s\n' "$SENSITIVE_COPY_FILES" | while IFS= read -r f; do ls -l "$f" 2>/dev/null; done
else
    status OK 'No ns.conf/.F1.key/.F2.key copies found in the selected web-facing and temporary paths.'
fi

subsection 'Known webshell hashes in selected file trees'
KNOWN_WEBSHELL_HASHES='6f5a2a452a7901323abd21879c6cecccb47c06aeeaccb1b467212f3b11e4b1e7
ed082f744f035035900f67edf438f2f7d0528ac501234f63d476d65273cdb9a1
5ea5ea61e9062822bee3f66ef5ff47c217178d9e31936ad6daf10c5dfae44d12
7add390ceee4a1373211b3e340451b34f08965fc4d805f94c9b8cebdc0775774
ae22ef2517b5c0fb47f78745b9cb5260acee0e751b89bcd354640ff8bc8d29ec
1bd314b661396c7086f6367fbbb48025e03ca2de69c073d53a8b0a38aa5fbb7d
79c65fa04541032e251fa4796b97800374b63c7982593dd1a2e0db605d429186'
WEBSHELL_HASH_HITS=''
if command -v sha256 >/dev/null 2>&1 || command -v sha256sum >/dev/null 2>&1; then
    for d in /var/netscaler/logon/LogonPoint/custom /var/vpn /var/python/bin /var/netscaler/gui/vpn/scripts/linux /netscaler/ns_gui/vpn/scripts/linux /netscaler/gui/vpns/scripts/vista /netscaler/gui/vpns/scripts/mac /netscaler/ns_gui/vpns/scripts/vista /netscaler/ns_gui/vpns/scripts/mac; do
        [ -d "$d" ] || continue
        for f in $(find "$d" -type f -print 2>/dev/null); do
            if command -v sha256 >/dev/null 2>&1; then FILE_HASH=$(sha256 -q "$f" 2>/dev/null); else FILE_HASH=$(sha256sum "$f" 2>/dev/null | awk '{print $1}'); fi
            if printf '%s\n' "$KNOWN_WEBSHELL_HASHES" | grep -F -x -q "$FILE_HASH"; then
                WEBSHELL_HASH_HITS="${WEBSHELL_HASH_HITS}${WEBSHELL_HASH_HITS:+
}$FILE_HASH  $f"
            fi
        done
    done
    if [ -n "$WEBSHELL_HASH_HITS" ]; then
        status ACTION 'File matching a publicly reported NetScaler webshell, package, or payload SHA-256 found. Hash matches are specific sample indicators; preserve the file and investigate the appliance and HA peer:'
        printf '%s\n' "$WEBSHELL_HASH_HITS"
    elif [ ! -d /var/netscaler/logon/LogonPoint/custom ] && [ ! -d /var/vpn ]; then
        status CHECK 'Neither target customization directory exists; the known webshell hash check could not run.'
    else
        status OK 'No file matching the selected publicly reported webshell SHA-256 values was found in the targeted directories. Victim-specific variants may have different hashes.'
    fi
else
    status CHECK 'No SHA-256 utility is available; the selected public webshell hash checks could not run.'
fi
subsection 'Hidden .ctxs files and content indicators'
CTX_RECEIVER_FILES=$(find /var/netscaler/logon /netscaler/ns_gui /var/vpn -type f -name '.ctxs*' -print 2>/dev/null)
if [ -n "$CTX_RECEIVER_FILES" ]; then
    status ACTION 'Hidden .ctxs* file found in a web-facing path; investigate as a possible webshell and preserve evidence:'
    printf '%s\n' "$CTX_RECEIVER_FILES"
    printf '%s\n' "$CTX_RECEIVER_FILES" | while IFS= read -r f; do
        [ -f "$f" ] || continue
        ls -l "$f" 2>&1
        if command -v sha256 >/dev/null 2>&1; then sha256 "$f" 2>&1; elif command -v sha256sum >/dev/null 2>&1; then sha256sum "$f" 2>&1; else status CHECK "No SHA-256 utility available for $f."; fi
        CTX_CONTENT_HITS=$(grep -nE -i 'NSC_TASS|CsrfToken|base64_decode[[:space:]]*\(|eval[[:space:]]*\(|shell_exec[[:space:]]*\(|passthru[[:space:]]*\(|HTTP_X_UX|HTTP_NSC_' "$f" 2>/dev/null | head -40)
        if [ -n "$CTX_CONTENT_HITS" ]; then
            status ACTION "Webshell/command-execution-related content pattern found in $f; preserve and inspect the file in context:"
            printf '%s\n' "$CTX_CONTENT_HITS"
        else
            status CHECK "No selected content signatures found in $f; inspect the complete file and compare its hash with a trusted same-build baseline."
        fi
    done
elif [ -d /var/netscaler/logon ] || [ -d /netscaler/ns_gui ] || [ -d /var/vpn ]; then
    status OK 'No .ctxs* files found in the candidate web-facing paths.'
else
    status CHECK 'Candidate web-facing paths are absent; .ctxs* file coverage is unknown.'
fi

printf '\n--- Publicly reported NX-CVE-OK test markers ---\n'
NX_MARKER_DIRS_FOUND=0
NX_MARKER_HITS=''
for d in /netscaler/ns_gui /var/netscaler; do
    [ -d "$d" ] || continue
    NX_MARKER_DIRS_FOUND=1
    found=$(grep -r -l -I -F 'NX-CVE-OK' "$d" 2>/dev/null | head -50)
    if [ -n "$found" ]; then NX_MARKER_HITS="${NX_MARKER_HITS}${NX_MARKER_HITS:+
--- $d ---
}$found"; fi
done
if [ -n "$NX_MARKER_HITS" ]; then
    status CHECK 'NX-CVE-OK marker found. This can show that a vulnerability check reached the appliance; it is not proof that a backdoor was installed. Preserve the file and correlate its time/content with logs and authorized testing:'
    printf '%s\n' "$NX_MARKER_HITS"
elif [ "$NX_MARKER_DIRS_FOUND" -eq 1 ]; then
    status OK 'No NX-CVE-OK marker found in the readable candidate web directories. A reboot may rebuild /netscaler/ns_gui and remove earlier markers.'
else
    status CHECK 'Neither /netscaler/ns_gui nor /var/netscaler is present; NX-CVE-OK marker coverage is unavailable.'
fi

printf '\n--- CVE-2026-88771 exploit-written file indicators ---\n'
PAYLOAD_DIRS_FOUND=0
for d in /var/vpn /var/ns /netscaler/ns_gui /netscaler/ns_gui/admin_ui /var/netscaler /var/tmp /tmp; do [ -d "$d" ] && PAYLOAD_DIRS_FOUND=1; done
PAYLOAD_FILES=$( { find /var/vpn /var/ns /netscaler/ns_gui /var/netscaler -type f -name 'nx_verify.html' -print 2>/dev/null; ls -d /var/tmp/wtw* /var/tmp/watchTowr* /var/tmp/boom* 2>/dev/null; } | sort -u)
for f in /netscaler/ns_gui/admin_ui/e.txt /var/netscaler/logon/insight-new.js; do
    [ -f "$f" ] && PAYLOAD_FILES="${PAYLOAD_FILES}${PAYLOAD_FILES:+
}$f"
done
ID_OUTPUT_FILES=''
for d in /var/tmp /tmp /var/vpn /var/netscaler/logon /netscaler/ns_gui/vpn /netscaler/ns_gui/admin_ui; do
    [ -d "$d" ] || continue
    for f in $(find "$d" -type f -size -2k -mtime -30 -print 2>/dev/null); do
        if grep -qE '^uid=[0-9]+\([^)]*\)[[:space:]]+gid=[0-9]+' "$f" 2>/dev/null; then
            ID_OUTPUT_FILES="${ID_OUTPUT_FILES}${ID_OUTPUT_FILES:+
}$f"
        fi
    done
done
if [ -n "$ID_OUTPUT_FILES" ]; then PAYLOAD_FILES="${PAYLOAD_FILES}${PAYLOAD_FILES:+
}$ID_OUTPUT_FILES"; fi
if [ -n "$PAYLOAD_FILES" ]; then
    if [ -n "$ID_OUTPUT_FILES" ]; then
        status ACTION 'File(s) containing uid/gid command output were found; this is strong evidence that a command ran. Preserve files before further response:'
    else
        status CHECK 'Known exploit-test/canary or payload-target file(s) found. nx_verify.html can be created by testing and does not alone prove a backdoor; validate every hit and preserve unexpected files:'
    fi
    for f in $(printf '%s\n' "$PAYLOAD_FILES" | sort -u); do
        ls -l "$f" 2>&1
        case "$f" in
            /var/netscaler/logon/insight-new.js|/netscaler/ns_gui/admin_ui/e.txt)
                status CHECK "Payload-targeted file exists: $f. Its presence alone is not proof of compromise. Do not print contents automatically; it may contain appliance configuration data. Preserve and inspect it securely."
                ;;
            *) printf '%s\n' "$f" ;;
        esac
    done
elif [ "$PAYLOAD_DIRS_FOUND" -eq 0 ]; then
    status CHECK 'None of the payload-search paths exists; exploit-artifact coverage is unknown.'
else
    status OK 'No known exploit canary names or recent small files containing uid/gid command output were found in checked paths.'
fi

subsection 'Unexpected .dot files beneath LogonPoint/custom'
DOT_COUNT=0
for d in /var/netscaler/logon/LogonPoint/custom; do
    if [ -d "$d" ]; then
        echo "--- Searching $d ---"
        dot_files=$(find "$d" -name '*.dot' -print 2>/dev/null)
        if [ -n "$dot_files" ]; then
            status ACTION '.dot files found; investigate creation times and preserve them for analysis:'
            printf '%s\n' "$dot_files" | while IFS= read -r f; do
                ls -l "$f" 2>&1
                if command -v sha256 >/dev/null 2>&1; then sha256 "$f" 2>&1; elif command -v sha256sum >/dev/null 2>&1; then sha256sum "$f" 2>&1; fi
                DOT_CONTENT_HITS=$(grep -nE -i 'base64|eval|XMLHttpRequest|document[.]cookie|NSC_TASS|CsrfToken|<\?php|shell_exec|passthru|curl[[:space:]]|wget[[:space:]]' "$f" 2>/dev/null | head -40)
                if [ -n "$DOT_CONTENT_HITS" ]; then status CHECK "Selected script/content patterns found in $f; assess whether the file is expected:"; printf '%s\n' "$DOT_CONTENT_HITS"; else status CHECK "No selected content signatures found in $f; inspect the file and compare its metadata/hash with a trusted baseline."; fi
            done
            DOT_COUNT=1
        else
            status OK 'No .dot files found at this path.'
        fi
    else
        status CHECK "Directory $d is absent; verify the correct LogonPoint/custom path for this build."
    fi
done

printf '\n--- Hidden files in additional web directories ---\n'
if [ -d /netscaler/ns_gui/vpn ]; then
    HIDDEN_FILES=$(find /netscaler/ns_gui/vpn -type f -name '.*' -print 2>/dev/null | head -100)
    if [ -n "$HIDDEN_FILES" ]; then
        status CHECK 'Hidden files found under /netscaler/ns_gui/vpn; compare with a known-good build and investigate unexpected files:'
        echo "$HIDDEN_FILES"
    else
        status OK 'No hidden files found under /netscaler/ns_gui/vpn.'
    fi
else
    status CHECK 'The additional web directory /netscaler/ns_gui/vpn is absent; verify the path for this build.'
fi

printf '\n--- Recently modified web-served files (last 14 days) ---\n'
WEB_DIRS_FOUND=0
for d in /var/netscaler/logon /netscaler/ns_gui /var/vpn /var/nsproflog /var/python /var/netscaler/gui /netscaler/gui /netscaler/portal; do [ -d "$d" ] && WEB_DIRS_FOUND=$((WEB_DIRS_FOUND + 1)); done
RECENT_WEB_FILES=$(find /var/netscaler/logon /netscaler/ns_gui /var/vpn /var/nsproflog /var/python /var/netscaler/gui /netscaler/gui /netscaler/portal -type f \( -name '*.php' -o -name '*.xml' -o -name '*.js' -o -name '*.html' -o -name '*.xhtml' -o -name '*.py' -o -name '*.pl' -o -name '*.sh' \) -mtime -14 -print 2>/dev/null | head -100)
if [ -n "$RECENT_WEB_FILES" ]; then
    status CHECK 'Web/application files changed within 14 days; check timestamps against upgrades and approved changes. This is a heuristic, not an IOC by itself:'
    echo "$RECENT_WEB_FILES"
    WEB_BOOT_EPOCH=$(sysctl -n kern.boottime 2>/dev/null | sed -nE 's/.*sec = ([0-9]+),.*/\1/p')
    WEB_CHANGE_GROUPS=$(find /var/netscaler/logon /netscaler/ns_gui /var/vpn /var/nsproflog /var/python /var/netscaler/gui /netscaler/gui /netscaler/portal -type f \( -name '*.php' -o -name '*.xml' -o -name '*.js' -o -name '*.html' -o -name '*.xhtml' -o -name '*.py' -o -name '*.pl' -o -name '*.sh' \) -mtime -14 -print 2>/dev/null | perl -ne 'BEGIN{$b=shift @ARGV} chomp; @s=stat($_); next unless @s; $m=int($s[9]/60)*60; $g{$m}++; $f{$m}.="\n  $_"; END { for $m (sort {$a<=>$b} keys %g) { $near=(defined($b) && $b ne "" && abs($m-$b)<=1800) ? "; within 30 min of current boot" : ""; print scalar(localtime($m)), " [",$g{$m}," file(s)$near]",$f{$m},"\n" } }' "$WEB_BOOT_EPOCH" | head -100)
    if [ -n "$WEB_CHANGE_GROUPS" ]; then
        printf '\nModification-time groups (clusters near the current boot are marked; upgrade activity and HA sync still require change records/peer comparison):\n%s\n' "$WEB_CHANGE_GROUPS"
    fi
elif [ "$WEB_DIRS_FOUND" -eq 0 ]; then
    status CHECK 'None of the candidate web directories exists; file-change coverage is unknown.'
else
    status OK 'No matching web/application files with modification times within the last 14 days were found in the scanned paths.'
fi

printf '\n--- New script files and ELF binaries in served-file trees ---\n'
if [ -r "${INSTALL_STATE_FILE-}" ]; then
    RECENT_EXEC_CANDIDATES=$(find /var/netscaler/logon /netscaler/ns_gui /var/vpn /var/nsproflog /var/python /var/netscaler/gui /netscaler/gui /netscaler/portal /tmp /var/tmp -type f -newer "$INSTALL_STATE_FILE" -print 2>/dev/null | head -200)
    EXEC_WINDOW_LABEL='since installns_state'
else
    RECENT_EXEC_CANDIDATES=$(find /var/netscaler/logon /netscaler/ns_gui /var/vpn /var/nsproflog /var/python /var/netscaler/gui /netscaler/gui /netscaler/portal /tmp /var/tmp -type f -mtime -14 -print 2>/dev/null | head -200)
    EXEC_WINDOW_LABEL='within the last 14 days (install marker unavailable)'
fi
SCRIPT_FILE_HITS=''
ELF_FILE_HITS=''
if [ -n "$RECENT_EXEC_CANDIDATES" ]; then
    printf '%s\n' "$RECENT_EXEC_CANDIDATES" | while IFS= read -r f; do
        case "$f" in
            *.php|*.pl|*.py|*.sh|*.xhtml)
                ls -l "$f" 2>/dev/null
                if command -v file >/dev/null 2>&1; then file "$f" 2>/dev/null; fi
                ;;
        esac
        if command -v file >/dev/null 2>&1 && file "$f" 2>/dev/null | grep -q 'ELF'; then file "$f" 2>/dev/null; fi
    done
    status CHECK "Candidate PHP/Perl/Python/shell files and ELF identification were reviewed in a capped sample ($EXEC_WINDOW_LABEL). Entries can be legitimate product/update files; inspect names, contents, hashes, owners, and change records."
else
    status OK "No candidate files newer than the selected review-window marker were found in the scanned served/temp trees ($EXEC_WINDOW_LABEL)."
fi
if ! command -v file >/dev/null 2>&1; then
    status CHECK 'The file utility is unavailable; ELF binary identification could not run.'
fi

printf '\n--- Custom LogonPoint language JavaScript files ---\n'
LANGUAGE_DIR=/var/netscaler/logon/LogonPoint/custom
if [ -d "$LANGUAGE_DIR" ]; then
    LANGUAGE_FILES=''
    for f in "$LANGUAGE_DIR"/strings.*.js; do
        [ -f "$f" ] || continue
        LANGUAGE_FILES="${LANGUAGE_FILES}${LANGUAGE_FILES:+
}$f"
    done
    if [ -n "$LANGUAGE_FILES" ]; then
        printf '%s\n' "$LANGUAGE_FILES"
        LANGUAGE_PATTERN_HITS=0
        LANGUAGE_BASELINE_COUNT=0
        LANGUAGE_BASELINE_MISMATCHES=''
        LANGUAGE_HASH_UNAVAILABLE=0
        for f in $LANGUAGE_FILES; do
            LANGUAGE_BASELINE_COUNT=$((LANGUAGE_BASELINE_COUNT + 1))
            ls -l "$f" 2>&1
            LANGUAGE_HASH=''
            if command -v sha256 >/dev/null 2>&1; then
                LANGUAGE_SHA_OUTPUT=$(sha256 "$f" 2>&1)
                printf '%s\n' "$LANGUAGE_SHA_OUTPUT"
                LANGUAGE_HASH=$(printf '%s\n' "$LANGUAGE_SHA_OUTPUT" | sed -nE 's/.*([[:xdigit:]]{64}).*/\1/p' | head -1 | tr 'A-F' 'a-f')
            elif command -v sha256sum >/dev/null 2>&1; then
                LANGUAGE_SHA_OUTPUT=$(sha256sum "$f" 2>&1)
                printf '%s\n' "$LANGUAGE_SHA_OUTPUT"
                LANGUAGE_HASH=$(printf '%s\n' "$LANGUAGE_SHA_OUTPUT" | awk '{print tolower($1)}')
            else
                LANGUAGE_HASH_UNAVAILABLE=1
            fi
            [ -n "$LANGUAGE_HASH" ] || LANGUAGE_HASH_UNAVAILABLE=1
            if [ "${CURRENT_INPUT-}" = '14.1-73.37.nc' ] || [ "${CURRENT_INPUT-}" = '14.1-73.37' ]; then
                LANGUAGE_EXPECTED_HASH=''
                case "${f##*/}" in
                    strings.de.js) LANGUAGE_EXPECTED_HASH='60a9b62d59f1e025b9d1b413ec7c926dbe02134d82e8dea902fcb087c2d81879' ;;
                    strings.en.js) LANGUAGE_EXPECTED_HASH='a5366bdf12ecdd7ff4c87d34ec238717b0c1864598ace0fbd94a5f73f151060f' ;;
                    strings.es.js) LANGUAGE_EXPECTED_HASH='747d21f81f78d55435bc3857cc201f716979f3422d91427ae1355deda1826b5e' ;;
                    strings.fr.js) LANGUAGE_EXPECTED_HASH='ee4203c88bd3de082bc67f1de694d93edca795e1106f9f1dbe2e891b3873f83c' ;;
                    strings.it.js) LANGUAGE_EXPECTED_HASH='8fc91bd3436bc6f958ba2f2897956fb3a24c068f55008adb01f3cb32869fec20' ;;
                    strings.ja.js) LANGUAGE_EXPECTED_HASH='735e1b0e6ac42ea647198836ec1da79043342596806f83b24584abe79e437405' ;;
                    strings.ko.js) LANGUAGE_EXPECTED_HASH='4ff2bdcc36c70c2a8cf298a8b92dc536a14e3fe655aa6de3ac9c1eafb27b4ac4' ;;
                    strings.nl.js) LANGUAGE_EXPECTED_HASH='e0898d41e8c5e0b3b4174307be81ad908c23b3b11180083f4252e5b06d8e23b1' ;;
                    strings.pt.js) LANGUAGE_EXPECTED_HASH='847d7fc0724470578d4ef8548a2b0eedef54da9ea61c964986e32ae74d90de73' ;;
                    strings.ru.js) LANGUAGE_EXPECTED_HASH='10a1acb645b3a4a7cbc1135088429ac3214643facc3f3c783c909446c4142379' ;;
                    strings.zh-CN.js) LANGUAGE_EXPECTED_HASH='e1076b3642968044149abe2aabcf681dd22bf3dfb6c1d144f8f3f32a2f12b422' ;;
                    strings.zh-TW.js) LANGUAGE_EXPECTED_HASH='77417011220bf8e1d1e51d26c780875cbc51593275ff4080d73bb1da2016fbbb' ;;
                    *) LANGUAGE_BASELINE_MISMATCHES="${LANGUAGE_BASELINE_MISMATCHES}${LANGUAGE_BASELINE_MISMATCHES:+
}Unrecognized language file: $f" ;;
                esac
                if [ -n "$LANGUAGE_EXPECTED_HASH" ] && [ -n "$LANGUAGE_HASH" ] && [ "$LANGUAGE_HASH" != "$LANGUAGE_EXPECTED_HASH" ]; then
                    LANGUAGE_BASELINE_MISMATCHES="${LANGUAGE_BASELINE_MISMATCHES}${LANGUAGE_BASELINE_MISMATCHES:+
}Hash differs: $f"
                fi
            fi
            LANGUAGE_HITS=$(grep -nE -i 'new[[:space:]]+XMLHttpRequest|[.]open[[:space:]]*\(|[.]send[[:space:]]*\(|fetch[[:space:]]*\(|sendBeacon|document[.]cookie|btoa[[:space:]]*\(|atob[[:space:]]*\(|https?://' "$f" 2>/dev/null)
            if [ -n "$LANGUAGE_HITS" ]; then
                LANGUAGE_PATTERN_HITS=$((LANGUAGE_PATTERN_HITS + 1))
                status CHECK "Review request creation or exfiltration-like code in $f. The word XMLHttpRequest as a callback parameter alone is intentionally not matched; inspect destinations and any credential collection:"
                echo "$LANGUAGE_HITS"
            fi
        done
        if [ "$LANGUAGE_PATTERN_HITS" -eq 0 ]; then
            status OK 'No selected network/request-related patterns found in strings.*.js files.'
        fi
        if [ "${CURRENT_INPUT-}" = '14.1-73.37.nc' ] || [ "${CURRENT_INPUT-}" = '14.1-73.37' ]; then
            if [ "$LANGUAGE_BASELINE_COUNT" -eq 12 ] && [ "$LANGUAGE_HASH_UNAVAILABLE" -eq 0 ] && [ -z "$LANGUAGE_BASELINE_MISMATCHES" ]; then
                status OK 'All 12 strings.*.js files, filenames, and SHA-256 hashes match the internal clean-sample reference for NetScaler 14.1-73.37. This is an internal single-appliance reference, not a Citrix-published checksum set or a universal baseline.'
            else
                status CHECK "Language-file baseline differs or could not be fully checked (observed count: $LANGUAGE_BASELINE_COUNT; expected: 12; hash tool unavailable: $LANGUAGE_HASH_UNAVAILABLE). Review filenames and hashes against a trusted same-build appliance."
                [ -n "$LANGUAGE_BASELINE_MISMATCHES" ] && printf '%s\n' "$LANGUAGE_BASELINE_MISMATCHES"
            fi
        fi
    else
        status OK 'No strings.*.js language files found in the LogonPoint/custom directory.'
        if [ "${CURRENT_INPUT-}" = '14.1-73.37.nc' ] || [ "${CURRENT_INPUT-}" = '14.1-73.37' ]; then
            status CHECK 'The internal 14.1-73.37 reference contains 12 strings.*.js files, but none were found here.'
        fi
    fi
else
    status CHECK "Language-file directory $LANGUAGE_DIR is absent; this targeted content check could not run."
fi

printf '\n--- Additional LogonPoint customization baseline files ---\n'
if [ "${CURRENT_INPUT-}" = '14.1-73.37.nc' ] || [ "${CURRENT_INPUT-}" = '14.1-73.37' ]; then
    CUSTOM_ASSET_EXPECTED_COUNT=15
    CUSTOM_ASSET_OBSERVED_COUNT=0
    CUSTOM_ASSET_BASELINE_MISMATCHES=''
    for name in script.js style.css ajax-loader.gif strings.de.json strings.en.json strings.es.json strings.fr.json strings.it.json strings.ja.json strings.nl.json strings.pt.json strings.ko.json strings.ru.json strings.zh-CN.json strings.zh-TW.json; do
        f="$LANGUAGE_DIR/$name"
        [ -f "$f" ] || continue
        CUSTOM_ASSET_OBSERVED_COUNT=$((CUSTOM_ASSET_OBSERVED_COUNT + 1))
        CUSTOM_ASSET_HASH=$(sha256_of "$f")
        CUSTOM_ASSET_EXPECTED_HASH=''
        case "${f##*/}" in
            script.js) CUSTOM_ASSET_EXPECTED_HASH='31d53110df746be20920919bd72b80408e758a44852d3cf4a3d88e1b7bd5460a' ;;
            style.css) CUSTOM_ASSET_EXPECTED_HASH='0ecdfbe22feb58756224e2e3b9f38abeafcf4c491f79cdba6ebb8de52acc044b' ;;
            ajax-loader.gif) CUSTOM_ASSET_EXPECTED_HASH='b98f0466a81ba5642c9bafbc00964f0e559945a4ec996a165d2179d03bd5e8ca' ;;
            strings.de.json|strings.en.json|strings.fr.json|strings.it.json|strings.ja.json|strings.pt.json|strings.nl.json|strings.ko.json|strings.ru.json|strings.zh-TW.json)
                CUSTOM_ASSET_EXPECTED_HASH='8eb95bcbc154530931e15fc418c8b1fe991095671409552099ea1aa596999ede' ;;
            strings.es.json|strings.zh-CN.json)
                CUSTOM_ASSET_EXPECTED_HASH='d914176fd50bd7f565700006a31aa97b79d3ad17cee20c8e5ff2061d5cb74817' ;;
        esac
        printf '%s\n' "$f"
        printf 'Observed SHA-256: %s\n' "${CUSTOM_ASSET_HASH:-unavailable}"
        if [ -n "$CUSTOM_ASSET_HASH" ] && [ "$CUSTOM_ASSET_HASH" = "$CUSTOM_ASSET_EXPECTED_HASH" ]; then
            status OK "$f matches the internal clean 14.1-73.37 single-appliance reference. This is not a vendor checksum."
        elif [ -n "$CUSTOM_ASSET_HASH" ]; then
            status CHECK "$f differs from the internal clean 14.1-73.37 reference; validate intended customization and compare with another trusted same-build appliance."
            printf 'Reference SHA-256: %s\n' "$CUSTOM_ASSET_EXPECTED_HASH"
            CUSTOM_ASSET_BASELINE_MISMATCHES="${CUSTOM_ASSET_BASELINE_MISMATCHES}${CUSTOM_ASSET_BASELINE_MISMATCHES:+
}$f"
        else
            status CHECK "Could not calculate SHA-256 for $f."
            CUSTOM_ASSET_BASELINE_MISMATCHES="${CUSTOM_ASSET_BASELINE_MISMATCHES}${CUSTOM_ASSET_BASELINE_MISMATCHES:+
}$f"
        fi
    done
    if [ "$CUSTOM_ASSET_OBSERVED_COUNT" -eq "$CUSTOM_ASSET_EXPECTED_COUNT" ] && [ -z "$CUSTOM_ASSET_BASELINE_MISMATCHES" ]; then
        status OK 'All 15 additional LogonPoint assets (script.js, style.css, ajax-loader.gif, and strings.*.json) match the internal clean 14.1-73.37 reference.'
    else
        status CHECK "LogonPoint baseline coverage is partial or differs (observed $CUSTOM_ASSET_OBSERVED_COUNT of $CUSTOM_ASSET_EXPECTED_COUNT expected files). Missing files and intentional customizations require local validation."
        for name in script.js style.css ajax-loader.gif strings.de.json strings.en.json strings.es.json strings.fr.json strings.it.json strings.ja.json strings.nl.json strings.pt.json strings.ko.json strings.ru.json strings.zh-CN.json strings.zh-TW.json; do
            [ -f "$LANGUAGE_DIR/$name" ] || printf 'Missing reference file: %s/%s\n' "$LANGUAGE_DIR" "$name"
        done
    fi
else
    status CHECK 'These additional LogonPoint hashes are a single-appliance 14.1-73.37 reference and were not compared because the running build is outside that exact scope.'
fi

section '5. Log coverage and event correlation'
subsection 'Purpose and follow-up'
printf '%s\n' 'Purpose: establish which retained logs overlap the suspected pre-patch period, then search for selected HTTP, authentication, DTLS, and system-event indicators.'
printf '%s\n' 'Time handling: the CVE-2026-88771 campaign review begins with the reported activity window shown above and ends at the verified update time. Older path hits (for example, routine scans from 2025) are historical context, not evidence of this campaign by themselves.'
printf '%s\n' 'For a hit: record the original timestamp and source, correlate HTTP and authentication entries with file/config changes, and preserve the raw logs. A missing match is meaningful only for the periods and log formats actually retained.'
printf '\n--- Log retention and pre-patch coverage ---\n'
printf 'The checks below only cover files currently available on this appliance. File timestamps are a retention clue, not proof that logs are complete or contain every event.\n'
printf 'Public incident-response reporting places CVE-2026-88771 exploitation as early as 2026-09-05. If the appliance was internet-facing and below the fixed build then, include that period in the investigation where retained logs permit.\n'
LOG_FILES_LIST=''
for pattern in /var/log/httpaccess* /var/log/httperror* /var/log/ns.log* /var/log/messages* /var/log/notice.log* /var/log/nsvpn.log*; do
    for f in $pattern; do
        [ -f "$f" ] && [ -r "$f" ] && LOG_FILES_LIST="${LOG_FILES_LIST}${LOG_FILES_LIST:+
}$f"
    done
done
if [ -n "$LOG_FILES_LIST" ]; then
    LOG_TIMES=$(printf '%s\n' "$LOG_FILES_LIST" | perl -ne 'chomp; @s=stat($_); print "$s[9]\n" if @s' 2>/dev/null | sort -n)
    LOG_OLDEST_EPOCH=$(printf '%s\n' "$LOG_TIMES" | head -1)
    LOG_COUNT_FILES=$(printf '%s\n' "$LOG_FILES_LIST" | wc -l | tr -d ' ')
    [ -n "$LOG_OLDEST_EPOCH" ] && printf 'Oldest candidate log file mtime: %s\n' "$(date -r "$LOG_OLDEST_EPOCH" '+%Y-%m-%d %H:%M' 2>/dev/null || echo unknown)"
    printf 'Readable candidate files: %s\n' "$LOG_COUNT_FILES"
    if [ -n "${INSTALL_EPOCH-}" ]; then
        if [ -n "$LOG_OLDEST_EPOCH" ] && [ "$LOG_OLDEST_EPOCH" -le "$INSTALL_EPOCH" ]; then
            status CHECK 'At least one candidate log file has a modification time at or before installns_state. This suggests some pre-install log material may remain, but does not prove continuous coverage; inspect timestamps inside rotated logs and gaps.'
    else
        status CHECK 'No candidate log file modification time predates installns_state. This does not prove the logs lack older entries; inspect timestamps inside rotated logs, but pre-install coverage is not established by file metadata.'
    fi
    else
        status CHECK 'No installns_state timestamp is available for comparison. Review file contents, rotation history, and earliest log timestamps against a verified change record; file modification times alone do not prove coverage.'
    fi
else
    status CHECK 'No readable candidate HTTP/system logs found; log-based IOC checks have no usable retention coverage.'
fi
printf '\nLocal log source inventory (rotation/retention context):\n'
for pattern in /var/log/httpaccess* /var/log/httperror* /var/log/ns.log* /var/log/messages* /var/log/notice.log* /var/log/nsvpn.log* /var/log/sh.log* /var/log/bash.log*; do
    for f in $pattern; do [ -f "$f" ] && ls -l "$f" 2>/dev/null; done
done
status CHECK 'This script cannot query remote syslog, NetScaler Console, SIEM, AppFlow, Web Logging, firewall, or Active Directory event stores. Check those independently, document time ranges/timezones/retention, and correlate relevant events such as Windows 4624/4625.'
status CHECK 'File modification times only estimate log retention. Inspect timestamps inside rotated logs and identify gaps, early rotation, truncation, and clock/timezone/NTP discrepancies before treating a no-hit result as meaningful.'
subsection 'Reboot-related system log records'
FOUND_REBOOT_LOG=0
for f in /var/log/messages /var/log/ns.log /var/log/boot.log; do
    if [ -r "$f" ]; then
        FOUND_REBOOT_LOG=1
        printf '\n    Log/file: %s\n' "$f"
        matches=$(grep -E -i -n '(^|[^[:alnum:]_])(reboot(ing|ed)?|shutdown|cold[ ._-]?start|warm[ ._-]?start|boot(ed|ing)?|power[[:space:]]+(off|failure|loss|cycle))([^[:alnum:]_]|$)' "$f" 2>/dev/null |
            grep -Eiv 'CMD_EXECUTED|CLI CMD|nsprofmon_mgmt[.]pl:' | tail -100)
        if [ -n "$matches" ]; then echo "$matches"; else status OK 'No reboot-related keywords found in this log.'; fi
    fi
done
[ "$FOUND_REBOOT_LOG" -eq 1 ] || status CHECK 'No readable candidate system logs were found at the paths checked.'

subsection 'Authentication service (nsaaad) crashes and restart-limit events'
NSAAAD_LOG_COVERAGE=0
for f in /var/log/ns.log* /var/log/messages* /var/log/notice.log* /var/log/nsvpn.log*; do
    [ -f "$f" ] && [ -r "$f" ] && NSAAAD_LOG_COVERAGE=1
done
NSAAAD_EVENTS=$(zgrep -hEi '(^|[[:space:]:])proc[[:space:]]+nsaaad[[:space:]][^[:cntrl:]]*(SIGNALED|EXITED)|(^|[[:space:]:])nsaaad([[:space:]]+[0-9]+|[[:space:]]*\([0-9]+\))?[[:space:]]+(unexpectedly died|has had its maximum number of restarts)|Pitboss declaring system failure|All monitored processes have exited' /var/log/ns.log* /var/log/messages* /var/log/notice.log* /var/log/nsvpn.log* 2>/dev/null |
    grep -Eiv 'nsprofmon_mgmt[.]pl:|process_kernel_socket:[^[:cntrl:]]*call to authenticate user|cascade_auth:|start_ldap_auth:|receive_ldap_user_search_event:|AAAD API:|AAAD RESP:|LOGIN_FAILED|AAA LOGIN REQ|aaad_authenticate_req|Could not match login claims|CMD_EXECUTED|CLI CMD' | tail -30)
if [ -n "$NSAAAD_EVENTS" ]; then
    status CHECK 'Authentication-service exit or general monitored-process restart-limit events found. These are availability/triage clues, not proof of payload installation. Correlate appliance time and timezone with SAML requests, reboot history and change records:'
    printf '%s\n' "$NSAAAD_EVENTS"
elif [ "$NSAAAD_LOG_COVERAGE" -eq 0 ]; then
    status CHECK 'No readable candidate system logs; authentication-service crash coverage unavailable.'
else
    status OK 'No selected nsaaad exit/restart-limit event patterns found in retained system logs. Other message formats and rotated-away history are outside coverage.'
fi
NSAAAD_CORE_DIRS=0
for d in /var/core /var/crash; do [ -d "$d" ] && [ -r "$d" ] && NSAAAD_CORE_DIRS=$((NSAAAD_CORE_DIRS + 1)); done
NSAAAD_CORES=$(find /var/core /var/crash -type f -iname '*nsaaad*' -print 2>/dev/null | head -40)
if [ -n "$NSAAAD_CORES" ]; then
    status CHECK 'nsaaad-named core/crash files found (all retained ages, at most 40 shown). Preserve for offline analysis and correlate with request/event timestamps; do not trigger a new core dump automatically:'
    printf '%s\n' "$NSAAAD_CORES"
elif [ "$NSAAAD_CORE_DIRS" -eq 0 ]; then
    status CHECK 'No readable core/crash directory; nsaaad core inventory unavailable.'
else
    status OK 'No nsaaad-named files returned from the retained core/crash inventory.'
fi

subsection 'HTTPD reload and signal events'
HTTPD_RELOAD_LOGS=$(zgrep -E -i -n 'apachectl[[:space:]]+graceful|httpd[^[:cntrl:]]*(SIGHUP|SIGUSR1)|graceful[^[:cntrl:]]*(restart|reload)' /var/log/httperror* /var/log/messages* /var/log/ns.log* 2>/dev/null | tail -40)
if [ -n "$HTTPD_RELOAD_LOGS" ]; then
    status CHECK 'HTTPD graceful-reload or signal references found in retained logs; correlate with httpd.conf and web-file changes:'
    printf '%s\n' "$HTTPD_RELOAD_LOGS"
else
    status OK 'No selected HTTPD graceful-reload/signal references found in the searched logs.'
fi
subsection 'CVE-2026-88772 DTLS and NSPPE event correlation'
DTLS_EVENT_LINES=$(zgrep -E -i -n 'SSL_HANDSHAKE_FAILURE.*DTLSv1[.]0.*Handshake failure-Internal Error' /var/log/ns.log* /var/log/messages* /var/log/notice.log* /var/log/nsvpn.log* 2>/dev/null | tail -30)
NSPPE_EVENT_LINES=$(zgrep -E -i -n 'orphan rings|pitboss[^[:cntrl:]]*NOT restarting NSPPE|NSPPE[^[:cntrl:]]*(exit|crash|signal|terminated)' /var/log/ns.log* /var/log/messages* /var/log/notice.log* /var/log/nsvpn.log* 2>/dev/null | tail -50)
if [ -n "$DTLS_EVENT_LINES" ]; then
    printf '%s\n' "$DTLS_EVENT_LINES"
    DTLS_EVENT_FOUND=1
else
    DTLS_EVENT_FOUND=0
fi
if [ -n "$NSPPE_EVENT_LINES" ]; then
    printf '%s\n' "$NSPPE_EVENT_LINES"
    NSPPE_EVENT_FOUND=1
else
    NSPPE_EVENT_FOUND=0
fi
if [ "$DTLS_EVENT_FOUND" -eq 1 ] && [ "$NSPPE_EVENT_FOUND" -eq 1 ]; then
    status ACTION 'Both the reported DTLS handshake-failure pattern and NSPPE termination/orphan-ring indicators appear in retained system logs. This is a high-priority correlation lead, not proof by itself; correlate timestamps on the same appliance with core files and other evidence.'
elif [ "$DTLS_EVENT_FOUND" -eq 1 ]; then
    status CHECK 'Reported DTLS handshake-failure pattern found without a matching NSPPE event in the scanned logs. Review timestamps, log coverage, and source addresses; a handshake error alone is not proof of exploitation.'
elif [ "$NSPPE_EVENT_FOUND" -eq 1 ]; then
    status CHECK 'NSPPE termination/orphan-ring indicator found without the reported DTLS handshake pattern. Unexpected crashes have other causes; correlate with DTLS logs, core files, and maintenance events.'
else
    status OK 'No selected CVE-2026-88772 DTLS/NSPPE event patterns found in available ns.log/messages files. This covers only retained log content and does not rule out exploitation.'
fi

subsection 'Encoded-command references in HTTP and system logs'
LOG_COUNT=0
MATCH_COUNT=0
for d in /var/log /var/nslog; do
    [ -d "$d" ] || continue
    for f in "$d"/*http*access* "$d"/*http* "$d"/ns.log "$d"/messages; do
        [ -f "$f" ] && [ -r "$f" ] || continue
        LOG_COUNT=$((LOG_COUNT + 1))
        case "$f" in
            *.gz) hits=$(zgrep -E -i -n 'b64decode|base64_decode' "$f" 2>/dev/null | tail -100) ;;
            *.bz2|*.xz) continue ;;
            *) hits=$(grep -E -i -n 'b64decode|base64_decode' "$f" 2>/dev/null | tail -100) ;;
        esac
        if [ -n "$hits" ]; then
            MATCH_COUNT=$((MATCH_COUNT + 1))
            status ACTION "b64decode match(es) in $f; review in context and correlate timestamps:"
            echo "$hits"
        fi
    done
done
if [ "$LOG_COUNT" -eq 0 ]; then
    status CHECK 'No readable candidate logs found; absence of log data cannot be treated as a clean result.'
elif [ "$MATCH_COUNT" -eq 0 ]; then
    status OK "No b64decode matches in $LOG_COUNT readable candidate log file(s) scanned. This covers only retained log content; use the pre-patch coverage result above before drawing conclusions about the exposure window."
fi

printf '\n--- CVE-2026-88771 two-stage log-chain indicators ---\n'
HTTP_IOC_LOGS_FOUND=0
for f in /var/log/httpaccess* /var/log/httperror*; do [ -f "$f" ] && [ -r "$f" ] && HTTP_IOC_LOGS_FOUND=1; done
INDEX_LINES=$(zgrep -hE -i 'INDEX:[A-Za-z0-9+/=]{8,}' /var/log/httpaccess* /var/log/httperror* 2>/dev/null | tail -20)
INDEX_PAYLOADS=$(zgrep -hoE 'INDEX:[A-Za-z0-9+/=]{8,}' /var/log/httpaccess* /var/log/httperror* 2>/dev/null | sort -u | head -10)
if [ -n "$INDEX_PAYLOADS" ]; then
    status ACTION 'Base64 INDEX: payload candidate(s) found in HTTP logs. These are public-chain indicators, not proof of successful execution. Decoded content is displayed as inert text only:'
    for encoded in $INDEX_PAYLOADS; do
        decoded=$(printf '%s' "${encoded#INDEX:}" | perl -MMIME::Base64 -ne 'print decode_base64($_)' 2>/dev/null | tr -c '[:print:]' ' ' | cut -c1-180)
        printf '  %s -> %s\n' "$encoded" "$decoded"
    done
    printf '%s\n' "$INDEX_LINES" | tail -10
elif [ "$HTTP_IOC_LOGS_FOUND" -eq 0 ]; then
    status CHECK 'No readable HTTP access/error logs found; the INDEX: payload check has no coverage.'
else
    status OK 'No INDEX: base64 token found in available HTTP access/error logs. This covers retained files and the searched format only.'
fi

subsection 'Tagged Base64 User-Agent candidates (including K: payloads)'
# Only inspect the User-Agent field of conventional combined Apache logs.
# Decode into inert text, bound size and replace control characters; never eval.
if [ "$HTTP_IOC_LOGS_FOUND" -eq 0 ]; then
    status CHECK 'No readable candidate HTTP logs; tagged User-Agent coverage unavailable.'
elif ! command -v perl >/dev/null 2>&1; then
    status CHECK 'Perl unavailable; tagged User-Agent parsing/decoding did not run.'
else
    TAGGED_UA_RESULTS=$(zgrep -hE '"[A-Za-z]{1,8}:[A-Za-z0-9+/]{40,}={0,2}#?"[[:space:]]*$' /var/log/httpaccess* 2>/dev/null |
        perl -MMIME::Base64 -ne '
        @q=split(/"/,$_); next unless @q>=7;
        $u=$q[-2]; next unless $u =~ /^([A-Za-z]{1,8}):([A-Za-z0-9+\/]{40,}={0,2})#?$/;
        ($tag,$b)=($1,$2); next if length($b)>8192 || length($b)%4;
        next if $seen{$u}++; next if ++$count>20;
        $v=decode_base64($b);
        $strong=($v =~ /(?:curl|wget|base64|b64decode|httpd[.]conf|[.]ctxs|[.]slap)/i && $v =~ /(?:\|\s*(?:sh|bash)|;|`|\$\(|chmod\s+6[0-7]{3})/);
        $v =~ s/[^\x20-\x7e]/./g;
        print ($strong ? "[ACTION]" : "[CHECK]")," Tagged UA candidate (",$tag,"): ",substr($v,0,240),"\n";
        ')
    if [ -n "$TAGGED_UA_RESULTS" ]; then
        printf '%s\n' "$TAGGED_UA_RESULTS"
        status CHECK 'Decoded tagged User-Agent previews are inert text. ACTION requires both selected command/artifact markers and shell syntax, and indicates an attempt requiring investigation, not execution. At most 20 distinct candidates; correlate timestamps in original logs locally.'
    else
        status OK 'No tagged Base64 User-Agent candidate returned in the selected combined access-log format. Custom formats and URL-safe/shorter tokens are outside coverage.'
    fi
fi

subsection 'Whole-User-Agent Base64 candidates'
progress 'Attack logs: whole-User-Agent Base64 candidates'
# Common/combined Apache layout only: the last quoted field must be a Base64
# token, >=40 characters. Bound decoding at 8192 encoded bytes, never execute it.
UA_ACCESS_LOGS_FOUND=0
for f in /var/log/httpaccess*; do [ -f "$f" ] && [ -r "$f" ] && UA_ACCESS_LOGS_FOUND=1; done
UA_BASE64_CANDIDATES=$(zgrep -hE '"[A-Za-z0-9+/]{40,}={0,2}"[[:space:]]*$' /var/log/httpaccess* 2>/dev/null |
    awk -F '"' 'NF >= 7 {candidate=$(NF-1); if (candidate ~ /^[A-Za-z0-9+\/]+={0,2}$/ && length(candidate)>=40 && length(candidate)<=8192 && length(candidate)%4==0) print candidate}' |
    sort -u | head -20)
if [ -n "$UA_BASE64_CANDIDATES" ]; then
    status CHECK 'Whole-User-Agent Base64 candidate(s) found in common/combined HTTP access logs. Encoding alone is not an exploit indicator. Correlate the original timestamp, source, request, and decoded text; at most 20 unique candidates are shown as inert text:'
    if command -v perl >/dev/null 2>&1; then
        while IFS= read -r encoded; do
            [ -n "$encoded" ] || continue
            decoded=$(printf '%s' "$encoded" | perl -MMIME::Base64 -ne 'print decode_base64($_)' 2>/dev/null | LC_ALL=C tr -c '[:print:]' '.' | cut -c1-240)
            printf '  Encoded prefix: %.32s...\n  Decoded preview: %s\n' "$encoded" "$decoded"
        done <<EOF_UA_BASE64
$UA_BASE64_CANDIDATES
EOF_UA_BASE64
    else
        status CHECK 'Perl Base64 decoding is unavailable; inspect matching User-Agent fields offline. No payload was executed.'
    fi
elif [ "$UA_ACCESS_LOGS_FOUND" -eq 0 ]; then
    status CHECK 'No readable HTTP access logs available; whole-User-Agent Base64 coverage is unavailable.'
else
    status OK 'No whole-User-Agent Base64 candidate matched the selected common/combined access-log format. Custom formats, shorter blobs, URL-safe Base64, and error-log-only content are outside coverage.'
fi

subsection 'Authentication reconnaissance markers'
SYS_IOC_LOGS_FOUND=0
for f in /var/log/ns.log* /var/log/messages* /var/log/notice.log* /var/log/nsvpn.log*; do [ -f "$f" ] && [ -r "$f" ] && SYS_IOC_LOGS_FOUND=1; done
# CERT-EU describes the authentication-log marker followed by shell syntax as
# the second part of the chain. Do not infer that a background helper executed it.
SCANNER_PROBE_HITS=$(zgrep -E -i -c 'scanner-probe' /var/log/ns.log* /var/log/messages* /var/log/notice.log* /var/log/nsvpn.log* /var/log/httperror* /var/log/httperror-vpn* 2>/dev/null | awk -F: '{n+=$NF} END{print n+0}')
if [ "$SCANNER_PROBE_HITS" -gt 0 ]; then
    status CHECK "The string scanner-probe occurs in retained candidate logs ($SCANNER_PROBE_HITS matching line(s)). TENEX observed it as reconnaissance before crafted log injections; by itself it may be an authorized scanner or unrelated login. Review timestamps and nearby username/PPE records locally."
else
    status OK 'No scanner-probe string found in the retained candidate authentication/system logs. Coverage depends on log format and retention.'
fi
subsection 'PPE/pitboss log injection and two-stage correlation'
PITBOSS_LINES=$(zgrep -hE -i 'pitboss PPE (missed too many heartbeats|unexpectedly died)[[:space:]]?NSPPE(-[0-9]+)?[^[:cntrl:]]*(;|%3[bB]|`|%60|\$\(|\$\{IFS\}|%24%7BIFS%7D)' /var/log/ns.log* /var/log/messages* /var/log/notice.log* /var/log/nsvpn.log* 2>/dev/null | tail -40)
if [ -n "$PITBOSS_LINES" ]; then
    status ACTION 'System/authentication-log line matches a publicly reported PPE trigger (missed heartbeats or unexpectedly died) followed by shell syntax. This records an exploit attempt; it does not prove the line was later processed or that a command ran. Preserve and correlate it:'
    printf '%s\n' "$PITBOSS_LINES"
elif [ "$SYS_IOC_LOGS_FOUND" -eq 0 ]; then
    status CHECK 'No readable ns.log/messages/notice/nsvpn files found; the authentication-trigger check has no coverage.'
else
    status OK 'No selected PPE-trigger (missed heartbeats or unexpectedly died) plus shell-syntax pattern found in retained ns.log/messages/notice/nsvpn files.'
fi
if [ -n "$PITBOSS_LINES" ] && [ -n "$INDEX_LINES" ]; then
    status ACTION 'Both selected stages of the publicly described log chain are present. Raise incident priority and correlate timestamps with httpd.conf changes, webshell/payload artifacts, and system events. Available log matches cannot confirm whether the background helper processed the trigger or whether a command executed.'
elif [ -n "$PITBOSS_LINES" ]; then
    status CHECK 'The authentication trigger was found without an INDEX: token in available HTTP logs. Review log format, coverage, and other delivery paths.'
elif [ -n "$INDEX_LINES" ]; then
    status CHECK 'An INDEX: token was found without the selected authentication trigger. Review decoded text and correlate its timestamp with authentication logs and resulting files.'
fi


subsection 'Multi-signal authentication-log injection without a PPE trigger'
# Require authentication context and multiple independent execution-chain clues.
# Audit/scanner command echoes are excluded. Counts avoid exposing usernames/secrets.
LOGIN_CHAIN_COUNT=$(zgrep -hEi 'LOGIN_FAILED|AAA LOGIN REQ|aaad_authenticate_req|Could not match login claims|AAAD API: sending login req|AAAD RESP: received resp' /var/log/ns.log* /var/log/messages* /var/log/notice.log* /var/log/nsvpn.log* 2>/dev/null |
    grep -Eiv 'CMD_EXECUTED|CLI CMD|deyda-netscaler|netscaler-ioc-check' |
    grep -Ei '(\$\{?IFS\}?|%24(%7[bB])?IFS|base64[^[:cntrl:]]*(-d|--decode)|b64decode)' |
    grep -Ei '(/var/log/htt|%2[fF]var%2[fF]log%2[fF]htt|\|[[:space:]]*(sh|bash)|%7[cC][[:space:]]*(sh|bash))' | wc -l | tr -d ' ')
if [ "$LOGIN_CHAIN_COUNT" -gt 0 ]; then
    status ACTION "$LOGIN_CHAIN_COUNT retained authentication line(s) combine IFS/Base64 decoding with an HTTP-log read or shell pipeline. These are exploit-like attempt records, even without pitboss text; preserve and correlate original timestamps, commands and file artifacts. No execution is established by this count."
elif [ "$SYS_IOC_LOGS_FOUND" -eq 0 ]; then
    status CHECK 'No readable candidate authentication/system logs; multi-signal login-chain coverage unavailable.'
else
    status OK 'No selected multi-signal login injection pattern found in retained authentication/system logs. Single signals and other encodings remain outside this heuristic.'
fi

# HTTP/source coverage for the dedicated request checks below.
RECON_LOGS_FOUND=0
for f in /var/log/httpaccess* /var/log/httperror* /var/log/httperror-vpn*; do [ -f "$f" ] && [ -r "$f" ] && RECON_LOGS_FOUND=1; done

subsection 'Unusual HTTP response and diagnostic-path requests'
# Parse request, status and bytes as separate fields; a 404 alone is harmless.
if [ "$RECON_LOGS_FOUND" -eq 0 ]; then
    status CHECK 'No readable candidate HTTP logs; unusual-response/diagnostic-path coverage unavailable.'
elif ! command -v perl >/dev/null 2>&1; then
    status CHECK 'Perl unavailable; structured unusual-response parsing did not run.'
else
    HTTP_RESPONSE_LEADS=$(zgrep -hE '"[A-Z]+[[:space:]]' /var/log/httpaccess* 2>/dev/null |
        perl -ne '
        @q=split(/"/,$_); next unless @q>=3;
        ($method,$uri)=split(/\s+/,$q[1]); next unless defined $uri;
        next unless $q[2] =~ /^\s*(\d{3})\s+(\d+|-)(?:\s|$)/;
        ($code,$bytes)=($1,$2);
        if ($uri =~ m{^/nsconmsg(?:[/?]|$)}i) {$diag++}
        if ($uri =~ /\.(?:deb|sig|ico)(?:[?]|$)/i && ($code==404 || $code==202) && $bytes ne "-" && $bytes>=1000) {$large++}
        END {print "Diagnostic /nsconmsg requests: ",0+$diag,"\nPackage/icon requests with 404/202 and >=1000 response bytes: ",0+$large,"\n"}
        ')
    printf '%s\n' "$HTTP_RESPONSE_LEADS"
    if printf '%s\n' "$HTTP_RESPONSE_LEADS" | grep -Eq ': [1-9][0-9]*$'; then
        status CHECK 'Selected diagnostic-path or unusual package/icon response leads found. Status and byte count do not prove exfiltration or a webshell. Review original source/time/path, intended resource and response content where retained; avoid fetching suspect endpoints.'
    else
        status OK 'No selected diagnostic-path or unusual package/icon response lead returned from conventional access-log records. Unknown byte sizes/custom formats are outside coverage.'
    fi
fi

subsection 'Reconnaissance: nsepa.deb and vp_probe_nonexist'
NSEPA_PROBES=$(zgrep -E -i -n 'nsepa[.]deb' /var/log/httpaccess* 2>/dev/null | grep -E '"[[:space:]]*206[[:space:]]+1([[:space:]]|$)' | tail -20)
VP_PROBE_HITS=$(zgrep -E -i -n 'vp_probe_nonexist' /var/log/httpaccess* /var/log/httperror* /var/log/httperror-vpn* 2>/dev/null | tail -20)
if [ -n "$NSEPA_PROBES" ]; then
    status CHECK 'HTTP access logs contain nsepa.deb requests answered with HTTP 206 and a one-byte response. Public reporting associates this with reconnaissance/probing; it does not establish exploitation. Review source, timestamps, and adjacent requests:'
    printf '%s\n' "$NSEPA_PROBES"
elif [ "$RECON_LOGS_FOUND" -eq 0 ]; then
    status CHECK 'No readable candidate HTTP logs found for the nsepa.deb one-byte probe check; coverage is unavailable.'
else
    status OK 'No nsepa.deb HTTP 206 one-byte probe pattern found in available access logs. This is limited to retained logs and the selected format.'
fi
if [ -n "$VP_PROBE_HITS" ]; then
    status CHECK 'The public-research marker vp_probe_nonexist occurs in retained HTTP access/error logs. Treat it as a reconnaissance lead, not a compromise indicator; correlate source and timestamp with other activity:'
    printf '%s\n' "$VP_PROBE_HITS"
elif [ "$RECON_LOGS_FOUND" -eq 0 ]; then
    status CHECK 'No readable candidate HTTP logs found for the vp_probe_nonexist check; coverage is unavailable.'
else
    status OK 'No vp_probe_nonexist marker found in available HTTP access/error logs. This is limited to retained logs and the selected format.'
fi
subsection 'Authentication endpoint requests and payload combinations'
EXPLOIT_PATH_HITS=$(zgrep -E -i -n '(/nf/auth/doAuthentication[.]do|/cgi/login|/p/u/doLogon[.]do|/logon/LogonPoint/tmindex[.]html|/logon/LogonPoint/Authentication/GetUserName)' /var/log/httpaccess* /var/log/httperror* /var/log/httperror-vpn* 2>/dev/null | tail -40)
if [ -n "$EXPLOIT_PATH_HITS" ]; then
    status CHECK 'Requests to endpoints observed in public honeypot/research reporting found. These are legitimate NetScaler paths; the requests alone are not IOCs. Review any logged username/body/User-Agent for shell metacharacters or payloads and correlate with auth/system logs:'
    printf '%s\n' "$EXPLOIT_PATH_HITS"
else
    status OK 'No requests to selected public exploit/authentication paths found in available HTTP logs; this is limited by log retention and format.'
fi
AUTH_POISON_HTTP_HITS=$(zgrep -E -i -n '(/nf/auth/doAuthentication[.]do|/cgi/login|/p/u/doLogon[.]do|/logon/LogonPoint/tmindex[.]html|/logon/LogonPoint/Authentication/GetUserName)[^[:cntrl:]]*(pitboss|NSPPE|PPE unexpectedly died|missed too many heartbeats|%3[bB]|%60|\$\{IFS\}|curl[[:space:]]|wget[[:space:]]|fetch[[:space:]])' /var/log/httpaccess* /var/log/httperror* /var/log/httperror-vpn* 2>/dev/null | tail -30)
if [ -n "$AUTH_POISON_HTTP_HITS" ]; then
    status ACTION 'A logged exploit-path request also contains a public log-poisoning trigger or shell/download marker. Review the full request and correlate with ns.log/messages and file artifacts; this indicates an attempt, not automatically successful execution:'
    printf '%s\n' "$AUTH_POISON_HTTP_HITS"
fi
subsection 'VPN icon requests combined with encoded PHP markers'
ICO_STAGE_HITS=$(zgrep -E -i -n '/vpn/media/[^[:space:]]+[.]ico[^[:cntrl:]]*PD9[A-Za-z0-9+/=]{12,}|PD9[A-Za-z0-9+/=]{12,}[^[:cntrl:]]*/vpn/media/[^[:space:]]+[.]ico' /var/log/httpaccess* /var/log/httperror* /var/log/httperror-vpn* 2>/dev/null | tail -30)
if [ -n "$ICO_STAGE_HITS" ]; then
    status ACTION 'HTTP log line combines a /vpn/media/*.ico request with a User-Agent-like base64 PHP prefix (PD9). Treat as a targeted exploitation lead and correlate with log injection and resulting files:'
    printf '%s\n' "$ICO_STAGE_HITS"
else
    status OK 'No selected /vpn/media/*.ico plus base64-PHP (PD9...) pattern found in available HTTP logs.'
fi
subsection 'Webshell/tunneler HTTP markers and staging-path requests'
UX_HEADER_LOG_HITS=$(zgrep -E -i -n 'HTTP_NSC_(LDAP|CLIENTTYPE)|HTTP_X_UX(_[0-9]+)?|/vpn/media/[^[:space:]]+[.]ico|/vpn/scripts/(linux|vista|mac)/[^[:space:]]+[.](sig|deb|php)' /var/log/httpaccess* /var/log/httperror* /var/log/httperror-vpn* 2>/dev/null | tail -40)
if [ -n "$UX_HEADER_LOG_HITS" ]; then
    status CHECK 'HTTP logs contain reported webshell/tunneler header names or VPN staging-path requests. Logs may not record request headers; correlate timestamps and inspect response status, size, duration, and corresponding error-log entries:'
    printf '%s\n' "$UX_HEADER_LOG_HITS"
else
    status OK 'No selected WHIPSHOT/SLAPSHOT header names or reported VPN staging-path requests found in available HTTP logs; coverage depends on retained logs and log format.'
fi
PITSCALER_HTTP_HITS=$(zgrep -E -i -n 'ns-88771-poc|/vpn/media/[^[:space:]]+[.]ico|PD9[A-Za-z0-9+/=]{12,}|NSC_TASS|CsrfToken' /var/log/httpaccess* /var/log/httperror* /var/log/httperror-vpn* 2>/dev/null | tail -40)
if [ -n "$PITSCALER_HTTP_HITS" ]; then
    status CHECK 'HTTP logs contain additional public-research markers (test strings, staging paths, base64-PHP prefix, or cookie names). These are triage clues; cookie names alone and ns-88771-poc can be benign/authorized tests. Do not expose cookie values; correlate method, URI, response, and timestamps with other evidence:'
    printf '%s\n' "$PITSCALER_HTTP_HITS" | awk '
        BEGIN { IGNORECASE=1 }
        /ns-88771-poc/ { test++ }
        /\/vpn\/media\/[^ ]+[.]ico/ { media++ }
        /PD9[A-Za-z0-9+\/=]{12,}/ { payload++ }
        /NSC_TASS/ { tass++ }
        /CsrfToken/ { csrf++ }
        END { printf "Matching log lines by marker (values omitted): ns-88771-poc=%d; /vpn/media/*.ico=%d; base64-PHP prefix=%d; NSC_TASS=%d; CsrfToken=%d\n", test, media, payload, tass, csrf }
    '
else
    status OK 'No additional selected public-research HTTP markers found in retained HTTP logs; header/body logging and retention limit coverage.'
fi

subsection 'Bootstrap and downloader log markers'
BOOTSTRAP_LOG_COUNTS=$(zgrep -hE '/api/v1/install/|PLATYPUS_INGRESS_CA|AGENT_TOKEN|plt_[[:alnum:]]{12,}[.]|fetch([^[:cntrl:]]{0,40})-qo[[:space:]]+/v([[:space:]]|$)|:443/t/[[:xdigit:]]{6}' \
    /var/log/httpaccess* /var/log/httperror* /var/log/ns.log* /var/log/messages* /var/log/notice.log* /var/log/nsvpn.log* /var/log/sh.log* /var/log/bash.log* 2>/dev/null |
    awk '{total++; if (/\/api\/v1\/install\//) bootstrap++; if (/PLATYPUS_INGRESS_CA|AGENT_TOKEN|plt_/) token++; if (/fetch|:443\/t\//) download++} END {printf "%d %d %d %d", total, bootstrap, token, download}')
BOOTSTRAP_TOTAL=$(printf '%s\n' "$BOOTSTRAP_LOG_COUNTS" | awk '{print $1}')
BOOTSTRAP_ENDPOINT=$(printf '%s\n' "$BOOTSTRAP_LOG_COUNTS" | awk '{print $2}')
BOOTSTRAP_TOKEN=$(printf '%s\n' "$BOOTSTRAP_LOG_COUNTS" | awk '{print $3}')
BOOTSTRAP_DOWNLOAD=$(printf '%s\n' "$BOOTSTRAP_LOG_COUNTS" | awk '{print $4}')
if [ "${BOOTSTRAP_TOTAL:-0}" -gt 0 ]; then
    status CHECK "Bootstrap/downloader markers occur in retained logs: total=${BOOTSTRAP_TOTAL:-0}, install-endpoint=${BOOTSTRAP_ENDPOINT:-0}, token/CA=${BOOTSTRAP_TOKEN:-0}, downloader=${BOOTSTRAP_DOWNLOAD:-0}. Counts overlap. Token values and raw matching lines are withheld; review original logs locally and correlate with staged files/processes before concluding execution."
else
    status OK 'No selected bootstrap/downloader log marker found in readable retained candidate logs; review the general log-coverage result.'
fi

subsection 'Reported receiver/tunnel requests and exfiltration destination'
# HTTP headers are not normally retained in common access logs. Look only in
# existing retained text; do not claim a clean X-Cmd result if no header was seen.
SLAP_REQUEST_HITS=$(zgrep -hE -i '[.]slap[.]receiver|receiver[.]deb|receiver[.]v2[.]min([.][[:xdigit:]]+)?[.]css|httpd[.]conf[.]slap[.]bak|/(flash/)?nsconfig/[.]slap/|/var/tmp/[.]ux/(slapshot|whipd|whippid)[.]py' \
    /var/log/httpaccess* /var/log/httperror* /var/log/ns.log* /var/log/messages* /var/log/notice.log* /var/log/nsvpn.log* /var/log/sh.log* /var/log/bash.log* 2>/dev/null | head -40)
if [ -n "$SLAP_REQUEST_HITS" ]; then
    status CHECK 'Retained logs refer to paths from the supplied sample analysis. Requests may be probes; correlate timestamps and files. A 404 response does not rule out the described webshell behavior:'
    SLAP_REQUEST_COUNT=$(printf '%s\n' "$SLAP_REQUEST_HITS" | awk 'NF{n++} END{print n+0}')
    printf 'Displayed sample count: %s (capped at 40); raw lines withheld to protect cookies, commands, and configuration values. Review original logs locally.\n' "$SLAP_REQUEST_COUNT"
else
    status OK 'No selected sample-associated receiver/tunnel path pattern found in readable retained candidate logs; this does not cover unlogged headers or removed logs.'
fi
SLAP_XCMD_COUNT=$(zgrep -hiE -c 'X-Cmd|HTTP_X_CMD' /var/log/httpaccess* /var/log/httperror* /var/log/ns.log* /var/log/messages* /var/log/notice.log* /var/log/nsvpn.log* 2>/dev/null | awk '{n+=$0} END{print n+0}')
if [ "$SLAP_XCMD_COUNT" -gt 0 ]; then
    status CHECK "X-Cmd/HTTP_X_CMD marker found in retained logs ($SLAP_XCMD_COUNT line(s)). Values are omitted; inspect original records locally and correlate with decoded-command code, process and socket evidence."
else
    status CHECK 'No X-Cmd marker found in retained candidate logs. Standard access logs normally omit request headers, so this is not header-level coverage; inspect authorized captures/proxy/WAF telemetry.'
fi
SLAP_LOOT_CHAIN_COUNT=$(zgrep -hE -c '213[.]209[.]159[.]55:443/t/380d56/|/var/tmp/[.]s2loot|/var/tmp/[.]slap-|curl[^[:cntrl:]]*(-T|--upload-file|-X[[:space:]]*PUT|--request[[:space:]]*PUT)[^[:cntrl:]]*(nsconfig|ns_sys_backup|380d56)' \
    /var/log/sh.log* /var/log/bash.log* /var/log/ns.log* /var/log/messages* /var/log/notice.log* /var/log/nsvpn.log* 2>/dev/null | awk '{n+=$0} END{print n+0}')
if [ "$SLAP_LOOT_CHAIN_COUNT" -gt 0 ]; then
    status CHECK "Reported staging/upload-chain marker found in retained logs ($SLAP_LOOT_CHAIN_COUNT line(s)). Preserve original evidence and correlate curl result, egress and staged archive; a logged command/path does not prove transfer completion. Raw values are withheld."
else
    status OK 'No selected staging/upload-chain marker found in readable retained shell/system logs. Removed logs and absent command auditing limit coverage.'
fi
SLAP_DESTINATION_COUNT=$(zgrep -hE -c '(^|[^0-9.])213[.]209[.]159[.]55([^0-9.]|$)' /var/log/httpaccess* /var/log/httperror* /var/log/ns.log* /var/log/messages* /var/log/notice.log* /var/log/nsvpn.log* /var/log/sh.log* /var/log/bash.log* 2>/dev/null | awk '{n+=$0} END{print n+0}')
if [ "$SLAP_DESTINATION_COUNT" -gt 0 ]; then
    status CHECK "Sample-reported destination 213[.]209[.]159[.]55 occurs in retained logs ($SLAP_DESTINATION_COUNT line(s)). A string reference does not prove a connection/upload. Correlate with outbound firewall records for port 443 and /t/380d56/loot_ paths; payload and query values are omitted."
else
    status OK 'No selected sample-reported destination IP string found in readable retained candidate logs. Actual outbound transfer history requires external telemetry.'
fi
if command -v sockstat >/dev/null 2>&1; then
    SLAP_CONNECTIONS=$(sockstat -4 -c 2>/dev/null | awk '$5 == "tcp4" && $7 ~ /^213[.]209[.]159[.]55:443$/ {print}')
    if [ -n "$SLAP_CONNECTIONS" ]; then
        status ACTION 'A current IPv4 socket points to the sample-reported destination 213[.]209[.]159[.]55:443. Preserve PID/socket evidence and investigate immediately; a connection alone does not establish what data was transferred:'
        printf '%s\n' "$SLAP_CONNECTIONS"
    fi
fi
printf '%s\n' 'Follow-up: inspect external egress records from NSIP/SNIP for configuration/key/backup transfers and internal tunneling, including /nsconfig, F1.key/F2.key, ns.conf saved copies, and /var/ns_sys_backup. Do not print archive or private-key contents. NSGW banner or HTTP 404 alone is insufficient. No active network probe is performed.'


subsection 'Operator-reported payload delivery: pyrlnk.cc domains'
# Domain boundaries exclude lookalikes such as evilpyrlnk.cc / pyrlnk.cc.example.
# Count only, no attacker URLs/tokens or logged credential fields are printed.
PYRLNK_LOG_COVERAGE=0
for f in /var/log/httpaccess* /var/log/httperror* /var/log/ns.log* /var/log/messages* /var/log/notice.log* /var/log/nsvpn.log* /var/log/sh.log* /var/log/bash.log* /var/log/named* /var/log/dns*; do
    [ -f "$f" ] && [ -r "$f" ] && PYRLNK_LOG_COVERAGE=1
done
PYRLNK_DOMAIN_PATTERN='(^|[^[:alnum:]_.-])([[:alnum:]-]+[.])*pyrlnk[.]cc([^[:alnum:]_.-]|$)'
PYRLNK_LOG_COUNT=$(zgrep -hiE -c "$PYRLNK_DOMAIN_PATTERN" /var/log/httpaccess* /var/log/httperror* /var/log/ns.log* /var/log/messages* /var/log/notice.log* /var/log/nsvpn.log* /var/log/sh.log* /var/log/bash.log* /var/log/named* /var/log/dns* 2>/dev/null | awk '{n+=$0} END{print n+0}')
if [ "$PYRLNK_LOG_COUNT" -gt 0 ]; then
    status CHECK "Operator-reported payload-delivery domain pyrlnk[.]cc or a subdomain occurs in $PYRLNK_LOG_COUNT retained log line(s). The report is independently unverified; a logged download command is not proof of execution or transfer, and the destination is not the incoming attacker source. Preserve originals and correlate timestamps with nsaaad events, /v artifacts, DNS and outbound firewall telemetry. URL/token values are withheld."
elif [ "$PYRLNK_LOG_COVERAGE" -eq 0 ]; then
    status CHECK 'No readable candidate logs; pyrlnk.cc delivery-domain coverage unavailable.'
else
    status OK 'No pyrlnk.cc or subdomain reference found in retained candidate logs. Encoded destinations, removed records and external-only DNS/egress history are outside coverage.'
fi
printf '%s\n' 'Follow-up: validate the dated domain report with your security team; assess an egress block for the base domain/subdomains using approved DNS/proxy/firewall controls. Do not infer HTTPS merely from port 443. This script performs no DNS lookup, download or automatic blocking.'

subsection 'Public callback destinations and DNS references'
PUBLIC_CALLBACK_HITS=$(zgrep -E -i -n 'instances[.]httpworkbench[.]com|httpworkbench[.]com|entretiensol[.]com|gsocket[.]io|31[.]56[.]197[.]72|64[.]94[.]85[.]67|139[.]180[.]152[.]138|77[.]83[.]199[.]39|104[.]248[.]244[.]66|23[.]27[.]143[.]20|62[.]133[.]62[.]80|45[.]141[.]21[.]130|199[.]233[.]217[.]13|130[.]94[.]20[.]222' /var/log/httpaccess* /var/log/httperror* /var/log/httperror-vpn* /var/log/ns.log* /var/log/messages* /var/log/notice.log* /var/log/nsvpn.log* 2>/dev/null | tail -40)
if [ -n "$PUBLIC_CALLBACK_HITS" ]; then
    status CHECK 'References to selected public NetScaler campaign payload/callback indicators found in retained logs. IPs/domains are time-sensitive, may be reused or victim-specific, and must not be treated as a blocklist or attribution by themselves:'
    printf '%s\n' "$PUBLIC_CALLBACK_HITS"
else
    status OK 'No references to the selected public payload/callback indicators found in the searched retained logs. The source IoC lists are not exhaustive.'
fi
printf '%s\n' 'Network follow-up from TENEX: review VLAN/firewall/IDS telemetry for the cleartext mDNS service name platypus-mesh.tcp over UDP/5353 and investigate unknown participants. This appliance-local script cannot recover historical multicast traffic or inspect other hosts on the VLAN.'
DNS_CALLBACK_HITS=$(zgrep -E -i -n 'httpworkbench[.]com' /var/log/messages* /var/log/ns.log* /var/log/named* /var/log/dns* 2>/dev/null | tail -30)
if [ -n "$DNS_CALLBACK_HITS" ]; then
    status CHECK 'A public-research DNS test/callback domain appears in local logs. Confirm whether the query originated from the ADC and correlate with endpoint, HTTP, and egress telemetry; domain presence alone does not prove compromise:'
    printf '%s\n' "$DNS_CALLBACK_HITS"
else
    status CHECK 'No httpworkbench.com query was found in candidate local logs. ADC-originated DNS activity may only be visible in external resolver, firewall, or SIEM telemetry.'
fi

printf '\n--- Script extension references in HTTP error logs ---\n'
ERROR_LOGS_FOUND=0
for f in /var/log/httperror.log*; do [ -f "$f" ] && ERROR_LOGS_FOUND=1; done
PHP_ERROR_HITS=$(zgrep -E -i -n '\.php' /var/log/httperror.log* 2>/dev/null | tail -50)
SCRIPT_ERROR_HITS=$(zgrep -E -i -n '\.(sh|pl|sig|deb|rpm|tgz)' /var/log/httperror.log* /var/log/httperror-vpn.log* 2>/dev/null | tail -50)
if [ -n "$PHP_ERROR_HITS" ]; then status CHECK 'PHP references found in HTTP error logs; review the request context and correlate timestamps:'; echo "$PHP_ERROR_HITS"; elif [ "$ERROR_LOGS_FOUND" -eq 0 ]; then status CHECK 'No candidate HTTP error log files found; coverage is unknown.'; else status OK 'No PHP references found in candidate HTTP error logs.'; fi
if [ -n "$SCRIPT_ERROR_HITS" ]; then status CHECK 'References to .sh/.pl/.sig/.deb/.rpm/.tgz paths found in HTTP error logs; review the full request and correlate timestamps:'; echo "$SCRIPT_ERROR_HITS"; elif [ "$ERROR_LOGS_FOUND" -eq 1 ]; then status OK 'No .sh/.pl/.sig/.deb/.rpm/.tgz references found in candidate HTTP error logs.'; fi

printf '\n--- Unusual HTTP methods, responses, and resource references ---\n'
HTTP_REQUEST_LOGS_FOUND=0
for f in /var/log/httpaccess* /var/log/httperror* /var/log/httperror-vpn*; do [ -f "$f" ] && [ -r "$f" ] && HTTP_REQUEST_LOGS_FOUND=1; done
HTTP_METHOD_RESOURCE_HITS=$(zgrep -E -i -n 'POST|[[:space:]]404[[:space:]]|[[:space:]]500[[:space:]]' /var/log/httpaccess* /var/log/httperror* /var/log/httperror-vpn* 2>/dev/null | grep -E -i '/(nf/auth/doAuthentication[.]do|cgi/login|p/u/doLogon[.]do|logon/LogonPoint/Authentication/GetUserName)|[.](php|pl|sh|sig|deb|rpm|tgz)([?[:space:]/]|$)|/vpn/media/[^[:space:]]+[.]ico' | tail -60)
if [ -n "$HTTP_METHOD_RESOURCE_HITS" ]; then
    status CHECK 'HTTP log lines combine POST/error response markers with selected authentication, script, package, or VPN-media resources. Review method, source, status, response size/duration when logged, and nearby authentication/system events:'
    printf '%s\n' "$HTTP_METHOD_RESOURCE_HITS"
elif [ "$HTTP_REQUEST_LOGS_FOUND" -eq 0 ]; then
    status CHECK 'No readable candidate HTTP access/error logs found for method/resource review.'
else
    status OK 'No selected POST/error-response plus authentication/script/package/VPN-media pattern found in available HTTP logs.'
fi
printf '%s\n' 'Coverage: selected conventional access-log checks parse status and response bytes. This broader text search does not parse every log format or reconstruct response content/duration; review original records for suspected 404 staging.'

subsection 'Administrative-account and EPA modification audit evidence'
ACCESS_AUDIT_FOUND=0
ACCESS_AUDIT_HITS=0
for f in /var/log/ns.log* /var/log/messages* /var/log/notice.log* /var/log/nsvpn.log* /var/log/sh.log* /var/log/bash.log* /var/log/audit.log*; do
    [ -f "$f" ] && [ -r "$f" ] || continue
    ACCESS_AUDIT_FOUND=$((ACCESS_AUDIT_FOUND + 1))
    ACCESS_AUDIT_PATTERN='(add|set|rm)[[:space:]]+system[[:space:]]+user|bind[[:space:]]+system[[:space:]]+(user|group)|set[[:space:]]+authentication[[:space:]]+epaAction.*defaultEPAGroup|unbind[[:space:]]+(authentication[[:space:]]+(vserver|policylabel)|vpn[[:space:]]+vserver)|save[[:space:]]+ns[[:space:]]+config'
    case "$f" in
        *.gz) ACCESS_FILE_HITS=$(zgrep -E -i -n "$ACCESS_AUDIT_PATTERN" "$f" 2>/dev/null | tail -40) ;;
        *) ACCESS_FILE_HITS=$(grep -E -i -n "$ACCESS_AUDIT_PATTERN" "$f" 2>/dev/null | tail -40) ;;
    esac
    if [ -n "$ACCESS_FILE_HITS" ]; then
        ACCESS_AUDIT_HITS=$((ACCESS_AUDIT_HITS + 1))
        status CHECK "Selected administrative/authentication change commands occur in $f (up to 40 matches). Validate operator, source, result code, timestamp/timezone, approved changes, and effective bindings. These lines are not automatically one transaction or proof of execution:"
        # Omit whole matched command tails when they could contain user credentials.
        printf '%s\n' "$ACCESS_FILE_HITS" | awk '{
            lower=tolower($0)
            if(match(lower, /(add|set)[[:space:]]+system[[:space:]]+user/))
                print substr($0,1,RSTART-1) "[system-user command details omitted: may contain credentials]"
            else print $0
        }'
    fi
done
if [ "$ACCESS_AUDIT_FOUND" -eq 0 ]; then
    status CHECK 'No readable candidate administrative/system/shell audit logs found; account/EPA change-history coverage is unavailable.'
elif [ "$ACCESS_AUDIT_HITS" -eq 0 ]; then
    status OK 'No selected account/EPA modification commands found in retained candidate logs. Local logs can omit changes or rotate; review remote audit/SIEM records as well.'
fi
printf '%s\n' 'Follow-up: correlate user creation and rights bindings with EPA changes/unbinds and config-save events at matching times and from the same operator/source. Review remote audit and approved change records; this check performs keyword extraction, not automatic transaction correlation.'

printf '\n--- Suspicious command patterns in shell audit logs ---\n'
SHELL_AUDIT_LOGS_FOUND=0
SHELL_AUDIT_HITS=''
for f in /var/log/sh.log* /var/log/bash.log*; do
    [ -f "$f" ] && [ -r "$f" ] || continue
    SHELL_AUDIT_LOGS_FOUND=1
    case "$f" in
        *.gz) matches=$(zgrep -E -i -n 'database\.php|/flash/nsconfig/keys|LDAPTLS_REQCERT|ldapsearch|(^|[[:space:]])openssl([[:space:]]|$)|/nsconfig/ns\.conf|/etc/auth\.conf|cp /usr/bin/bash|F1\.key|F2\.key|nobody|(^|[^[:alnum:]_])id([^[:alnum:]_]|$)|curl[[:space:]]|wget[[:space:]]|/ns_gui/vpn|/var/netscaler/logon|/var/vpn|/var/tmp' "$f" 2>/dev/null | tail -50) ;;
        *) matches=$(grep -E -i -n 'database\.php|/flash/nsconfig/keys|LDAPTLS_REQCERT|ldapsearch|(^|[[:space:]])openssl([[:space:]]|$)|/nsconfig/ns\.conf|/etc/auth\.conf|cp /usr/bin/bash|F1\.key|F2\.key|nobody|(^|[^[:alnum:]_])id([^[:alnum:]_]|$)|curl[[:space:]]|wget[[:space:]]|/ns_gui/vpn|/var/netscaler/logon|/var/vpn|/var/tmp' "$f" 2>/dev/null | tail -50) ;;
    esac
    if [ -n "$matches" ]; then SHELL_AUDIT_HITS="$SHELL_AUDIT_HITS\n--- $f ---\n$matches"; fi
done
if [ -n "$SHELL_AUDIT_HITS" ]; then status CHECK 'Command-pattern matches found in available shell audit logs; these are heuristic and need contextual review:'; printf '%b\n' "$SHELL_AUDIT_HITS" | head -120; elif [ "$SHELL_AUDIT_LOGS_FOUND" -eq 1 ]; then status OK 'No configured command patterns found in readable shell audit logs.'; else status CHECK 'No readable sh.log/bash.log files found; shell command-history coverage is unknown.'; fi

printf '\n--- Gateway/VPN access-log session indicators ---\n'
VPN_ACCESS_FILES_FOUND=0
for f in /var/log/httpaccess-vpn.log*; do [ -f "$f" ] && [ -r "$f" ] && VPN_ACCESS_FILES_FOUND=1; done
VPN_200_NO_RECEIVER=$(zgrep -E -v 'CitrixReceiver' /var/log/httpaccess-vpn.log* 2>/dev/null | grep ' 200 ' | tail -50)
VPN_HEADLESS=$(zgrep -E -i -n 'HeadlessChrome' /var/log/httpaccess-vpn.log* 2>/dev/null | tail -50)
if [ "$VPN_ACCESS_FILES_FOUND" -eq 0 ]; then
    status CHECK 'No readable httpaccess-vpn.log files found; Gateway/VPN session-log checks have no coverage.'
else
    if [ -n "$VPN_200_NO_RECEIVER" ]; then
        status CHECK 'HTTP 200 VPN-access lines without a CitrixReceiver marker found. Browser/clientless sessions can be legitimate; correlate user/session, source address, user-agent, and authentication result:'
        printf '%s\n' "$VPN_200_NO_RECEIVER"
    else
        status OK 'No HTTP 200 VPN-access lines without a CitrixReceiver marker found in retained logs.'
    fi
    if [ -n "$VPN_HEADLESS" ]; then
        status CHECK 'HeadlessChrome user-agent lines found in VPN access logs; validate whether browser automation or a supported client explains them:'
        printf '%s\n' "$VPN_HEADLESS"
    else
        status OK 'No HeadlessChrome user-agent lines found in retained VPN access logs.'
    fi
fi
status CHECK 'The script does not reconstruct sessions across changing source IPs/countries/user-agents or determine whether sessions remained valid after password/MFA changes; perform that correlation in Gateway/AAA telemetry or SIEM.'

printf '\n--- Current network-connection snapshot ---\n'
if command -v sockstat >/dev/null 2>&1; then
    CURRENT_CONNECTIONS=$(sockstat -4 -c 2>&1 | head -80)
elif command -v netstat >/dev/null 2>&1; then
    CURRENT_CONNECTIONS=$(netstat -an 2>&1 | head -80)
else
    CURRENT_CONNECTIONS=''
fi
if [ -n "$CURRENT_CONNECTIONS" ]; then
    status CHECK 'Point-in-time network connections are listed for review; distinguish expected NetScaler traffic from unexpected outbound connections, internal scans, tunnels, or data transfers:'
    printf '%s\n' "$CURRENT_CONNECTIONS"
else
    status CHECK 'No supported socket/network inventory utility returned data; inspect network telemetry outside the appliance.'
fi
status CHECK 'Firewall, DNS, SMB/LDAP/Kerberos/RDP, traffic-volume, and internal-scan history require external network/firewall/SIEM telemetry and are not inferred from this connection snapshot.'


section '6. Post-scan validation'
subsection 'Purpose and follow-up'
printf '%s\n' 'Purpose: complete vendor-supported integrity validation that this read-only helper does not perform.'
subsection 'Firewall containment reminder: reported payload IP'
status CHECK 'BLOCKING RECOMMENDATION: block 213.209.159.55 on upstream firewalls for inbound access to public NetScaler VIPs and outbound connections from the appliance (NSIP/SNIP, including TCP 443). Validate and document the rule with the security team; this script cannot inspect or confirm upstream firewall enforcement.'
printf '%s\n' 'Context: the IP is a reported payload destination. The operator-provided community comment also describes it as an incoming attack source; that attribution is not independently verified here. An IP reference inside a crafted username does not identify the incoming request source.'
printf '%s\n' 'Port 443 may carry plain HTTP in this reported activity. An IP block does not replace patching, the applicable SAML workaround or incident investigation; delivery infrastructure can change. No firewall/ADC configuration is modified by this script.'

subsection 'File Integrity Monitoring'
status CHECK 'Run the supported Citrix/NetScaler File Integrity Monitoring scan and compare results with a known-good baseline; this script does not run that scan.'
else
section 'Appliance-only checks'
status CHECK 'Skipped: this run targets an exported configuration file. Run the script locally on each ADC to scan logs, files, reboots, and other host indicators.'
fi

section '7. Incident response guidance — use if compromise is suspected'
cat <<'IRGUIDE'
These are response reminders, not automated actions. Follow your incident-response process and coordinate with security, operations, and legal teams as appropriate.

1. Preserve evidence before changing the appliance: for VPX, coordinate a hypervisor snapshot; record system time, timezone, and NTP configuration; preserve local, remote syslog, and NetScaler Console logs. Generate a support bundle.
2. NSPPE core-dump collection causes a warm restart and disconnects SSH. Do not start it casually: first preserve other available evidence and coordinate the required restart with incident response and service owners. Preserve NSPPE core files for offline analysis.
3. Contain suspected compromise by isolating the appliance as directed by the incident-response lead, considering service impact. Investigate connected authentication, web, management, and application systems for lateral activity.
4. If compromise is confirmed, plan a trusted rebuild/replacement rather than relying on patching or deleting suspicious files. Restore only a known-good configuration backup that predates compromise, then validate the configuration.
5. Revoke or rotate secrets and credentials stored on or used through the appliance, including service-account credentials, shared secrets, API keys, and affected user accounts. Revoke certificates/private keys as appropriate; after rebuild, rotate local passwords and key-encryption keys and replace revoked certificates.
6. Harden the rebuilt system, keep NetScaler management services off the public internet, and monitor closely for at least 90 days. Preserve chain-of-custody evidence if legal or law-enforcement action may follow.

Citrix guidance: https://support.citrix.com/external/article/CTX694799/steps-to-take-if-netscaler-adc-is-suspec.html
IRGUIDE

section '8. Triage summary and next actions'
ACTION_COUNT=$(awk '/^===== 1[.] Platform and uptime =====/{scan=1; next} scan && /^\[ACTION\]/{n++} END{print n+0}' "$OUT")
CHECK_COUNT=$(awk '/^===== 1[.] Platform and uptime =====/{scan=1; next} scan && /^\[CHECK\]/{n++} END{print n+0}' "$OUT")
OK_COUNT=$(awk '/^===== 1[.] Platform and uptime =====/{scan=1; next} scan && /^\[OK\]/{n++} END{print n+0}' "$OUT")
printf 'Finding-message counts: ACTION=%s, CHECK=%s, OK=%s. These counts are not a risk score.\n' "$ACTION_COUNT" "$CHECK_COUNT" "$OK_COUNT"
if [ "$ACTION_COUNT" -gt 0 ]; then
    printf '%s\n' 'PRIORITY 1 — ACTION: preserve matching files and raw logs; record time/timezone; do not clean up or reboot before evidence is secured.'
    printf '%s\n' 'Correlate each hit across HTTP access/error logs, ns.log/messages/notice/nsvpn, file metadata, and approved change records. Escalate to incident response.'
else
    printf '%s\n' 'PRIORITY 1 — No selected high-priority pattern was reported. This does not exclude activity outside scanned paths, formats, or retention.'
fi
if [ "$CHECK_COUNT" -gt 0 ]; then
    printf '%s\n' 'PRIORITY 2 — CHECK: resolve each item in its section against same-build baselines, change records, and (for HA) the peer node. Record the evidence and disposition.'
fi
printf '%s\n' 'PRIORITY 3 — Coverage: confirm logs reach the relevant pre-patch period; document any gaps. Missing/rotated logs are not a clean result.'
printf '%s\n' 'PRIORITY 4 — Validation: run Citrix/NetScaler File Integrity Monitoring or the Console advisory scan as a separate check.'

printf '\nCompleted. Plain-text report saved at: %s\n' "$OUT"
exec 1>&3 2>&4 3>&- 4>&-
if [ -t 1 ]; then
    safe_display "$OUT" | awk '{gsub(/\[OK\]/, "\033[32m[OK]\033[0m"); gsub(/\[ACTION\]/, "\033[31m[ACTION]\033[0m"); gsub(/\[CHECK\]/, "\033[93m[CHECK]\033[0m"); print}'
else
    safe_display "$OUT"
fi
