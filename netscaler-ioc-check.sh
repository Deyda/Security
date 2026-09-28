#!/bin/sh
# NetScaler ADC defensive triage helper
# Version 9.9
#
# Deyda Consulting GmbH
# Website: https://www.deyda-consulting.de
#
# Author: Manuel Winkel
#
# NetScaler Security Readiness: https://www.deyda-consulting.de/expertise/netscaler-security-readiness/
# Security Readiness provides managed NetScaler security update readiness,
# including update planning, applicable workarounds, and validation.
# 
# Read-only. Run from the ADC shell. Firmware is detected from /nsconfig/ns.conf;
# Enhanced ISN is taken from live CLI input or arguments. Exported-config mode uses ns.conf:
# sh /path/to/netscaler-ioc-check.sh
# or
# # sh /path/to/netscaler-ioc-check.sh 14.1-73.37.nc ENABLED
# 
# Exported configuration: sh /path/to/netscaler-ioc-check.sh --config /path/to/ns.conf
# 
# Report statuses: [OK] no finding in the scanned scope; [ACTION] potential indicator requires investigation;
# [CHECK] manual validation is needed or scan coverage is incomplete.

PATH=/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin
export PATH
umask 077
HOST=$(hostname 2>/dev/null || echo unknown-host)
NOW=$(date '+%Y-%m-%d_%H%M%S' 2>/dev/null || echo unknown-time)
OUT="/var/tmp/netscaler-ioc-check_${HOST}_${NOW}.txt"
CONFIG=/nsconfig/ns.conf
RUNNING_ON_ADC=YES

# Prefer explicitly supplied CLI output; otherwise detect the build from the saved
# configuration header, then nsconmsg. Ask the operator only if neither is available.
CURRENT_INPUT=${1-}
ISN_INPUT=${2-}
ISN_CONFIG_STATE=NOT_EXPLICITLY_SET
ISN_SOURCE='operator-supplied value'
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
if [ -z "$CURRENT_INPUT" ]; then
    VERSION_LINE=''
    if [ -r "$CONFIG" ]; then VERSION_LINE=$(head -n 5 "$CONFIG" 2>/dev/null | grep -iE '^#NS[0-9]+\.[0-9]+ Build' | head -1); fi
    if [ -z "$VERSION_LINE" ] && command -v nsconmsg >/dev/null 2>&1; then
        VERSION_LINE=$(nsconmsg -K /var/nslog/newnslog -d setime 2>/dev/null | grep -iE 'NS[0-9]+\.[0-9]+ Build' | head -1)
    fi
    if [ -n "$VERSION_LINE" ]; then
        CURRENT_INPUT=$(printf '%s\n' "$VERSION_LINE" | sed -E -n 's/.*NS([0-9]+\.[0-9]+) Build ([0-9]+\.[0-9]+).*/\1-\2/p')
    fi
    if [ -z "$CURRENT_INPUT" ]; then
        printf 'Build could not be detected. Enter the version/build from "show ns version" (or press Enter to skip): ' >&2
        IFS= read -r CURRENT_INPUT || CURRENT_INPUT=''
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
    else
        printf 'No readable ns.conf setting found. Enter the current CLI output or ENABLED/DISABLED (Enter to skip): ' >&2
        IFS= read -r ISN_INPUT || ISN_INPUT=''
        if [ -n "$ISN_INPUT" ]; then ISN_SOURCE='operator-supplied CLI value'; else ISN_SOURCE='not supplied'; fi
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
exec > "$OUT" 2>&1

section() { printf '\n===== %s =====\n' "$1"; }
status() { printf '[%s] %s\n' "$1" "$2"; }
FW_PATCHED=UNKNOWN

printf 'NetScaler IOC and CVE triage report\nHost: %s\nTime: %s\n' "$HOST" "$NOW"
printf 'Mode: read-only; no configuration changes, restarts, or cleanup performed\n'
printf 'Report: %s\n' "$OUT"
printf 'Interpretation: [OK] means no matching indicator was found in the scanned source; it does not prove the appliance is clean or patched.\n'
printf 'Build input/source: %s\n' "${CURRENT_INPUT:-not supplied}"
printf 'Enhanced ISN state/source: %s / %s\n' "$ISN_STATE" "$ISN_SOURCE"
printf 'Enhanced ISN setting in saved config %s: %s\n' "$CONFIG" "$ISN_CONFIG_STATE"

section 'Platform and uptime'
if [ "$RUNNING_ON_ADC" = YES ]; then
    uname -a 2>&1
    uptime 2>&1
else
    status CHECK "Offline configuration mode: host checks and live ADC state are not available; config file is $CONFIG."
fi

section 'Citrix bulletin CTX697096: CVE-2026-88771 through CVE-2026-88778'
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
                status OK 'Entered firmware build meets or exceeds the fixed-build threshold in the bulletin.'
            else
                FW_PATCHED=NO
                status ACTION 'Entered firmware build is below the fixed-build threshold; update urgently.'
            fi
        else
            status CHECK "Could not select a fixed-build threshold for detected family $FW_FAMILY."
        fi
    else
        status CHECK 'Version input was not recognized. Paste the version/build from show ns version, e.g. 14.1-73.37.nc.'
    fi
else
    status CHECK 'Firmware comparison skipped; rerun with the version from show ns version as argument, e.g. sh netscaler-ioc-check.sh 14.1-73.37.nc.'
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

    section 'CVE-2026-88772: DTLS enabled on Gateway or DTLS virtual server'
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

    section 'CVE-2026-88773: HTTP configuration enabled'
    scan_config 'HTTP or SSL LB/CS/VPN/AAA virtual servers' '^[[:space:]]*add (lb|cs|vpn|authentication) vserver .* (HTTP|SSL)([[:space:]]|$)' ACTION OK
    if [ "$FW_PATCHED" = YES ]; then
        status OK 'HTTP/SSL vServers are present in the saved config, but the entered build meets the fixed threshold; no CVE-driven config change is indicated.'
    else
        status CHECK 'HTTP/SSL vServers can be relevant to this CVE on an unverified or below-threshold build. Confirm active state in the running configuration.'
    fi

    section 'CVE-2026-88774: HTTP URL-based policy expressions'
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

    section 'CVE-2026-88775: Gateway or AAA virtual server'
    scan_config 'VPN or authentication virtual servers' '^[[:space:]]*add (vpn|authentication) vserver ' ACTION OK
    if [ "$FW_PATCHED" = YES ]; then
        status OK 'Gateway/AAA vServers are present, but the entered build meets the fixed threshold; no CVE-driven config change is indicated.'
    else
        status CHECK 'Confirm whether matching Gateway/AAA vServers are active if the build is unverified or below threshold.'
    fi

    section 'CVE-2026-88776: Oracle load-balancing virtual server'
    scan_config 'Oracle LB virtual servers' '^[[:space:]]*add lb vserver .* ORACLE([[:space:]]|$)' ACTION OK
    if [ "$FW_PATCHED" != YES ]; then status CHECK 'Confirm any Oracle LB match is active if the build is unverified or below threshold.'; fi

    section 'CVE-2026-88777: non-HTTP L7 / FTP / RTSP / DNS64 / NAT64 patterns'
    scan_config 'FTP vServers, services, and monitors' '^[[:space:]]*add (lb|cs) vserver .* FTP([[:space:]]|$)|^[[:space:]]*add service .* FTP([[:space:]]|$)|^[[:space:]]*add lb monitor .* FTP(-EXTENDED)?([[:space:]]|$)' ACTION OK
    scan_config 'LSN groups and enabled FTP/RTSP ALG settings' '^[[:space:]]*add lsn group |^[[:space:]]*set lsn group .*-(ftp|rtspalg)[[:space:]]+ENABLED' ACTION OK
    scan_config 'DNS64 and NAT64 configuration' '^[[:space:]]*add lb vserver .* DNS .* -dns64 ENABLED|^[[:space:]]*add dns policy64 |^[[:space:]]*add nat64 ' ACTION OK
    if [ "$FW_PATCHED" = YES ]; then
        status OK 'The entered build meets the fixed threshold; the matches above are configuration inventory, not an indication that a CVE-driven change remains necessary.'
    else
        status CHECK 'LSN groups may use FTP ALG by default; confirm per-group settings and whether DNS64 policy objects are bound to an active DNS vServer. Matches are clues, not proof of exposure.'
    fi

section 'CVE-2026-88778: Enhanced ISN Generation and supported vServer types'
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

if [ "$RUNNING_ON_ADC" = YES ]; then
section 'Recent reboot / shutdown history'
if command -v last >/dev/null 2>&1; then
    last -n 80 2>&1 | head -80
    status CHECK 'Correlate any unexpected reboot/cold-start time with HTTP access logs; no reboot entry is not proof that none occurred.'
else
    status CHECK 'The last command is unavailable; review system event and reboot history manually.'
fi
printf '\nRecent reboot-related system log lines (available logs only):\n'
FOUND_REBOOT_LOG=0
for f in /var/log/messages /var/log/ns.log /var/log/boot.log; do
    if [ -r "$f" ]; then
        FOUND_REBOOT_LOG=1
        echo "--- $f ---"
        matches=$(grep -E -i -n 'reboot|shutdown|power|cold.?start|warm.?start|boot(ed|ing)?' "$f" 2>/dev/null | tail -100)
        if [ -n "$matches" ]; then echo "$matches"; else status OK 'No reboot-related keywords found in this log.'; fi
    fi
done
[ "$FOUND_REBOOT_LOG" -eq 1 ] || status CHECK 'No readable candidate system logs were found at the paths checked.'

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

printf '\n--- Possible temporary callhome artifacts ---\n'
CALLHOME_FILES=$(find /var/tmp -type f -name 'callhome_tmps*' -print 2>/dev/null | head -50)
if [ -n "$CALLHOME_FILES" ]; then
    status CHECK 'callhome_tmps* files found; verify whether they are expected for this appliance and preserve unexpected files:'
    echo "$CALLHOME_FILES"
else
    status OK 'No callhome_tmps* files found under /var/tmp.'
fi

printf '\n--- Firmware installation directory / possible review window ---\n'
if [ -d /var/nsinstall ]; then
    ls -lt /var/nsinstall 2>/dev/null | head -8
    status CHECK 'Use the installation history as context only; verify the actual upgrade date and review the exposure window in available logs.'
else
    status CHECK '/var/nsinstall is unavailable; determine the last firmware installation date from change records.'
fi

printf '\n--- Cron entries for nobody ---\n'
if command -v crontab >/dev/null 2>&1; then
    NOBODY_CRON=$(crontab -u nobody -l 2>/dev/null | grep -v '^[[:space:]]*#' | grep -v '^[[:space:]]*$')
    if [ -n "$NOBODY_CRON" ]; then status CHECK "Crontab entries exist for nobody; verify they are expected:"; echo "$NOBODY_CRON"; else status OK 'No non-comment crontab entries found for nobody, if supported by this build.'; fi
else
    status CHECK 'crontab utility is unavailable; check scheduled tasks using the platform-supported method.'
fi

printf '\n--- Processes running as nobody other than httpd ---\n'
NOBODY_PROCESSES=$(ps auxww 2>/dev/null | grep '^nobody' | grep -v '/bin/httpd' | grep -v '[g]rep' | head -50)
if [ -n "$NOBODY_PROCESSES" ]; then status CHECK 'Processes owned by nobody found; distinguish expected services from unexpected processes:'; echo "$NOBODY_PROCESSES"; else status OK 'No non-httpd processes owned by nobody were returned by ps.'; fi

printf '\n--- Python references in rc.netscaler ---\n'
if [ -r /flash/nsconfig/rc.netscaler ]; then
    RCN_PYTHON=$(grep -E -i -n 'python' /flash/nsconfig/rc.netscaler 2>/dev/null)
    if [ -n "$RCN_PYTHON" ]; then status CHECK 'Python reference(s) found in rc.netscaler; compare with the approved startup configuration:'; echo "$RCN_PYTHON"; else status OK 'No Python references found in rc.netscaler.'; fi
else
    status CHECK '/flash/nsconfig/rc.netscaler is absent or unreadable; this persistence check could not run.'
fi


section 'httpd.conf metadata and indicators'
FOUND_HTTPD=0
for f in /etc/httpd.conf /nsconfig/httpd.conf /netscaler/httpd.conf; do
    if [ -e "$f" ]; then
        FOUND_HTTPD=1
        echo "--- $f ---"
        ls -l "$f" 2>&1
        if command -v stat >/dev/null 2>&1; then stat "$f" 2>&1; else status CHECK 'stat utility is unavailable; use the displayed ls metadata and compare against a known-good baseline.'; fi
        if find "$f" -mtime -14 -print 2>/dev/null | grep -q .; then status CHECK 'Modification time is within 14 days; compare with approved changes and a known-good baseline.'; else status OK 'Modification time is not within the last 14 days.'; fi
        if [ -r "$f" ]; then
            hits=$(grep -E -i -n 'b64decode|base64|LogonPoint/custom|/bin/sh' "$f" 2>/dev/null)
            if [ -n "$hits" ]; then status ACTION 'Search strings found in this file; inspect and preserve evidence:'; echo "$hits"; else status OK 'None of the searched strings were found in this file.'; fi
        else
            status CHECK "$f exists but is not readable; indicator search could not be performed."
        fi
        status CHECK 'File metadata is shown, but change detection requires comparison with a known-good baseline or File Integrity Monitoring.'
    fi
done
[ "$FOUND_HTTPD" -eq 1 ] || status CHECK 'No known httpd.conf path found; verify the correct path for this ADC build.'

section '/bin/sh permissions and metadata'
if [ -e /bin/sh ]; then
    ls -l /bin/sh 2>&1
    ls -ln /bin/sh 2>&1
    if command -v file >/dev/null 2>&1; then file /bin/sh 2>&1; else status CHECK 'file utility is unavailable; compare the SHA-256 hash and metadata with a trusted appliance on the same build.'; fi
    if command -v stat >/dev/null 2>&1; then stat /bin/sh 2>&1; else status CHECK 'stat utility is unavailable; use ls/hash output and compare against a known-good appliance.'; fi
    if command -v sha256 >/dev/null 2>&1; then sha256 /bin/sh 2>&1; elif command -v sha256sum >/dev/null 2>&1; then sha256sum /bin/sh 2>&1; fi
    ls -ld /bin /bin/sh 2>&1
    status CHECK 'Compare permissions, owner, timestamps, and hash with a known-good appliance on the same build; this script cannot declare them normal.'
else
    status ACTION '/bin/sh was not found at the expected path; verify platform paths and investigate.'
fi

printf '\nSetuid/setgid mode check:\n'
SHELL_MODE=$(ls -l /bin/sh 2>/dev/null | awk 'NR==1{print $1}')
case "$SHELL_MODE" in
    *s*) status ACTION "/bin/sh has a setuid/setgid permission marker ($SHELL_MODE); preserve evidence and compare with a trusted baseline." ;;
    '') status CHECK 'Could not read /bin/sh mode.' ;;
    *) status OK "/bin/sh has no setuid/setgid permission marker ($SHELL_MODE); still compare owner, mode, timestamp, and hash with a same-build baseline." ;;
esac


section 'Unexpected .dot files beneath LogonPoint/custom'
DOT_COUNT=0
for d in /var/netscaler/logon/LogonPoint/custom; do
    if [ -d "$d" ]; then
        echo "--- Searching $d ---"
        dot_files=$(find "$d" -name '*.dot' -print 2>/dev/null)
        if [ -n "$dot_files" ]; then
            status ACTION '.dot files found; investigate creation times and preserve them for analysis:'
            echo "$dot_files"
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
elif [ "$WEB_DIRS_FOUND" -eq 0 ]; then
    status CHECK 'None of the candidate web directories exists; file-change coverage is unknown.'
else
    status OK 'No matching web/application files with modification times within the last 14 days were found in the scanned paths.'
fi


section 'b64decode references in available HTTP / system logs'
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
    status OK "No b64decode matches in $LOG_COUNT readable candidate log file(s) scanned. This does not rule out compromise."
fi

printf '\n--- Script extension references in HTTP error logs ---\n'
ERROR_LOGS_FOUND=0
for f in /var/log/httperror.log*; do [ -f "$f" ] && ERROR_LOGS_FOUND=1; done
PHP_ERROR_HITS=$(zgrep -E -i -n '\.php' /var/log/httperror.log* 2>/dev/null | tail -50)
SCRIPT_ERROR_HITS=$(zgrep -E -i -n '\.(sh|pl)' /var/log/httperror.log* 2>/dev/null | tail -50)
if [ -n "$PHP_ERROR_HITS" ]; then status CHECK 'PHP references found in HTTP error logs; review the request context and correlate timestamps:'; echo "$PHP_ERROR_HITS"; elif [ "$ERROR_LOGS_FOUND" -eq 0 ]; then status CHECK 'No candidate HTTP error log files found; coverage is unknown.'; else status OK 'No PHP references found in candidate HTTP error logs.'; fi
if [ -n "$SCRIPT_ERROR_HITS" ]; then status CHECK 'References to .sh/.pl paths found in HTTP error logs; review the full request and correlate timestamps:'; echo "$SCRIPT_ERROR_HITS"; elif [ "$ERROR_LOGS_FOUND" -eq 1 ]; then status OK 'No .sh/.pl references found in candidate HTTP error logs.'; fi

printf '\n--- Suspicious command patterns in shell audit logs ---\n'
SHELL_AUDIT_LOGS_FOUND=0
SHELL_AUDIT_HITS=''
for f in /var/log/sh.log* /var/log/bash.log*; do
    [ -f "$f" ] && [ -r "$f" ] || continue
    SHELL_AUDIT_LOGS_FOUND=1
    case "$f" in
        *.gz) matches=$(zgrep -E -i -n 'database\.php|/flash/nsconfig/keys|LDAPTLS_REQCERT|ldapsearch|(^|[[:space:]])openssl([[:space:]]|$)|/nsconfig/ns\.conf|del /etc/auth\.conf|cp /usr/bin/bash|F1\.key|F2\.key' "$f" 2>/dev/null | tail -50) ;;
        *) matches=$(grep -E -i -n 'database\.php|/flash/nsconfig/keys|LDAPTLS_REQCERT|ldapsearch|(^|[[:space:]])openssl([[:space:]]|$)|/nsconfig/ns\.conf|del /etc/auth\.conf|cp /usr/bin/bash|F1\.key|F2\.key' "$f" 2>/dev/null | tail -50) ;;
    esac
    if [ -n "$matches" ]; then SHELL_AUDIT_HITS="$SHELL_AUDIT_HITS\n--- $f ---\n$matches"; fi
done
if [ -n "$SHELL_AUDIT_HITS" ]; then status CHECK 'Command-pattern matches found in available shell audit logs; these are heuristic and need contextual review:'; printf '%b\n' "$SHELL_AUDIT_HITS" | head -120; elif [ "$SHELL_AUDIT_LOGS_FOUND" -eq 1 ]; then status OK 'No configured command patterns found in readable shell audit logs.'; else status CHECK 'No readable sh.log/bash.log files found; shell command-history coverage is unknown.'; fi

printf '\n--- Browser/clientless VPN log requests (heuristic) ---\n'
VPN_LOGS_FOUND=0
for f in /var/log/httpaccess-vpn.log*; do [ -f "$f" ] && VPN_LOGS_FOUND=1; done
NON_RECEIVER_HITS=$(zgrep -E -i -v 'CitrixReceiver' /var/log/httpaccess-vpn.log* 2>/dev/null | grep ' 200 ' | tail -50)
if [ -n "$NON_RECEIVER_HITS" ]; then
    NON_RECEIVER_COUNT=$(printf '%s\n' "$NON_RECEIVER_HITS" | wc -l | tr -d ' ')
    status CHECK "$NON_RECEIVER_COUNT successful requests without a CitrixReceiver marker. Browser/clientless Gateway access and static resources (for example plugins.xml, CSS, or JavaScript) can be normal; this is not an IOC by itself. Review source and timing only if that access is unexpected. Showing up to 5 examples:"
    printf '%s\n' "$NON_RECEIVER_HITS" | tail -5
elif [ "$VPN_LOGS_FOUND" -eq 0 ]; then
    status CHECK 'No candidate VPN access log files found; this check could not run.'
else
    status OK 'No matching successful non-Receiver requests found in candidate VPN access logs.'
fi
if [ "$VPN_LOGS_FOUND" -eq 1 ]; then
    HEADLESS_CHROME_HITS=$(zgrep -E -i -n 'HeadlessChrome' /var/log/httpaccess-vpn.log* 2>/dev/null | tail -5)
    if [ -n "$HEADLESS_CHROME_HITS" ]; then
        status CHECK 'HeadlessChrome user-agent found in VPN access logs; automation can be legitimate, review source, URL, and timing:'
        echo "$HEADLESS_CHROME_HITS"
    else
        status OK 'No HeadlessChrome user-agent found in candidate VPN access logs.'
    fi
fi
status CHECK 'For HA pairs, run this check on both nodes. A clean result on one node does not establish the state of its peer.'
status CHECK 'For official Citrix IoCs, use the supported NetScaler Console Security Advisory scan or work with Citrix Support. Preserve relevant logs and evidence before rebooting or upgrading if compromise is suspected.'

section 'File Integrity Monitoring'
status CHECK 'Run the supported Citrix/NetScaler File Integrity Monitoring scan and compare results with a known-good baseline; this script does not run that scan.'
else
section 'Appliance-only checks'
status CHECK 'Skipped: this run targets an exported configuration file. Run the script locally on each ADC to scan logs, files, reboots, and other host indicators.'
fi

printf '\nCompleted. Plain-text report saved at: %s\n' "$OUT"
exec 1>&3 2>&4 3>&- 4>&-
if [ -t 1 ]; then
    awk '{gsub(/\[OK\]/, "\033[32m[OK]\033[0m"); gsub(/\[ACTION\]/, "\033[31m[ACTION]\033[0m"); gsub(/\[CHECK\]/, "\033[93m[CHECK]\033[0m"); print}' "$OUT"
else
    cat "$OUT"
fi
