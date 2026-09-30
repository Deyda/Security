#!/bin/sh
# NetScaler ADC defensive triage helper
# Version 9.20
#
# Deyda Consulting GmbH
# Website: https://www.deyda-consulting.de
# Author: Manuel Winkel
# NetScaler Security Readiness: https://www.deyda-consulting.de/expertise/netscaler-security-readiness/
# NetScaler CVE checklist (DE): https://www.deyda.net/index.php/de/2026/08/28/netscaler-cve-checkliste-updates-sicherheitspruefung-und-incident-response/
# NetScaler CVE checklist (EN): https://www.deyda.net/index.php/en/2026/08/28/netscaler-cve-checklist-updates-security-assessment-and-incident-response/
# Security Readiness provides managed NetScaler security update readiness,
# including update planning, applicable workarounds, and validation.
# Read-only. Run from the ADC shell. No interactive prompts are used. Missing or
# undetected values stay UNKNOWN and produce CHECK results; the scan continues.
#
# Positional parameters (in this exact order):
#   1. FIRMWARE_VERSION  Version/build from "show ns version", e.g. 14.1-73.37.nc.
#                        If omitted, the script tries /nsconfig/ns.conf, then nsconmsg.
#   2. ENHANCED_ISN      ENABLED or DISABLED (or the full CLI output). If omitted, the
#                        saved /nsconfig/ns.conf setting is used; absent means DISABLED.
#   3. PATCH_DATE        Date the fixed build was installed, in YYYY-MM-DD format.
#                        This is optional and is used to assess available pre-patch log coverage.
#
# Run with automatic detection / no prompts:
#   sh /path/to/netscaler-ioc-check.sh
# Supply all values explicitly:
#   sh /path/to/netscaler-ioc-check.sh 14.1-73.37.nc ENABLED 2026-09-28
# Scan an exported ns.conf (configuration checks only; no appliance/log checks):
#   sh /path/to/netscaler-ioc-check.sh --config /path/to/ns.conf 14.1-73.37.nc ENABLED 2026-09-28
# Do not pass a compact date such as 20260928: PATCH_DATE must be YYYY-MM-DD.
# Report statuses: [OK] no finding in the scanned scope; [ACTION] potential indicator requires investigation;
# [CHECK] manual validation is needed or scan coverage is incomplete.
# The plain-text report is saved in /var/tmp.

PATH=/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin
export PATH
umask 077
HOST=$(hostname 2>/dev/null || echo unknown-host)
NOW=$(date '+%Y-%m-%d_%H%M%S' 2>/dev/null || echo unknown-time)
OUT="/var/tmp/netscaler-ioc-check_${HOST}_${NOW}.txt"
CONFIG=/nsconfig/ns.conf
RUNNING_ON_ADC=YES

# Prefer explicitly supplied CLI output; otherwise detect the build from the saved
# configuration header, then nsconmsg. If neither is available, continue with an unknown build.
CURRENT_INPUT=${1-}
ISN_INPUT=${2-}
PATCH_DATE_INPUT=${3-}
ISN_CONFIG_STATE=NOT_EXPLICITLY_SET
ISN_SOURCE='not supplied'
if [ -n "$ISN_INPUT" ]; then ISN_SOURCE='operator-supplied value'; fi
if [ "${1-}" = '--config' ]; then
    CONFIG=${2-}
    CURRENT_INPUT=${3-}
    ISN_INPUT=${4-}
    PATCH_DATE_INPUT=${5-}
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
exec > "$OUT" 2>&1

section() { printf '\n===== %s =====\n' "$1"; }
subsection() { printf '\n--- %s ---\n' "$1"; }
status() { printf '[%s] %s\n' "$1" "$2"; }
FW_PATCHED=UNKNOWN

printf 'NetScaler IOC and CVE triage report\nHost: %s\nTime: %s\n' "$HOST" "$NOW"
printf 'Prepared by: Deyda Consulting GmbH\nAuthor: Manuel Winkel\nWebsite: https://www.deyda-consulting.de\n'
printf 'Related articles (DE): https://www.deyda.net/index.php/de/2026/08/28/netscaler-cve-checkliste-updates-sicherheitspruefung-und-incident-response/\n'
printf 'Related articles (EN): https://www.deyda.net/index.php/en/2026/08/28/netscaler-cve-checklist-updates-security-assessment-and-incident-response/\n'
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

section 'Security bulletin and CVE configuration checks'
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
    if [ "$FW_PATCHED" = YES ]; then
        status OK 'HTTP/SSL vServers are present in the saved config, but the entered build meets the fixed threshold; no CVE-driven config change is indicated.'
    else
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
    if [ "$FW_PATCHED" = YES ]; then
        status OK 'Gateway/AAA vServers are present, but the entered build meets the fixed threshold; no CVE-driven config change is indicated.'
    else
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

if [ "$RUNNING_ON_ADC" = YES ]; then
section 'System integrity and persistence checks'
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

subsection 'Shell binaries and privilege-escalation artifacts'
if [ -e /bin/sh ]; then
    ls -l /bin/sh 2>&1
    ls -ln /bin/sh 2>&1
    if command -v file >/dev/null 2>&1; then file /bin/sh 2>&1; else status CHECK 'file utility is unavailable; compare the SHA-256 hash and metadata with a trusted appliance on the same build.'; fi
    if command -v stat >/dev/null 2>&1; then stat /bin/sh 2>&1; else status CHECK 'stat utility is unavailable; use ls/hash output and compare against a known-good appliance.'; fi
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
ROOT_SUID_GID=$(find /var -type f -user root \( -perm -4000 -o -perm -2000 \) -exec ls -ld {} \; 2>/dev/null | head -100)
if [ -n "$ROOT_SUID_GID" ]; then
    status CHECK 'Root-owned SUID/SGID files found under /var. NetScaler may contain legitimate entries; compare paths and modes with a trusted same-build baseline:'
    printf '%s\n' "$ROOT_SUID_GID"
else
    status OK 'No root-owned SUID/SGID files were returned under /var.'
fi


section 'Web server configuration and served-file checks'
subsection 'httpd.conf metadata and indicators'
FOUND_HTTPD=0
for f in /etc/httpd.conf /nsconfig/httpd.conf /netscaler/httpd.conf; do
    if [ -e "$f" ]; then
        FOUND_HTTPD=1
        echo "--- $f ---"
        ls -l "$f" 2>&1
        if command -v stat >/dev/null 2>&1; then stat "$f" 2>&1; else status CHECK 'stat utility is unavailable; use the displayed ls metadata and compare against a known-good baseline.'; fi
        if find "$f" -mtime -14 -print 2>/dev/null | grep -q .; then status CHECK 'Modification time is within 14 days; compare with approved changes and a known-good baseline.'; else status OK 'Modification time is not within the last 14 days.'; fi
        if [ -r "$f" ]; then
            hits=$(grep -E -i -n 'b64decode|base64|LogonPoint/custom|/bin/sh|/\.ctxs|receiver[.]min|^[[:space:]]*(Alias|AliasMatch)[[:space:]].*(receiver|\.ctxs)|^[[:space:]]*(php_flag|php_admin_flag)[[:space:]]+engine[[:space:]]+on|^[[:space:]]*php_engine[[:space:]]+on|^[[:space:]]*(AddHandler|SetHandler)[[:space:]].*php' "$f" 2>/dev/null)
            MANDIANT_HTTPD_HITS=$(grep -E -i -n '^[[:space:]]*(AddType|AddHandler|SetHandler)[[:space:]].*application/x-httpd-php.*[.](deb|sig|rpm|tgz|html)([[:space:]]|$)|^[[:space:]]*AliasMatch[[:space:]].*/vpn/(media|theme|images)/.*(/vpn/scripts/linux|/gui/vpn/scripts/linux|/ns_gui/vpn/scripts/linux)' "$f" 2>/dev/null)
            if [ -n "$MANDIANT_HTTPD_HITS" ]; then status ACTION 'Non-standard PHP handler or VPN web-path alias matching publicly reported persistence patterns found; preserve httpd.conf and compare with a trusted same-build baseline:'; echo "$MANDIANT_HTTPD_HITS"; fi
            if [ -n "$hits" ]; then status CHECK 'Potential webshell alias, PHP-enabling directive, encoded-command, or payload-related configuration indicator found; compare with a trusted same-build baseline and preserve unexpected changes:'; echo "$hits"; else status OK 'No selected webshell aliases, PHP-enabling directives, encoded-command, or payload indicators found. Standard NetScaler PHP mappings and php_flag engine off are not treated as indicators by themselves.'; fi
        else
            status CHECK "$f exists but is not readable; indicator search could not be performed."
        fi
        status CHECK 'File metadata is shown, but change detection requires comparison with a known-good baseline or File Integrity Monitoring.'
    fi
done
[ "$FOUND_HTTPD" -eq 1 ] || status CHECK 'No known httpd.conf path found; verify the correct path for this ADC build.'

printf '\n--- NetScaler webshell aliases and PHP configuration indicators ---\n'
HTTPD_CANDIDATES_FOUND=0
for f in /etc/httpd.conf /nsconfig/httpd.conf /netscaler/httpd.conf; do [ -r "$f" ] && HTTPD_CANDIDATES_FOUND=1; done
RECEIVER_ALIAS_HITS=$(grep -nE -i 'receiver[.]min([.][a-f0-9]+)?[.]css|Alias(Match)?[[:space:]].*/[.]ctxs([[:space:]]|$)' /etc/httpd.conf /nsconfig/httpd.conf /netscaler/httpd.conf 2>/dev/null)
if [ -n "$RECEIVER_ALIAS_HITS" ]; then
    status ACTION 'NetScaler webshell alias indicator found in httpd.conf; preserve the file and investigate the referenced target and timestamps:'
    printf '%s\n' "$RECEIVER_ALIAS_HITS"
elif [ "$HTTPD_CANDIDATES_FOUND" -eq 0 ]; then
    status CHECK 'No readable candidate httpd.conf file found; the webshell-alias check could not run.'
else
    status OK 'No receiver.min.css or .ctxs alias patterns found in the candidate httpd.conf files.'
fi
WEB_CUSTOM_DIRS_FOUND=0
for d in /var/netscaler/logon/LogonPoint/custom /var/vpn /var/netscaler; do [ -d "$d" ] && WEB_CUSTOM_DIRS_FOUND=1; done
UNEXPECTED_PHP_XHTML=$(find /var/netscaler -type f \( -name '*.php' -o -name '*.xhtml' \) ! -path '/var/netscaler/gui/admin_ui/*' ! -path '/var/netscaler/websocketd/*' -print 2>/dev/null | head -100)
if [ -n "$UNEXPECTED_PHP_XHTML" ]; then
    status CHECK 'PHP/XHTML files found outside the known admin_ui and websocketd paths; review each against this appliance build and approved customizations:'
    WEB_CONTENT_HITS=''
    for f in $UNEXPECTED_PHP_XHTML; do
        ls -l "$f" 2>&1
        FILE_CONTENT_HITS=$(grep -nE -i 'base64_decode[[:space:]]*\(|eval[[:space:]]*\(|passthru[[:space:]]*\(|shell_exec[[:space:]]*\(|system[[:space:]]*\(|proc_open[[:space:]]*\(|NSC_TASS' "$f" 2>/dev/null)
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
    files=$(find "$d" -type f \( -name '*.sig' -o -name '*.deb' -o -name '*.php' \) -print 2>/dev/null | head -100)
    if [ -n "$files" ]; then STAGING_FILES="${STAGING_FILES}${STAGING_FILES:+
--- $d ---
}$files"; fi
done
if [ -n "$STAGING_FILES" ]; then
    status CHECK 'Files with .sig/.deb/.php extensions found in VPN script staging paths reported in public research. These paths may contain legitimate vendor files; verify ownership, hashes, contents, and timestamps against the same build:'
    printf '%s\n' "$STAGING_FILES"
    printf '%s\n' "$STAGING_FILES" | while IFS= read -r f; do
        case "$f" in ---*) continue ;; esac
        [ -f "$f" ] || continue
        ls -l "$f" 2>/dev/null
        if grep -qE -i 'HTTP_NSC_(LDAP|CLIENTTYPE)|HTTP_X_UX(_[0-9]+)?|UXD_IDLE_EXIT|base64_decode[[:space:]]*\(|eval[[:space:]]*\(|shell_exec[[:space:]]*\(|<FATO>' "$f" 2>/dev/null; then
            status ACTION "Webshell/tunneler behavior strings found in $f; preserve it and investigate as a potential compromise artifact."
        fi
    done
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
UX_HEADER_LOG_HITS=$(zgrep -E -i -n 'HTTP_NSC_(LDAP|CLIENTTYPE)|HTTP_X_UX(_[0-9]+)?|/vpn/media/[^[:space:]]+[.]ico|/vpn/scripts/(linux|vista|mac)/[^[:space:]]+[.](sig|deb|php)' /var/log/httpaccess* /var/log/httperror* /var/log/httperror-vpn* 2>/dev/null | tail -40)
if [ -n "$UX_HEADER_LOG_HITS" ]; then
    status CHECK 'HTTP logs contain reported webshell/tunneler header names or VPN staging-path requests. Logs may not record request headers; correlate timestamps and inspect response status, size, duration, and corresponding error-log entries:'
    printf '%s\n' "$UX_HEADER_LOG_HITS"
else
    status OK 'No selected WHIPSHOT/SLAPSHOT header names or reported VPN staging-path requests found in available HTTP logs; coverage depends on retained logs and log format.'
fi

MISPLACED_PHP=$(grep -rlE '<\?[[:space:]]*php|passthru[[:space:]]*\(|NSC_TASS' /var/netscaler/logon/LogonPoint/custom /var/vpn 2>/dev/null)
if [ -n "$MISPLACED_PHP" ]; then
    status ACTION 'PHP/webshell-like code found in Gateway customization paths where it is unexpected; inspect contents and preserve evidence:'
    printf '%s\n' "$MISPLACED_PHP"
elif [ ! -d /var/netscaler/logon/LogonPoint/custom ] && [ ! -d /var/vpn ]; then
    status CHECK 'Neither target customization directory exists; misplaced-PHP content coverage is unknown.'
else
    status OK 'No selected PHP/webshell signatures found in LogonPoint/custom or /var/vpn.'
fi
KNOWN_RECEIVER_HASH='6f5a2a452a7901323abd21879c6cecccb47c06aeeaccb1b467212f3b11e4b1e7'
RECEIVER_HASH_HITS=''
if command -v sha256 >/dev/null 2>&1 || command -v sha256sum >/dev/null 2>&1; then
    for d in /var/netscaler/logon/LogonPoint/custom /var/vpn; do
        [ -d "$d" ] || continue
        for f in $(find "$d" -type f -print 2>/dev/null); do
            if command -v sha256 >/dev/null 2>&1; then FILE_HASH=$(sha256 -q "$f" 2>/dev/null); else FILE_HASH=$(sha256sum "$f" 2>/dev/null | awk '{print $1}'); fi
            [ "$FILE_HASH" = "$KNOWN_RECEIVER_HASH" ] && RECEIVER_HASH_HITS="${RECEIVER_HASH_HITS}${RECEIVER_HASH_HITS:+
}$f"
        done
    done
    if [ -n "$RECEIVER_HASH_HITS" ]; then
        status ACTION 'File matching a publicly reported .ctxs.receiver webshell SHA-256 found; preserve it and investigate the appliance and HA peer:'
        printf '%s\n' "$RECEIVER_HASH_HITS"
    elif [ ! -d /var/netscaler/logon/LogonPoint/custom ] && [ ! -d /var/vpn ]; then
        status CHECK 'Neither target customization directory exists; the known webshell hash check could not run.'
    else
        status OK 'No file matching the known .ctxs.receiver SHA-256 was found in the targeted directories.'
    fi
else
    status CHECK 'No SHA-256 utility is available; the known .ctxs.receiver hash check could not run.'
fi
CTX_RECEIVER_FILES=$(find /var/netscaler/logon /netscaler/ns_gui /var/vpn -type f -name '.ctxs*' -print 2>/dev/null)
if [ -n "$CTX_RECEIVER_FILES" ]; then
    status ACTION 'Hidden .ctxs* file found in a web-facing path; investigate as a possible webshell and preserve evidence:'
    printf '%s\n' "$CTX_RECEIVER_FILES"
elif [ -d /var/netscaler/logon ] || [ -d /netscaler/ns_gui ] || [ -d /var/vpn ]; then
    status OK 'No .ctxs* files found in the candidate web-facing paths.'
else
    status CHECK 'Candidate web-facing paths are absent; .ctxs* file coverage is unknown.'
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
    status ACTION 'Exploit-associated canary or command-output file(s) found; a matching uid/gid output is strong evidence that a command ran. Preserve files before further response:'
    for f in $(printf '%s\n' "$PAYLOAD_FILES" | sort -u); do
        ls -l "$f" 2>&1
        case "$f" in
            /var/netscaler/logon/insight-new.js|/netscaler/ns_gui/admin_ui/e.txt)
                status CHECK "Payload-targeted file exists: $f. Do not print its contents automatically; it may contain appliance configuration data. Preserve and inspect it securely."
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
        for f in $LANGUAGE_FILES; do
            ls -l "$f" 2>&1
            if command -v sha256 >/dev/null 2>&1; then sha256 "$f" 2>&1; elif command -v sha256sum >/dev/null 2>&1; then sha256sum "$f" 2>&1; fi
            LANGUAGE_HITS=$(grep -nE -i 'new[[:space:]]+XMLHttpRequest|[.]open[[:space:]]*\(|[.]send[[:space:]]*\(|fetch[[:space:]]*\(|sendBeacon|document[.]cookie|btoa[[:space:]]*\(|atob[[:space:]]*\(|https?://' "$f" 2>/dev/null)
            if [ -n "$LANGUAGE_HITS" ]; then
                LANGUAGE_PATTERN_HITS=$((LANGUAGE_PATTERN_HITS + 1))
                status CHECK "Review request creation or exfiltration-like code in $f. The word XMLHttpRequest as a callback parameter alone is intentionally not matched; inspect destinations and any credential collection:"
                echo "$LANGUAGE_HITS"
            fi
        done
        if [ "$LANGUAGE_PATTERN_HITS" -eq 0 ]; then
            status OK 'No selected network/request-related patterns found in strings.*.js files. Compare their hashes with a trusted same-build baseline anyway.'
        fi
    else
        status OK 'No strings.*.js language files found in the LogonPoint/custom directory.'
    fi
else
    status CHECK "Language-file directory $LANGUAGE_DIR is absent; this targeted content check could not run."
fi

section 'Log coverage and event analysis'
printf '\n--- Log retention and pre-patch coverage ---\n'
printf 'The checks below only cover files currently available on this appliance. File timestamps are a retention clue, not proof that logs are complete or contain every event.\n'
LOG_FILES_LIST=''
for pattern in /var/log/httpaccess* /var/log/httperror* /var/log/ns.log* /var/log/messages*; do
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
    if [ -n "$PATCH_DATE_INPUT" ]; then
        PATCH_EPOCH=$(printf '%s\n' "$PATCH_DATE_INPUT" | perl -MTime::Local -ne 'if (/^(\d{4})-(\d{2})-(\d{2})$/) { print timelocal(0,0,0,$3,$2-1,$1) }' 2>/dev/null)
        if [ -z "$PATCH_EPOCH" ]; then
            status CHECK 'Patch date was not recognized; use YYYY-MM-DD. Historical log coverage could not be compared.'
        elif [ -n "$LOG_OLDEST_EPOCH" ] && [ "$LOG_OLDEST_EPOCH" -le "$PATCH_EPOCH" ]; then
            status CHECK 'At least one candidate log file predates the patch date by file mtime. This does not prove continuous pre-patch log coverage; inspect rotation, gaps, and timestamps inside the logs.'
        else
            status CHECK 'Available candidate log files do not appear to predate the patch date; a clean IOC search cannot assess the pre-patch exposure window.'
        fi
    else
        status CHECK 'Patch installation date was not supplied; pre-patch log coverage cannot be assessed.'
    fi
else
    status CHECK 'No readable candidate HTTP/system logs found; log-based IOC checks have no usable retention coverage.'
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

subsection 'CVE-2026-88772 DTLS and NSPPE event correlation'
DTLS_EVENT_LINES=$(zgrep -E -i -n 'SSL_HANDSHAKE_FAILURE.*DTLSv1[.]0.*Handshake failure-Internal Error' /var/log/ns.log* /var/log/messages* 2>/dev/null | tail -30)
NSPPE_EVENT_LINES=$(zgrep -E -i -n 'orphan rings|NOT restarting NSPPE|NSPPE[^[:cntrl:]]*(exit|crash|signal|terminated)' /var/log/ns.log* /var/log/messages* 2>/dev/null | tail -50)
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

printf '\n--- CVE-2026-88771 targeted log indicators: INDEX User-Agent and pitboss/PPE injection ---\n'
HTTP_IOC_LOGS_FOUND=0
for f in /var/log/httpaccess* /var/log/httperror*; do [ -f "$f" ] && [ -r "$f" ] && HTTP_IOC_LOGS_FOUND=1; done
INDEX_LINES=$(zgrep -hE -i 'INDEX:[A-Za-z0-9+/=]{8,}' /var/log/httpaccess* /var/log/httperror* 2>/dev/null | tail -20)
INDEX_PAYLOADS=$(zgrep -hoE 'INDEX:[A-Za-z0-9+/=]{8,}' /var/log/httpaccess* /var/log/httperror* 2>/dev/null | sort -u | head -10)
if [ -n "$INDEX_PAYLOADS" ]; then
    status ACTION 'Base64 INDEX: payload(s) found in HTTP logs; this is a targeted-attack indicator. Decoded text is shown as inert text only and is never executed:'
    for encoded in $INDEX_PAYLOADS; do
        decoded=$(printf '%s' "${encoded#INDEX:}" | perl -MMIME::Base64 -ne 'print decode_base64($_)' 2>/dev/null | tr -c '[:print:]' ' ' | cut -c1-180)
        printf '  %s -> %s\n' "$encoded" "$decoded"
    done
    printf '%s\n' "$INDEX_LINES" | tail -10
elif [ "$HTTP_IOC_LOGS_FOUND" -eq 0 ]; then
    status CHECK 'No readable HTTP access/error logs found; the INDEX: User-Agent check has no log coverage.'
else
    status OK 'No INDEX: base64 payload patterns found in available HTTP access/error logs. This covers only retained log content; see the pre-patch coverage result above.'
fi
SYS_IOC_LOGS_FOUND=0
for f in /var/log/ns.log* /var/log/messages*; do [ -f "$f" ] && [ -r "$f" ] && SYS_IOC_LOGS_FOUND=1; done
PITBOSS_LINES=$(zgrep -hE -i 'pitboss.*PPE.*(missed too many heartbeats|unexpectedly died).*NSPPE[^[:cntrl:]]*(;|%3[bB]|`|%60|\$\(|\$\{IFS\}|%24%7BIFS%7D)' /var/log/ns.log* /var/log/messages* 2>/dev/null | tail -30)
if [ -n "$PITBOSS_LINES" ]; then
    status ACTION 'PPE/pitboss log entries contain shell metacharacters after the crafted NSPPE trigger. This is strong evidence of exploit attempts being logged, not by itself proof that commands executed. Correlate with timestamps, HTTP logs, and command-output artifacts:'
    printf '%s\n' "$PITBOSS_LINES"
elif [ "$SYS_IOC_LOGS_FOUND" -eq 0 ]; then
    status CHECK 'No readable ns.log/messages files found; pitboss/PPE log-injection check has no log coverage.'
else
    status OK 'No selected pitboss/PPE log-injection strings found in available ns.log/messages files. This covers only retained log content; see the pre-patch coverage result above.'
fi

printf '\n--- Script extension references in HTTP error logs ---\n'
ERROR_LOGS_FOUND=0
for f in /var/log/httperror.log*; do [ -f "$f" ] && ERROR_LOGS_FOUND=1; done
PHP_ERROR_HITS=$(zgrep -E -i -n '\.php' /var/log/httperror.log* 2>/dev/null | tail -50)
SCRIPT_ERROR_HITS=$(zgrep -E -i -n '\.(sh|pl|sig|deb|rpm|tgz)' /var/log/httperror.log* /var/log/httperror-vpn.log* 2>/dev/null | tail -50)
if [ -n "$PHP_ERROR_HITS" ]; then status CHECK 'PHP references found in HTTP error logs; review the request context and correlate timestamps:'; echo "$PHP_ERROR_HITS"; elif [ "$ERROR_LOGS_FOUND" -eq 0 ]; then status CHECK 'No candidate HTTP error log files found; coverage is unknown.'; else status OK 'No PHP references found in candidate HTTP error logs.'; fi
if [ -n "$SCRIPT_ERROR_HITS" ]; then status CHECK 'References to .sh/.pl/.sig/.deb/.rpm/.tgz paths found in HTTP error logs; review the full request and correlate timestamps:'; echo "$SCRIPT_ERROR_HITS"; elif [ "$ERROR_LOGS_FOUND" -eq 1 ]; then status OK 'No .sh/.pl/.sig/.deb/.rpm/.tgz references found in candidate HTTP error logs.'; fi

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
status CHECK 'This live sweep does not run YARA against disk images or core dumps. If compromise is suspected, preserve appliance images and NSPPE core dumps for offline forensic analysis.'

section 'Post-scan validation'
subsection 'File Integrity Monitoring'
status CHECK 'Run the supported Citrix/NetScaler File Integrity Monitoring scan and compare results with a known-good baseline; this script does not run that scan.'
else
section 'Appliance-only checks'
status CHECK 'Skipped: this run targets an exported configuration file. Run the script locally on each ADC to scan logs, files, reboots, and other host indicators.'
fi

section 'Incident response guidance — use if compromise is suspected'
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

printf '\nCompleted. Plain-text report saved at: %s\n' "$OUT"
exec 1>&3 2>&4 3>&- 4>&-
if [ -t 1 ]; then
    awk '{gsub(/\[OK\]/, "\033[32m[OK]\033[0m"); gsub(/\[ACTION\]/, "\033[31m[ACTION]\033[0m"); gsub(/\[CHECK\]/, "\033[93m[CHECK]\033[0m"); print}' "$OUT"
else
    cat "$OUT"
fi
