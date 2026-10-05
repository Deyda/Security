#!/bin/sh
#
# Deyda Consulting | NetScaler ADC Defensive Triage
# Script:  deyda-netscaler-ioc-check.sh
# Version: 9.74
#
# GEIGER detection enhancements are integrated into the read-only checks below.
# Optional campaign start override: GEIGER_CAMPAIGN_START=YYYY-MM-DD.
# Sample-specific checks below additionally use the operator-supplied 380d56
# analysis screenshot and follow-up description (2026-10-02), not independently verified. No partial hash
# is used. Paths/ports alone are CHECK; matching behavior requires investigation.
# New operator-reported lead (2026-10-02): pylrk.cc and its subdomains as
# attempted payload delivery destinations; independently reported and time-sensitive. The earlier misspelling is not searched.
# The SAML workaround is detected by request expression and DROP action, not policy
# name; AAA_REQUEST bindings are checked. Exact internal package hash matches are
# reported independent of the firmware label; GEIGER execution/log features are below.
# Confidential vendor policy expressions are neither embedded nor printed.
# Earlier changes: tighten real nsaaad lifecycle matching; exclude LDAP username payloads
# and monitoring command echoes; bound reboot keywords to avoid powerbi noise.
# Explicit upstream firewall blocking reminder for 213.209.159.55;
# exclude authentication payload text from nsaaad crash classification;
# broaden restart-limit patterns and add bounded pylrk.cc log counts;
# align result groups with their own headings; initialize install marker
# before core checks; deduplicate CVE messages and baseline context; saved SAML
# configurations; authentication-service crash triage; SAML workaround inventory;
# tagged User-Agent payloads; multi-signal login injection; unusual HTTP responses;
# open-file and /flash privileged-file inventories. No mitigation is applied.
# Additional leads: operator-supplied Gotham advisory/checker package (2026-10-02).
# Its observations are scoped to inspected systems, not universal patch guarantees.
# Additional SAML reconnaissance leads: Lupovis probe/1 and oversized SAML requests,
# plus the Gotham-reported 138.199.60.0/24 range (CHECK-only; shared VPN/hosting range).
# These leads were reviewed from the supplied public community checker v1.13;
# the detection logic here is independently implemented and is not vendor IoC coverage.
#
# Publisher
#   Deyda Consulting GmbH
#   Website: https://www.deyda-consulting.de
#   Author: Manuel Winkel
#   Security Readiness:
#   https://www.deyda-consulting.de/expertise/netscaler-security-readiness/
#
# References
#   GEIGER variant and additions: Patrick Wagner (shared with permission)
#   Community SAML reconnaissance leads reviewed from checker v1.13:
#   https://github.com/ThomasPoppelgaard/netscaler-ctx697096-checker
#   Additional security bulletin: CTX697174 (CVE-2026-88779, SAML SP/IdP DoS)
#   https://support.citrix.com/external/article/CTX697174
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
#   below use internal samples from one clean 14.1-73.37 appliance and one clean
#   14.1-73.41 appliance; these are not Citrix-published checksums.
#
# Optional CLI captures for the additional Global Deny List assessment:
#   DEYDA_GDL_SIGNATURES_FILE=/path/to/signatures.txt
#   DEYDA_GDL_STATS_FILE=/path/to/denylist-aaa-request.txt
#   Capture "show appfw signatures" and "stat denylist global AAA_REQUEST"
#   in the ADC CLI, then set these variables when invoking the script. Captures
#   are reported as operator-supplied evidence, not live verification. If omitted,
#   the appliance attempts the two read-only queries via /netscaler/cli_script.sh
#   or /netscaler/nscli -c,
#   each limited to 15 seconds. Missing CLI support produces CHECK, no prompts.
#
# Status labels: [OK] no match in scanned scope; [ACTION] investigate indicator;
# [CHECK] manual validation required or scan coverage incomplete.
# Report output: /var/tmp/deyda-netscaler-ioc-check_<host>_<time>.txt
#
PATH=/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin
export PATH
umask 077
SCRIPT_VERSION='9.74'
# GEIGER: identify this script by its resolved path, not by an assumed file name.
GEIGER_SELF_PATH=$(realpath "$0" 2>/dev/null)
[ -n "$GEIGER_SELF_PATH" ] || GEIGER_SELF_PATH=$(cd "$(dirname "$0")" 2>/dev/null && printf '%s/%s' "$(pwd -P)" "$(basename "$0")")
GEIGER_SELF_BASE=${GEIGER_SELF_PATH##*/}
GEIGER_CAMPAIGN_START=${GEIGER_CAMPAIGN_START:-2026-09-05}
GEIGER_LOG_DIR=/var/log
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

# Scope internal hashes by parsed build rather than exact presentation text.
# Keep editions without a supplied reference outside this standard-build baseline.
reference_build_supported() {
    printf '%s\n' "${CURRENT_INPUT-}" | grep -Eiq 'FIPS|NDcPP' && return 1
    _reference_build=$(printf '%s\n' "${CURRENT_INPUT-}" | sed -nE 's/.*(14[.]1|13[.]1)[^0-9]*([0-9]+[.][0-9]+).*/\1-\2/p' | head -1)
    [ "$_reference_build" = '14.1-73.37' ]
}
reference_hash_build() {
    printf '%s\n' "${CURRENT_INPUT-}" | grep -Eiq 'FIPS|NDcPP' && return 1
    _hash_reference_build=$(printf '%s\n' "${CURRENT_INPUT-}" | sed -nE 's/.*(14[.]1|13[.]1)[^0-9]*([0-9]+[.][0-9]+).*/\1-\2/p' | head -1)
    case "$_hash_reference_build" in
        14.1-73.37|14.1-73.41) printf '%s' "$_hash_reference_build" ;;
        *) return 1 ;;
    esac
}
reference_hash_build_supported() {
    [ -n "$(reference_hash_build)" ]
}

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

# GEIGER: sort grep/zgrep matches by the timestamp inside each line. Rotated file
# names sort as ns.log.1, ns.log.10, ns.log.2, so "tail" alone does not return the
# newest lines. Without perl the input order is kept.
GEIGER_CHRONO_PL='
use strict;
use warnings;
use POSIX qw(mktime floor);
# Embedded in a single-quoted shell string: never use an apostrophe here.
# Sorts grep/zgrep output by the timestamp inside each line. Accepts plain lines
# and "path:" or "path:lineno:" prefixes. Lines without a timestamp keep their
# order and come first, so "tail" still returns the newest dated lines.
my %MONTH = (Jan => 0, Feb => 1, Mar => 2, Apr => 3, May => 4, Jun => 5,
             Jul => 6, Aug => 7, Sep => 8, Oct => 9, Nov => 10, Dec => 11);
my $now = time;
my (%anchor, @rows);
my $sequence = 0;
while (my $line = <STDIN>) {
    $line =~ s/\r?\n\z//;
    my ($path, $content) = (undef, $line);
    if ($line =~ m{^(/[^:\s]*):(.*)\z}s) {
        ($path, $content) = ($1, $2);
        $content =~ s/^\d+://;
    }
    push @rows, [stamp($content, $path), $sequence++, $line];
}
print map { "$_->[2]\n" } sort { $a->[0] <=> $b->[0] || $a->[1] <=> $b->[1] } @rows;

sub stamp {
    my ($text, $path) = @_;
    if ($text =~ /^([A-Z][a-z]{2})\s{1,2}(\d{1,2})\s(\d{2}):(\d{2}):(\d{2})\s/) {
        my $mon = $MONTH{$1};
        return -1 unless defined $mon;
        # Syslog has no year: anchor on the file mtime (or now) and step back a year if needed.
        my $ref = $now;
        if (defined $path) {
            $anchor{$path} = (stat $path)[9] unless exists $anchor{$path};
            $ref = $anchor{$path} if defined $anchor{$path};
        }
        my $year = (localtime $ref)[5];
        my $t = mktime($5, $4, $3, $2, $mon, $year, 0, 0, -1);
        $t = mktime($5, $4, $3, $2, $mon, $year - 1, 0, 0, -1) if defined $t && $t > $ref + 2 * 86400;
        return defined $t ? $t : -1;
    }
    if ($text =~ m{\[(\d{2})/([A-Z][a-z]{2})/(\d{4}):(\d{2}):(\d{2}):(\d{2})\s([+-])(\d{2})(\d{2})\]}) {
        my $mon = $MONTH{$2};
        return -1 unless defined $mon;
        my ($y, $m, $d) = ($3, $mon + 1, $1);
        $y -= 1 if $m <= 2;
        my $era  = floor($y / 400);
        my $yoe  = $y - $era * 400;
        my $doy  = int((153 * ($m > 2 ? $m - 3 : $m + 9) + 2) / 5) + $d - 1;
        my $days = $era * 146097 + $yoe * 365 + int($yoe / 4) - int($yoe / 100) + $doy - 719468;
        return $days * 86400 + $4 * 3600 + $5 * 60 + $6 - ($8 * 3600 + $9 * 60) * ($7 eq "-" ? -1 : 1);
    }
    if ($text =~ /^\[[A-Z][a-z]{2}\s([A-Z][a-z]{2})\s{1,2}(\d{1,2})\s(\d{2}):(\d{2}):(\d{2})(?:\.\d+)?\s(\d{4})\]/) {
        my $mon = $MONTH{$1};
        return -1 unless defined $mon;
        my $t = mktime($5, $4, $3, $2, $mon, $6 - 1900, 0, 0, -1);
        return defined $t ? $t : -1;
    }
    return -1;
}
'
chrono_sort() {
    if command -v perl >/dev/null 2>&1; then
        perl -e "$GEIGER_CHRONO_PL"
    else
        cat
    fi
}

# GEIGER: read-only log analysis for points 1, 2 and 4 (attempt summary, source IPs,
# execution traces, per-family coverage). The embedded program opens logs read-only,
# starts gzip/sha256 only via list-form exec with fixed arguments and never evaluates
# log content. Argument 1: coverage | injection.
GEIGER_ANALYSIS_PL='
use strict;
use warnings;
use POSIX qw(strftime mktime floor);

# Embedded in deyda-netscaler-ioc-check.sh inside a single-quoted shell
# string: this program must never contain an apostrophe character.
# Arguments: mode logdir campaign-date install-epoch boot-epoch self-path report-path
my ($MODE, $LOGDIR, $CAMPAIGN_TEXT, $INSTALL_ARG, $BOOT_ARG, $SELF_PATH, $REPORT_PATH) = @ARGV;
$MODE        = "" unless defined $MODE;
$LOGDIR      = "/var/log" unless defined $LOGDIR && length $LOGDIR;
$SELF_PATH   = "" unless defined $SELF_PATH;
$REPORT_PATH = "" unless defined $REPORT_PATH;
my $INSTALL_EPOCH = defined $INSTALL_ARG && $INSTALL_ARG =~ /^\d+\z/ ? $INSTALL_ARG : undef;
my $BOOT_EPOCH    = defined $BOOT_ARG    && $BOOT_ARG    =~ /^\d+\z/ ? $BOOT_ARG    : undef;
eval { setpriority(0, 0, 10); 1 };    # lower our own CPU priority; failure is harmless

my $CORRELATION_WINDOW = 5;            # seconds around an attempt for source-IP correlation
my $GAP_THRESHOLD      = 24 * 3600;    # coverage gaps longer than this are reported
my $MAX_LINE_BYTES     = 16384;        # longer log lines are truncated before matching
my $MAX_HASH_BYTES     = 16 * 1024 * 1024;
my $MAX_GROUPS         = 500;          # distinct payloads kept in memory
my $MAX_FINDING_KEYS   = 2000;         # distinct lines kept per finding bucket
my $MAX_CORRELATED     = 50000;        # HTTP requests kept for correlation
my $MAX_IP_KEYS        = 100000;
my $MAX_LIST           = 40;           # lines shown per finding
my $MAX_TIMELINE       = 60;           # minute rows shown in the timeline

my %MONTH = (Jan => 0, Feb => 1, Mar => 2, Apr => 3, May => 4, Jun => 5,
             Jul => 6, Aug => 7, Sep => 8, Oct => 9, Nov => 10, Dec => 11);
my %FAMILY_KIND = (
    "ns.log" => "syslog", "nsvpn.log" => "syslog", "messages" => "syslog", "notice.log" => "syslog",
    "auth.log" => "syslog", "sh.log" => "syslog", "bash.log" => "syslog",
    "httpaccess.log" => "access", "httpaccess-vpn.log" => "access",
    "httperror.log" => "error", "httperror-vpn.log" => "error",
);
my @FAMILY_ORDER       = qw(ns.log nsvpn.log messages notice.log auth.log sh.log bash.log
                            httpaccess.log httpaccess-vpn.log httperror.log httperror-vpn.log);
my @ATTEMPT_FAMILIES   = qw(ns.log nsvpn.log messages notice.log auth.log httperror.log httperror-vpn.log);
my @ACCESS_FAMILIES    = qw(httpaccess.log httpaccess-vpn.log);
my @SHELL_FAMILIES     = qw(sh.log bash.log);
my @REFERENCE_FAMILIES = qw(ns.log nsvpn.log messages notice.log auth.log httperror.log httperror-vpn.log);

# The injected value follows the pitboss text; a shell separator must come next.
my $TRIGGER_RE      = qr/pitboss\s+PPE\s+(?:missed\s+too\s+many\s+heartbeats|unexpectedly\s+died)\s*NSPPE(?:-\d+)?/i;
my $INJECT_START_RE = qr/^\s*(?:[;|&\x60]|\$\(|\$\{?IFS|%0a|%3b|%60|%7c|%26)/i;
my $AUTH_PATH_RE    = qr{^/(?:nf/auth/|p/u/|cgi/(?:login|samlauth|authenticate)|saml/|oauth/|logon/LogonPoint/Authentication/)}i;
my $IPV4_RE         = qr/\d{1,3}(?:\.\d{1,3}){3}/;

# Read/search commands: a payload string in them is analysis, not execution.
my %VIEWER_WORDS = map { $_ => 1 } qw(
    grep egrep fgrep zgrep zegrep zfgrep bzgrep xzgrep rg ag ack less more most cat zcat bzcat xzcat
    head tail view vi vim nano ee ls file stat strings hexdump xxd od wc sort uniq cut awk nawk gawk
    sed find locate sha256 sha256sum md5 md5sum diff cmp nsconmsg
);
# Commands that can download, run or write; with a payload string they indicate execution.
my %ACTION_WORDS = map { $_ => 1 } qw(
    fetch curl wget ftp tftp nc ncat socat sh bash ksh csh tcsh zsh perl python python2 python3 php
    ruby chmod chown chgrp cp mv rm tar gzip gunzip id whoami uname touch mkdir ln openssl base64
    expr kill pkill nohup ssh scp echo printf dd tee
);
# Report helpers of this script: their logged command lines are our own output.
my %OWN_OUTPUT_WORDS = map { $_ => 1 } qw(status section subsection progress);

my $SELF_BASE   = basename_of($SELF_PATH);
my $REPORT_BASE = basename_of($REPORT_PATH);
# Own names count only as whole file names of at least 8 characters, so a short or
# generic script name cannot hide unrelated shell-audit lines.
my $OWN_RE      = join "|", "GEIGER_",
                  map { "(?<![A-Za-z0-9._-])" . quotemeta($_) . "(?![A-Za-z0-9._-])" }
                  grep { length >= 8 } ($SELF_BASE, $REPORT_BASE);
my $TOOL_RE     = "deyda-netscaler-ioc-check|netscaler-ioc-check";

my $GZIP        = find_tool("gzip");
my $SHA256      = find_tool("sha256");
my $SHA256SUM   = find_tool("sha256sum");
my $HAVE_DIGEST = eval { require Digest::SHA; 1 } ? 1 : 0;

my $CAMPAIGN_EPOCH = parse_local_date($CAMPAIGN_TEXT);

my (%FILES, @SKIPPED);
discover_files();

if ($MODE eq "coverage") {
    for my $family (@FAMILY_ORDER) {
        read_log($_, undef, 1) for @{ $FILES{$family} || [] };
    }
    report_coverage();
    exit 0;
}
if ($MODE ne "injection") {
    status("CHECK", "GEIGER analysis was called with an unknown mode; nothing was evaluated.");
    exit 0;
}

# ---------------------------------------------------------------- pass 1: attempts and events

my (%GROUPS, %ATTEMPT_SECONDS, %NSAAAD_EVENTS, %REBOOT_EVENTS, %AUTH_REQUESTS_BY_IP, @CORRELATED);
my ($GROUP_OVERFLOW, $CORRELATED_OVERFLOW) = (0, 0);
for my $family (@ATTEMPT_FAMILIES) {
    for my $file (@{ $FILES{$family} || [] }) {
        read_log($file, sub { scan_attempt_line($file, @_) }, 1);
    }
}
# Access logs after the syslog families: attempt times are known by then.
for my $family (@ACCESS_FAMILIES) {
    for my $file (@{ $FILES{$family} || [] }) {
        read_log($file, sub { scan_access_line($file, @_) }, 1);
    }
}

my @GROUP_LIST = sort {
    (defined $a->{first} ? 0 : 1) <=> (defined $b->{first} ? 0 : 1)
        || ($a->{first} || 0) <=> ($b->{first} || 0)
        || $b->{lines} <=> $a->{lines}
} values %GROUPS;
my $group_number = 0;
for my $group (@GROUP_LIST) {
    $group->{id}     = "G" . ++$group_number;
    $group->{order}  = $group_number;
    $group->{tokens} = payload_tokens($group->{norm});
}
my %GROUP_ORDER = map { $_->{id} => $_->{order} } @GROUP_LIST;

# Search rules for payload hosts, URL path segments and file paths.
my (@TOKEN_RULES, @REFERENCE_RULES, %PATH_REFERENCES, %GROUP_WORDS);
for my $group (@GROUP_LIST) {
    my $tokens = $group->{tokens};
    $GROUP_WORDS{ $group->{id} } = { map { $_ => 1 } command_words($group->{norm}) };
    for my $path (@{ $tokens->{paths} }) {
        next if generic_path($path);
        push @TOKEN_RULES, { group => $group->{id}, token => $path,
                             re => qr/(?<![A-Za-z0-9._\/~-])\Q$path\E(?![A-Za-z0-9._\/-])/ };
        my $ref = $PATH_REFERENCES{$path} ||= { first => undef, groups => {}, mode => undef };
        $ref->{groups}{ $group->{id} } = 1;
        $ref->{first} = $group->{first}
            if defined $group->{first} && (!defined $ref->{first} || $group->{first} < $ref->{first});
        $ref->{mode} = $tokens->{modes}{$path} if defined $tokens->{modes}{$path};
    }
    for my $token (@{ $tokens->{hosts} }, @{ $tokens->{segments} }) {
        next if length $token < 4 || $token =~ /^localhost(?::\d+)?\z/i;
        my $rule = { group => $group->{id}, token => $token,
                     re => qr/(?<![A-Za-z0-9.-])\Q$token\E(?![A-Za-z0-9-])/ };
        push @TOKEN_RULES, $rule;
        push @REFERENCE_RULES, $rule;
    }
}
my $ANY_TOKEN_RE     = combine_rules(@TOKEN_RULES);
my $ANY_REFERENCE_RE = combine_rules(@REFERENCE_RULES);

# ---------------------------------------------------------------- pass 2: shell audit

my %FINDINGS;
my %SHELL_STATS = (lines => 0, own => 0, tool => 0);
for my $family (@SHELL_FAMILIES) {
    for my $file (@{ $FILES{$family} || [] }) {
        read_log($file, sub { scan_shell_line($file, @_) }, 1);
    }
}
for my $file (@{ $FILES{"notice.log"} || [] }) {
    read_log($file, sub { scan_shell_line($file, @_) }, 0) unless $file->{error};
}

# ---------------------------------------------------------------- pass 3: other lines naming payload hosts

if ($ANY_REFERENCE_RE) {
    for my $family (@REFERENCE_FAMILIES) {
        for my $file (@{ $FILES{$family} || [] }) {
            read_log($file, sub { scan_reference_line($file, @_) }, 0) unless $file->{error};
        }
    }
}

my @SHELL_INTERVALS = shell_intervals();
# Files that could not be read completely make every "nothing found" result incomplete.
my @READ_ERRORS  = grep { $_->{error} } map { @{ $FILES{$_} || [] } } @FAMILY_ORDER;
my $SHELL_ERRORS = grep { $_->{family} =~ /^(?:sh\.log|bash\.log|notice\.log)\z/ } @READ_ERRORS;
my @ALL_SECONDS     = sort { $a <=> $b } keys %ATTEMPT_SECONDS;
report_attempts();
my @CANDIDATES = correlate_sources();
report_sources();
report_execution();
report_chronology();
exit 0;

# ================================================================= reports

sub report_coverage {
    heading("GEIGER: per-family log coverage from log content");
    out("Oldest and newest entries are read from the log lines; file modification times are not used.",
        sprintf("Reference points: campaign start %s (GEIGER_CAMPAIGN_START); install marker %s.",
                defined $CAMPAIGN_EPOCH ? fmt_time($CAMPAIGN_EPOCH) : "invalid date",
                defined $INSTALL_EPOCH ? fmt_time($INSTALL_EPOCH) : "unknown"),
        "",
        sprintf("%-19s %5s %-19s %-19s %4s  %-8s %-8s", "family", "files", "oldest entry", "newest entry",
                "gaps", "campaign", "install"));
    my (@not_campaign, @not_install, @gap_lines, @errors);
    for my $family (@FAMILY_ORDER) {
        next unless $FILES{$family};
        my $cov = family_coverage($family);
        my $campaign = !defined $cov->{oldest} || !defined $CAMPAIGN_EPOCH ? "n/a"
                     : $cov->{oldest} <= $CAMPAIGN_EPOCH ? "yes" : "NO";
        my $install  = !defined $cov->{oldest} || !defined $INSTALL_EPOCH ? "n/a"
                     : $cov->{oldest} <= $INSTALL_EPOCH ? "yes" : "NO";
        out(sprintf("%-19s %5d %-19s %-19s %4d  %-8s %-8s", $family, $cov->{files}, fmt_time($cov->{oldest}),
                    fmt_time($cov->{newest}), scalar @{ $cov->{gaps} }, $campaign, $install));
        push @not_campaign, $family if $campaign eq "NO";
        push @not_install,  $family if $install eq "NO";
        push @gap_lines, map { sprintf "  %s: no entries from %s to %s", $family, fmt_time($_->[0]), fmt_time($_->[1]) }
                             @{ $cov->{gaps} };
        push @errors, map { sprintf "  %s: %s", show($_->{path}), $_->{error} } grep { $_->{error} } @{ $FILES{$family} };
    }
    out("", "Families without any file: " . (join(", ", grep { !$FILES{$_} } @FAMILY_ORDER) || "none"));
    if (!%FILES) {
        status("CHECK", "No supported log file was found in " . show($LOGDIR) . "; local log coverage is unavailable.");
        return;
    }
    if (@not_campaign) {
        status("CHECK", "These log families do not reach back to the campaign start, so local logs cannot rule out "
            . "earlier attempts or execution: " . join(", ", @not_campaign) . ". Use remote syslog/SIEM for the missing period.");
    } elsif (defined $CAMPAIGN_EPOCH) {
        status("OK", "All present log families reach back to the campaign start.");
    }
    status("CHECK", "Not covering the install marker: " . join(", ", @not_install)
        . ". The pre-update exposure window is not visible in these families.") if @not_install;
    if (@gap_lines) {
        status("CHECK", sprintf("Coverage gaps longer than %d hours (no entries; rotation, downtime or deletion):",
                                $GAP_THRESHOLD / 3600));
        out(limit_list(\@gap_lines, $MAX_LIST));
    }
    if (@errors) {
        status("CHECK", "Some log files could not be read completely:");
        out(@errors);
    }
    if (@SKIPPED) {
        status("CHECK", "Skipped files (not regular or unsupported compression):");
        out(map { "  " . show($_) } @SKIPPED);
    }
}

sub report_attempts {
    heading("GEIGER: injection attempts, complete and grouped by payload");
    if (@READ_ERRORS) {
        status("CHECK", scalar(@READ_ERRORS) . " log file(s) could not be read completely. All GEIGER results below "
            . "are incomplete for these files; rerun the script and keep the files for offline analysis:");
        out(map { "  " . show($_->{path}) . ": " . show($_->{error}) } @READ_ERRORS);
    }
    out("Every matching line is counted. Attempt seconds = distinct seconds per payload, because one attempt is",
        "logged several times (nsaaad, RADIUS/LDAP, AAA). Payloads are shown as inert, defanged text.");
    if (!@GROUP_LIST) {
        status("OK", "No line with the pitboss/NSPPE trigger followed by a shell separator was found in the retained "
            . "logs. The per-family coverage above limits this result.");
        return;
    }
    my $lines = 0;
    $lines += $_->{lines} for @GROUP_LIST;
    status("ACTION", sprintf("%d payload variant(s), %d matching line(s), %d attempt second(s) between %s and %s. "
        . "Each variant is listed below; execution is assessed in the execution-trace check.",
        scalar @GROUP_LIST, $lines, scalar @ALL_SECONDS, fmt_time($ALL_SECONDS[0]), fmt_time($ALL_SECONDS[-1])));
    for my $group (@GROUP_LIST) {
        my $tokens  = $group->{tokens};
        my @seconds = keys %{ $group->{seconds} };
        my $inside  = grep { in_intervals($_, \@SHELL_INTERVALS) } @seconds;
        out("", sprintf("%s  first %s  last %s", $group->{id}, fmt_time($group->{first}), fmt_time($group->{last})),
            sprintf("    matching lines: %d   attempt seconds: %d   lines without timestamp: %d",
                    $group->{lines}, scalar @seconds, $group->{unparsed}),
            "    log families: " . join(", ", map { "$_=$group->{families}{$_}" } sort keys %{ $group->{families} }),
            "    payload:      " . show($group->{raw}, 300),
            "    normalized:   " . show($group->{norm}, 300));
        out("    hosts:        " . join(", ", map { show_host($_) } @{ $tokens->{hosts} })) if @{ $tokens->{hosts} };
        out("    paths:        " . join(", ", map { show($_) } @{ $tokens->{paths} })) if @{ $tokens->{paths} };
        out("    client IPs in the same line: " . count_list($group->{clients})) if %{ $group->{clients} };
        out("    vServer IPs:  " . count_list($group->{vservers})) if %{ $group->{vservers} };
        out(sprintf("    shell-audit coverage: %d of %d attempt second(s) inside sh.log/bash.log coverage",
                    $inside, scalar @seconds));
    }
    status("CHECK", "$GROUP_OVERFLOW further line(s) with new payloads were not grouped (limit $MAX_GROUPS).")
        if $GROUP_OVERFLOW;
    my %external;
    for my $group (@GROUP_LIST) {
        $external{$_} = 1 for grep { external_host($_) } @{ $group->{tokens}{hosts} };
    }
    out("", "External hosts named in payloads (defanged): " . (join(", ", map { show_host($_) } sort keys %external) || "none"));
}

sub report_sources {
    heading("GEIGER: source IPs of the attempts");
    if (!@GROUP_LIST) { out("No attempts, nothing to correlate."); return }
    my %direct;
    for my $group (@GROUP_LIST) {
        for my $ip (keys %{ $group->{clients} }) {
            $direct{$ip}{count} += $group->{clients}{$ip};
            $direct{$ip}{groups}{ $group->{id} } = 1;
        }
    }
    if (%direct) {
        status("CHECK", "Client IPs logged in the same line as an attempt (AAA/HTTP records). The last Client_ip field "
            . "of a line is used, because the user name itself is attacker-controlled:");
        out(map { sprintf "  %-22s lines=%-6d payloads=%s", show($_), $direct{$_}{count},
                      join(",", sort { $GROUP_ORDER{$a} <=> $GROUP_ORDER{$b} } keys %{ $direct{$_}{groups} }) }
            sort { $direct{$b}{count} <=> $direct{$a}{count} || $a cmp $b } keys %direct);
    }
    if (@CANDIDATES) {
        status("CHECK", sprintf("Time-correlated candidates: authentication requests in the HTTP access logs within "
            . "+/-%d s of an attempt. Correlation, not proof: legitimate users can sign in at the same time. An "
            . "address that matches many attempt seconds is a strong candidate.", $CORRELATION_WINDOW));
        out(sprintf("  %-22s %-24s %s", "address", "matched attempt seconds", "auth requests in logs"));
        my $last = $#CANDIDATES < 14 ? $#CANDIDATES : 14;
        out(map { sprintf "  %-22s %-24s %d", show($_->[0]), "$_->[1] of " . scalar(@ALL_SECONDS), $_->[2] }
            @CANDIDATES[0 .. $last]);
        status("CHECK", "Correlation input was truncated at $MAX_CORRELATED requests.") if $CORRELATED_OVERFLOW;
    }
    if (!%direct && !@CANDIDATES) {
        status("CHECK", "No source IP could be determined from local logs (no Client_ip field and no authentication "
            . "request near the attempt times). Check firewall, WAF or NetScaler Console records.");
    }
}

sub report_execution {
    heading("GEIGER: execution traces of the injected commands");
    out(sprintf("Shell-audit lines analysed: %d (own runs excluded: %d; other triage tools excluded: %d).",
                $SHELL_STATS{lines}, $SHELL_STATS{own}, $SHELL_STATS{tool}),
        "Shell-audit coverage: " . (@SHELL_INTERVALS
            ? join("; ", map { fmt_time($_->[0]) . " to " . fmt_time($_->[1]) } @SHELL_INTERVALS) : "none"));
    my $trace = 0;
    if (findings("trigger")) {
        $trace = 1;
        status("ACTION", "A shell command contains the injection trigger itself: the injected user name reached a "
            . "shell. Treat the appliance as compromised and preserve evidence:");
        out(finding_lines("trigger"));
    }
    if (findings("token")) {
        $trace = 1;
        status("ACTION", "Shell commands run a download/exec/write command together with hosts, URL segments or "
            . "paths from the payloads (matched tokens in brackets). Verify each line and preserve evidence:");
        out(finding_lines("token"));
    }
    if (findings("mention")) {
        status("CHECK", "Shell commands mention payload hosts or paths without a matching command word. Review them:");
        out(finding_lines("mention"));
    }
    if (findings("viewer")) {
        out("", "Note: payload strings also appear in read/search commands (grep, cat, ...). These are typically an "
            . "administrator investigating and are not counted as execution:");
        out(finding_lines("viewer"));
    }
    if (!$trace) {
        if (!@SHELL_INTERVALS) {
            status("CHECK", "No shell-audit log was readable; execution cannot be assessed with local logs.");
        } elsif (@GROUP_LIST) {
            my $outside = grep { !in_intervals($_, \@SHELL_INTERVALS) } @ALL_SECONDS;
            status($SHELL_ERRORS ? "CHECK" : "OK",
                sprintf("No trigger text and no payload command in %d shell-audit line(s).", $SHELL_STATS{lines})
                . ($SHELL_ERRORS ? " Incomplete: $SHELL_ERRORS shell-audit file(s) could not be read (see above)." : ""));
            status("CHECK", sprintf("%d of %d attempt second(s) lie outside the shell-audit coverage and cannot be "
                . "assessed with local logs.", $outside, scalar @ALL_SECONDS)) if $outside;
        } else {
            status($SHELL_ERRORS ? "CHECK" : "OK", "No trigger text in the shell-audit logs."
                . ($SHELL_ERRORS ? " Incomplete: $SHELL_ERRORS shell-audit file(s) could not be read (see above)." : ""));
        }
    }
    out("", "Download/exec patterns in shell-audit logs, independent of the attempts (catches payloads whose",
        "authentication lines have rotated away; local and private URLs are ignored):");
    if (findings("generic")) {
        status("CHECK", "Shell commands with a download from an external URL, a pipe into an interpreter, /dev/tcp or "
            . "Base64 decoding. Compare with known administration and NetScaler scripts:");
        out(finding_lines("generic"));
    } elsif (@SHELL_INTERVALS) {
        status($SHELL_ERRORS ? "CHECK" : "OK", "No such pattern in the shell-audit logs."
            . ($SHELL_ERRORS ? " Incomplete: $SHELL_ERRORS shell-audit file(s) could not be read (see above)." : ""));
    }
    if ($ANY_REFERENCE_RE) {
        if (findings("inbound")) {
            status("CHECK", "Inbound requests from payload hosts (AAA logins, AppFW blocks and their SNMP traps), "
                . "counted by event type. They confirm the attacker source and are not execution traces:");
            out(finding_lines("inbound"));
        }
        if (findings("reference")) {
            status("CHECK", "Other log lines mention a payload host outside the injected user names (for example "
                . "fetch/curl errors, DNS or connection messages). Review them:");
            out(finding_lines("reference"));
        } else {
            status(@READ_ERRORS ? "CHECK" : "OK", "No log line outside the injected user names and inbound requests "
                . "mentions a payload host (no fetch/curl error, DNS or connection message)."
                . (@READ_ERRORS ? " Incomplete: some log files could not be read (see above)." : ""));
        }
    }
    if (%PATH_REFERENCES) {
        out("", "Files named in the payloads (metadata only, contents are never printed). The ADC root filesystem and",
            "/netscaler are rebuilt at boot, so a missing file there says nothing about the time before the last",
            "boot. /var, /flash and /nsconfig persist.");
        check_artifacts();
    }
}

sub report_chronology {
    heading("GEIGER: attempts, nsaaad deaths and pitboss reboots in time order");
    my (%day, %minute);
    for my $group (@GROUP_LIST) {
        for my $t (keys %{ $group->{seconds} }) {
            $day{ fmt_day($t) }{attempts}++;
            $minute{ $t - $t % 60 }{attempts}{ $group->{id} }++;
        }
    }
    for my $t (values %NSAAAD_EVENTS) { $day{ fmt_day($t) }{nsaaad}++; $minute{ $t - $t % 60 }{nsaaad}++ }
    for my $t (keys %REBOOT_EVENTS)   { $day{ fmt_day($t) }{reboot}++; $minute{ $t - $t % 60 }{reboot}++ }
    if (!%day) {
        out("No attempts, nsaaad deaths or pitboss reboots in the retained logs.");
        return;
    }
    out("Sorted by parsed timestamp and deduplicated across log families.", "",
        sprintf("%-10s %9s %14s %8s", "date", "attempts", "nsaaad deaths", "reboots"));
    out(map { sprintf "%-10s %9d %14d %8d", $_, $day{$_}{attempts} || 0, $day{$_}{nsaaad} || 0, $day{$_}{reboot} || 0 }
        sort keys %day);
    my @rows;
    for my $start (sort { $a <=> $b } keys %minute) {
        my $m = $minute{$start};
        my @parts;
        push @parts, "attempts " . join(" ", map { "$_=$m->{attempts}{$_}" }
                                        sort { $GROUP_ORDER{$a} <=> $GROUP_ORDER{$b} } keys %{ $m->{attempts} })
            if $m->{attempts};
        push @parts, "nsaaad died=$m->{nsaaad}" if $m->{nsaaad};
        push @parts, "REBOOT=$m->{reboot}"      if $m->{reboot};
        push @rows, "  " . strftime("%Y-%m-%d %H:%M", localtime $start) . "  " . join("; ", @parts);
    }
    out("", "Per minute:", limit_list(\@rows, $MAX_TIMELINE));
    status("CHECK", sprintf("%d reboot(s) initiated by pitboss after monitored processes exited. Repeated nsaaad deaths "
        . "right after attempts indicate a denial-of-service effect; correlate with service outages.",
        scalar keys %REBOOT_EVENTS)) if %REBOOT_EVENTS;
}

# ================================================================= helpers

sub out     { print map { "$_\n" } @_ }
sub heading { print "\n--- $_[0] ---\n" }
sub status  { print "\n[$_[0]] $_[1]\n" }

sub find_tool {
    my ($name) = @_;
    for my $dir (split /:/, defined $ENV{PATH} ? $ENV{PATH} : "") {
        my $path = "$dir/$name";
        return $path if -f $path && -x _;
    }
    return undef;
}

sub basename_of { my ($path) = @_; $path =~ s{.*/}{}; return $path }

sub parse_local_date {
    my ($text) = @_;
    return undef unless defined $text && $text =~ /^(\d{4})-(\d{2})-(\d{2})\z/;
    return undef if $2 < 1 || $2 > 12 || $3 < 1 || $3 > 31;
    return mktime(0, 0, 0, $3, $2 - 1, $1 - 1900, 0, 0, -1);
}

sub days_from_civil {
    my ($y, $m, $d) = @_;
    $y -= 1 if $m <= 2;
    my $era = floor($y / 400);
    my $yoe = $y - $era * 400;
    my $doy = int((153 * ($m > 2 ? $m - 3 : $m + 9) + 2) / 5) + $d - 1;
    my $doe = $yoe * 365 + int($yoe / 4) - int($yoe / 100) + $doy;
    return $era * 146097 + $doe - 719468;
}

# Syslog lines carry no year: use the year of the file mtime and step back one
# year if the result would lie after that mtime.
sub make_syslog_parser {
    my ($anchor) = @_;
    my %cache;
    return sub {
        my ($line) = @_;
        return undef unless $line =~ /^([A-Z][a-z]{2})\s{1,2}(\d{1,2})\s(\d{2}):(\d{2}):(\d{2})\s/;
        my $mon = $MONTH{$1};
        return undef unless defined $mon;
        my ($mday, $hh, $mm, $ss) = ($2, $3, $4, $5);
        my $key = "$mon/$mday/$hh";
        if (!exists $cache{$key}) {
            my $year = (localtime $anchor)[5];
            my $base = mktime(0, 0, $hh, $mday, $mon, $year, 0, 0, -1);
            $base = mktime(0, 0, $hh, $mday, $mon, $year - 1, 0, 0, -1)
                if defined $base && $base > $anchor + 2 * 86400;
            $cache{$key} = $base;
        }
        return defined $cache{$key} ? $cache{$key} + $mm * 60 + $ss : undef;
    };
}

sub parse_access_time {
    my ($line) = @_;
    return undef unless $line =~ m{\[(\d{2})/([A-Z][a-z]{2})/(\d{4}):(\d{2}):(\d{2}):(\d{2})\s([+-])(\d{2})(\d{2})\]};
    my $mon = $MONTH{$2};
    return undef unless defined $mon;
    my $offset = ($8 * 3600 + $9 * 60) * ($7 eq "-" ? -1 : 1);
    return days_from_civil($3, $mon + 1, $1) * 86400 + $4 * 3600 + $5 * 60 + $6 - $offset;
}

sub parse_error_time {
    my ($line) = @_;
    return undef unless $line =~ /^\[[A-Z][a-z]{2}\s([A-Z][a-z]{2})\s{1,2}(\d{1,2})\s(\d{2}):(\d{2}):(\d{2})(?:\.\d+)?\s(\d{4})\]/;
    my $mon = $MONTH{$1};
    return undef unless defined $mon;
    return mktime($5, $4, $3, $2, $mon, $6 - 1900, 0, 0, -1);
}

sub fmt_time { my ($t) = @_; return defined $t ? strftime("%Y-%m-%d %H:%M:%S", localtime $t) : "n/a" }
sub fmt_day  { my ($t) = @_; return strftime("%Y-%m-%d", localtime $t) }

sub discover_files {
    opendir(my $dh, $LOGDIR) or return;
    for my $name (sort readdir $dh) {
        for my $family (@FAMILY_ORDER) {
            next unless $name =~ /^\Q$family\E(?:\.(\d+))?(\.gz|\.bz2|\.xz|\.zst)?\z/;
            my ($index, $compression) = (defined $1 ? $1 : -1, defined $2 ? $2 : "");
            my $path = "$LOGDIR/$name";
            my @st = lstat $path;
            if (!@st || !-f _) { push @SKIPPED, "$path (not a regular file)"; last }
            if ($compression ne "" && $compression ne ".gz") { push @SKIPPED, "$path (unsupported compression)"; last }
            push @{ $FILES{$family} }, { path => $path, family => $family, kind => $FAMILY_KIND{$family},
                                         index => $index, gz => $compression eq ".gz" ? 1 : 0,
                                         mtime => $st[9], lines => 0, unparsed => 0 };
            last;
        }
    }
    closedir $dh;
    # Rotated files oldest first (highest rotation index), the live file last.
    for my $family (keys %FILES) {
        $FILES{$family} = [ sort { $b->{index} <=> $a->{index} || $a->{mtime} <=> $b->{mtime} } @{ $FILES{$family} } ];
    }
}

sub read_log {
    my ($file, $callback, $track) = @_;
    my $fh;
    if ($file->{gz}) {
        if (!$GZIP) { $file->{error} ||= "gzip not found"; return 0 }
        if (!open($fh, "-|", $GZIP, "-dc", $file->{path})) { $file->{error} ||= "cannot start gzip: $!"; return 0 }
    } elsif (!open($fh, "<", $file->{path})) {
        $file->{error} ||= "cannot open: $!";
        return 0;
    }
    binmode $fh;
    my $parser = $file->{kind} eq "syslog" ? make_syslog_parser($file->{mtime})
               : $file->{kind} eq "access" ? \&parse_access_time : \&parse_error_time;
    while (my $line = <$fh>) {
        $line =~ s/\r?\n\z//;
        $line = substr($line, 0, $MAX_LINE_BYTES) if length $line > $MAX_LINE_BYTES;
        my $t = $parser->($line);
        if ($track) {
            $file->{lines}++;
            if (defined $t) {
                $file->{first} = $t if !defined $file->{first} || $t < $file->{first};
                $file->{last}  = $t if !defined $file->{last}  || $t > $file->{last};
            } else {
                $file->{unparsed}++;
            }
        }
        $callback->($line, $t) if $callback;
    }
    $file->{error} ||= "gzip reported an error (file truncated or corrupt)" if !close($fh) && $file->{gz};
    return 1;
}

# ---------------------------------------------------------------- pass callbacks

sub scan_attempt_line {
    my ($file, $line, $t) = @_;
    return if $file->{family} eq "notice.log" && $line =~ /_command="/;    # shell audit, pass 2
    my $text    = $line;
    my $payload = extract_payload($text);
    if (!defined $payload && $file->{kind} ne "syslog" && $line =~ /%[0-9A-Fa-f]{2}/) {
        $text    = url_decode($line);
        $payload = extract_payload($text);
    }
    if (defined $payload) {
        record_attempt($file, $text, $t, $payload, undef);
        return;
    }
    return unless $file->{kind} eq "syslog" && defined $t;
    return if $line =~ $TRIGGER_RE;
    $NSAAAD_EVENTS{"$t:$1"} = $t if $line =~ /\bnsaaad\s*\((\d+)\)\s+unexpectedly died/i;
    $REBOOT_EVENTS{$t} = 1       if $line =~ /All monitored processes have exited, rebooting/i;
}

sub scan_access_line {
    my ($file, $line, $t) = @_;
    my ($ip, $path) = $line =~ m{^(\S+)\s.*?"[A-Z]{3,10}\s+(\S+)};
    $ip = undef unless defined $ip && valid_ipv4($ip);
    my $text    = $line;
    my $payload = extract_payload($text);
    if (!defined $payload && $line =~ /%[0-9A-Fa-f]{2}/) {
        $text    = url_decode($line);
        $payload = extract_payload($text);
    }
    record_attempt($file, $text, $t, $payload, $ip) if defined $payload;
    return unless defined $t && defined $ip && defined $path && $path =~ $AUTH_PATH_RE;
    $AUTH_REQUESTS_BY_IP{$ip}++ if exists $AUTH_REQUESTS_BY_IP{$ip} || keys(%AUTH_REQUESTS_BY_IP) < $MAX_IP_KEYS;
    for my $delta (-$CORRELATION_WINDOW .. $CORRELATION_WINDOW) {
        next unless $ATTEMPT_SECONDS{ $t + $delta };
        if (@CORRELATED < $MAX_CORRELATED) { push @CORRELATED, [$t, $ip] } else { $CORRELATED_OVERFLOW++ }
        last;
    }
}

sub scan_shell_line {
    my ($file, $line, $t) = @_;
    return if $file->{family} eq "notice.log" && $line !~ /_command="/;
    if ($line =~ /$OWN_RE/)  { $SHELL_STATS{own}++;  return }
    if ($line =~ /$TOOL_RE/) { $SHELL_STATS{tool}++; return }
    my $command = normalize_command(shell_command_text($line));
    my @words   = command_words($command);
    my $first   = @words ? $words[0] : "";
    if ($OWN_OUTPUT_WORDS{$first}) { $SHELL_STATS{own}++; return }
    $SHELL_STATS{lines}++;
    my $viewer  = viewer_command($command, $first);
    my $trigger = defined extract_payload($command) ? 1 : 0;
    my %hit;
    if ($ANY_TOKEN_RE && $command =~ $ANY_TOKEN_RE) {
        for my $rule (@TOKEN_RULES) {
            $hit{ $rule->{group} }{ $rule->{token} } = 1 if $command =~ $rule->{re};
        }
    }
    my $note = join "; ", map { "$_: " . join(" ", sort keys %{ $hit{$_} }) }
                          sort { $GROUP_ORDER{$a} <=> $GROUP_ORDER{$b} } keys %hit;
    if ($trigger) {
        add_finding($viewer ? "viewer" : "trigger", $command, $t, $file, $note);
        return;
    }
    if (%hit) {
        my $runs = grep { my $w = $_; $ACTION_WORDS{$w} || grep { $GROUP_WORDS{$_}{$w} } keys %hit } @words;
        add_finding($viewer ? "viewer" : $runs ? "token" : "mention", $command, $t, $file, $note);
        return;
    }
    return if $viewer;
    my $reason = generic_exec_reason($command);
    add_finding("generic", $command, $t, $file, $reason) if defined $reason;
}

sub scan_reference_line {
    my ($file, $line, $t) = @_;
    return if $line =~ $TRIGGER_RE;
    return if $file->{family} eq "notice.log" && $line =~ /_command="/;
    return unless $line =~ $ANY_REFERENCE_RE;
    return if $line =~ /$OWN_RE/ || $line =~ /$TOOL_RE/;
    my %tokens;
    for my $rule (@REFERENCE_RULES) { $tokens{ $rule->{token} } = 1 if $line =~ $rule->{re} }
    my $tokens = join(" ", sort keys %tokens);
    # Requests from a payload host (AAA logins, AppFW blocks and their SNMP traps) show
    # inbound attacker activity, not an execution side effect: count them by event type.
    my $inbound = grep { $line =~ /\b(?:Client_ip|client ip\s*:)\s*\Q$_\E(?![\d.])/i } keys %tokens;
    if ($inbound || $line =~ /\bAPPFW\b|appfwLogMsg/) {
        my $type = $line =~ /\bdefault\s+([A-Z][A-Z0-9_]*)\s+([A-Za-z][A-Za-z0-9_]*)/ ? "$1 $2" : "other";
        add_finding("inbound", "$type from $tokens", $t, $file, undef);
        return;
    }
    add_finding("reference", $line, $t, $file, $tokens);
}

# ---------------------------------------------------------------- payload handling

sub extract_payload {
    my ($text) = @_;
    return undef unless $text =~ $TRIGGER_RE;
    my $rest = substr($text, $+[0]);
    return undef unless $rest =~ $INJECT_START_RE;
    # The injected value ends where the logging code appends its own fields.
    $rest =~ s/(?:,\s*vsid\s*:|\s+-\s+Client_ip\s|\s+\(client ip\s*:|\s+@\s+$IPV4_RE|\s+from server\s|\s+-\s+Failure_reason).*\z//s;
    # Attackers close the command with a shell comment (";# X").
    $rest =~ s/;?\s*#.*\z//s;
    $rest =~ s/^[\s;]+//;
    $rest =~ s/[\s;]+\z//;
    return length $rest ? substr($rest, 0, 1024) : undef;
}

sub record_attempt {
    my ($file, $text, $t, $payload, $direct_ip) = @_;
    my $norm  = normalize_command($payload);
    my $group = $GROUPS{$norm};
    if (!$group) {
        if (keys(%GROUPS) >= $MAX_GROUPS) { $GROUP_OVERFLOW++; return }
        $group = $GROUPS{$norm} = { raw => $payload, norm => $norm, lines => 0, unparsed => 0,
                                    seconds => {}, families => {}, clients => {}, vservers => {} };
    }
    $group->{lines}++;
    $group->{families}{ $file->{family} }++;
    if (defined $t) {
        $group->{seconds}{$t} = 1;
        $ATTEMPT_SECONDS{$t}  = 1;
        $group->{first} = $t if !defined $group->{first} || $t < $group->{first};
        $group->{last}  = $t if !defined $group->{last}  || $t > $group->{last};
    } else {
        $group->{unparsed}++;
    }
    # The user name is attacker-controlled; the logging code appends the real
    # client and vServer fields after it, so the last occurrence counts.
    my $client = $direct_ip;
    if (!defined $client) {
        my @found = ($text =~ /\bClient_ip\s+($IPV4_RE)\b/gi, $text =~ /\bclient ip\s*:\s*($IPV4_RE)\b/gi);
        $client = $found[-1] if @found;
    }
    $group->{clients}{$client}++ if defined $client && valid_ipv4($client);
    my @vservers = $text =~ /\bvserver ip\s*:\s*($IPV4_RE)\b/gi;
    $group->{vservers}{ $vservers[-1] }++ if @vservers && valid_ipv4($vservers[-1]);
}

# Undo the usual evasion forms so that equivalent payloads group together and
# their hosts/paths can be extracted. The result is only matched, never run.
sub normalize_command {
    my ($text) = @_;
    my $n = $text;
    $n =~ s/\$\{IFS\}|\$IFS(?![A-Za-z0-9_])/ /g;
    $n =~ s/%([0-9A-Fa-f]{2})/chr(hex $1)/ge;
    if ($n =~ /(?:^|[;\s])IFS=([^A-Za-z0-9\s:\/.\-])/) {
        my $separator = $1;
        $n =~ s/\Q$separator\E/ /g;
    }
    $n =~ s/\\(?=[A-Za-z\/])/ /g;
    $n =~ s/\s+/ /g;
    $n =~ s/^ | \z//g;
    return $n;
}

sub payload_tokens {
    my ($n) = @_;
    my (%hosts, %segments, %paths, %modes);
    while ($n =~ m{\b(?:https?|ftp|tftp)://([^\s/;|&\x60\x27"<>()?#\\]+)([^\s;|&\x60\x27"<>()\\]*)}gi) {
        my ($hostport, $path) = ($1, $2);
        $hostport =~ s/^[^@]*@//;
        next unless length $hostport;
        $hosts{ lc $hostport } = 1;
        (my $host = $hostport) =~ s/:\d+\z//;
        $hosts{ lc $host } = 1;
        $path =~ s/[?#].*\z//;
        $segments{$_} = 1 for grep { length >= 6 } split m{/}, $path;
    }
    (my $without_urls = $n) =~ s{\b(?:https?|ftp|tftp)://\S+}{ }gi;
    while ($without_urls =~ m{(?<![A-Za-z0-9._/~-])(/[A-Za-z0-9._/-]*[A-Za-z0-9._-])}g) {
        my $path = $1;
        next if length $path > 255 || $path =~ m{(?:^|/)\.\.(?:/|\z)};
        $paths{$path} = 1;
    }
    while ($without_urls =~ m{\bchmod\s+([0-7]{3,4})\s+(/[A-Za-z0-9._/-]+)}g) { $modes{$2} = $1 }
    while ($without_urls =~ /(?<![\d.])($IPV4_RE)(?!\d|\.\d)/g) { $hosts{$1} = 1 if valid_ipv4($1) }
    return { hosts => [sort keys %hosts], segments => [sort keys %segments],
             paths => [sort keys %paths], modes => \%modes };
}

# Command names at command positions (line start and after ; | & backtick $( ).
sub command_words {
    my ($command) = @_;
    my @words;
    for my $segment (split /[;|&\x60\n]|\$\(/, $command) {
        my $s = $segment;
        $s =~ s/^[\s({!]+//;
        1 while $s =~ s/^[A-Za-z_][A-Za-z0-9_]*=(?:"[^"]*"|\S*)\s*//;
        $s =~ s/^(?:nice|nohup|time|exec|command|env)\s+(?:-\S+\s+)*//;
        my ($word) = $s =~ /^([^\s<>]+)/;
        next unless defined $word;
        $word =~ s{.*/}{};
        push @words, lc $word if $word =~ /^[A-Za-z][A-Za-z0-9._+-]*\z/;
    }
    return @words;
}

sub generic_path {
    my ($path) = @_;
    return 1 if $path =~ m{^/(?:bin|sbin|usr|lib|libexec|dev|proc|rescue)(?:/|\z)};
    return 1 if $path =~ m{^/(?:tmp|var|var/tmp|var/log|flash|nsconfig|netscaler|etc|root|home)/?\z};
    # Standard configuration files: payloads read them, but boot scripts and administrators
    # also touch them (for example chmod 600 /flash/nsconfig/ns.conf* at every boot).
    return 1 if $path =~ m{^/(?:flash/)?nsconfig/(?:ns\.conf|rc\.netscaler|ntp\.conf|httpd\.conf|crontab)(?:\.[A-Za-z0-9_-]+)?\z};
    return 1 if $path =~ m{^/(?:flash/)?nsconfig/keys/?\z};
    return 1 if $path =~ m{^/etc/(?:passwd|master\.passwd|group|httpd\.conf|crontab|monitrc|rc\.conf|ntp\.conf|resolv\.conf|hosts|shells)\z};
    return 0;
}

# Read-only use of a viewer command: no redirection, no in-place edit, no tee, no
# pipe into an interpreter. "cat a>b" or "sed -i" write and are not viewers.
sub viewer_command {
    my ($command, $first) = @_;
    return 0 unless $VIEWER_WORDS{$first};
    return 0 if $command =~ />/;
    return 0 if $command =~ /(?:^|\s)-i(?:\S*)?(?:\s|\z)/ && $first =~ /^(?:sed|awk|gawk|nawk)\z/;
    return 0 if $command =~ /\|\s*(?:\S*\/)?(?:tee|sh|bash|ksh|csh|tcsh|zsh|perl|python[0-9.]*)(?:\s|;|\z)/;
    return 1;
}

sub shell_command_text {
    my ($line) = @_;
    my $command = $line =~ /\b[A-Za-z]*_?command="(.*)"\s*\z/s ? $1
                : $line =~ /\]:\s+(.*)\z/s                    ? $1
                :                                              $line;
    $command =~ s/[\x80-\x8f]//g;    # FreeBSD sh marks quoting with bytes 0x81-0x88
    return $command;
}

sub generic_exec_reason {
    my ($command) = @_;
    my @urls = $command =~ m{\b((?:https?|ftp|tftp)://[^\s;|&\x60\x27"<>()]+)}gi;
    if (grep { external_url($_) } @urls) {
        return "download from external URL"
            if $command =~ /\b(?:fetch|curl|wget|tftp|ftp|nc|ncat|socat|perl|python[0-9.]*)\b/i;
    }
    return "pipe into interpreter" if $command =~ /\|\s*(?:\S*\/)?(?:sh|bash|ksh|csh|tcsh|zsh|perl|python[0-9.]*)(?:\s|;|\z)/;
    return "/dev/tcp or /dev/udp"  if $command =~ m{/dev/(?:tcp|udp)/};
    return "Base64 decoding"       if $command =~ /\bbase64\s+(?:-d|-D|--decode)\b|b64decode/i;
    return undef;
}

sub url_decode { my ($text) = @_; $text =~ s/%([0-9A-Fa-f]{2})/chr(hex $1)/ge; return $text }

sub valid_ipv4 {
    my ($ip) = @_;
    return 0 unless defined $ip && $ip =~ /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\z/;
    return ($1 <= 255 && $2 <= 255 && $3 <= 255 && $4 <= 255) ? 1 : 0;
}

sub public_ipv4 {
    my ($ip) = @_;
    return 0 unless valid_ipv4($ip);
    my ($o1, $o2) = split /\./, $ip;
    return 0 if $o1 == 0 || $o1 == 10 || $o1 == 127 || $o1 >= 224;
    return 0 if $o1 == 169 && $o2 == 254;
    return 0 if $o1 == 172 && $o2 >= 16 && $o2 <= 31;
    return 0 if $o1 == 192 && $o2 == 168;
    return 0 if $o1 == 100 && $o2 >= 64 && $o2 <= 127;
    return 1;
}

sub external_host {
    my ($hostport) = @_;
    (my $host = $hostport) =~ s/:\d+\z//;
    return 0 if $host =~ /^(?:localhost|.*\.local|.*\.localdomain)\z/i;
    return public_ipv4($host) if $host =~ /^[\d.]+\z/;
    return $host =~ /\./ ? 1 : 0;
}

sub external_url {
    my ($url) = @_;
    return 0 unless $url =~ m{^[A-Za-z]+://(?:[^@/]*@)?([^/:?#]+)};
    return external_host($1);
}

# ---------------------------------------------------------------- findings

sub add_finding {
    my ($bucket, $text, $t, $file, $note) = @_;
    my $store = $FINDINGS{$bucket} ||= {};
    my $entry = $store->{$text};
    if (!$entry) {
        if (keys(%$store) >= $MAX_FINDING_KEYS) { $FINDINGS{"$bucket:overflow"}{count}++; return }
        $entry = $store->{$text} = { count => 0, families => {}, note => $note };
    }
    $entry->{count}++;
    $entry->{families}{ $file->{family} } = 1;
    if (defined $t) {
        $entry->{first} = $t if !defined $entry->{first} || $t < $entry->{first};
        $entry->{last}  = $t if !defined $entry->{last}  || $t > $entry->{last};
    }
}

sub findings { my ($bucket) = @_; return $FINDINGS{$bucket} && %{ $FINDINGS{$bucket} } ? 1 : 0 }

sub finding_lines {
    my ($bucket) = @_;
    my $store = $FINDINGS{$bucket};
    my @entries = sort { (defined $a->[1]{first} ? $a->[1]{first} : 0) <=> (defined $b->[1]{first} ? $b->[1]{first} : 0) }
                  map { [$_, $store->{$_}] } keys %$store;
    my @lines;
    for my $item (@entries) {
        my ($text, $e) = @$item;
        my $when = !defined $e->{first} ? "time unknown"
                 : fmt_time($e->{first}) . ($e->{last} != $e->{first} ? " .. " . fmt_time($e->{last}) : "");
        push @lines, sprintf("  %s  (%dx, %s)%s", $when, $e->{count}, join(",", sort keys %{ $e->{families} }),
                             defined $e->{note} && length $e->{note} ? " [" . show($e->{note}, 200) . "]" : ""),
                     "    " . show($text, 400);
    }
    my @result = limit_list(\@lines, 2 * $MAX_LIST);
    my $overflow = $FINDINGS{"$bucket:overflow"};
    push @result, "  ... $overflow->{count} further distinct line(s) not kept (limit $MAX_FINDING_KEYS)" if $overflow;
    return @result;
}

# ---------------------------------------------------------------- coverage

sub family_coverage {
    my ($family) = @_;
    my %cov = (files => scalar @{ $FILES{$family} }, gaps => []);
    my @files = sort { $a->{first} <=> $b->{first} } grep { defined $_->{first} } @{ $FILES{$family} };
    return \%cov unless @files;
    $cov{oldest} = $files[0]{first};
    my $reach = $files[0]{last};
    for my $file (@files[1 .. $#files]) {
        push @{ $cov{gaps} }, [$reach, $file->{first}] if $file->{first} - $reach > $GAP_THRESHOLD;
        $reach = $file->{last} if $file->{last} > $reach;
    }
    $cov{newest} = $reach;
    return \%cov;
}

# Covered time ranges of the shell-audit logs (sh.log and bash.log merged).
sub shell_intervals {
    my @ranges = sort { $a->[0] <=> $b->[0] } map { [$_->{first}, $_->{last}] }
                 grep { defined $_->{first} } map { @{ $FILES{$_} || [] } } @SHELL_FAMILIES;
    my @merged;
    for my $range (@ranges) {
        if (@merged && $range->[0] - $merged[-1][1] <= $GAP_THRESHOLD) {
            $merged[-1][1] = $range->[1] if $range->[1] > $merged[-1][1];
        } else {
            push @merged, [@$range];
        }
    }
    return @merged;
}

sub in_intervals {
    my ($t, $intervals) = @_;
    for my $range (@$intervals) { return 1 if $t >= $range->[0] && $t <= $range->[1] }
    return 0;
}

# ---------------------------------------------------------------- source-IP correlation

sub correlate_sources {
    return () unless @CORRELATED && @ALL_SECONDS;
    my @requests = sort { $a->[0] <=> $b->[0] } @CORRELATED;
    my %windows;
    my $start = 0;
    for my $second (@ALL_SECONDS) {
        $start++ while $start < @requests && $requests[$start][0] < $second - $CORRELATION_WINDOW;
        my %seen;
        for (my $i = $start; $i < @requests && $requests[$i][0] <= $second + $CORRELATION_WINDOW; $i++) {
            $seen{ $requests[$i][1] } = 1;
        }
        $windows{$_}++ for keys %seen;
    }
    return sort { $b->[1] <=> $a->[1] || $b->[2] <=> $a->[2] || $a->[0] cmp $b->[0] }
           map { [$_, $windows{$_}, $AUTH_REQUESTS_BY_IP{$_} || 0] } keys %windows;
}

# ---------------------------------------------------------------- file artifacts

sub check_artifacts {
    for my $path (sort keys %PATH_REFERENCES) {
        next if $path eq $SELF_PATH || $path eq $REPORT_PATH;
        my $ref        = $PATH_REFERENCES{$path};
        my $groups     = join(",", sort { $GROUP_ORDER{$a} <=> $GROUP_ORDER{$b} } keys %{ $ref->{groups} });
        my $persistent = $path =~ m{^/(?:var|flash|nsconfig)/} ? 1 : 0;
        my @st = lstat $path;
        if (!@st) {
            if ($persistent) {
                status("OK", show($path) . " ($groups): absent on a persistent filesystem.");
            } elsif (defined $BOOT_EPOCH && defined $ref->{first} && $BOOT_EPOCH > $ref->{first}) {
                status("CHECK", show($path) . " ($groups): absent, but the path is volatile and the ADC booted at "
                    . fmt_time($BOOT_EPOCH) . ", after the first attempt (" . fmt_time($ref->{first})
                    . "). Absence is not meaningful.");
            } else {
                status("OK", show($path) . " ($groups): absent (volatile path, no boot since the first attempt).");
            }
            next;
        }
        my $mode = $st[2] & 07777;
        my $type = -l _ ? "symlink" : -f _ ? "file" : -d _ ? "directory" : "other";
        my @facts = (sprintf("type=%s mode=%04o uid=%d gid=%d size=%d mtime=%s",
                             $type, $mode, $st[4], $st[5], $st[7], fmt_time($st[9])));
        if ($type eq "symlink") {
            my $target = readlink $path;
            push @facts, "link target=" . show(defined $target ? $target : "");
        }
        if ($type eq "file" && $st[7] <= $MAX_HASH_BYTES) {
            my $digest = sha256_file($path);
            push @facts, "sha256=" . (defined $digest ? $digest : "unavailable");
        }
        my @reasons;
        push @reasons, "modified at or after the first referencing attempt"
            if defined $ref->{first} && $st[9] >= $ref->{first} - 60;
        push @reasons, "permissions match the payload chmod $ref->{mode}"
            if defined $ref->{mode} && ($mode & 0777) == (oct($ref->{mode}) & 0777);
        if (@reasons) {
            status("ACTION", show($path) . " ($groups) exists: " . join("; ", @reasons) . ". Preserve it before any change.");
        } else {
            status("CHECK", show($path) . " ($groups) exists and predates the attempts. Verify that it is legitimate.");
        }
        out(map { "  " . $_ } @facts);
    }
}

sub sha256_file {
    my ($path) = @_;
    if ($HAVE_DIGEST) {
        my $digest = eval { Digest::SHA->new(256)->addfile($path, "b")->hexdigest };
        return $digest if defined $digest;
    }
    for my $command (grep { defined $_->[0] } [$SHA256, "-q"], [$SHA256SUM]) {
        open(my $fh, "-|", @$command, $path) or next;
        my $text = do { local $/; <$fh> };
        close $fh;
        return lc $1 if defined $text && $text =~ /\b([0-9a-fA-F]{64})\b/;
    }
    return undef;
}

# ---------------------------------------------------------------- output helpers

# Log text is untrusted: printable ASCII only, bounded length, public hosts defanged.
sub show {
    my ($text, $max) = @_;
    $max ||= 400;
    $text = "" unless defined $text;
    $text =~ s/[^\x20-\x7e]/./g;
    $text = substr($text, 0, $max) . " [...]" if length $text > $max;
    return defang($text);
}

sub defang {
    my ($text) = @_;
    $text =~ s{\bhttp(s?)://}{hxxp$1://}gi;
    $text =~ s{\b((?:hxxps?|ftp|tftp)://(?:[^@/\s]*@)?)([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z][A-Za-z0-9-]*)}{$1 . defang_last_dot($2)}gie;
    $text =~ s{(?<![\d.\[])((\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3}))(?!\d|\.\d)}{public_ipv4($1) ? "$2.$3.$4\[.]$5" : $1}ge;
    return $text;
}

sub defang_last_dot { my ($host) = @_; $host =~ s/\.([^.]+)\z/[.]$1/; return $host }

# Bare host names: defang the last dot of a name; IPv4 addresses go through defang().
sub show_host {
    my ($hostport) = @_;
    my $text = show($hostport, 200);
    return $text if index($text, "[.]") >= 0 || $hostport !~ /[A-Za-z]/;
    $text =~ s/\.([^.:]+)((?::\d+)?)\z/[.]$1$2/;
    return $text;
}

sub count_list {
    my ($counts) = @_;
    return join ", ", map { show($_) . " ($counts->{$_})" }
                      sort { $counts->{$b} <=> $counts->{$a} || $a cmp $b } keys %$counts;
}

# Keep the beginning and the end of long chronological lists.
sub limit_list {
    my ($items, $max) = @_;
    return @$items if @$items <= $max;
    my $half = int($max / 2);
    return (@$items[0 .. $half - 1],
            sprintf("  ... %d line(s) omitted ...", @$items - 2 * $half),
            @$items[$#$items - $half + 1 .. $#$items]);
}

sub combine_rules {
    my @rules = @_;
    return undef unless @rules;
    my $alternation = join "|", map { $_->{re} } @rules;
    return qr/$alternation/;
}
'
geiger_analysis() {
    if command -v perl >/dev/null 2>&1; then
        perl -e "$GEIGER_ANALYSIS_PL" -- "$1" "$GEIGER_LOG_DIR" "$GEIGER_CAMPAIGN_START" \
            "${INSTALL_EPOCH-}" "${GEIGER_BOOT_EPOCH-}" "$GEIGER_SELF_PATH" "$OUT"
    else
        status CHECK 'perl is unavailable; the GEIGER log analysis could not run.'
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
sha256_from_stream() {
    # Accept native FreeBSD SHA256(path)=digest and GNU digest-first output.
    # Check the token length explicitly; older BSD sed implementations need not
    # behave consistently for a 64-character interval expression.
    awk '{
        candidate=$NF
        if(length(candidate)!=64 || candidate ~ /[^0-9a-fA-F]/) candidate=$1
        if(length(candidate)==64 && candidate !~ /[^0-9a-fA-F]/) {print tolower(candidate); exit}
    }'
}
sha256_of() {
    _hash_path=$1
    if command -v sha256 >/dev/null 2>&1; then
        sha256 "$_hash_path" 2>/dev/null | sha256_from_stream
    elif command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$_hash_path" 2>/dev/null | sha256_from_stream
    fi
}
check_1417337_reference() {
    REFERENCE_MATCH=UNKNOWN
    _ref_path=$1
    _ref_hash=$2
    _reference_build=$(reference_hash_build) || return 0
    _actual_hash=$(sha256_of "$_ref_path")
    if [ -n "$_actual_hash" ]; then
        printf 'SHA-256 observed:  %s\n' "$_actual_hash"
        printf 'SHA-256 reference: %s\n' "$_ref_hash"
    fi
    if [ -z "$_actual_hash" ]; then
        status CHECK "Could not calculate SHA-256 for $_ref_path against the internal $_reference_build sample."
    elif [ "$_actual_hash" = "$_ref_hash" ]; then
        REFERENCE_MATCH=YES
        status OK "$_ref_path SHA-256 matches the internal $_reference_build reference from one clean appliance; this is not a Citrix-published checksum."
    else
        status CHECK "$_ref_path SHA-256 differs from the internal one-appliance $_reference_build reference; compare edition, configuration, and a trusted peer before treating it as anomalous."
    fi
}
reference_suid_1417337() {
    case "$1" in
        /var/nslog/nslog.nextfile) check_nslog_nextfile_state "$1" ;;
        /var/run/nsprofmgmt.pid) check_nsprofmgmt_pid "$1" ;;
        /var/configd_devno)
            case "$(reference_hash_build)" in
                14.1-73.37) check_1417337_reference "$1" '5b76771117eacc288a42de079a719402e26528e997cfa82241c4d7a842eba5d2' ;;
                14.1-73.41) check_1417337_reference "$1" '7aa41973005e4f74eab7fc630d49fc5d96afc16edd786f9c22ca3d8cd993bb75' ;;
            esac
            ;;
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
        status OK 'nsprofmgmt.pid mode and numeric owner/group match the internal sample; size, timestamp, and hash are intentionally not compared.'
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
        status OK 'nslog.nextfile mode and numeric owner/group match the internal sample; size, timestamp, and hash are intentionally not compared.'
    else
        status CHECK "nslog.nextfile mode/owner/group differ from the internal sample (observed ${_state_meta:-unavailable}); validate against a trusted same-build peer."
    fi
}
FW_PATCHED=UNKNOWN

printf 'Deyda Consulting NetScaler IOC and CVE triage report\n'
printf 'Host: %s\nTime: %s\nScript version: %s\nScript path: %s\n\n' "$HOST" "$NOW" "$SCRIPT_VERSION" "$GEIGER_SELF_PATH"
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

Read the report in this order: executive summary and priority finding map; status definitions; firmware/CVE applicability; host integrity and persistence; web configuration and files; log coverage and attack indicators; then next actions.
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
    status CHECK "Firmware comparison skipped; rerun with the version from show ns version as argument, e.g. sh $GEIGER_SELF_BASE 14.1-73.37.nc."
fi
printf '\nCVE configuration matches below show feature/precondition clues from the configuration file.\n'
printf 'The preceding threshold applies to CTX697096 (88771-88778). CVE-2026-88779 has a separate SAML assessment and newer thresholds below.\n'
printf 'For each CVE, a matching precondition on its fixed build is configuration context; it may matter when assessing exposure before the update.\n'

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

subsection 'CVE-2026-88779: SAML SP or IdP denial of service (CTX697174)'
printf '%s\n' 'Memory overflow leading to denial of service; configured SAML SP or SAML IdP is the bulletin precondition.'
printf '%s\n' 'Fixed minimums: standard 14.1 / 14.1 FIPS 73.41; standard 13.1 64.28; 13.1 FIPS/NDcPP 37.282.'
printf '%s\n' 'Source: supplied CTX697174 bulletin dated 2026-10-04; verify the current vendor bulletin before changes.'
if [ -r "$CONFIG" ]; then
    SAML_DOS_SP=$(awk 'tolower($0) ~ /^[[:space:]]*add[[:space:]]+authentication[[:space:]]+samlaction[[:space:]]+/ { n++ } END { print n+0 }' "$CONFIG")
    SAML_DOS_IDP=$(awk 'tolower($0) ~ /^[[:space:]]*add[[:space:]]+authentication[[:space:]]+samlidpprofile[[:space:]]+/ { n++ } END { print n+0 }' "$CONFIG")
    printf 'Saved-config SAML SP actions: %s; SAML IdP profiles: %s\n' "$SAML_DOS_SP" "$SAML_DOS_IDP"
    if [ "$SAML_DOS_SP" -eq 0 ] && [ "$SAML_DOS_IDP" -eq 0 ]; then
        status OK 'No SAML SP action or SAML IdP profile found in the scanned saved configuration; CVE-2026-88779 precondition not found in this source.'
    elif [ -n "${FW_FAMILY-}" ] && [ -n "${FW_BUILD-}" ]; then
        SAML_DOS_REQUIRED=''
        case "$FW_FAMILY" in
            14.1) SAML_DOS_REQUIRED='73.41' ;;
            13.1)
                if [ "$FW_MAJOR" -eq 37 ] || printf '%s\n' "$CURRENT_INPUT" | grep -Eiq 'FIPS|NDcPP'; then
                    SAML_DOS_REQUIRED='37.282'
                else
                    SAML_DOS_REQUIRED='64.28'
                fi ;;
        esac
        if [ -n "$SAML_DOS_REQUIRED" ]; then
            SAML_DOS_MAJOR=${SAML_DOS_REQUIRED%.*}
            SAML_DOS_MINOR=${SAML_DOS_REQUIRED#*.}
            printf 'CVE-2026-88779 firmware comparison: %s-%s; fixed minimum %s-%s.\n' "$FW_FAMILY" "$FW_BUILD" "$FW_FAMILY" "$SAML_DOS_REQUIRED"
            if [ "$FW_MAJOR" -gt "$SAML_DOS_MAJOR" ] || { [ "$FW_MAJOR" -eq "$SAML_DOS_MAJOR" ] && [ "$FW_MINOR" -ge "$SAML_DOS_MINOR" ]; }; then
                status OK 'SAML precondition found, but the assessed firmware meets the CVE-2026-88779 fixed-build threshold. Earlier compromise and crash causes require separate investigation.'
            else
                status ACTION 'SAML SP/IdP precondition found and firmware is below the CVE-2026-88779 fixed build; install the relevant update promptly. Workaround-policy recognition does not clear this firmware finding.'
            fi
        else
            status CHECK 'SAML SP/IdP precondition found, but a CVE-2026-88779 threshold could not be selected; verify release, edition and live build.'
        fi
    else
        status CHECK 'SAML SP/IdP precondition found, but the full firmware build is unknown; verify show ns version against CTX697174.'
    fi
    printf 'Scope: %s is saved configuration, not necessarily live configuration. Only object counts are displayed; SAML secrets are omitted.\n' "$CONFIG"
else
    status CHECK 'Saved configuration unreadable; CVE-2026-88779 SAML SP/IdP applicability could not be assessed.'
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
# Parse names and bindings without exposing proprietary policy expressions.
# OK confirms selected saved-config structure/bindings, not exact vendor approval.
# GEIGER: the request workaround is an interim measure until the CVE-2026-88779 fixed
# build. On a fixed build missing workaround parts are informational, not ACTION.
GEIGER_SAML_FIXED=NO
if [ -n "${SAML_DOS_REQUIRED-}" ] && [ -n "${FW_MAJOR-}" ] && [ -n "${FW_MINOR-}" ]; then
    if [ "$FW_MAJOR" -gt "${SAML_DOS_REQUIRED%.*}" ] || { [ "$FW_MAJOR" -eq "${SAML_DOS_REQUIRED%.*}" ] && [ "$FW_MINOR" -ge "${SAML_DOS_REQUIRED#*.}" ]; }; then
        GEIGER_SAML_FIXED=YES
    fi
fi
if [ -r "$CONFIG" ]; then
    awk -v fixed="$GEIGER_SAML_FIXED" '
    function tokens(text, fields,    i,c,nextc,quoted,value,n,active,k) {
        for(k in fields) delete fields[k]
        n=0; value=""; quoted=0; active=0
        for(i=1;i<=length(text);i++) {
            c=substr(text,i,1)
            if(c=="\\" && quoted && i<length(text)) {
                nextc=substr(text,i+1,1)
                if(nextc=="\"" || nextc=="\\") {value=value nextc; i++; active=1; continue}
            }
            if(c=="\"") {quoted=!quoted; active=1; continue}
            if(c ~ /[ \t\r]/ && !quoted) {
                if(active) {fields[++n]=value; value=""; active=0}
            } else {value=value c; active=1}
        }
        if(active) fields[++n]=value
        return n
    }
    function target_policy(name) {return selected[name]}
    function result(level,message) {printf "%s\t%s\n",level,message}
    {
        n=tokens($0,t)
        if(n<3 || t[1] ~ /^#/) next
        verb=tolower(t[1]); kind=tolower(t[2]); object=tolower(t[3])
        if(verb=="enable" && kind=="ns" && object=="feature" && toupper(t[4])=="RESPONDER") responder_enabled=1
        if(verb=="add" && kind=="authentication" && object=="samlaction") saml++
        if(verb=="add" && kind=="authentication" && object=="samlidpprofile") other++
        if((verb=="add" || verb=="set") && kind=="vpn" && object=="sessionaction")
            for(i=5;i<n;i++) if(tolower(t[i])=="-samlsso" && tolower(t[i+1])=="enabled") other++
        if(verb=="add" && kind=="responder" && object=="policy") {
            name=t[4]; expression=tolower(t[5])
            # Names vary between Citrix builds/advisories. Identify the policy
            # by its endpoint and SAML payload field, then require a DROP action.
            cgi_match=(index(expression,"http.req.url.path.set_text_mode(ignorecase)") && index(expression,"/cgi/samlauth") && index(expression,"samlresponse"))
            saml_login_match=(index(expression,"http.req.url.path.set_text_mode(ignorecase)") && index(expression,"/saml/login") && index(expression,"samlrequest"))
            if((cgi_match || saml_login_match) && toupper(t[6])=="DROP") {
                definitions[name]=1; selected[name]=1; valid[name]=1
            }
        }
        if(verb=="add" && (kind=="vpn" || kind=="authentication") && object=="vserver") {
            key=kind SUBSEP t[4]; servers[key]=kind " vServer " t[4]
        }
        if(verb=="bind" && (kind=="vpn" || kind=="authentication") && object=="vserver") {
            policy=""; type=""; disabled=0
            for(i=5;i<n;i++) {
                option=tolower(t[i])
                if(option=="-policy" || option=="-policyname") policy=t[i+1]
                if(option=="-type") type=tolower(t[i+1])
                if(option=="-state" && tolower(t[i+1])=="disabled") disabled=1
            }
            if(target_policy(policy) && type=="aaa_request" && !disabled) bindings[kind SUBSEP t[4] SUBSEP policy]=1
        }
    }
    END {
        result("INFO","Saved SAML action count: " (saml+0))
        count=0; for(name in definitions) count++
        if(!saml && !other && !count) {
            result("OK","No selected SAML configuration or recognized workaround policy found; this SAML workaround check is not applicable in the scanned saved configuration.")
            exit
        }
        warning=(saml || other)?"ACTION":"CHECK"
        prefix="WARNING: "
        if(fixed=="YES") {
            warning="INFO"; prefix="Info (not required on the fixed build): "
            result("OK","Firmware meets the CVE-2026-88779 fixed build; the SAML request workaround is an interim measure until that build and is not required. The workaround inventory below is informational.")
        }
        if(!count) result(warning,prefix "No responder policy matching the /cgi/samlauth + SAMLResponse (or /saml/login + SAMLRequest) expression and DROP action was found in saved configuration. Verify the current Citrix mitigation and save the configuration.")
        for(name in definitions) {
            if(valid[name]) result("INFO",name " matches a SAML endpoint/body-field pattern and DROP action. The full policy expression is not printed; verify it against current Citrix guidance.")
            else result(warning,prefix name " is defined but does not contain the expected selected expression/action markers.")
        }
        total=0; covered=0; missing=0
        for(key in servers) {
            total++; ok=0; matched=""
            for(name in definitions) if(valid[name] && bindings[key SUBSEP name]) {ok=1; matched=name; break}
            if(ok) {
                covered++
                result("OK",servers[key] ": " matched " is defined with recognized structure and an enabled AAA_REQUEST binding in saved configuration.")
            } else {
                missing++
                result(warning,prefix servers[key] " has no enabled AAA_REQUEST binding to a recognized policy with the selected structure. Check the required frontend binding.")
            }
        }
        if(total && !missing) result("OK","Recognized SAML workaround coverage found for all " total " saved Authentication/VPN vServers.")
        else if(!total) result(fixed=="YES" ? "INFO" : "CHECK","No Authentication/VPN vServers were found; frontend binding coverage cannot be established.")
        else result(warning,(fixed=="YES" ? prefix : "") "SAML workaround coverage incomplete: " covered " of " total " saved Authentication/VPN vServers have a recognized enabled AAA_REQUEST binding.")
        if(count) {
            if(responder_enabled) result("OK","RESPONDER feature enablement is present in the saved configuration.")
            else result(warning,prefix "A matching SAML workaround policy is present, but 'enable ns feature RESPONDER' is not recorded in the saved configuration. Verify the live feature state with 'show ns feature'; a bound policy is ineffective if Responder is disabled.")
        }
        result("INFO","Scope: saved configuration only; selected structure is not exact expression validation. Verify current Support instructions, priorities, effective live flow and legitimate sign-ins. Global bindings are not counted as AAA_REQUEST coverage.")
    }
    ' "$CONFIG" | while IFS="$(printf '\t')" read -r SAML_LEVEL SAML_MESSAGE; do
        if [ "$SAML_LEVEL" = INFO ]; then printf '%s\n' "$SAML_MESSAGE"; else status "$SAML_LEVEL" "$SAML_MESSAGE"; fi
    done
else
    status CHECK 'Saved configuration unreadable; SAML workaround inventory unavailable.'
fi

# Query only two fixed read-only CLI commands. No credentials, input evaluation,
# arbitrary CLI commands, configuration writes or counter resets are used.
gdl_read_cli() {
    case "$1" in
        'show appfw signatures'|'stat denylist global AAA_REQUEST') ;;
        *) return 1 ;;
    esac
    [ "$RUNNING_ON_ADC" = YES ] || return 1
    command -v perl >/dev/null 2>&1 || return 1
    # A pending alarm survives exec and bounds CLI/authentication waits to 15s.
    if [ -x /netscaler/cli_script.sh ]; then
        perl -e 'alarm 15; exec {"/netscaler/cli_script.sh"} "/netscaler/cli_script.sh", $ARGV[0]; exit 127;' "$1" </dev/null 2>&1
    elif [ -x /netscaler/nscli ]; then
        perl -e 'alarm 15; exec {"/netscaler/nscli"} "/netscaler/nscli", "-c", $ARGV[0]; exit 127;' "$1" </dev/null 2>&1
    else
        return 1
    fi
}

# Deliberately restrict the version parser to the Default Signatures object;
# a higher version on another object must not clear a stale default version.
gdl_default_version() {
    awk '
    {
        line=$0; low=tolower(line)
        if(low ~ /(^|[[:space:]])name[[:space:]]*:/) {
            sub(/^.*[Nn][Aa][Mm][Ee][[:space:]]*:[[:space:]]*/, "", line)
            in_default=(tolower(line) ~ /^["\047]?[*]default[[:space:]]+signatures(["\047[:space:]]|$)/)
        }
        if(in_default && low ~ /encrypted[[:space:]]+version[[:space:]]*:/) {
            sub(/^.*[Vv][Ee][Rr][Ss][Ii][Oo][Nn][[:space:]]*:[[:space:]]*/, "", line)
            if(line ~ /^[vV]?[0-9]+([[:space:]]|$)/) {
                sub(/^[vV]/,"",line); sub(/[[:space:]].*$/, "", line)
                print line; exit
            }
        }
    }'
}

gdl_counter_state() {
    awk '
    {
        line=$0; low=tolower(line)
        if(low ~ /(rules?[[:space:]_-]*(evaluated|matched|hits)|packets?[[:space:]_-]*(evaluated|matched|dropped|denied)|total[[:space:]_-]*(hits|matches))([[:space:]]|:|=)/) {
            sub(/^[^:=]*[:=][[:space:]]*/, "", line)
            if(line ~ /^[0-9]+([[:space:]]|$)/) { seen=1; if(line+0>0) positive=1 }
        }
    }
    END { if(positive) print "ACTIVITY"; else if(seen) print "ZERO"; else print "UNPARSED" }'
}

subsection 'CVE-2026-88779: Global Deny List signatures and AAA_REQUEST statistics'
printf '%s\n' 'Additional mitigation checks from the supplied Citrix Community guidance; these do not replace the fixed-build assessment above.'
printf '%s\n' 'Console service, or on-premises Console with Cloud Connect, and Virtual patching Enabled are required. Local signatures/statistics alone do not verify these Console settings.'
GDL_SCOPE=UNKNOWN
if [ -r "$CONFIG" ] && [ "${SAML_DOS_SP:-0}" -eq 0 ] && [ "${SAML_DOS_IDP:-0}" -eq 0 ]; then
    GDL_SCOPE=NO_SAML
elif [ -n "${FW_FAMILY-}" ] && [ -n "${FW_BUILD-}" ]; then
    if [ -n "${SAML_DOS_REQUIRED-}" ] && { [ "$FW_MAJOR" -gt "${SAML_DOS_MAJOR:-999999}" ] || { [ "$FW_MAJOR" -eq "${SAML_DOS_MAJOR:-999999}" ] && [ "$FW_MINOR" -ge "${SAML_DOS_MINOR:-999999}" ]; }; }; then
        GDL_SCOPE=FIXED
    elif printf '%s\n' "$CURRENT_INPUT" | grep -Eiq 'FIPS|NDcPP' || { [ "$FW_FAMILY" = '13.1' ] && [ "$FW_MAJOR" -eq 37 ]; }; then
        GDL_SCOPE=EDITION_UNCONFIRMED
    elif [ "$FW_FAMILY" = '14.1' ]; then
        if [ "$FW_MAJOR" -gt 73 ] || { [ "$FW_MAJOR" -eq 73 ] && [ "$FW_MINOR" -ge 41 ]; }; then GDL_SCOPE=FIXED
        elif [ "$FW_MAJOR" -eq 73 ] && [ "$FW_MINOR" -ge 37 ]; then GDL_SCOPE=SUPPORTED_RANGE
        else GDL_SCOPE=OUTSIDE_RANGE; fi
    elif [ "$FW_FAMILY" = '13.1' ]; then
        if [ "$FW_MAJOR" -gt 64 ] || { [ "$FW_MAJOR" -eq 64 ] && [ "$FW_MINOR" -ge 28 ]; }; then GDL_SCOPE=FIXED
        elif [ "$FW_MAJOR" -eq 64 ] && [ "$FW_MINOR" -ge 23 ]; then GDL_SCOPE=SUPPORTED_RANGE
        else GDL_SCOPE=OUTSIDE_RANGE; fi
    fi
fi
printf 'Reported mitigation scope: %s\n' "$GDL_SCOPE"
case "$GDL_SCOPE" in
    NO_SAML) status OK 'No SAML SP/IdP prerequisite found in saved configuration; this CVE-specific Global Deny List mitigation is not required by the scanned configuration.' ;;
    FIXED) status OK 'Firmware meets the CVE-2026-88779 fixed threshold; Global Deny List mitigation is not a prerequisite for that firmware result.' ;;
    *)
        case "$GDL_SCOPE" in
            SUPPORTED_RANGE) printf '%s\n' 'Build is in the reported standard-version mitigation range. Verify signature version >=24 and Console prerequisites until updating.' ;;
            OUTSIDE_RANGE) status CHECK 'Build is outside the published mitigation ranges (14.1-73.37..<73.41 or 13.1-64.23..<64.28); do not assume Global Deny List protection. Update to the applicable fixed build.' ;;
            EDITION_UNCONFIRMED) status CHECK 'The supplied Global Deny List guidance does not establish these mitigation ranges for FIPS/NDcPP; confirm support for this edition with Citrix.' ;;
            *) status CHECK 'Build or SAML applicability is unknown; Global Deny List mitigation applicability is unverified.' ;;
        esac
        GDL_SIGNATURE_OUTPUT=''; GDL_SIGNATURE_RC=1
        GDL_STATS_OUTPUT=''; GDL_STATS_RC=1
        if [ -n "${DEYDA_GDL_SIGNATURES_FILE-}" ]; then
            if [ -f "$DEYDA_GDL_SIGNATURES_FILE" ] && [ -r "$DEYDA_GDL_SIGNATURES_FILE" ]; then
                GDL_SIGNATURE_OUTPUT=$(cat "$DEYDA_GDL_SIGNATURES_FILE"); GDL_SIGNATURE_RC=0
                printf 'Signature source: operator-supplied CLI capture %s (not a live verification).\n' "$DEYDA_GDL_SIGNATURES_FILE"
            fi
        elif [ "$RUNNING_ON_ADC" = YES ]; then
            GDL_SIGNATURE_OUTPUT=$(gdl_read_cli 'show appfw signatures'); GDL_SIGNATURE_RC=$?
            printf '%s\n' 'Signature source: attempted local read-only ADC CLI query (15-second limit).'
        fi
        if [ -n "${DEYDA_GDL_STATS_FILE-}" ]; then
            if [ -f "$DEYDA_GDL_STATS_FILE" ] && [ -r "$DEYDA_GDL_STATS_FILE" ]; then
                GDL_STATS_OUTPUT=$(cat "$DEYDA_GDL_STATS_FILE"); GDL_STATS_RC=0
                printf 'Statistics source: operator-supplied CLI capture %s (not a live verification).\n' "$DEYDA_GDL_STATS_FILE"
            fi
        elif [ "$RUNNING_ON_ADC" = YES ]; then
            GDL_STATS_OUTPUT=$(gdl_read_cli 'stat denylist global AAA_REQUEST'); GDL_STATS_RC=$?
            printf '%s\n' 'Statistics source: attempted local read-only ADC CLI query (15-second limit).'
        fi
        if [ "$GDL_SIGNATURE_RC" -eq 0 ] && ! printf '%s\n' "$GDL_SIGNATURE_OUTPUT" | grep -Eiq '(^|[[:space:]])(ERROR:|not authorized|permission denied|authentication failed|unknown command|invalid command)'; then
            GDL_VERSION=$(printf '%s\n' "$GDL_SIGNATURE_OUTPUT" | gdl_default_version)
            if [ -n "$GDL_VERSION" ]; then
                printf 'Default Signatures / Encrypted Version observed: %s\n' "$GDL_VERSION"
                if [ "$GDL_VERSION" -ge 24 ]; then
                    status OK 'Default Signatures encrypted version is >=24 in the selected source. This confirms the version only, not effective mitigation or Console configuration.'
                else
                    status CHECK 'Default Signatures encrypted version is below 24; the required signature revision is not confirmed. Check Console connectivity, Virtual patching and signature delivery; prioritize the firmware update.'
                fi
            else
                status CHECK 'A numeric Encrypted Version could not be parsed for *Default Signatures; verify show appfw signatures manually. No signature-version OK was inferred.'
            fi
        else
            status CHECK 'Signature query/capture unavailable or unsuccessful; run show appfw signatures in the ADC CLI and verify *Default Signatures / Encrypted Version >=24.'
        fi
        if [ "$GDL_STATS_RC" -eq 0 ] && printf '%s\n' "$GDL_STATS_OUTPUT" | grep -Eiq 'denylist|AAA_REQUEST|rule.*evaluat' && ! printf '%s\n' "$GDL_STATS_OUTPUT" | grep -Eiq '(^|[[:space:]])(ERROR:|not authorized|permission denied|authentication failed|unknown command|invalid command)'; then
            printf '\nAAA_REQUEST statistics (selected source; inspect counters and Last Hit Time):\n'
            printf '%s\n' "$GDL_STATS_OUTPUT" | head -100
            GDL_COUNTER_STATE=$(printf '%s\n' "$GDL_STATS_OUTPUT" | gdl_counter_state)
            case "$GDL_COUNTER_STATE" in
                ACTIVITY) status OK 'Positive evaluation/match counters were observed. This shows recorded activity, not complete protection; distinguish evaluated requests from blocked hits and inspect Last Hit Time.' ;;
                ZERO) status OK 'Recognized counters are zero in the selected statistics. Zero is not a failure indication and does not prove that mitigation is disabled or working.' ;;
                *) status CHECK 'Statistics were retrieved, but the counter layout was not recognized; inspect evaluation/hit counters and Last Hit Time manually. No activity was inferred from dates or unrelated numbers.' ;;
            esac
        else
            status CHECK 'AAA_REQUEST statistics query/capture unavailable or unsuccessful; run stat denylist global AAA_REQUEST in the ADC CLI. Missing statistics are not proof of disabled mitigation.'
        fi
        status CHECK 'Confirm in NetScaler Console: service or on-premises with Cloud Connect; Virtual patching Status Enabled. This remote setting cannot be verified from local ns.conf alone.'
        ;;
esac

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
printf '%s\n' 'Payload search: up to 500 readable regular files below 1 MiB in /var/tmp, /tmp, /nsconfig, and /flash/nsconfig; this script (by resolved path) and generated reports excluded. Larger files, unreadable files, and other paths are outside coverage.'
while IFS= read -r f; do
    [ -n "$f" ] && [ -r "$f" ] || continue
    # GEIGER: exclude the running script by resolved path and all generated reports.
    [ "$f" = "$GEIGER_SELF_PATH" ] && continue
    case "$f" in /var/tmp/deyda-netscaler-ioc-check_*.txt|/var/tmp/deyda-netscaler-ioc-check_*.txt) continue ;; esac
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
    NSMON_RUNNING=$(printf '%s\n' "$NSMON_PS" | awk -v self="$GEIGER_SELF_BASE" '/nsmon[.]pl|\/var\/tmp\/[.]nsmon\// && !/awk|grep|deyda-netscaler-ioc-check/ && (self == "" || index($0, self) == 0) {print}')
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
    SLAP_PROCESSES=$(printf '%s\n' "$SLAP_PROCESS_SNAPSHOT" | awk -v self="$GEIGER_SELF_BASE" '/\/(flash\/)?nsconfig\/[.]slap\/|\/var\/tmp\/[.]ux\/(slapshot|whipd|whippid)[.]py/ && !/awk|grep|deyda-netscaler-ioc-check/ && (self == "" || index($0, self) == 0) {print}')
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
    elif reference_build_supported; then
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
for f in /nsconfig/rc.netscaler /nsconfig/nsafter.sh /flash/nsconfig/rc.netscaler /etc/monitrc; do
    if [ -e "$f" ]; then
        PERSIST_FILES_FOUND=$((PERSIST_FILES_FOUND + 1))
        printf '\n    File: %s\n' "$f"
        ls -la "$f" 2>&1
        case "$f" in
            /nsconfig/rc.netscaler)
                ;;
            /flash/nsconfig/rc.netscaler)
                if [ -r /nsconfig/rc.netscaler ] && cmp -s /nsconfig/rc.netscaler "$f"; then
                    status OK '/flash/nsconfig/rc.netscaler is byte-for-byte identical to /nsconfig/rc.netscaler; no static content hash baseline is applied because this startup file may be customized.'
                else
                    status CHECK 'The two rc.netscaler copies differ or the primary copy is unreadable; compare their contents with the approved startup configuration.'
                fi
                ;;
            /etc/monitrc)
                case "$(reference_hash_build)" in
                    14.1-73.37) check_1417337_reference "$f" 'ab1aae7ba469c122ae16a992da9ddc4b12f81301b0b05d8eba2b379a06d56e54' ;;
                    14.1-73.41) check_1417337_reference "$f" '2c6d46cc538b48bf8d7e4ba0d598025114d554fd8a28c391c6290e9c7f98e0ee' ;;
                esac
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

HA_LOG_HITS=$(zgrep -E -i -n 'nsfsyncd|(^|[^[:alnum:]_])HA[[:space:]_-]+(sync|synchronization|state|fail|error)|(^|[^[:alnum:]_])(sync|synchronization)[[:space:]_-]+(HA|peer)' /var/log/ns.log* /var/log/messages* /var/log/notice.log* /var/log/nsvpn.log* 2>/dev/null | chrono_sort | tail -60)
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
        SHELL_HASH=$(printf '%s\n' "$SHA_OUTPUT" | sha256_from_stream)
    elif command -v sha256sum >/dev/null 2>&1; then
        SHA_OUTPUT=$(sha256sum /bin/sh 2>&1)
        printf '%s\n' "$SHA_OUTPUT"
        SHELL_HASH=$(printf '%s\n' "$SHA_OUTPUT" | sha256_from_stream)
    fi
    SHELL_REFERENCE_BUILD=$(reference_hash_build)
    case "$SHELL_REFERENCE_BUILD" in
        14.1-73.37) SHELL_EXPECTED_HASH='2c1310d7c4d7dfb1ef47b137be1eb572cc743cc609898ae38320963cc0578665' ;;
        14.1-73.41) SHELL_EXPECTED_HASH='8c121937b172124e5895e5296dff5227841b1f8d9a698489377b65e3adb309c7' ;;
        *) SHELL_EXPECTED_HASH='' ;;
    esac
    if [ -n "$SHELL_EXPECTED_HASH" ]; then
        if [ "$SHELL_HASH" = "$SHELL_EXPECTED_HASH" ]; then
            status OK "/bin/sh SHA-256 matches the internal $SHELL_REFERENCE_BUILD reference from one clean appliance; this is not a vendor-published checksum."
        elif [ -n "$SHELL_HASH" ]; then
            status CHECK "/bin/sh SHA-256 differs from the internal $SHELL_REFERENCE_BUILD reference; compare platform/edition and another trusted same-build appliance before treating it as anomalous."
        else
            status CHECK "Could not calculate /bin/sh SHA-256 for comparison with the internal $SHELL_REFERENCE_BUILD reference."
        fi
    fi
    ls -ld /bin /bin/sh 2>&1
    SHELL_META=$(ls -ln /bin/sh 2>/dev/null | awk 'NR==1{print $1 ":" $3 ":" $4 ":" $5}')
    if reference_hash_build_supported && [ "$SHELL_META" = '-r-xr-xr-x:0:0:165368' ]; then
        status OK "/bin/sh mode, numeric owner/group, and size match the internal clean-sample reference for $(reference_hash_build); timestamps are host-specific and are not compared. This is not a vendor-published baseline."
    else
        status CHECK "Compare /bin/sh mode, owner, group, size, timestamp, and hash with a trusted same-build reference; observed metadata: ${SHELL_META:-unavailable}. The internal reference is not a vendor-published universal baseline."
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
                    /var/configd_devno)
                        case "$(reference_hash_build)" in
                            14.1-73.37) _expected='5b76771117eacc288a42de079a719402e26528e997cfa82241c4d7a842eba5d2' ;;
                            14.1-73.41) _expected='7aa41973005e4f74eab7fc630d49fc5d96afc16edd786f9c22ca3d8cd993bb75' ;;
                        esac
                        ;;
                esac
                _reference_build=$(reference_hash_build)
                _observed=$(sha256_of "$f")
                if [ -n "$_reference_build" ] && [ -n "$_expected" ] && [ -n "$_observed" ] && [ "$_observed" = "$_expected" ]; then
                    status OK "$f is newer than installns_state but matches the internal $_reference_build reference; recency alone is not suspicious. Reference is from one clean appliance, not Citrix."
                else
                    ls -ldn "$f" 2>&1
                    status CHECK "$f is newer than installns_state and does not match a usable internal reference for the detected build; validate runtime changes and compare with another clean same-build appliance."
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
        elif { reference_hash_build_supported; } && [ "$CUSTOMSNMPD_HASH" = '1dd0887ff21b18b0eb78a336e76d4dc3bb6f4fc645e9d864414a2958cb1637fe' ]; then
            status OK "/var/python/bin/customsnmpd matches the internal clean-appliance $(reference_hash_build) SHA-256 reference; this is not a Citrix-published checksum."
        elif { reference_hash_build_supported; }; then
            status CHECK "/var/python/bin/customsnmpd differs from the internal one-appliance $(reference_hash_build) reference. Compare edition, approved changes, and another trusted same-build node."
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
if reference_hash_build_supported; then
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
            status CHECK "$f is absent but exists in the internal clean $(reference_hash_build) reference; verify whether the component is expected on this appliance."
            PYTHON_REFERENCE_MISMATCHES=$((PYTHON_REFERENCE_MISMATCHES + 1))
            continue
        fi
        PYTHON_OBSERVED=$(sha256_of "$f")
        if [ -n "$PYTHON_OBSERVED" ] && [ "$PYTHON_OBSERVED" = "$PYTHON_EXPECTED" ]; then
            status OK "$f matches the internal clean $(reference_hash_build) SHA-256 reference. This is not a Citrix-published checksum."
        else
            status CHECK "$f differs from the internal clean $(reference_hash_build) reference or could not be hashed; validate approved changes and compare with another trusted same-build appliance."
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
        status OK "All $PYTHON_REFERENCE_COUNT referenced Python files under /var/python/bin match the internal clean $(reference_hash_build) hashes; no additional .py files were found."
    fi
fi
subsection 'configd state-file metadata baseline'
if reference_hash_build_supported; then
    if [ -f /var/configd_devno ]; then
        CONFIGD_DEVNO_META=$(ls -ln /var/configd_devno 2>/dev/null | awk 'NR==1{print $1 ":" $3 ":" $4 ":" $5}')
        if [ "$CONFIGD_DEVNO_META" = '-rwxr-Sr--:0:0:129' ]; then
            status OK "/var/configd_devno mode, numeric owner/group, and size match the internal clean $(reference_hash_build) sample."
        else
            status CHECK "/var/configd_devno metadata differs from the internal clean sample (-rwxr-Sr--:0:0:129); observed: ${CONFIGD_DEVNO_META:-unavailable}. Compare with another trusted same-build appliance."
        fi
    else
        status CHECK "/var/configd_devno is absent on this appliance, but was present on the internal $(reference_hash_build) reference; verify whether it is expected here and compare with a trusted peer."
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
# GEIGER: exclude the running script by resolved path; other copies of this tool and
# generated reports by name, including date-prefixed copies.
COOKIE_COMMAND_CANDIDATES=$(find /var/netscaler/logon/LogonPoint/custom /var/vpn /nsconfig/.slap /flash/nsconfig/.slap -type f -size -2048k \
    ! -path "$GEIGER_SELF_PATH" ! -name '*deyda-netscaler-ioc-check*.sh' ! -name '*deyda-netscaler-ioc-check_*.txt' \
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
                if [ "$ACTUAL_HASH" = "$EXPECTED_HASH" ]; then
                    status OK "$f SHA-256 exactly matches the internal reference captured on clean 14.1-73.37 and 14.1-73.41 reference appliances. Identical bytes are confirmed; the reference is not Citrix-published and does not establish provenance for this appliance."
                    STAGING_REFERENCE_MATCHES=$((STAGING_REFERENCE_MATCHES + 1))
                else
            status CHECK "$f SHA-256 differs from the internal reference; inspect before disposition."
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
        status OK 'Every VPN staging file found matches a known package hash in the internal 14.1-73.37 / 14.1-73.41 reference set; presence alone is expected on this reference build. The hashes are not Citrix-published.'
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
# GEIGER: the running script is excluded by resolved path (a renamed copy matched itself).
PLATYPUS_BOOTSTRAPS=$(find /tmp /var/tmp /netscaler.local /var/core -type f -size -1024k \
    ! -path "$GEIGER_SELF_PATH" ! -name '*deyda-netscaler-ioc-check_*.txt' ! -name '*deyda-netscaler-ioc-check*.sh' \
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
        [ "$f" = "$GEIGER_SELF_PATH" ] && continue    # GEIGER: not the running script itself
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
            if reference_hash_build_supported; then
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
        if reference_hash_build_supported; then
            if [ "$LANGUAGE_BASELINE_COUNT" -eq 12 ] && [ "$LANGUAGE_HASH_UNAVAILABLE" -eq 0 ] && [ -z "$LANGUAGE_BASELINE_MISMATCHES" ]; then
                status OK "All 12 strings.*.js files, filenames, and SHA-256 hashes match the internal clean-sample reference for NetScaler $(reference_hash_build). This is an internal single-appliance reference, not a Citrix-published checksum set or a universal baseline."
            else
                status CHECK "Language-file baseline differs or could not be fully checked (observed count: $LANGUAGE_BASELINE_COUNT; expected: 12; hash tool unavailable: $LANGUAGE_HASH_UNAVAILABLE). Review filenames and hashes against a trusted same-build appliance."
                [ -n "$LANGUAGE_BASELINE_MISMATCHES" ] && printf '%s\n' "$LANGUAGE_BASELINE_MISMATCHES"
            fi
        fi
    else
        status OK 'No strings.*.js language files found in the LogonPoint/custom directory.'
        if reference_hash_build_supported; then
            status CHECK "The internal $(reference_hash_build) reference contains 12 strings.*.js files, but none were found here."
        fi
    fi
else
    status CHECK "Language-file directory $LANGUAGE_DIR is absent; this targeted content check could not run."
fi

printf '\n--- Additional LogonPoint customization baseline files ---\n'
if reference_hash_build_supported; then
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
            strings.de.json|strings.en.json|strings.fr.json|strings.it.json|strings.ja.json|strings.pt.json|strings.nl.json|strings.ko.json|strings.ru.json|strings.zh-CN.json|strings.zh-TW.json)
                CUSTOM_ASSET_EXPECTED_HASH='8eb95bcbc154530931e15fc418c8b1fe991095671409552099ea1aa596999ede' ;;
            strings.es.json)
                CUSTOM_ASSET_EXPECTED_HASH='d914176fd50bd7f565700006a31aa97b79d3ad17cee20c8e5ff2061d5cb74817' ;;
        esac
        printf '%s\n' "$f"
        printf 'Observed SHA-256: %s\n' "${CUSTOM_ASSET_HASH:-unavailable}"
        if [ -n "$CUSTOM_ASSET_HASH" ] && [ "$CUSTOM_ASSET_HASH" = "$CUSTOM_ASSET_EXPECTED_HASH" ]; then
            status OK "$f matches the internal clean $(reference_hash_build) single-appliance reference. This is not a vendor checksum."
        elif [ -n "$CUSTOM_ASSET_HASH" ]; then
            status CHECK "$f differs from the internal clean $(reference_hash_build) reference; validate intended customization and compare with another trusted same-build appliance."
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
        status OK "All 15 additional LogonPoint assets (script.js, style.css, ajax-loader.gif, and strings.*.json) match the internal clean $(reference_hash_build) reference."
    else
        status CHECK "LogonPoint baseline coverage is partial or differs (observed $CUSTOM_ASSET_OBSERVED_COUNT of $CUSTOM_ASSET_EXPECTED_COUNT expected files). Missing files and intentional customizations require local validation."
        for name in script.js style.css ajax-loader.gif strings.de.json strings.en.json strings.es.json strings.fr.json strings.it.json strings.ja.json strings.nl.json strings.pt.json strings.ko.json strings.ru.json strings.zh-CN.json strings.zh-TW.json; do
            [ -f "$LANGUAGE_DIR/$name" ] || printf 'Missing reference file: %s/%s\n' "$LANGUAGE_DIR" "$name"
        done
    fi
else
    status CHECK 'These additional LogonPoint hashes are single-appliance 14.1-73.37 and 14.1-73.41 references and were not compared because the running build is outside that exact scope.'
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
# GEIGER: per-family coverage from the log lines themselves (point 4); the file
# mtime summary above can look complete while ns.log only reaches back hours.
progress 'Log coverage: per-family entries (GEIGER)'
GEIGER_BOOT_EPOCH=$(sysctl -n kern.boottime 2>/dev/null | sed -nE 's/.*sec = ([0-9]+),.*/\1/p')
geiger_analysis coverage
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
    grep -Eiv 'nsprofmon_mgmt[.]pl:|process_kernel_socket:[^[:cntrl:]]*call to authenticate user|cascade_auth:|start_ldap_auth:|receive_ldap_user_search_event:|AAAD API:|AAAD RESP:|LOGIN_FAILED|AAA LOGIN REQ|aaad_authenticate_req|Could not match login claims|CMD_EXECUTED|CLI CMD' | chrono_sort | tail -30)
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
HTTPD_RELOAD_LOGS=$(zgrep -E -i -n 'apachectl[[:space:]]+graceful|httpd[^[:cntrl:]]*(SIGHUP|SIGUSR1)|graceful[^[:cntrl:]]*(restart|reload)' /var/log/httperror* /var/log/messages* /var/log/ns.log* 2>/dev/null | chrono_sort | tail -40)
if [ -n "$HTTPD_RELOAD_LOGS" ]; then
    status CHECK 'HTTPD graceful-reload or signal references found in retained logs; correlate with httpd.conf and web-file changes:'
    printf '%s\n' "$HTTPD_RELOAD_LOGS"
else
    status OK 'No selected HTTPD graceful-reload/signal references found in the searched logs.'
fi
subsection 'CVE-2026-88772 DTLS and NSPPE event correlation'
DTLS_EVENT_LINES=$(zgrep -E -i -n 'SSL_HANDSHAKE_FAILURE.*DTLSv1[.]0.*Handshake failure-Internal Error' /var/log/ns.log* /var/log/messages* /var/log/notice.log* /var/log/nsvpn.log* 2>/dev/null | chrono_sort | tail -30)
NSPPE_EVENT_LINES=$(zgrep -E -i -n 'orphan rings|pitboss[^[:cntrl:]]*NOT restarting NSPPE|NSPPE[^[:cntrl:]]*(exit|crash|signal|terminated)' /var/log/ns.log* /var/log/messages* /var/log/notice.log* /var/log/nsvpn.log* 2>/dev/null | chrono_sort | tail -50)
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
INDEX_LINES=$(zgrep -hE -i 'INDEX:[A-Za-z0-9+/=]{8,}' /var/log/httpaccess* /var/log/httperror* 2>/dev/null | chrono_sort | tail -20)
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
PITBOSS_LINES=$(zgrep -hE -i 'pitboss PPE (missed too many heartbeats|unexpectedly died)[[:space:]]?NSPPE(-[0-9]+)?[^[:cntrl:]]*(;|%3[bB]|`|%60|\$\(|\$\{IFS\}|%24%7BIFS%7D)' /var/log/ns.log* /var/log/messages* /var/log/notice.log* /var/log/nsvpn.log* 2>/dev/null | chrono_sort | tail -40)
if [ -n "$PITBOSS_LINES" ]; then
    status ACTION 'System/authentication-log line matches a publicly reported PPE trigger (missed heartbeats or unexpectedly died) followed by shell syntax. This records an exploit attempt; it does not prove the line was later processed or that a command ran. Preserve and correlate it:'
    printf '%s\n' "$PITBOSS_LINES"
    printf '%s\n' 'GEIGER: newest 40 matching lines in time order; the complete summary by payload follows below.'
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

# GEIGER: complete attempt summary, source IPs, execution traces and time order
# (points 1-3) instead of judging the attack from the newest 40 lines above.
progress 'Attack logs: injection summary and execution traces (GEIGER)'
geiger_analysis injection


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
NSEPA_PROBES=$(zgrep -E -i -n 'nsepa[.]deb' /var/log/httpaccess* 2>/dev/null | grep -E '"[[:space:]]*206[[:space:]]+1([[:space:]]|$)' | chrono_sort | tail -20)
VP_PROBE_HITS=$(zgrep -E -i -n 'vp_probe_nonexist' /var/log/httpaccess* /var/log/httperror* /var/log/httperror-vpn* 2>/dev/null | chrono_sort | tail -20)
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
subsection 'SAML reconnaissance: probe User-Agent, oversized requests, and reported source range'
printf '%s\n' 'These community-reported patterns are hunting leads, not Citrix-published IoCs. A match needs timestamp, source, request, and authentication/crash correlation.'
SAML_PROBE_HITS=$(zgrep -E -i -n '"probe/1"|"(GET|POST|HEAD) /(saml/login|cgi/samlauth)' /var/log/httpaccess* 2>/dev/null \
    | awk 'tolower($0) ~ /probe\/1/ || (tolower($0) ~ /"(get|post|head) \/(saml\/login|cgi\/samlauth)/ && length($0) > 2500)' \
    | chrono_sort | tail -30)
if [ -n "$SAML_PROBE_HITS" ]; then
    status CHECK 'SAML access logs contain the reported probe/1 User-Agent or a request longer than 2500 characters to /saml/login or /cgi/samlauth. This is a hunting lead, not proof of exploitation; correlate source, time, nsaaad events, and sign-in outcome:'
    printf '%s\n' "$SAML_PROBE_HITS" | cut -c1-320
elif [ "$RECON_LOGS_FOUND" -eq 0 ]; then
    status CHECK 'No readable HTTP access logs are available for the SAML reconnaissance check.'
else
    status OK 'No probe/1 User-Agent or selected oversized SAML request found in retained HTTP access logs; other formats and rotated-out logs are outside coverage.'
fi
GOTHAM_SAML_RANGE_HITS=$(zgrep -E -i -n '(^|[^0-9.])138[.]199[.]60[.]([0-9]{1,3})([^0-9]|$)' \
    /var/log/httpaccess* /var/log/httperror* /var/log/httperror-vpn* /var/log/ns.log* /var/log/messages* /var/log/notice.log* /var/log/nsvpn.log* 2>/dev/null \
    | chrono_sort | tail -30)
if [ -n "$GOTHAM_SAML_RANGE_HITS" ]; then
    status CHECK 'Log lines contain an address in the community-reported 138.199.60.0/24 range. This range may include shared VPN/hosting infrastructure; treat it as a correlation lead, not attribution or an automatic block recommendation:'
    printf '%s\n' "$GOTHAM_SAML_RANGE_HITS" | cut -c1-320
elif [ "$RECON_LOGS_FOUND" -eq 0 ]; then
    status CHECK 'No readable candidate HTTP logs are available for the reported SAML source-range check; system-log coverage may still have been searched above.'
else
    status OK 'No 138.199.60.0/24 address found in the selected retained logs. This is limited to searched files and retention.'
fi
subsection 'Authentication endpoint requests and payload combinations'
EXPLOIT_PATH_HITS=$(zgrep -E -i -n '(/nf/auth/doAuthentication[.]do|/cgi/login|/p/u/doLogon[.]do|/logon/LogonPoint/tmindex[.]html|/logon/LogonPoint/Authentication/GetUserName)' /var/log/httpaccess* /var/log/httperror* /var/log/httperror-vpn* 2>/dev/null | chrono_sort | tail -40)
if [ -n "$EXPLOIT_PATH_HITS" ]; then
    status CHECK 'Requests to endpoints observed in public honeypot/research reporting found. These are legitimate NetScaler paths; the requests alone are not IOCs. Review any logged username/body/User-Agent for shell metacharacters or payloads and correlate with auth/system logs:'
    printf '%s\n' "$EXPLOIT_PATH_HITS"
else
    status OK 'No requests to selected public exploit/authentication paths found in available HTTP logs; this is limited by log retention and format.'
fi
AUTH_POISON_HTTP_HITS=$(zgrep -E -i -n '(/nf/auth/doAuthentication[.]do|/cgi/login|/p/u/doLogon[.]do|/logon/LogonPoint/tmindex[.]html|/logon/LogonPoint/Authentication/GetUserName)[^[:cntrl:]]*(pitboss|NSPPE|PPE unexpectedly died|missed too many heartbeats|%3[bB]|%60|\$\{IFS\}|curl[[:space:]]|wget[[:space:]]|fetch[[:space:]])' /var/log/httpaccess* /var/log/httperror* /var/log/httperror-vpn* 2>/dev/null | chrono_sort | tail -30)
if [ -n "$AUTH_POISON_HTTP_HITS" ]; then
    status ACTION 'A logged exploit-path request also contains a public log-poisoning trigger or shell/download marker. Review the full request and correlate with ns.log/messages and file artifacts; this indicates an attempt, not automatically successful execution:'
    printf '%s\n' "$AUTH_POISON_HTTP_HITS"
fi
subsection 'VPN icon requests combined with encoded PHP markers'
ICO_STAGE_HITS=$(zgrep -E -i -n '/vpn/media/[^[:space:]]+[.]ico[^[:cntrl:]]*PD9[A-Za-z0-9+/=]{12,}|PD9[A-Za-z0-9+/=]{12,}[^[:cntrl:]]*/vpn/media/[^[:space:]]+[.]ico' /var/log/httpaccess* /var/log/httperror* /var/log/httperror-vpn* 2>/dev/null | chrono_sort | tail -30)
if [ -n "$ICO_STAGE_HITS" ]; then
    status ACTION 'HTTP log line combines a /vpn/media/*.ico request with a User-Agent-like base64 PHP prefix (PD9). Treat as a targeted exploitation lead and correlate with log injection and resulting files:'
    printf '%s\n' "$ICO_STAGE_HITS"
else
    status OK 'No selected /vpn/media/*.ico plus base64-PHP (PD9...) pattern found in available HTTP logs.'
fi
subsection 'Webshell/tunneler HTTP markers and staging-path requests'
UX_HEADER_LOG_HITS=$(zgrep -E -i -n 'HTTP_NSC_(LDAP|CLIENTTYPE)|HTTP_X_UX(_[0-9]+)?|/vpn/media/[^[:space:]]+[.]ico|/vpn/scripts/(linux|vista|mac)/[^[:space:]]+[.](sig|deb|php)' /var/log/httpaccess* /var/log/httperror* /var/log/httperror-vpn* 2>/dev/null | chrono_sort | tail -40)
if [ -n "$UX_HEADER_LOG_HITS" ]; then
    status CHECK 'HTTP logs contain reported webshell/tunneler header names or VPN staging-path requests. Logs may not record request headers; correlate timestamps and inspect response status, size, duration, and corresponding error-log entries:'
    printf '%s\n' "$UX_HEADER_LOG_HITS"
else
    status OK 'No selected WHIPSHOT/SLAPSHOT header names or reported VPN staging-path requests found in available HTTP logs; coverage depends on retained logs and log format.'
fi
PITSCALER_HTTP_HITS=$(zgrep -E -i -n 'ns-88771-poc|/vpn/media/[^[:space:]]+[.]ico|PD9[A-Za-z0-9+/=]{12,}|NSC_TASS|CsrfToken' /var/log/httpaccess* /var/log/httperror* /var/log/httperror-vpn* 2>/dev/null | chrono_sort | tail -40)
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


subsection 'Operator-reported payload delivery: pylrk.cc domains'
# Domain boundaries exclude lookalikes such as evilpylrk.cc / pylrk.cc.example.
# Count only, no attacker URLs/tokens or logged credential fields are printed.
PYLRK_LOG_COVERAGE=0
for f in /var/log/httpaccess* /var/log/httperror* /var/log/ns.log* /var/log/messages* /var/log/notice.log* /var/log/nsvpn.log* /var/log/sh.log* /var/log/bash.log* /var/log/named* /var/log/dns*; do
    [ -f "$f" ] && [ -r "$f" ] && PYLRK_LOG_COVERAGE=1
done
PYLRK_DOMAIN_PATTERN='(^|[^[:alnum:]_.-])([[:alnum:]-]+[.])*pylrk[.]cc([^[:alnum:]_.-]|$)'
PYLRK_LOG_COUNT=$(zgrep -hiE -c "$PYLRK_DOMAIN_PATTERN" /var/log/httpaccess* /var/log/httperror* /var/log/ns.log* /var/log/messages* /var/log/notice.log* /var/log/nsvpn.log* /var/log/sh.log* /var/log/bash.log* /var/log/named* /var/log/dns* 2>/dev/null | awk '{n+=$0} END{print n+0}')
if [ "$PYLRK_LOG_COUNT" -gt 0 ]; then
    status CHECK "Operator-reported payload-delivery domain pylrk[.]cc or a subdomain occurs in $PYLRK_LOG_COUNT retained log line(s). The report is independently unverified; a logged download command is not proof of execution or transfer, and the destination is not the incoming attacker source. Preserve originals and correlate timestamps with nsaaad events, /v artifacts, DNS and outbound firewall telemetry. URL/token values are withheld."
elif [ "$PYLRK_LOG_COVERAGE" -eq 0 ]; then
    status CHECK 'No readable candidate logs; pylrk.cc delivery-domain coverage unavailable.'
else
    status OK 'No pylrk.cc or subdomain reference found in retained candidate logs. Encoded destinations, removed records and external-only DNS/egress history are outside coverage.'
fi
printf '%s\n' 'Follow-up: validate the dated domain report with your security team; assess an egress block for the base domain/subdomains using approved DNS/proxy/firewall controls. Do not infer HTTPS merely from port 443. This script performs no DNS lookup, download or automatic blocking.'

subsection 'Public callback destinations and DNS references'
PUBLIC_CALLBACK_HITS=$(zgrep -E -i -n 'instances[.]httpworkbench[.]com|httpworkbench[.]com|entretiensol[.]com|gsocket[.]io|31[.]56[.]197[.]72|64[.]94[.]85[.]67|139[.]180[.]152[.]138|77[.]83[.]199[.]39|104[.]248[.]244[.]66|23[.]27[.]143[.]20|62[.]133[.]62[.]80|45[.]141[.]21[.]130|199[.]233[.]217[.]13|130[.]94[.]20[.]222' /var/log/httpaccess* /var/log/httperror* /var/log/httperror-vpn* /var/log/ns.log* /var/log/messages* /var/log/notice.log* /var/log/nsvpn.log* 2>/dev/null | chrono_sort | tail -40)
if [ -n "$PUBLIC_CALLBACK_HITS" ]; then
    status CHECK 'References to selected public NetScaler campaign payload/callback indicators found in retained logs. IPs/domains are time-sensitive, may be reused or victim-specific, and must not be treated as a blocklist or attribution by themselves:'
    printf '%s\n' "$PUBLIC_CALLBACK_HITS"
else
    status OK 'No references to the selected public payload/callback indicators found in the searched retained logs. The source IoC lists are not exhaustive.'
fi
printf '%s\n' 'Network follow-up from TENEX: review VLAN/firewall/IDS telemetry for the cleartext mDNS service name platypus-mesh.tcp over UDP/5353 and investigate unknown participants. This appliance-local script cannot recover historical multicast traffic or inspect other hosts on the VLAN.'
DNS_CALLBACK_HITS=$(zgrep -E -i -n 'httpworkbench[.]com' /var/log/messages* /var/log/ns.log* /var/log/named* /var/log/dns* 2>/dev/null | chrono_sort | tail -30)
if [ -n "$DNS_CALLBACK_HITS" ]; then
    status CHECK 'A public-research DNS test/callback domain appears in local logs. Confirm whether the query originated from the ADC and correlate with endpoint, HTTP, and egress telemetry; domain presence alone does not prove compromise:'
    printf '%s\n' "$DNS_CALLBACK_HITS"
else
    status CHECK 'No httpworkbench.com query was found in candidate local logs. ADC-originated DNS activity may only be visible in external resolver, firewall, or SIEM telemetry.'
fi

printf '\n--- Script extension references in HTTP error logs ---\n'
ERROR_LOGS_FOUND=0
for f in /var/log/httperror.log*; do [ -f "$f" ] && ERROR_LOGS_FOUND=1; done
PHP_ERROR_HITS=$(zgrep -E -i -n '\.php' /var/log/httperror.log* 2>/dev/null | chrono_sort | tail -50)
SCRIPT_ERROR_HITS=$(zgrep -E -i -n '\.(sh|pl|sig|deb|rpm|tgz)' /var/log/httperror.log* /var/log/httperror-vpn.log* 2>/dev/null | chrono_sort | tail -50)
if [ -n "$PHP_ERROR_HITS" ]; then status CHECK 'PHP references found in HTTP error logs; review the request context and correlate timestamps:'; echo "$PHP_ERROR_HITS"; elif [ "$ERROR_LOGS_FOUND" -eq 0 ]; then status CHECK 'No candidate HTTP error log files found; coverage is unknown.'; else status OK 'No PHP references found in candidate HTTP error logs.'; fi
if [ -n "$SCRIPT_ERROR_HITS" ]; then status CHECK 'References to .sh/.pl/.sig/.deb/.rpm/.tgz paths found in HTTP error logs; review the full request and correlate timestamps:'; echo "$SCRIPT_ERROR_HITS"; elif [ "$ERROR_LOGS_FOUND" -eq 1 ]; then status OK 'No .sh/.pl/.sig/.deb/.rpm/.tgz references found in candidate HTTP error logs.'; fi

printf '\n--- Unusual HTTP methods, responses, and resource references ---\n'
HTTP_REQUEST_LOGS_FOUND=0
for f in /var/log/httpaccess* /var/log/httperror* /var/log/httperror-vpn*; do [ -f "$f" ] && [ -r "$f" ] && HTTP_REQUEST_LOGS_FOUND=1; done
HTTP_METHOD_RESOURCE_HITS=$(zgrep -E -i -n 'POST|[[:space:]]404[[:space:]]|[[:space:]]500[[:space:]]' /var/log/httpaccess* /var/log/httperror* /var/log/httperror-vpn* 2>/dev/null | grep -E -i '/(nf/auth/doAuthentication[.]do|cgi/login|p/u/doLogon[.]do|logon/LogonPoint/Authentication/GetUserName)|[.](php|pl|sh|sig|deb|rpm|tgz)([?[:space:]/]|$)|/vpn/media/[^[:space:]]+[.]ico' | chrono_sort | tail -60)
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
        *.gz) matches=$(zgrep -E -i -n 'database\.php|/flash/nsconfig/keys|LDAPTLS_REQCERT|ldapsearch|(^|[[:space:]])openssl([[:space:]]|$)|/nsconfig/ns\.conf|/etc/auth\.conf|cp /usr/bin/bash|F1\.key|F2\.key|nobody|(^|[^[:alnum:]_])id([^[:alnum:]_]|$)|curl[[:space:]]|wget[[:space:]]|fetch[[:space:]]|/ns_gui/vpn|/var/netscaler/logon|/var/vpn|/var/tmp' "$f" 2>/dev/null | tail -50) ;;
        *) matches=$(grep -E -i -n 'database\.php|/flash/nsconfig/keys|LDAPTLS_REQCERT|ldapsearch|(^|[[:space:]])openssl([[:space:]]|$)|/nsconfig/ns\.conf|/etc/auth\.conf|cp /usr/bin/bash|F1\.key|F2\.key|nobody|(^|[^[:alnum:]_])id([^[:alnum:]_]|$)|curl[[:space:]]|wget[[:space:]]|fetch[[:space:]]|/ns_gui/vpn|/var/netscaler/logon|/var/vpn|/var/tmp' "$f" 2>/dev/null | tail -50) ;;
    esac
    if [ -n "$matches" ]; then SHELL_AUDIT_HITS="$SHELL_AUDIT_HITS\n--- $f ---\n$matches"; fi
done
if [ -n "$SHELL_AUDIT_HITS" ]; then status CHECK 'Command-pattern matches found in available shell audit logs; these are heuristic and need contextual review:'; printf '%b\n' "$SHELL_AUDIT_HITS" | head -120; elif [ "$SHELL_AUDIT_LOGS_FOUND" -eq 1 ]; then status OK 'No configured command patterns found in readable shell audit logs.'; else status CHECK 'No readable sh.log/bash.log files found; shell command-history coverage is unknown.'; fi

printf '\n--- Gateway/VPN access-log session indicators ---\n'
VPN_ACCESS_FILES_FOUND=0
for f in /var/log/httpaccess-vpn.log*; do [ -f "$f" ] && [ -r "$f" ] && VPN_ACCESS_FILES_FOUND=1; done
VPN_200_NO_RECEIVER=$(zgrep -E -v 'CitrixReceiver' /var/log/httpaccess-vpn.log* 2>/dev/null | grep ' 200 ' | chrono_sort | tail -50)
VPN_HEADLESS=$(zgrep -E -i -n 'HeadlessChrome' /var/log/httpaccess-vpn.log* 2>/dev/null | chrono_sort | tail -50)
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
printf '%s\n' 'Port 443 may carry plain HTTP in this reported activity. An IP block does not replace patching or incident investigation; delivery infrastructure can change. The SAML responder workaround is an interim mitigation for affected builds and is not required once the applicable CVE-2026-88779 fixed build is installed. No firewall/ADC configuration is modified by this script.'

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

section '8. Next actions'
ACTION_COUNT=$(awk '/^===== 1[.] Platform and uptime =====/{scan=1; next} scan && /^\[ACTION\]/{n++} END{print n+0}' "$OUT")
CHECK_COUNT=$(awk '/^===== 1[.] Platform and uptime =====/{scan=1; next} scan && /^\[CHECK\]/{n++} END{print n+0}' "$OUT")
OK_COUNT=$(awk '/^===== 1[.] Platform and uptime =====/{scan=1; next} scan && /^\[OK\]/{n++} END{print n+0}' "$OUT")
if [ "$ACTION_COUNT" -gt 0 ]; then
    printf '%s\n' '1. Preserve matching files, raw logs, and available core dumps. Record appliance time/timezone and do not clean up or restart before evidence is secured.'
    printf '%s\n' '2. Correlate each hit across HTTP access/error logs, ns.log/messages/notice/nsvpn, file metadata, firewall egress records, and approved change records. Escalate to incident response.'
else
    printf '%s\n' '1. No selected high-priority pattern was reported. This does not exclude activity outside scanned paths, formats, or retention.'
fi
if [ "$CHECK_COUNT" -gt 0 ]; then
    printf '%s\n' '3. Resolve CHECK items against same-build baselines, change records, and (for HA) the peer node. Record the evidence and disposition.'
fi
printf '%s\n' '4. Confirm log coverage reaches the relevant pre-patch period; document gaps. Missing or rotated logs are not a clean result.'
printf '%s\n' '5. Run Citrix/NetScaler File Integrity Monitoring or the Console advisory scan separately and retain its results.'

# Put a concise, scan-derived summary before the detailed sections while
# preserving every detailed check and raw evidence line in its original order.
SUMMARY_TMP=$(mktemp "${OUT}.summary.XXXXXX" 2>/dev/null)
REPORT_TMP=$(mktemp "${OUT}.final.XXXXXX" 2>/dev/null)
if [ -n "$SUMMARY_TMP" ] && [ -n "$REPORT_TMP" ]; then
    {
        printf '===== Executive summary =====\n'
        printf 'Finding-message counts: ACTION=%s, CHECK=%s, OK=%s. Counts are not a risk score.\n' "$ACTION_COUNT" "$CHECK_COUNT" "$OK_COUNT"
        if [ "$ACTION_COUNT" -gt 0 ]; then
            printf '%s\n' 'Assessment: selected high-priority indicators were found. They require investigation; they do not by themselves prove successful command execution or compromise.'
        elif [ "$CHECK_COUNT" -gt 0 ]; then
            printf '%s\n' 'Assessment: no selected ACTION indicator was reported, but CHECK items and scan-coverage limits remain to be resolved.'
        else
            printf '%s\n' 'Assessment: no selected ACTION or CHECK result was reported in the scanned scope. This is not proof that the appliance is clean.'
        fi
        if [ "$FW_PATCHED" = YES ]; then
            printf 'Firmware: %s meets the applicable fixed-build threshold assessed by this script. This does not rule out earlier compromise.\n' "${CURRENT_INPUT:-detected build}"
        elif [ "$FW_PATCHED" = NO ]; then
            printf 'Firmware: %s is below the applicable fixed-build threshold; update is a priority.\n' "${CURRENT_INPUT:-detected build}"
        else
            printf 'Firmware: fixed-build status is UNKNOWN; verify the running build before drawing a conclusion.\n'
        fi
        printf 'Enhanced ISN: %s (source: %s).\n' "${ISN_STATE:-UNKNOWN}" "${ISN_SOURCE:-unknown}"
        if [ "${GEIGER_SAML_FIXED-UNKNOWN}" = YES ]; then
            printf '%s\n' 'SAML workaround: this build meets the CVE-2026-88779 fixed threshold; responder-policy coverage is informational and not required for that CVE.'
        elif [ "${GEIGER_SAML_FIXED-UNKNOWN}" = NO ]; then
            printf '%s\n' 'SAML workaround: review the policy and binding results below; interim mitigation may be required on an affected build.'
        fi
        if [ "$ACTION_COUNT" -gt 0 ]; then
            printf '\nPriority finding areas (details remain in the sections below):\n'
            awk '
                function clean(s) {sub(/^===== /,"",s); sub(/ =====$/, "", s); sub(/^--- /,"",s); sub(/ ---$/, "", s); return s}
                /^===== / {major=$0; minor=""; next}
                /^--- / {minor=$0; next}
                /^\[ACTION\]/ {
                    title=clean(major)
                    if(minor!="") title=title " / " clean(minor)
                    if(title=="") title="General checks"
                    if(!seen[title]++) print "  - " title
                }
            ' "$OUT"
        fi
        printf '\n%s\n' 'Read the coverage and time-range notes before treating a no-hit result as meaningful.'
        printf '\n'
    } > "$SUMMARY_TMP"
    awk -v summary="$SUMMARY_TMP" '
        /^===== How to read this report =====$/ {
            while ((getline line < summary) > 0) print line
            close(summary)
            print ""
        }
        {print}
    ' "$OUT" > "$REPORT_TMP" && mv "$REPORT_TMP" "$OUT"
    rm -f "$SUMMARY_TMP" "$REPORT_TMP"
else
    [ -n "$SUMMARY_TMP" ] && rm -f "$SUMMARY_TMP"
    [ -n "$REPORT_TMP" ] && rm -f "$REPORT_TMP"
    printf '%s\n' 'Executive summary could not be inserted; detailed report remains available.'
fi

printf '\nCompleted. Plain-text report saved at: %s\n' "$OUT"
exec 1>&3 2>&4 3>&- 4>&-
if [ -t 1 ]; then
    safe_display "$OUT" | awk '{gsub(/\[OK\]/, "\033[32m[OK]\033[0m"); gsub(/\[ACTION\]/, "\033[31m[ACTION]\033[0m"); gsub(/\[CHECK\]/, "\033[93m[CHECK]\033[0m"); print}'
else
    safe_display "$OUT"
fi
