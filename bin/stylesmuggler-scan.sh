#!/usr/bin/env bash
# StyleSmuggler compromise scanner.
#
# Read-only. Detects the implant, its persistence, and traces of exploitation.
# Run as root to cover every account on a shared host, or as the site user for
# a single store.
#
# Usage: stylesmuggler-scan.sh [MAGENTO_ROOT ...]
# Exit:  0 clean, 1 indicators found, 2 usage error.

set -uo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=_common.sh
. "$DIR/_common.sh"

FOUND=0
KNOWN_HASHES="
e315687a1dfe61ef4a5a5642214db6d3b2b05d81391285eebc2af664641a26a7
8334b434fa3fe9f59cebe9609b11e0b1fd19d10212c45c705adec1902a1d06ef
"
C2_HOSTS="247.cdnflare.xyz 99.84.67.186"
# Directories worth walking for a dropped binary. Kept short on purpose:
# a full-filesystem walk on a busy store is slow and rarely tells you more.
SEARCH_DIRS="/home /root /tmp /var/tmp /dev/shm /var/www /srv"

mapfile -t ROOTS < <(find_magento_roots "$@")

say "StyleSmuggler scanner — $(hostname -f 2>/dev/null || hostname) — $(date -Iseconds)"
if [ "${#ROOTS[@]}" -eq 0 ]; then
    warn "no Magento roots found; host-level checks only"
else
    say "Magento roots: ${#ROOTS[@]}"
    for r in "${ROOTS[@]}"; do say "  $r  ($(magento_version "$r" || echo 'version unknown'))"; done
fi

hdr "1. Implant binary and lock files"
hits=$(find $SEARCH_DIRS -xdev \
        \( -name 'gvfsd-user' -o -name '.gvfsd_*.lock' -o -name '.kw_*' -o -name 'kworker-linux-*' \) \
        2>/dev/null)
[ -n "$hits" ] && { bad "implant artefacts:"; sed 's/^/          /' <<<"$hits"; FOUND=1; } \
               || ok "none"

hdr "2. Cron persistence"
crons=""
if [ "$(id -u)" -eq 0 ]; then
    for u in $(cut -d: -f1 /etc/passwd 2>/dev/null); do
        line=$(crontab -l -u "$u" 2>/dev/null | grep -i 'gvfsd\|\.kw_')
        [ -n "$line" ] && crons+="$u: $line"$'\n'
    done
else
    crons=$(crontab -l 2>/dev/null | grep -i 'gvfsd\|\.kw_')
fi
[ -n "$crons" ] && { bad "persistence entries:"; sed 's/^/          /' <<<"$crons"; FOUND=1; } \
                || ok "none"

hdr "3. Processes disguised as kernel threads"
# Genuine kernel threads are always root-owned and have no resident memory.
# A bracketed comm on a site uid with real RSS is the implant.
procs=$(ps -eo pid,user,rss,args --no-headers 2>/dev/null | awk '$4 ~ /^\[/ && $2 != "root"')
[ -n "$procs" ] && { bad "non-root process with a kernel-thread name:"; sed 's/^/          /' <<<"$procs"; FOUND=1; } \
                || ok "none"

hdr "4. Known malware hashes"
match=""
while IFS= read -r f; do
    [ -n "$f" ] || continue
    h=$(sha256sum "$f" 2>/dev/null | cut -d' ' -f1)
    grep -qxF "$h" <<<"$KNOWN_HASHES" && match+="$f  $h"$'\n'
done < <(find $SEARCH_DIRS -xdev -type f -size +500k -size -6M -perm -u+x 2>/dev/null)
[ -n "$match" ] && { bad "known sample:"; sed 's/^/          /' <<<"$match"; FOUND=1; } \
                || ok "no hash matches"

hdr "5. PHP smuggled into reports and logs (stage 1)"
poison=""
for r in "${ROOTS[@]:-}"; do
    [ -n "$r" ] || continue
    p=$(grep -rl 'X_TRACE_\|<?php' "$r/var/report/" "$r/var/log/" 2>/dev/null | head -20)
    [ -n "$p" ] && poison+="$p"$'\n'
done
[ -n "$poison" ] && { bad "executable PHP inside report/log files:"; sed 's/^/          /' <<<"$poison"; FOUND=1; } \
                 || ok "none"

hdr "6. Exploit attempts in access logs (stage 2)"
logs=$(ls /var/log/nginx/access.log /var/log/apache2/access.log \
          /home/*/domains/*/logs/access.log /home/*/logs/access.log \
          /var/www/*/logs/access.log 2>/dev/null)
seen=""
for lf in $logs; do
    [ -f "$lf" ] || continue
    n=$(grep -acE 'styles(\[|%5B)|generatorClass|with_resolved|X_TRACE_|cdnflare' "$lf" 2>/dev/null)
    [ "${n:-0}" -gt 0 ] && seen+="$lf: $n requests"$'\n'
done
if [ -n "$seen" ]; then
    bad "exploit signature present:"; sed 's/^/          /' <<<"$seen"; FOUND=1
    say "        source IPs:"
    for lf in $logs; do
        [ -f "$lf" ] || continue
        grep -aE 'styles(\[|%5B)|generatorClass|with_resolved' "$lf" 2>/dev/null \
            | grep -aoE '^[0-9a-fA-F.:]+' | sort | uniq -c | sort -rn | head -5 | sed 's/^/          /'
    done
else
    ok "no signature in readable access logs"
fi

hdr "7. Live connections to known C2"
c2=""
for h in $C2_HOSTS; do
    for ip in $(getent hosts "$h" 2>/dev/null | awk '{print $1}'); do
        ss -tan 2>/dev/null | grep -q "$ip" && c2+="$h ($ip)"$'\n'
    done
done
[ -n "$c2" ] && { bad "active C2 connection:"; sed 's/^/          /' <<<"$c2"; FOUND=1; } \
             || ok "none"

hdr "8. Mitigation state"
for r in "${ROOTS[@]:-}"; do
    [ -n "$r" ] || continue
    n=$(grep -l 'StyleSmuggler mitigation' \
          "$r/setup/src/Magento/Setup/Module/Di/Code/Scanner/ArrayScanner.php" 2>/dev/null | wc -l)
    [ "$n" -gt 0 ] && ok "DI guard present: $r" || warn "DI guard MISSING: $r"
done
grep -rqs 'StyleSmuggler' /etc/nginx /etc/apache2 /etc/httpd 2>/dev/null \
    && ok "web-server rules deployed" || warn "web-server rules NOT found"

say ""
if [ "$FOUND" -eq 1 ]; then
    printf '%sRESULT: INDICATORS FOUND.%s Preserve evidence, do not reboot.\n' "$C_RED$C_BLD" "$C_OFF"
    say "Capture before cleaning: process list, /proc/<pid>/exe, crontabs, the binary, access logs."
    exit 1
fi
printf '%sRESULT: clean%s — no StyleSmuggler indicators.\n' "$C_GRN$C_BLD" "$C_OFF"
exit 0
