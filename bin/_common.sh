#!/usr/bin/env bash
# Shared helpers. Sourced by the other scripts; not meant to run on its own.

C_RED=$'\033[31m'; C_GRN=$'\033[32m'; C_YEL=$'\033[33m'; C_BLD=$'\033[1m'; C_OFF=$'\033[0m'
[ -t 1 ] || { C_RED=""; C_GRN=""; C_YEL=""; C_BLD=""; C_OFF=""; }

say(){ printf '%s\n' "$*"; }
hdr(){ printf '\n%s== %s%s\n' "$C_BLD" "$*" "$C_OFF"; }
ok(){  printf '  %s[ok]%s   %s\n'   "$C_GRN" "$C_OFF" "$*"; }
warn(){ printf '  %s[warn]%s %s\n'  "$C_YEL" "$C_OFF" "$*"; }
bad(){ printf '  %s[HIT]%s  %s\n'   "$C_RED" "$C_OFF" "$*"; }

# A Magento root is any directory holding app/etc/env.php plus bin/magento.
# Searched: explicit args, then $PWD, then common hosting layouts.
find_magento_roots() {
    if [ "$#" -gt 0 ]; then
        for d in "$@"; do
            [ -f "$d/app/etc/env.php" ] && printf '%s\n' "${d%/}"
        done
        return
    fi
    [ -f "./app/etc/env.php" ] && { printf '%s\n' "$(pwd)"; return; }
    {
        ls -d /var/www/*/                       2>/dev/null
        ls -d /var/www/*/*/                     2>/dev/null
        ls -d /var/www/html/                    2>/dev/null
        ls -d /home/*/public_html/              2>/dev/null
        ls -d /home/*/domains/*/public_html/    2>/dev/null
        ls -d /home/*/www/                      2>/dev/null
        ls -d /srv/*/                           2>/dev/null
        ls -d /usr/share/nginx/*/               2>/dev/null
    } 2>/dev/null | while read -r d; do
        [ -f "${d}app/etc/env.php" ] && printf '%s\n' "${d%/}"
    done | sort -u
}

magento_version() {
    local root="$1"
    if [ -f "$root/composer.json" ]; then
        # Must match the require entry (key followed by ':'), not the project's
        # own "name" field, which carries no version.
        grep -oE '"magento/product-(community|enterprise)-edition"[[:space:]]*:[[:space:]]*"[^"]+"' \
            "$root/composer.json" 2>/dev/null \
            | grep -oE '[0-9]+\.[0-9]+\.[0-9]+(-p[0-9]+)?' | head -1
    fi
}
