#!/usr/bin/env bash
# StyleSmuggler mitigation installer.
#
# Applies two independent layers. Either one alone breaks the attack chain:
#   A. Web-server rules that block the exploit request before it reaches PHP.
#   B. A CLI-only guard on the Magento DI scanners the chain terminates in.
#
# Usage:
#   sudo ./install.sh                      # autodetect everything
#   sudo ./install.sh /path/to/magento     # target specific store(s)
#   sudo ./install.sh --dry-run            # show what would change
#   sudo ./install.sh --revert             # undo layer B, restore config backups
#
# Re-runnable. Run it again after every deploy: `composer install` reverts
# layer B, because setup/ ships from magento/magento2-base.

set -uo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$DIR/bin/_common.sh"

DRY=0; REVERT=0; ROOTS_ARG=()
for a in "$@"; do
    case "$a" in
        --dry-run) DRY=1 ;;
        --revert)  REVERT=1 ;;
        -h|--help) sed -n '2,20p' "$0"; exit 0 ;;
        -*) say "unknown option: $a"; exit 2 ;;
        *) ROOTS_ARG+=("$a") ;;
    esac
done

run(){ if [ "$DRY" -eq 1 ]; then say "  would run: $*"; else "$@"; fi; }

[ "$(id -u)" -eq 0 ] || warn "not running as root; web-server changes will likely fail"

say "StyleSmuggler mitigation installer"
say "https://sansec.io/research/stylesmuggler"
[ "$DRY" -eq 1 ] && say "(dry run — nothing will be changed)"

mapfile -t ROOTS < <(find_magento_roots "${ROOTS_ARG[@]+"${ROOTS_ARG[@]}"}")

# ---------------------------------------------------------------
hdr "Magento stores"
if [ "${#ROOTS[@]}" -eq 0 ]; then
    warn "none found — pass paths explicitly if your layout is unusual"
else
    for r in "${ROOTS[@]}"; do say "  $r  ($(magento_version "$r" || echo 'version unknown'))"; done
fi

# ---------------------------------------------------------------
hdr "Layer A — web-server rules"
NGINX_SNIP=/etc/nginx/snippets/stylesmuggler.conf

if [ -d /etc/nginx ]; then
    if [ "$REVERT" -eq 1 ]; then
        run rm -f "$NGINX_SNIP"
        warn "removed $NGINX_SNIP — also delete the include line from your vhosts"
    else
        run mkdir -p /etc/nginx/snippets
        run cp "$DIR/nginx/stylesmuggler.conf" "$NGINX_SNIP"
        ok "installed $NGINX_SNIP"
        if grep -rqs 'snippets/stylesmuggler.conf' /etc/nginx/sites-enabled /etc/nginx/conf.d 2>/dev/null; then
            ok "include line already present in a vhost"
        else
            warn "NOT included yet. Add this inside each Magento server { } block:"
            say  "        include $NGINX_SNIP;"
        fi
    fi
    if [ "$DRY" -eq 0 ] && command -v nginx >/dev/null 2>&1; then
        if nginx -t >/dev/null 2>&1; then
            ok "nginx config valid"
            run systemctl reload nginx 2>/dev/null || run service nginx reload 2>/dev/null || true
        else
            bad "nginx -t FAILED — not reloading. Output:"
            nginx -t 2>&1 | sed 's/^/          /'
        fi
    fi
else
    say "  no /etc/nginx, skipping"
fi

for AP in /etc/apache2/conf-available /etc/httpd/conf.d; do
    [ -d "$AP" ] || continue
    if [ "$REVERT" -eq 1 ]; then
        run rm -f "$AP/stylesmuggler.conf"
        warn "removed $AP/stylesmuggler.conf"
    else
        run cp "$DIR/apache/stylesmuggler.conf" "$AP/stylesmuggler.conf"
        ok "installed $AP/stylesmuggler.conf"
        [ -d /etc/apache2/conf-available ] && [ "$DRY" -eq 0 ] && a2enconf stylesmuggler >/dev/null 2>&1 && ok "a2enconf stylesmuggler"
    fi
    if [ "$DRY" -eq 0 ] && command -v apachectl >/dev/null 2>&1; then
        if apachectl configtest >/dev/null 2>&1; then
            ok "apache config valid"
            run systemctl reload apache2 2>/dev/null || run systemctl reload httpd 2>/dev/null || true
        else
            bad "apachectl configtest FAILED — not reloading"
        fi
    fi
done

# ---------------------------------------------------------------
hdr "Layer B — CLI-only guard on the DI scanners"
if [ "${#ROOTS[@]}" -eq 0 ]; then
    say "  no stores to harden"
else
    FLAG=""
    [ "$REVERT" -eq 1 ] && FLAG="--revert"
    [ "$DRY" -eq 1 ] && FLAG="--check"
    "$DIR/bin/stylesmuggler-harden.py" $FLAG "${ROOTS[@]}" | sed 's/^/  /'

    if [ "$DRY" -eq 0 ] && [ "$REVERT" -eq 0 ] && command -v php >/dev/null 2>&1; then
        lint_ok=1
        for r in "${ROOTS[@]}"; do
            for f in setup/src/Magento/Setup/Module/Di/Code/Scanner/ArrayScanner.php \
                     setup/src/Magento/Setup/Module/Di/Code/Reader/ClassesScanner.php \
                     setup/src/Magento/Setup/Module/Di/Code/Scanner/XmlInterceptorScanner.php; do
                [ -f "$r/$f" ] || continue
                php -l "$r/$f" >/dev/null 2>&1 || { bad "syntax error: $r/$f"; lint_ok=0; }
            done
        done
        [ "$lint_ok" -eq 1 ] && ok "all guarded files parse cleanly"
    fi
fi

# ---------------------------------------------------------------
hdr "Next"
if [ "$REVERT" -eq 1 ]; then
    say "  Mitigation removed. Your stores are exposed again."
else
    say "  1. Scan for an existing compromise:  ./bin/stylesmuggler-scan.sh"
    say "  2. Verify a store blocks the request (expect an empty/closed response):"
    say "       curl -sk -o /dev/null -w '%{http_code}\\n' 'https://YOURSTORE/graphql?styles%5Bfirst%5D=x'"
    say "  3. Re-run this installer after every deploy — composer install reverts layer B."
fi
