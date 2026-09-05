# StyleSmuggler mitigation

Emergency mitigation for **StyleSmuggler**, the unauthenticated remote code execution
vulnerability in Magento Open Source and Adobe Commerce that Sansec disclosed on
5 September 2026.

> **There is no vendor patch.** Adobe's next scheduled bulletin is 8 September 2026, and
> whether it covers this bug is unknown. Sansec reproduced the chain on clean 2.4.7, 2.4.8
> and 2.4.9. Their first confirmed victim ran 2.4.6-p15 with the July and August 2026
> patches applied and `security:patch-status` clean.
>
> Your patch level tells you nothing about your exposure.

Advisory: <https://sansec.io/research/stylesmuggler>

## Quick start

```bash
git clone https://github.com/YOURORG/stylesmuggler-mitigation.git
cd stylesmuggler-mitigation

sudo ./bin/stylesmuggler-scan.sh      # are you already compromised?
sudo ./install.sh --dry-run           # see what would change
sudo ./install.sh                     # apply
```

Scan first. If the scanner reports indicators, you have an active compromise and
installing the mitigation does not clean it up. Preserve evidence before you touch
anything, and do not reboot.

## What it does

Two independent layers. Either one alone breaks the chain.

### Layer A: block the request at the web server

Drops the requests that carry the exploit before they ever reach PHP. Ships for
both nginx and Apache.

Every pattern is matched raw **and** URL-encoded. Real payloads arrive percent-encoded
as `styles%5Bfirst%5D`, so a rule that only matches the literal bracket blocks nothing.
This is the single most common way to get these rules wrong.

### Layer B: make Magento's DI scanners CLI-only

The attack ends inside Magento's dependency-injection compiler, in classes that perform
a variable-path `include`. Those classes exist solely to serve
`bin/magento setup:di:compile` and are never legitimately reached over HTTP, so a
`PHP_SAPI !== 'cli'` guard removes the primitive at no functional cost:

- `setup/src/Magento/Setup/Module/Di/Code/Scanner/ArrayScanner.php`
- `setup/src/Magento/Setup/Module/Di/Code/Reader/ClassesScanner.php`
- `setup/src/Magento/Setup/Module/Di/Code/Scanner/XmlInterceptorScanner.php`

**`composer install` reverts layer B.** `setup/` ships from `magento/magento2-base` and is
gitignored in most projects. The script is idempotent, so add it to your deploy:

```bash
./bin/stylesmuggler-harden.py /path/to/magento
./bin/stylesmuggler-harden.py --check /path/to/magento    # verify, change nothing
./bin/stylesmuggler-harden.py --revert /path/to/magento   # undo
```

## Are you compromised?

The sharpest signal is a process name. Genuine kernel threads are always owned by root
and have no resident memory. A bracketed name on a site user with real RSS is the implant:

```bash
ps -eo pid,user,rss,args --no-headers | awk '$4 ~ /^\[/ && $2 != "root"'
crontab -l | grep -i gvfsd
ls -la ~/.local/share/.gvfsd/ /tmp/.kw_* 2>/dev/null
```

### Indicators of compromise

```
247.cdnflare.xyz                 malware download host
99.84.67.186:443                 C2, WebSocket over TLS
88.216.72.181                    attacker source, seen at multiple victims

sha256  e315687a1dfe61ef4a5a5642214db6d3b2b05d81391285eebc2af664641a26a7
sha256  8334b434fa3fe9f59cebe9609b11e0b1fd19d10212c45c705adec1902a1d06ef

~/.local/share/.gvfsd/gvfsd-user
~/.local/share/.gvfsd/.gvfsd_<8hex>.lock
/tmp/.kw_<random><random>
crontab:  */5 * * * * exec <home>/.local/share/.gvfsd/gvfsd-user
process:  [kworker/u:8:0] owned by a non-root uid
```

The implant is a stripped static Rust binary of roughly 1.9 MB, built for both x86-64 and
arm64. In one observed infection it opened no outbound connection at all, reading its work
from the store's own Redis instead, so an absence of suspicious network traffic proves
nothing.

Two details that cost defenders time in the wild:

- Some variants poison `var/report/`, others poison `var/log/system.log`. Checking only one
  location misses the other.
- Malware scanners pointed at the document root miss this entirely. The implant installs
  into `~/.local/share/`, one level above.

## What this does not do

- It does not fix the vulnerability. Only Adobe can do that. Replace this with the official
  patch when one ships.
- It does not clean up an existing compromise. Use the scanner to find one, then do proper
  incident response: preserve evidence, rotate every credential the site user could read,
  and rebuild if you cannot account for what the implant did.
- It does not detect variants that differ from the two published samples.

If you would rather not run third-party rules, Sansec's own advice is to disable GraphQL
until Adobe ships a fix. Both web-server configs carry that as a commented block.

## Compatibility

| | |
|---|---|
| Magento | Open Source and Adobe Commerce 2.4.x, verified against 2.4.7-p2 |
| Web server | nginx, Apache 2.4 with mod_rewrite |
| OS | Linux. Scanner needs bash 4+, `ps`, `find`, `sha256sum` |
| Hardening script | Python 3.6+, no dependencies |

The installer autodetects stores under `/var/www`, `/home/*/public_html`,
`/home/*/domains/*/public_html`, `/srv` and the current directory. Pass paths explicitly
if your layout differs.

## Files

```
install.sh                     apply or revert everything
bin/stylesmuggler-scan.sh      read-only compromise scanner
bin/stylesmuggler-harden.py    layer B, with --check and --revert
nginx/stylesmuggler.conf       layer A for nginx
apache/stylesmuggler.conf      layer A for Apache
ansible/stylesmuggler.yml      fleet deployment
```

## A note on scope

This repository documents the vulnerable sink, because a fix has to name what it fixes.
It does not publish the assembled request that reaches it. Sansec withheld the full gadget
chain when they disclosed, and with no vendor patch available that restraint still holds.
Defenders lose nothing by it: every rule here works without knowing how to build the exploit.

Security contact: see `SECURITY.md`.

## Credits

Vulnerability discovery, naming and the original advisory belong to the
[Sansec](https://sansec.io) forensics team. This repository is an independent mitigation
built during a live incident response on 5 September 2026, and is not affiliated with
Sansec or Adobe.

If you run Magento at scale, buy Sansec's tools. They found this one.

## License

MIT. See `LICENSE`.
