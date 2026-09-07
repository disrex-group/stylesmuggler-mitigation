# StyleSmuggler mitigation snippets

> ### ⚠️ UPDATE — a deployable patch is now available
>
> The DI scanner guard this guide applies by hand in section 3 now ships as a
> `composer-patches` source patch in **[`patches/`](patches/)**. It reapplies on every
> `composer install`, so a deploy never reverts it, and it applies across 2.4.6 through
> 2.4.9. **If you deploy Magento with Composer, use it instead of the hand-edits.**
> See [patches/README.md](patches/README.md).

> ### Read this before you run anything
>
> **This repository was written with AI assistance, during a live incident, in a few hours.**
> It has not been through review, and it carries no warranty of any kind.
>
> **What is grounded in reality:** the web-server rules come from attack traffic captured on a
> store that was actually compromised on 5 September 2026. The vulnerable `include` was read
> out of Magento 2.4.7-p2 source on that same store. The indicators of compromise were
> observed first-hand, and cross-checked against Sansec's published advisory.
>
> The section 3 caller analysis was rerun on 10 installs spanning 2.4.6, 2.4.7-p2, 2.4.7-p10
> and 2.4.8-p2 through p5. The CLI guard was executed against a poisoned file under both the
> `cli` and a web SAPI, and it blocked the payload on the web side.
>
> **What is not verified:** the Apache rules were never run against a live Apache. Most of the
> cleanup commands were written rather than executed. The guard was exercised on a harness
> rather than inside a running store, and nothing here was tested on any distribution other
> than Ubuntu, or on shared hosting, Docker, or a control panel. The `vendor/` grep in section
> 3 finds modules that name the scanner classes directly; a module reaching them through a
> factory or a string would slip past it. Regexes that look obviously correct have a long
> history of not being.
>
> **So: read every command before you run it.** Understand what it does in *your* environment,
> not the one it was written in. Test on staging, take backups, and validate your web-server
> config before reloading. If a command here breaks your store, that is on the person who ran
> it without reading it.


Copy-paste mitigation for **StyleSmuggler**, the unauthenticated remote code execution
vulnerability in Magento Open Source and Adobe Commerce that Sansec disclosed on
5 September 2026.

> **There is no vendor patch.** Adobe's next scheduled bulletin is 8 September 2026, and
> whether it covers this bug is unknown. Sansec reproduced the chain on clean 2.4.7, 2.4.8
> and 2.4.9. Their first confirmed victim ran 2.4.6-p15 with the July and August 2026
> patches applied and `security:patch-status` clean.
>
> Your patch level tells you nothing about your exposure.

Advisory: <https://sansec.io/research/stylesmuggler>

---

## Start here

**Check whether you are already compromised before you apply anything.**

Blocking the exploit on an infected server accomplishes nothing. The attacker is already
inside, the implant restarts itself every five minutes, and these rules only stop the *next*
intrusion.

```
   ┌─────────────────────────────────────────────────────────────┐
   │  1. CHECK      §1 below, all read-only                      │
   └──────────────────────────┬──────────────────────────────────┘
                              │
              ┌───────────────┴───────────────┐
              │                               │
         hits found                      nothing found
              │                               │
              ▼                               ▼
   ┌──────────────────────┐        ┌──────────────────────┐
   │  2. CLEAN UP FIRST   │        │  2. Apply §2 and §3  │
   │  → CLEANUP.md        │───────>│     snippets         │
   │  do NOT skip to §2   │  then  │                      │
   └──────────────────────┘        └──────────────────────┘
```

| Document | For |
|---|---|
| **This file** | The snippets, and the read-only checks in §1 |
| **[CLEANUP.md](CLEANUP.md)** | You found indicators. Evidence, containment, where to hunt, what to rotate, clean vs rebuild |
| **[HOW-IT-WORKS.md](HOW-IT-WORKS.md)** | The mechanism, with diagrams. How a log file becomes an executable, why the implant is invisible to network monitoring, where each layer cuts |

---

## Read this first

**These are snippets, not an installer.** There is deliberately nothing here that runs
against your server. You read each rule, decide whether it fits your store, apply it
yourself, and validate before you reload.

Every store is different. A rule that is safe on a classic storefront can break a headless
build. Test on staging, keep a backup of any file you edit, and confirm your web-server
config parses before reloading. You own the change.

The MIT license applies, including the part in capitals about no warranty.

---

## 1. Check whether you are already compromised

All read-only. Nothing below modifies anything.

**The first sign is often an email, not a log.** If the store has emailed its owner a
garbled "failed transaction" notice full of raw `{{var ...}}` tags and a customer address
ending in `.invalid`, that is exploitation exhaust — see
[EARLY-WARNING-EMAIL.md](EARLY-WARNING-EMAIL.md). It is what caught this in the wild.

The sharpest signal is a process name. Genuine kernel threads are always owned by root and
have no resident memory, so a bracketed name on a site user with real RSS is the implant:

```bash
ps -eo pid,user,rss,args --no-headers | awk '$4 ~ /^\[/ && $2 != "root"'
# and the 6 Sep variant, which hides as fontconfig's cache builder instead:
ps -eo pid,user,comm,args | grep -iE 'kworker|fc-cache' | grep -v ' root '
```

Persistence and dropped files:

```bash
crontab -l | grep -i gvfsd
ls -la ~/.local/share/.gvfsd/ /tmp/.kw_* /tmp/.gvfsd-* 2>/dev/null
```

Stage 1 writes raw PHP into Magento's own report and log files. Check **both** locations,
because variants differ in which one they poison:

```bash
grep -rl 'X_TRACE_\|<?php' var/report/ var/log/ 2>/dev/null
```

Stage 2 in your access log:

```bash
grep -acE 'styles(\[|%5B)|generatorClass|with_resolved|cdnflare' /path/to/access.log
```

Across every account on a shared host, as root:

```bash
find /home /root /tmp /var/tmp /dev/shm \
  \( -name 'gvfsd-user' -o -name '.gvfsd_*.lock' -o -name '.kw_*' \) 2>/dev/null
```

### Indicators of compromise

Full cross-referenced list, with caveats: **[IOC.md](IOC.md)**. The short version:

```
247.cdnflare.xyz                 malware download host
5.181.86.133                     attacker source, bulk traffic
91.238.181.19                    attacker source, second wave (AS49434)
88.216.72.181                    attacker source, published by Sansec

sha256  e315687a1dfe61ef4a5a5642214db6d3b2b05d81391285eebc2af664641a26a7
sha256  8334b434fa3fe9f59cebe9609b11e0b1fd19d10212c45c705adec1902a1d06ef
sha256  251fabd50d7b18a8b5e1b3ef5d64e7198c17244778f6461fb1ab07f6169bf220

~/.local/share/.gvfsd/gvfsd-user
~/.local/share/.gvfsd/.gvfsd_<8hex>.lock
/tmp/.kw_<random><random>
crontab:  */5 * * * * exec <home>/.local/share/.gvfsd/gvfsd-user
process:  [kworker/u:8:0] owned by a non-root uid
```

Two things in IOC.md that cost us time: the traffic came from **27 addresses across two waves**, not the one in
the advisory, and the binary running in memory can hash differently from the file on disk.

The implant is a stripped static Rust binary of roughly 1.9 MB, built for x86-64 and arm64.
In one observed infection it opened no outbound connection at all, reading its work from the
store's own Redis instead. An absence of suspicious network traffic proves nothing.

Two details that cost defenders time in the wild:

- Some variants poison `var/report/`, others `var/log/system.log`. Checking one misses the other.
- Malware scanners pointed at the document root miss this entirely. The implant installs into
  `~/.local/share/`, one level above.

### If you found something

**Stop. Do not apply the snippets yet, and do not reboot.**

Go to **[CLEANUP.md](CLEANUP.md)**. It walks the whole thing in the order that works:
preserve evidence, remove persistence before killing processes, hunt every place the attacker
could have left something, rotate every secret the site user could read, and decide honestly
whether to clean or rebuild.

Three mistakes that cost people their second weekend:

- **Rebooting.** `/proc/<pid>/exe` is often the only copy of a binary the attacker deleted from disk.
- **Killing the process before removing the cron entry.** It comes straight back, and now they know you noticed.
- **Running `composer install` to "clean" it.** That overwrites the timestamps proving what was touched.

---

## 2. Block the request at the web server

> Only worth doing once §1 comes back clean, or once you have worked through
> [CLEANUP.md](CLEANUP.md). Rules on an infected server stop nothing that is already running.

> ### These rules are a speed bump, not a fix
>
> nginx and Apache can only inspect the URL query string. The attacks seen in the wild put
> the exploit parameters there, so these rules stop the campaign as it currently runs. But
> PHP merges GET and POST into `$_REQUEST`, and Magento reads from both, so **an attacker who
> moves the same parameters into the POST body walks straight past every rule below.**
>
> Measured on a live store with these rules deployed:
>
> | Request | Result |
> |---|---|
> | `GET /graphql?styles[first]=x` | blocked (444) |
> | `POST /graphql?styles[first]=x` | blocked (444) |
> | `POST /graphql` with `styles[first]=x` in the **body** | **reached PHP** |
> | `POST /graphql` with a JSON body | **reached PHP** |
>
> Deploy these rules, because they cost nothing and they stop what is hitting stores today.
> Do not stop here. **[Section 3](#3-make-the-di-scanners-cli-only) is the control that
> actually holds**, because it sits on the sink and does not care how the request arrived.

Full snippets: [`snippets/nginx.conf`](snippets/nginx.conf) and
[`snippets/apache.conf`](snippets/apache.conf). The nginx rules:

```nginx
# The gadget parameter. No legitimate Magento route uses it.
if ($query_string ~* "styles(\[|%5B)")                                  { return 444; }

# Object-injection driver parameters observed in the chain.
if ($query_string ~* "(generatorClass|with_resolved)")                  { return 444; }

# Magento template directives smuggled through the query string.
if ($query_string ~* "(\{\{|%7B%7B)\s*(block|config|trans|var|depend)") { return 444; }

# Raw PHP open tag in the query string.
if ($query_string ~* "(<\?|%3C%3F)")                                    { return 444; }

# Raw PHP open tag in the User-Agent.
if ($http_user_agent ~* "<\?(php|=)")                                   { return 444; }
```

Include that inside each Magento `server { }` block, then **run `nginx -t` and only reload
if it passes**.

### The mistake to avoid

Match every pattern raw **and** URL-encoded. Real payloads arrive percent-encoded as
`styles%5Bfirst%5D`, so a rule matching only the literal bracket blocks nothing at all.
This is the easiest way to deploy these rules and gain no protection.

### Before you commit to the `{{` and `styles[` rules

Both can in principle match a storefront search for that literal text. Check your own logs:

```bash
grep -acE 'styles(\[|%5B)|(\{\{|%7B%7B)(block|config|var)' /path/to/access.log
```

If that returns 0, as it will on almost every store, you have no false positives to worry about.

### Or just turn GraphQL off

Sansec's own advice, and the bluntest option. Headless and PWA storefronts need GraphQL;
most classic and Hyvä storefronts do not. Check before you decide:

```bash
grep -c '"POST /graphql' /path/to/access.log
```

```nginx
location ^~ /graphql { return 403; }
```

---

## 3. Make the DI scanners CLI-only

**This is the important one.** Unlike the web-server rules, it is not tied to how the request
is shaped, so it cannot be bypassed by moving parameters into the POST body.

The attack terminates inside Magento's dependency-injection compiler, in classes that perform
a variable-path `include`. Stock Magento drives all three from `bin/magento setup:di:compile`,
so refusing non-CLI execution removes the primitive.

Two of the three are free. One needs a check first.

| File under `setup/src/Magento/Setup/Module/Di/Code/` | Method | Guard it |
|---|---|---|
| `Scanner/ArrayScanner.php` | `collectEntities()` | always |
| `Scanner/XmlInterceptorScanner.php` | `_handleControllerClassName()` | always |
| `Reader/ClassesScanner.php` | `includeClass()` | run the check below first |

We grepped 2.4.6, 2.4.7-p2, 2.4.7-p10 and 2.4.8-p2 through p5. Nothing calls `ArrayScanner`
or `XmlInterceptorScanner` anywhere in those trees except their own unit tests, so guarding
those two costs you nothing.

`ClassesScanner` is different. Stock Magento only calls it from the DI compiler, but
third-party modules borrow it. `mageplaza/module-admin-permissions` injects it and calls
`getList()` from `Controller/Adminhtml/Grid/Rescan.php`, which runs over HTTP. Guard it there
and that admin screen throws a 500. Check your own `vendor/` before you touch this file:

```bash
grep -rl --include='*.php' \
  -e 'Di\\Code\\Reader\\ClassesScanner' \
  -e 'Di\\Code\\Scanner\\ArrayScanner' \
  -e 'Di\\Code\\Scanner\\XmlInterceptorScanner' \
  vendor app/code 2>/dev/null \
  | grep -v '/Test/' | grep -v '/magento2-base/setup/src/' | grep -v obsolete_
```

Empty output means guard all three. Any path printed is a module that can reach the scanners
over HTTP: guard the other two, leave `ClassesScanner` alone, and lean on the section 2 rules
for that store.

Add this guard as the **first statement** of the method in each file you are guarding:

```php
if (PHP_SAPI !== 'cli') {
    throw new \RuntimeException('Magento DI scanners are CLI-only.');
}
```

So `ArrayScanner::collectEntities()` becomes:

```php
public function collectEntities(array $files)
{
    if (PHP_SAPI !== 'cli') {
        throw new \RuntimeException('Magento DI scanners are CLI-only.');
    }

    $output = [];
    foreach ($files as $file) {
        // ... unchanged
```

Check your edits parse, and confirm a DI compile still works:

```bash
php -l setup/src/Magento/Setup/Module/Di/Code/Scanner/ArrayScanner.php
bin/magento setup:di:compile
```

`setup:di:compile` runs under the CLI SAPI, which is the side of the guard that stays open. It
passes on a store where you have just broken the admin, so it cannot tell you the guard was
safe. After it succeeds, open the admin panel and a storefront page and watch the PHP error
log for `Magento DI scanners are CLI-only`:

```bash
tail -f var/log/*.log /var/log/php*-fpm.log 2>/dev/null | grep -i 'DI scanners are CLI-only'
```

A hit names a page that legitimately reached a scanner. Undo that one file as below and keep
the other two guards.

### Undoing a guard

`magento2-base` ships a pristine copy of all three files, so you can restore one without
touching the rest of the install and without a full `composer install`:

```bash
BASE=vendor/magento/magento2-base/setup/src/Magento/Setup/Module/Di/Code
cp "$BASE/Reader/ClassesScanner.php" setup/src/Magento/Setup/Module/Di/Code/Reader/
```

Confirm the guard is gone, then let the page recover:

```bash
grep -c 'PHP_SAPI' setup/src/Magento/Setup/Module/Di/Code/Reader/ClassesScanner.php   # 0
```

If your pools run `opcache.validate_timestamps=1` the change lands within `revalidate_freq`
seconds. With revalidation off, PHP-FPM keeps serving the guarded bytecode until you reset the
cache or reload the service, so the admin stays broken until you do.

Swap `Reader/ClassesScanner.php` for `Scanner/ArrayScanner.php` or
`Scanner/XmlInterceptorScanner.php` to undo either of the other two.

**`composer install` reverts all of this.** `setup/` ships from `magento/magento2-base` and is
gitignored in most projects, so re-apply it after every deploy. Verify with:

```bash
grep -c 'PHP_SAPI' setup/src/Magento/Setup/Module/Di/Code/Scanner/ArrayScanner.php
```

---

## 3b. The same guard as a deployable patch

Section 3 is what you do by hand on a running box. For anything you deploy with
Composer, [`patches/`](patches/) ships the DI scanner guard as a `composer-patches`
file that reapplies on every `composer install`, so a deploy never quietly reverts it:

- `magento/magento2-base` — the three DI scanners become CLI-only (the sink, section 3)

It applies across 2.4.6 through 2.4.9, verified with `patch --dry-run` against every tag
and applied-and-linted on live 2.4.7-p2 and 2.4.8-p4, with `setup:di:compile` and the
storefront confirmed working afterwards.

```json
"extra": {
    "composer-exit-on-patch-failure": true,
    "patches": {
        "magento/magento2-base": {
            "StyleSmuggler: DI code scanners are CLI-only": "patches/magento/magento2-base/stylesmuggler-di-scanner-guard.patch"
        }
    }
}
```

There is deliberately **no patch on the entry point**. The exploit reaches Magento's
template filter through object injection, not a route, and the code that processes it
(`Magento\Email\Model\AbstractTemplate::getProcessedTemplate`) also renders every
legitimate transactional email, so it cannot be guarded without breaking mail. Close
the sink here, and rely on `disable_functions` (including `proc_open`) and `noexec` on
`/tmp`, `/var/tmp`, `/dev/shm` as the layers that do not depend on the entry point.
Full detail in [patches/README.md](patches/README.md) and
[HOW-IT-WORKS.md](HOW-IT-WORKS.md).

## 4. Confirm it works

Expect an empty response, because 444 closes the connection without replying:

```bash
curl -sk -o /dev/null -w '%{http_code}\n' 'https://YOURSTORE/graphql?styles%5Bfirst%5D=x'
```

Your storefront must still return 200:

```bash
curl -sk -o /dev/null -w '%{http_code}\n' 'https://YOURSTORE/'
```

---

## What this is not

- Not a fix. Only Adobe can ship that. Replace these rules with the official patch when it lands.
- The web-server rules in §2 are **bypassable by design**, since nginx and Apache cannot read
  POST bodies. They stop the current campaign, not a determined attacker. §3 is what holds.
- Not incident response. If you are already compromised, these rules change nothing about that.
- Not exhaustive. Variants that differ from the two published samples will not match.

## A note on scope

This repository names the vulnerable sink, because a fix has to say what it fixes. It does
not publish the assembled request that reaches it. Sansec withheld the full gadget chain when
they disclosed, and with no vendor patch available that restraint still holds. Defenders lose
nothing by it: every rule here works without knowing how to build the exploit.

## Credits

ProxiBlue (Lucas van Staden) independently published the same DI-scanner guard
(<https://gist.github.com/ProxiBlue/07373c92c8c70dc746bbfdcd1f07b789>); their originals are
in `patches/upstream/proxiblue/`. Convergent, independent work.

brideo / Upturn built a fuller Magento module on top of the same analysis, crediting us and
ProxiBlue: <https://github.com/brideo/stylesmuggler-patch> (MIT). It adds an application-layer
entry guard at `setTemplateStyles` that our patch cannot reach; see the patches README. If you
want defence in depth beyond the sink patch, use their module.


Vulnerability discovery, naming and the original advisory belong to the
[Sansec](https://sansec.io) forensics team. These snippets came out of a live incident
response on 5 September 2026 and are not affiliated with Sansec or Adobe.

If you run Magento at scale, buy Sansec's tools. They found this one.

## License

MIT, warranty disclaimer very much included. See [`LICENSE`](LICENSE).
