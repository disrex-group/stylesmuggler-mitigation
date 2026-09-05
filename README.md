# StyleSmuggler mitigation snippets

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
> **What is not verified:** the Apache rules were never run against a live Apache. Most of the
> cleanup commands were written rather than executed. Nothing was tested on any Magento
> version other than 2.4.7-p2, on any distribution other than Ubuntu, or on shared hosting,
> Docker, or a control panel. Regexes that look obviously correct have a long history of not
> being.
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

The sharpest signal is a process name. Genuine kernel threads are always owned by root and
have no resident memory, so a bracketed name on a site user with real RSS is the implant:

```bash
ps -eo pid,user,rss,args --no-headers | awk '$4 ~ /^\[/ && $2 != "root"'
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
a variable-path `include`. Those classes exist solely to serve `bin/magento setup:di:compile`
and are never legitimately reached over HTTP, so refusing non-CLI execution removes the
primitive at no functional cost.

Add this guard as the **first statement** of the method in each of the three files:

```php
if (PHP_SAPI !== 'cli') {
    throw new \RuntimeException('Magento DI scanners are CLI-only.');
}
```

| File under `setup/src/Magento/Setup/Module/Di/Code/` | Method |
|---|---|
| `Scanner/ArrayScanner.php` | `collectEntities()` |
| `Reader/ClassesScanner.php` | `includeClass()` |
| `Scanner/XmlInterceptorScanner.php` | `_handleControllerClassName()` |

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

**`composer install` reverts this.** `setup/` ships from `magento/magento2-base` and is
gitignored in most projects, so re-apply it after every deploy. Verify with:

```bash
grep -c 'PHP_SAPI' setup/src/Magento/Setup/Module/Di/Code/Scanner/ArrayScanner.php
```

---

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

Vulnerability discovery, naming and the original advisory belong to the
[Sansec](https://sansec.io) forensics team. These snippets came out of a live incident
response on 5 September 2026 and are not affiliated with Sansec or Adobe.

If you run Magento at scale, buy Sansec's tools. They found this one.

## License

MIT, warranty disclaimer very much included. See [`LICENSE`](LICENSE).
