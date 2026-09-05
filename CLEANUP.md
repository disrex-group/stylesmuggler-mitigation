# If you are already compromised

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


Blocking the exploit on an infected server accomplishes nothing. The attacker is already
inside, the implant restarts itself, and your web-server rules only stop the next intrusion.

**Clean first. Mitigate afterwards.**

This guide assumes nothing about your hosting. No agency stack, no particular control panel,
no root necessarily. Where a step needs privileges you may not have, there is a fallback.

Set this once and every command below works:

```bash
MAGENTO_ROOT=/path/to/your/store        # the directory holding app/etc/env.php
```

---

## The order that matters

```
   0. DON'T                     reboot, delete, or composer install yet
   1. CONFIRM                   is it actually this, or something else?
   2. PRESERVE                  evidence, before you destroy it
   3. CONTAIN                   persistence first, then processes, then files
   4. HUNT                      what else did they leave?
   5. ROTATE                    every secret the site user could read
   6. DECIDE                    clean, or rebuild?
   7. MITIGATE                  now the snippets are worth applying
```

Doing 7 before 3 is the most common mistake. Doing 3 before 2 destroys the evidence you need
for step 4 and for any breach-notification decision.

---

## 0. Things not to do yet

| Don't | Why |
|---|---|
| **Reboot** | Kills the running process before you can see what it held open, what it connected to, and which binary it came from. `/proc/<pid>/exe` is often the only copy left when the file is deleted from disk. |
| **Delete the binary first** | Cron respawns it within five minutes and you have lost the sample. |
| **`composer install`** or redeploy | Overwrites timestamps and modified files, destroying your ability to tell what the attacker touched. |
| **Restore a backup immediately** | You do not yet know when the compromise started. You may restore an already-infected backup, or lose the evidence proving the date. |
| **Assume it is only Magento** | The implant runs as your site user, not inside PHP. It can touch anything that user can. |

---

## 1. Confirm it is really this

All read-only.

```bash
# Non-root processes wearing kernel-thread names. The single sharpest signal:
# real kernel threads are ALWAYS root-owned with zero resident memory.
ps -eo pid,user,rss,args --no-headers | awk '$4 ~ /^\[/ && $2 != "root"'

# Persistence and dropped files
crontab -l 2>/dev/null | grep -i 'gvfsd\|\.kw_'
ls -la ~/.local/share/.gvfsd/ /tmp/.kw_* /tmp/.gvfsd-* 2>/dev/null

# Stage 1, in BOTH locations. Variants differ in which they poison.
grep -rl 'X_TRACE_\|<?php' "$MAGENTO_ROOT/var/report/" "$MAGENTO_ROOT/var/log/" 2>/dev/null

# Stage 2, in your access log (adjust the path to your setup)
grep -acE 'styles(\[|%5B)|generatorClass|with_resolved|cdnflare' /path/to/access.log
```

**No hits anywhere?** You are probably fine. Apply the snippets and move on.

**Hits?** Continue. And note what a *clean* process list does not prove: if the machine was
rebooted since the intrusion, or the implant exited, the files and logs still tell the story.

---

## 2. Preserve evidence before touching anything

Do this even if you are certain you will rebuild. It is five minutes, and it is the only
thing that can later answer "did customer data leave?"

```bash
Q=~/incident-$(date +%Y%m%d-%H%M); mkdir -p "$Q"; chmod 700 "$Q"

# The running process, before you kill it
ps -eo pid,ppid,user,lstart,rss,args > "$Q/processes.txt"
PID=$(ps -eo pid,user,args --no-headers | awk '$3 ~ /^\[kworker/ && $2 != "root" {print $1; exit}')
if [ -n "$PID" ]; then
  ls -l /proc/$PID/exe /proc/$PID/cwd  > "$Q/proc-links.txt" 2>&1
  ls -l /proc/$PID/fd/                 > "$Q/proc-fds.txt"   2>&1
  cat /proc/$PID/status                > "$Q/proc-status.txt" 2>&1
  # If the binary was deleted from disk, this is your only copy:
  cp /proc/$PID/exe "$Q/implant.bin" 2>/dev/null
fi

# The binary, if still on disk, plus its hash
cp -p ~/.local/share/.gvfsd/gvfsd-user "$Q/" 2>/dev/null
sha256sum "$Q/"*.bin "$Q/gvfsd-user" 2>/dev/null > "$Q/hashes.txt"

# Persistence, connections, and the logs that show the entry
crontab -l                            > "$Q/crontab.txt" 2>&1
ss -tanp 2>/dev/null || netstat -tanp 2>/dev/null > "$Q/connections.txt"
cp -p "$MAGENTO_ROOT/var/log/system.log" "$Q/" 2>/dev/null
cp -p /path/to/access.log "$Q/" 2>/dev/null
```

If you can run `tcpdump` and the implant is still alive, capture a few minutes of traffic
**before** killing it. That is what answers the data-exfiltration question:

```bash
sudo timeout 180 tcpdump -i any -s0 -w "$Q/capture.pcap" 'not port 22'
```

Then check it against the known C2:

```bash
tcpdump -nr "$Q/capture.pcap" 'host 99.84.67.186 or host 247.cdnflare.xyz' | head
```

---

## 3. Contain, in this order

**Persistence before processes.** Kill the process first and cron simply brings it back,
and now you have warned the attacker without stopping anything.

```bash
# 3a. Remove persistence FIRST
crontab -e            # delete any line referencing gvfsd or .kw_
crontab -l | grep -c gvfsd     # must return 0

# 3b. Now kill the processes
pkill -f 'kworker/u' -u "$(id -un)"
ps -eo pid,user,args --no-headers | awk '$3 ~ /^\[/ && $2 != "root"'   # must be empty

# 3c. Only now remove the files
rm -rf ~/.local/share/.gvfsd/
rm -f /tmp/.kw_* /tmp/.gvfsd-* 2>/dev/null

# 3d. Purge the poisoned files (you preserved copies in step 2)
: > "$MAGENTO_ROOT/var/log/system.log"
rm -f "$MAGENTO_ROOT"/var/report/*
```

Wait ten minutes, past two cron cycles, and re-check 3b. If the process returns, you missed a
persistence mechanism. Go to step 4.

---

## 4. Hunt: where else to look

This is the part people skip, and it is why infections come back. The implant runs as your
site user, so anything that user can write is a candidate. Work through all of it.

### 4a. Every scheduling mechanism on Linux

Not everyone uses crontab. Check all of these:

```bash
# user and system cron
crontab -l 2>/dev/null
sudo crontab -l 2>/dev/null
ls -la /etc/cron.d/ /etc/cron.{daily,hourly,weekly,monthly}/ 2>/dev/null
cat /etc/crontab 2>/dev/null
sudo ls -la /var/spool/cron/crontabs/ 2>/dev/null

# systemd, both system and per-user. A user timer survives without root.
systemctl list-timers --all 2>/dev/null
systemctl --user list-timers --all 2>/dev/null
ls -la ~/.config/systemd/user/ /etc/systemd/system/ 2>/dev/null

# at jobs and supervisor
atq 2>/dev/null
ls -la /etc/supervisor/conf.d/ 2>/dev/null
```

### 4b. Shell and login persistence

A line appended to a dotfile runs on every login or cron shell:

```bash
grep -nE 'curl|wget|base64|/tmp/\.|gvfsd|kworker' \
  ~/.bashrc ~/.bash_profile ~/.profile ~/.zshrc ~/.bash_login 2>/dev/null

ls -la ~/.config/autostart/ 2>/dev/null
cat ~/.ssh/authorized_keys 2>/dev/null      # any key you do not recognise
sudo cat /etc/ld.so.preload 2>/dev/null     # should not exist on most systems
```

### 4c. PHP-level persistence

`auto_prepend_file` runs code on **every** PHP request and survives a Magento reinstall:

```bash
grep -rn 'auto_prepend_file\|auto_append_file' \
  "$MAGENTO_ROOT/.user.ini" "$MAGENTO_ROOT/.htaccess" /etc/php*/ 2>/dev/null

# PHP files where none belong
find "$MAGENTO_ROOT/pub/media" -name '*.ph*' -type f 2>/dev/null
find "$MAGENTO_ROOT/pub" -maxdepth 2 -name '*.php' -newermt '30 days ago' 2>/dev/null

# .htaccess added to media dirs to re-enable PHP execution
find "$MAGENTO_ROOT/pub/media" -name '.htaccess' -newermt '30 days ago' 2>/dev/null
```

### 4d. Modified application code

If your store is in git, this is the fastest answer you will get all day:

```bash
cd "$MAGENTO_ROOT"
git status --short
git diff --stat
git ls-files --others --exclude-standard | grep -E '\.(php|phtml)$'
```

If it is not in git, fall back to timestamps and to Composer's own integrity view:

```bash
find "$MAGENTO_ROOT/app" "$MAGENTO_ROOT/vendor" "$MAGENTO_ROOT/pub" \
  -name '*.php' -newermt '30 days ago' -type f 2>/dev/null | head -50

composer install --dry-run 2>&1 | head
```

### 4e. Inside Magento itself

The implant had database access. Check what a backdoor would leave. Read-only SQL, run it
however you normally reach the database:

```sql
-- Admin accounts you did not create, or that appeared recently
SELECT user_id, username, email, created, logdate, is_active FROM admin_user ORDER BY created DESC;

-- API integrations and tokens
SELECT integration_id, name, created_at, status FROM integration;
SELECT * FROM oauth_token ORDER BY created_at DESC LIMIT 20;

-- Injected JavaScript: the classic card-skimmer hiding places
SELECT config_id, scope, path, LEFT(value,200) FROM core_config_data
 WHERE value LIKE '%<script%' OR value LIKE '%eval(%' OR value LIKE '%atob(%'
    OR value LIKE '%fromCharCode%';

-- Recently edited content
SELECT identifier, update_time FROM cms_block WHERE update_time > NOW() - INTERVAL 30 DAY;
SELECT identifier, update_time FROM cms_page  WHERE update_time > NOW() - INTERVAL 30 DAY;

-- Malicious scheduled jobs
SELECT * FROM cron_schedule WHERE job_code NOT LIKE 'magento%' ORDER BY scheduled_at DESC LIMIT 20;
```

Then confirm what your customers are actually served. A skimmer that lives in cache appears
here and nowhere else:

```bash
curl -s https://YOURSTORE/ | grep -oE '<script[^>]*src="[^"]+"' | sort -u
curl -s https://YOURSTORE/ | grep -cE 'atob\(|eval\(|fromCharCode'
```

Every script host in that list should be one you recognise.

### 4f. Session and cache storage

The implant we observed read Magento's session storage directly. Flush it, whichever backend
you use, so any stolen session is worthless:

```bash
# Redis (check app/etc/env.php for the db numbers your store uses)
redis-cli flushall

# File-based sessions
rm -f "$MAGENTO_ROOT"/var/session/sess_*

# Database sessions
# DELETE FROM session;
```

This logs out every customer and admin. That is the point.

### 4g. Other sites on the same machine

If the box hosts more than one store, the attacker scanned for Magento and probably found
them all:

```bash
sudo find /home /var/www /srv -maxdepth 4 -name env.php -path '*app/etc*' 2>/dev/null
```

Run step 1 against each one.

---

## 5. Rotate everything the site user could read

Code execution as the site user means every secret readable by that user is exposed. Not
"might be". Is.

```bash
grep -oE "'(key|password|username|host|dbname)'" "$MAGENTO_ROOT/app/etc/env.php" | sort -u
```

Rotate, at minimum:

- **Magento `crypt/key`** in `app/etc/env.php`. Everything encrypted in your database is
  encrypted with it, so re-encrypting stored credentials is part of the job.
- **Database password**
- **Every admin account password**, and invalidate all admin sessions
- **Payment provider API keys**, and every other integration credential in `env.php`
- **API tokens and integrations** you found in step 4e
- **SSH keys and deploy keys** the site user could read
- Anything in `.env` files, CI variables, or config that the user could read

If your store handles cardholder data directly, involve your acquirer. If it handles personal
data of EU residents, you have a GDPR Article 33 assessment to make, and a 72-hour clock that
started when you became aware.

---

## 6. Clean or rebuild?

Cleaning is honest only when you can answer, with evidence, what the attacker did.

**Rebuild from a known-good source when any of these are true:**

- The store is not in version control, so you cannot prove which files changed
- You found modified files in `vendor/` or `app/code/` you cannot explain
- The implant ran for days, not hours
- You cannot establish when the compromise started
- The attacker reached root, not just the site user

**Rebuilding well:**

1. New host or wiped host. Do not reuse a compromised filesystem.
2. Deploy application code from git, dependencies from `composer install`.
3. Import the database, then re-run every check in step 4e against it. A database can carry a
   backdoor across a rebuild.
4. Restore `pub/media` selectively. Copy images by extension; never copy the directory wholesale.
5. New credentials everywhere, per step 5.
6. Apply the snippets before the store goes public.

---

## 7. Now apply the mitigation

Only now do the [README](README.md) snippets do anything useful for you. Re-run step 1
afterwards to confirm nothing came back while you were working.

---

## Situational notes

**No root access, shared hosting.** Steps 1 through 5 work as your own user. You cannot see
other users' processes and cannot read system cron, so ask your host to check the machine. If
they will not, treat rebuilding on a different host as the safer option.

**Docker or Kubernetes.** Containers make this easier. Do not clean a container; rebuild the
image from source and redeploy. But check first whether the implant wrote into a **mounted
volume**, which survives the rebuild: `var/`, `pub/media`, and anything else persistent. Also
check whether `/tmp` is a volume rather than container-local.

**A control panel (cPanel, Plesk, DirectAdmin).** These add their own cron and startup
locations. Check the panel's scheduled-task UI as well as `crontab -l`, since entries created
through the panel may not be visible in both places.

**Your scanner reported clean.** Check what path it was given. Scanners scoped to the document
root miss this entirely; the implant installs into `~/.local/share/`, one level above.

---

## What "clean" does and does not prove

Finding nothing in step 4 means you found nothing. It does not prove nothing is there.

What you can say with confidence:

- No implant is running **now**
- No known persistence mechanism remains
- No modified file remains **that you can detect**

What you cannot say without evidence from step 2:

- That no data left the server
- That no credential was used elsewhere
- Exactly when the compromise began

That gap is why step 2 comes before step 3, and why it is worth the five minutes even when
you are certain you will rebuild.
