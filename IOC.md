# Indicators of compromise

> ### Read this before you run anything
>
> Written with AI assistance during a live incident response. Everything on this page was
> observed first-hand on two stores compromised on 5 September 2026, or published by Sansec.
> Nothing here is a substitute for checking your own logs.

Observed across two independent infections plus a third store that was targeted but not
successfully exploited, all on 5 September 2026. Cross-referenced with the
[Sansec advisory](https://sansec.io/research/stylesmuggler).

Items marked **new** did not appear in that advisory at the time of writing.

## Updates

This list grows as we mine the evidence further. Newest first, so returning readers can see
what changed since they last read it. Each dated entry is additive unless it says otherwise.

- **2026-09-06 (from Sansec's updated advisory)** — A second implant build appeared, using the
  process name `fc-cache` instead of `[kworker/u:8:0]`, with its own paths, cron schedule and a
  fake-NTP UDP C2 channel. New download host `209.141.43.95`, new C2 hosts, and three new
  hashes. **We did not observe this variant on our own stores** — our two infections were the
  earlier `kworker` build with a Redis-only channel and no external C2. Everything in this
  2026-09-06 entry is from [Sansec's advisory](https://sansec.io/research/stylesmuggler),
  reproduced here so the two lists stay in step; it is not first-hand. See the
  "fc-cache variant" section below.
- **2026-09-05, later revision** — Added a second-wave source IP (`91.238.181.19`, AS49434);
  documented a second trigger-header family (`X-<12 hex>` with no `TRACE`, alongside the
  original `X-TRACE-<10 hex>`); added response markers (`MG<20 hex>::...::/MG<20 hex>`) as
  proof-of-execution; added attacker user agents (`python-requests 2.15.0` and `/2.32.4`).
  Corrected the source-address count from 26 to 27. Removed one IPv6 address that was our own
  test traffic, not the attacker.
- **2026-09-05, initial** — First publication: malware hashes, `.gvfsd`/`.kw_` artefacts,
  self-restoring crontab, C2 hosts, the `var/log/system.log` poisoning path, and the initial
  source-address set.

---

## Malware

```
sha256  e315687a1dfe61ef4a5a5642214db6d3b2b05d81391285eebc2af664641a26a7   Sansec sample
sha256  8334b434fa3fe9f59cebe9609b11e0b1fd19d10212c45c705adec1902a1d06ef   on disk, both stores
sha256  251fabd50d7b18a8b5e1b3ef5d64e7198c17244778f6461fb1ab07f6169bf220   in-memory, one store

Sansec-published (fc-cache variant, 2026-09-06 — we did not observe these ourselves):
sha256  b79dfdc1eed860e0b76c629d6adfce251db379b0b45a6d728d4ef483f7551420
sha256  4352cabaa451e5a894535fbcc4d46628701303322a13745cb5479d7d0534ae8e   kworker-linux-x64
sha256  d2fbf9eb75c495bfea48790d3b228fab0c15a282419c3d3f5e49294c4e1a3e82   kworker-linux-arm64
```

**The third hash matters.** On one store the binary *running in memory* was a different build
from the file on disk: `/proc/<pid>/exe` pointed at a deleted inode and hashed differently from
the `gvfsd-user` sitting in the filesystem. The operator updates the implant in place. Hash the
running process, not only the file:

```bash
cp /proc/<pid>/exe /tmp/sample.bin && sha256sum /tmp/sample.bin
```

Roughly 1.9 MB, stripped, statically linked Rust, built for x86-64 and arm64.

## Filesystem and persistence

```
~/.local/share/.gvfsd/gvfsd-user
~/.local/share/.gvfsd/.gvfsd_<8hex>.lock
/tmp/.gvfsd_<8hex>.lock                     new, second lock outside the home directory
/tmp/.kw_<random><random>

crontab:  */5 * * * * exec <home>/.local/share/.gvfsd/gvfsd-user
crontab:  */5 * * * * exec /tmp/.kw_        new, variant pointing straight at /tmp
process:  [kworker/u:8:0] owned by a non-root uid
```

**The crontab entry restores itself, and it is written directly to the spool file.** One store
carried the same line repeated **1728 times**, and the implant re-appended it within a second
of removal. Because it writes to `/var/spool/cron/crontabs/<user>` instead of calling
`crontab`, syslog records no `REPLACE` and nothing appears to have happened.

Clean the crontab, kill the processes, remove the binary, **then clean the crontab again**.
Verify after a full cron cycle.

## fc-cache variant (Sansec, 2026-09-06 — not observed by us)

Sansec reports a second build from 6 September that disguises itself as `fc-cache` (the
fontconfig cache builder) instead of `[kworker/u:8:0]`. Same attack, different persistence and
a different C2 channel. Check for both names.

```
process:  fc-cache        owned by a non-root uid
path:     ~/.cache/fontconfig/fc-cache
lock:     /tmp/.fc_<8hex>.lock            holds the implant PID; hex = first half of agent id
drop:     /tmp/.fc-<8hex>/fc-cache
drop:     /tmp/fc-cache
drop:     /tmp/.cache_<random><random>
crontab:  13,43 * * * * <home>/.cache/fontconfig/fc-cache >/dev/null 2>&1
```

Its C2 is disguised as NTP: every 60s it sends 48-byte UDP packets to port 123 on a host named
`ntp.*`, where only the first four bytes are real NTP and the rest is a MessagePack record
(agent id, hostname, user, OS, memory/disk, uptime, root-or-not, implant version — `2.1.4` in
this build). Because it is UDP/123 to an `ntp.*` host, it slips past most egress filtering.

It first learns the store's public IP over plain HTTP from `api4.ipify.org`,
`ipv4.icanhazip.com`, `ipv4.ident.me` and `ipinfo.io`, with a User-Agent truncated after
`AppleWebKit/537.36` (matching no real browser). It reads `TracerPid` from
`/proc/self/status`: under a debugger it installs but never beacons.

```bash
ps -eo pid,comm,args | grep -iE 'kworker|fc-cache'
ls -la ~/.cache/fontconfig/fc-cache /tmp/.fc_*.lock /tmp/.fc-*/fc-cache /tmp/fc-cache /tmp/.cache_* 2>/dev/null
crontab -l | grep -iE 'gvfsd|fontconfig/fc-cache'
```

## Network

Everything under this heading with an `ntp.*`, `.run` or `.studio` host, plus `209.141.43.95`
and `windwsecurity.run`, is from Sansec's 2026-09-06 advisory and was **not seen on our stores**
(our infections used a Redis-only channel, no external C2).

```
247.cdnflare.xyz         malware download host    (2a06:98c1:3120::2, 2a06:98c1:3121::2)
209.141.43.95            malware download host    http://209.141.43.95/files/ (FranTech AS53667)
99.84.67.186:443         C2, WebSocket over TLS
windwsecurity.run:443    remote shell, WebSocket over TLS
ntp.timesysnc.net:123    C2, fake-NTP UDP
time.microsft.run:123    C2, fake-NTP UDP
pool.microsft.studio:123 C2, fake-NTP UDP
ntp.timesync.to:123      C2, fake-NTP UDP (fc-cache build)
ntp.synctime.to:123      C2, fallback
ntp.syncstime.to:123     C2, fallback
```

Everything except `247.cdnflare.xyz` is from Sansec's advisory; we saw none of it. Note the
typosquat hosts (`windwsecurity`, `microsft`, `timesysnc`) — deliberate lookalikes that read as
legitimate at a glance.

Neither of our two packet captures, both over 200 MB and taken while the implant was live,
contained a single packet to either address. On one store the implant instead held 28
connections to `127.0.0.1:6379`, reading Magento's session storage out of the store's own
Redis.

**Do not treat quiet network monitoring as evidence of a clean host.**

## Source addresses

### Hosting infrastructure, bulk traffic

```
5.181.86.133    new    CloudVPS       96 requests against one store
91.238.181.19   new    AS49434 (FR)   48 exploit requests, second wave (17:08 CEST, 5 Sep)
88.216.72.181          (Sansec)       45 requests
```

> **Corrected 2026-09-05.** An earlier version of this file listed two Hetzner IPv6 addresses
> here. They were our own servers, curling themselves during the verification step of our
> deployment tooling, swept up because the same grep that finds attack traffic also finds your
> own tests. If you derive a list this way, filter your own addresses and your own user agents
> (`curl/`, `Go-http-client/`, monitoring agents) before you publish or block anything.

### Residential proxy pool

**Do not blanket-block these.** They are consumer ISP addresses, which makes them proxy exits
on rented or compromised connections rather than attacker-owned infrastructure. Blocking them
costs you real customers later. They are listed so you can correlate your own logs and
recognise the shape: two to six requests each, spread thin, alongside the bulk sources above.

```
24.191.105.204   47.37.37.233    71.131.42.198    104.128.194.245   130.245.213.224
24.229.224.252   47.42.184.116   73.161.75.77     107.213.83.152    172.222.34.230
35.142.49.124    67.168.45.119   73.215.148.30    108.18.123.93     174.49.123.57
45.31.24.37      75.36.207.187   76.34.160.20     108.45.146.28     216.47.18.146
47.151.56.149    76.143.120.244  100.12.210.189   108.45.168.240
```

Blocking `88.216.72.181` alone, which is what the advisory's IOC list implies, stops less than
a quarter of the traffic we saw. In total we recorded 27 distinct source addresses across three
stores and two waves. The second wave, on the afternoon of 5 September and well after the
initial compromise, came almost entirely from `91.238.181.19` and was blocked at the web-server
layer.

## Request signatures

```
POST /graphql?styles[...]=            the exploit, percent-encoded in the wild
POST /paypal/transparent/response/?<?=eval(base64_decode('...    (published by Sansec)
GET  /customer/section/load/?sections=customer&force_new_section_timestamp=true
```

That last one is ordinary Magento traffic. In the variant we captured the payload rode in the
**User-Agent header** rather than the URL, so the request line on its own looks innocent.

### Trigger header

Two families were used, and the second dropped the `TRACE` word entirely:

```
X-TRACE-<10 hex>     morning of 5 Sep     e.g. X-TRACE-1713CB9C2F
X-<12 hex>           afternoon of 5 Sep   e.g. X-52988DAECE51, X-4427457CBAC9
```

The value is regenerated per request. We recovered dozens of distinct values from a single
store's logs, so the value is worthless as an indicator and the **shape** is what you match.
Match both families:

```bash
grep -rlE 'X[_-](TRACE[_-])?[0-9A-Fa-f]{10,12}' var/report/ var/log/ /var/log/nginx/
```

A detection pinned to `X-TRACE-` alone goes blind against the second family, which is exactly
what happened here within one day.

## Response markers

On execution the payload wraps its output in a per-request delimiter and echoes it back:

```
MG<20 hex>::<base64 result>::/MG<20 hex>    e.g. MG8a5ee8fd94fdb9fc6b50::...::/MG8a5ee8fd94fdb9fc6b50
```

The hex value differs per request, so match the shape. A response body or log line carrying
`MG<hex>::` and `::/MG<hex>` is proof the payload ran, not merely that it was sent:

```bash
grep -rlE 'MG[0-9a-f]{16,}::' var/log/ /var/log/nginx/
```

## User agents

The exploit requests carried a scripting client, never a browser, on `POST /graphql`:

```
python-requests 2.15.0      first wave  (note the space, not a slash)
python-requests/2.32.4      second wave
```

The version changed between waves, so treat "python-requests on POST /graphql with styles[]
parameters" as the signal rather than any one version string. Beware your own tooling: `curl/*`
and `Go-http-client/*` in these logs were our verification traffic, not the attacker.

## Poisoned files

```
var/log/system.log     both of our infections came in through here
var/report/<hash>      the location the published check looks at
```

**Check both.** The advisory suggests `grep -rl 'X_TRACE_' var/report/`. Neither store we
handled would have been caught by that alone. Both were poisoned through `var/log/system.log`
via an invalid store code that Magento logs verbatim. One held a single PHP block, the other
held 49.

## Contributing

Seen a hash, address or variant that is not here? Open an issue or a pull request. Send
anything about the vulnerability itself to [Sansec](https://sansec.io/contact) and Adobe
PSIRT rather than here.
