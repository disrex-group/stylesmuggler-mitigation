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

---

## Malware

```
sha256  e315687a1dfe61ef4a5a5642214db6d3b2b05d81391285eebc2af664641a26a7   Sansec sample
sha256  8334b434fa3fe9f59cebe9609b11e0b1fd19d10212c45c705adec1902a1d06ef   on disk, both stores
sha256  251fabd50d7b18a8b5e1b3ef5d64e7198c17244778f6461fb1ab07f6169bf220   new, see below
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

## Network

```
247.cdnflare.xyz     malware download host    (2a06:98c1:3120::2, 2a06:98c1:3121::2)
99.84.67.186:443     C2, WebSocket over TLS   (published by Sansec)
```

Neither of our two packet captures, both over 200 MB and taken while the implant was live,
contained a single packet to either address. On one store the implant instead held 28
connections to `127.0.0.1:6379`, reading Magento's session storage out of the store's own
Redis.

**Do not treat quiet network monitoring as evidence of a clean host.**

## Source addresses

### Hosting infrastructure, bulk traffic

```
5.181.86.133    new    CloudVPS     96 requests against one store
88.216.72.181          (Sansec)     45 requests
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
a quarter of the traffic we saw. In total we recorded 26 distinct source addresses across two
stores.

## Request signatures

```
POST /graphql?styles[...]=            the exploit, percent-encoded in the wild
POST /paypal/transparent/response/?<?=eval(base64_decode('...    (published by Sansec)
GET  /customer/section/load/?sections=customer&force_new_section_timestamp=true
```

That last one is ordinary Magento traffic. In the variant we captured the payload rode in the
**User-Agent header** rather than the URL, so the request line on its own looks innocent.

### Trigger header

```
X-TRACE-<10 hex>
```

The value is regenerated per request. We recovered dozens of distinct values from a single
store's logs, so the value itself is worthless as an indicator and the **prefix** is what you
match:

```bash
grep -rlE 'X[_-]TRACE[_-][0-9A-Fa-f]{10}' var/report/ var/log/ /var/log/nginx/
```

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
