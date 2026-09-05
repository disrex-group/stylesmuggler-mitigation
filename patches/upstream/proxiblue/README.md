# ProxiBlue's DI-scanner patches (independent, same fix)

These three patches are **ProxiBlue's**, not ours, reproduced here with credit.

Source: <https://gist.github.com/ProxiBlue/07373c92c8c70dc746bbfdcd1f07b789>
Author: ProxiBlue (Lucas van Staden)

## Why they are here

ProxiBlue published these independently, and they land on the **same three DI scanner
methods** as our `../../magento/magento2-base/stylesmuggler-di-scanner-guard.patch`,
with the same `PHP_SAPI !== 'cli'` guard and the same exception message. Two parties
arriving at the identical fix separately is the strongest signal available that it is
the right one. We include ProxiBlue's originals so that convergence is visible and
verifiable rather than asserted.

Verified: all three apply cleanly with `patch -p1 --dry-run` against Magento 2.4.6,
2.4.7, 2.4.8 and 2.4.9.

## Do not apply these on top of ours

They make the same edit to the same methods. Applying both our combined patch and these
three would fail on the second apply, or double-insert the guard. Pick one:

- **Our patch** (`../../magento/magento2-base/stylesmuggler-di-scanner-guard.patch`) —
  one file covering all three scanners, wired for composer-patches under
  `magento/magento2-base`.
- **ProxiBlue's three** — one patch per scanner. Same effect. Use these if you prefer
  per-file patches or are already tracking ProxiBlue's gist.

Either closes the sink. Neither is a complete fix on its own; see the repository root
for the layers that do not depend on the entry point (`disable_functions` incl.
`proc_open`, and `noexec`).

## Difference from our version

Only cosmetic: ProxiBlue's comment text and 6-line diff context differ slightly from
ours, and they ship three files where we ship one. The guard itself is identical.
