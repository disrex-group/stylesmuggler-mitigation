# StyleSmuggler source patch

> Written with AI assistance during a live incident. The guard is grounded in two
> real compromises; application was verified against Magento 2.4.6, 2.4.7, 2.4.8 and
> 2.4.9, and against live 2.4.7-p2 and 2.4.8-p4 installs with `setup:di:compile` and
> the storefront confirmed working afterwards. Read it before applying, and test a
> deploy on staging first.

One `patch -p1` file that hardens the StyleSmuggler **sink** in Magento source. It
replaces the hand-edit an incident-response run makes on a live box with something
your deploy pipeline reapplies on every `composer install`.

There is still no vendor fix. Remove this once Adobe ships one.

## What it does

| Patch | Package | Guard |
|---|---|---|
| `stylesmuggler-di-scanner-guard.patch` | `magento/magento2-base` | The three DI code scanners that `include`/`require` a caller-supplied path refuse to run outside CLI. |

The gadget chain ends when one of these DI scanners runs `include $file` on an
attacker-controlled path. All three exist only to serve `bin/magento setup:di:compile`
and are never legitimately reached over HTTP, so a `PHP_SAPI !== 'cli'` guard removes
the sink at no functional cost. Verified: `setup:di:compile` still runs, because it
runs from the CLI.

## Why there is no entry-point patch

An earlier version of this folder also shipped a patch on
`Magento\Email\Block\Adminhtml\Template\Preview`, on the theory that the email
template preview was the chain's front door. That was wrong, and it was removed.

The request parameters (`text`, `type`, `styles`) match that block's fields, but the
block has an **admin-only route** and the exploit never goes through it. The template
processing the gadget actually drives lives in the model
`Magento\Email\Model\AbstractTemplate::getProcessedTemplate`, reached through
object injection rather than routing. That method cannot be area-guarded: it renders
every legitimate transactional email in the frontend design area, so a guard there
would break order confirmations and newsletters.

So the entry point has no clean guard. The defensible layers are the sink guard here,
plus the two that do not depend on knowing the vulnerability at all:

- **`disable_functions` including `proc_open`** — no exec function, no dropped implant,
  whatever sink the attacker reaches.
- **`noexec` on `/tmp`, `/var/tmp`, `/dev/shm`** — the downloaded binary cannot run.

See the main README and HOW-IT-WORKS.md for those.

## Version coverage

The three target methods sit at identical surrounding lines from 2.4.6 through 2.4.9,
so the one patch applies across all of them. Tested with `patch -p1 --dry-run` against
every `.0` tag in that range, and applied-and-linted against live 2.4.7-p2 and 2.4.8-p4.

If a future release moves a method, `patch` reports a failed hunk rather than
mispatching. `composer-exit-on-patch-failure` then stops the deploy so you notice.

## Applying with composer-patches

You already have `cweagans/composer-patches`. Add to the root `composer.json`,
merging into any existing `extra.patches`:

```json
"extra": {
    "composer-exit-on-patch-failure": true,
    "patches": {
        "magento/magento2-base": {
            "StyleSmuggler: DI code scanners are CLI-only (Sansec 2026-09-05, no CVE yet)": "patches/magento/magento2-base/stylesmuggler-di-scanner-guard.patch"
        }
    }
}
```

Copy the `patches/` tree next to `composer.json`, then:

```bash
composer -o install
```

## Applying by hand (an already-running box)

```bash
cd <magento-root>
patch -p1 --forward < patches/magento/magento2-base/stylesmuggler-di-scanner-guard.patch
bin/magento setup:di:compile     # must still succeed
```

`--forward` skips a hunk that is already applied, so re-running is safe. If you applied
the guard some other way, the patch reports a failed hunk because the text is already
there in a different form — revert that first, or rely on composer-patches which works
from a clean vendor extract.

## Reverting

```bash
patch -p1 --reverse < patches/magento/magento2-base/stylesmuggler-di-scanner-guard.patch
```

Or drop the `extra.patches` entry and `composer -o install`.

## Verifying it took

```bash
grep -c 'StyleSmuggler mitigation' \
  <root>/setup/src/Magento/Setup/Module/Di/Code/Scanner/ArrayScanner.php

bin/magento setup:di:compile      # must still succeed
```
