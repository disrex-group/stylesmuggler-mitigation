# StyleSmuggler source patches

> Written with AI assistance during a live incident. The guards are grounded in
> two real compromises; the patch application was verified against Magento
> 2.4.6, 2.4.7, 2.4.8 and 2.4.9, and against live 2.4.7-p2 and 2.4.8-p4 installs.
> Read them before applying, and test a deploy on staging first.

Two `patch -p1` files that harden the StyleSmuggler chain in Magento source. They
replace the hand-edits an incident-response run makes on a live box with something
your deploy pipeline reapplies on every `composer install`.

There is still no vendor fix. Remove these once Adobe ships one.

## What each patch does

| Patch | Package | Guard |
|---|---|---|
| `stylesmuggler-di-scanner-guard.patch` | `magento/magento2-base` | The three DI code scanners that `include`/`require` a caller-supplied path refuse to run outside CLI. This is the **sink**. |
| `stylesmuggler-preview-area-guard.patch` | `magento/module-email` | The email template preview block refuses to render outside the admin area. This is the **entry point** — the request that starts the whole chain. |

The entry guard is the stronger of the two: it closes the front door, so every
gadget behind it becomes unreachable, including sinks these patches do not touch
(`TemplateEngine\Php` and friends, which cannot be guarded because every page
render uses them). The sink guard is defence in depth for the one case a future
gadget reaches a DI scanner by another route.

Neither touches a code path a normal storefront, a normal admin, or
`bin/magento setup:di:compile` uses. Verified: the DI compile runs fine with the
CLI guard in place, because it runs from the CLI.

## Version coverage

The target methods sit at the same place with identical surrounding lines from
2.4.6 through 2.4.9, so one patch per file applies across all of them. Tested with
`patch -p1 --dry-run` against every `.0` tag in that range, and applied-and-linted
against live 2.4.7-p2 and 2.4.8-p4.

If a future release moves a method, `patch` reports a failed hunk rather than
mispatching — `composer-exit-on-patch-failure` then stops the deploy so you notice.

## Applying with composer-patches

You already have `cweagans/composer-patches`. Add to the root `composer.json`,
merging into any existing `extra.patches`:

```json
"extra": {
    "composer-exit-on-patch-failure": true,
    "patches": {
        "magento/magento2-base": {
            "StyleSmuggler: DI code scanners are CLI-only (Sansec 2026-09-05, no CVE yet)": "patches/magento/magento2-base/stylesmuggler-di-scanner-guard.patch"
        },
        "magento/module-email": {
            "StyleSmuggler: email template preview is admin-area only (Sansec 2026-09-05)": "patches/magento/module-email/stylesmuggler-preview-area-guard.patch"
        }
    }
}
```

Copy the `patches/` tree next to `composer.json`, then:

```bash
composer -o install     # or: composer -o prod:di:compile after a patch change
```

## Applying by hand (an already-running box)

```bash
cd <magento-root>
patch -p1 --forward < stylesmuggler-di-scanner-guard.patch
cd vendor/magento/module-email
patch -p1 --forward < stylesmuggler-preview-area-guard.patch
```

`--forward` skips a hunk that is already applied instead of offering to reverse it,
so re-running is safe. Then `bin/magento setup:di:compile` and check the storefront
and the admin still load.

**If you already applied the guard some other way** (an IR script, an earlier
version of these files), the patch will report a failed hunk because the text is
already there in a different form. Revert that first, or rely on composer-patches
which always works from a clean vendor extract.

## Reverting

```bash
patch -p1 --reverse < stylesmuggler-di-scanner-guard.patch
```

Or drop the `extra.patches` entries and `composer -o install`.

## Verifying it took

```bash
grep -c 'StyleSmuggler mitigation' \
  <root>/setup/src/Magento/Setup/Module/Di/Code/Scanner/ArrayScanner.php \
  <root>/vendor/magento/module-email/Block/Adminhtml/Template/Preview.php

bin/magento setup:di:compile      # must still succeed
```
