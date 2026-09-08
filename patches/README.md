# APSB26-146: the official Adobe fix

Adobe released the fix for StyleSmuggler on 7 September 2026 as **APSB26-146**
(CVE-2026-75650, internal reference **VULN-39341**). It is rated CVSS 10.0 and Adobe
confirms it was exploited in the wild. This is the real fix. Apply it, and stop relying
on the interim mitigations this repository shipped before it existed.

Advisory: <https://helpx.adobe.com/security/products/magento/apsb26-146.html>
Knowledge base: <https://experienceleague.adobe.com/en/docs/commerce-knowledge-base/kb/announcements/commerce-apsb26-146>
Official hotfix: `https://repo.magento.com/patch/VULN-39341-composer-patches.zip`

## Why these files are here

Adobe ships VULN-39341 as single patch files rooted at the Magento project. Those do not
apply cleanly through `cweagans/composer-patches`, which patches per Composer package. The
folders below are the same patches repackaged per package by **yellowteak**
(<https://github.com/yellowteak/APSB26-146-patches>), reproduced here so you can apply the
official fix straight from `composer.json`. Credit for the repackaging is theirs.

**The patch content is Adobe's, not ours.** It is not covered by this repository's MIT
license; it is Adobe's official security fix, redistributed here for convenience. Refer to
Adobe's terms. If you want the untouched originals, take them from the hotfix zip above.

## What it fixes

The vulnerability class is one pattern: Magento instantiated an attacker-named class
(`objectManager->create($name)`, which resolves its constructor arguments and runs the
gadget) and only checked the type afterwards. The fix validates the type as a string,
before instantiation, everywhere that pattern appeared.

| Package | File | Change |
|---|---|---|
| `magento/framework` | `View/Element/BlockFactory.php` | Checks `is_a($resolvedType, BlockInterface, true)` before creating the block. Closes the `{{block class=…}}` gadget at its source. |
| `magento/framework` | `View/Layout/Generator/Block.php` | Catches the new `LogicException` from the factory. |
| `magento/framework` | `Webapi/ErrorProcessor.php` | Neutralises `<?` in the report and prepends `<?php exit;`. |
| `magento/module-backend` | `Model/Widget/Grid/Row/UrlGeneratorFactory.php` | Same type-before-instantiation check on the grid-row generator, the gadget pivot. |
| `magento/module-email` | `Model/AbstractTemplate.php` | `setTemplateStyles`/`setTemplateText` reject non-string input, killing the array injection vector. |
| `magento/module-email`, `magento/module-newsletter` | admin preview blocks | Require the admin ACL before rendering a preview. |
| `magento/magento2-base` | `pub/errors/processor.php` | Same report hardening as the webapi processor. |

Because the chain is cut at block instantiation, the DI code scanners the earlier interim
patch guarded are no longer reachable through the exploit. That interim patch is removed;
this one supersedes it.

## Applying, the easy way

```bash
composer require disrex/stylesmuggler-adobe-patches
```

That package is a Composer plugin: it detects your version and applies Adobe's patch itself, on
both Magento Open Source and Mage-OS. It needs no `cweagans/composer-patches` and no
`enable-patching`. Answer `y` when Composer asks whether to trust the plugin (or pre-allow it
for CI), otherwise it is skipped and nothing is patched. Details, version coverage and
limitations are in
[stylesmuggler-adobe-patches](https://github.com/disrex-group/stylesmuggler-adobe-patches).

## Applying by hand

If you would rather not add the package, apply the same patches directly:

1. Copy the folder matching your exact Magento version into `patches/` at your Composer
   project root, for example `patches/APSB26-146_249`.
2. Merge that folder's `patches.json` into your `composer.json`, under `extra.patches`.
   Keep `"composer-exit-on-patch-failure": true` so a failed hunk stops the deploy.
3. Run `composer -o install` and confirm every patch reports as applied.

```
patches/APSB26-146_244p18   2.4.4-p18
patches/APSB26-146_245p17   2.4.5-p17
patches/APSB26-146_246p15   2.4.6-p15
patches/APSB26-146_247p10   2.4.7-p10
patches/APSB26-146_248p5    2.4.8-p5
patches/APSB26-146_249      2.4.9
```

A patch that fails to apply almost always means the vendor file already moved in a newer
Magento release. Use the folder for your exact `magento/product-community-edition` version,
or apply Adobe's hotfix zip directly.

## Verifying

If you run Adobe's Quality Patches Tool:

```bash
vendor/bin/magento-patches -n status | grep '39341\|Status'
```

## After patching

Patching closes the door. It does not undo a break-in. If you found any indicator in
[IOC.md](../IOC.md), rotate the encryption key, database and admin credentials, API tokens
and payment-gateway keys, and work through [CLEANUP.md](../CLEANUP.md). Adobe's own bulletin
says the same.

## Credit for the interim period

Before Adobe's fix, three parties built the application-layer guards this repository used:
brideo / Upturn, Graycore, and ProxiBlue (Lucas van Staden), who independently reached the
same sink guard. Their work held the line until 7 September. It is superseded now, and the
credit stands.
