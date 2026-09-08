# Magento modules

> **Superseded by Adobe APSB26-146 (7 September 2026).** With the official patch applied
> (see [`../patches/`](../patches/)) the guard module is no longer needed: Adobe fixes the
> same block-instantiation, template-styles and error-report paths the module guarded, at
> the source. On a patched store, disable and remove it:
> `bin/magento module:disable Disrex_StyleSmugglerGuard && composer remove disrex/module-stylesmuggler-guard`.
> The rest of this page is kept as the record of the interim mitigation.

## Disrex_StyleSmugglerGuard

The application-layer guard module now lives in its own repository so you can install it
with a normal `composer require` instead of a path repository:

**https://github.com/disrex-group/module-stylesmuggler-guard**

```bash
composer require disrex/module-stylesmuggler-guard
bin/magento module:enable Disrex_StyleSmugglerGuard
bin/magento setup:upgrade && bin/magento setup:di:compile
```

It bundles the styles sanitiser, the `{{block}}` DI/Setup allow-list, store-not-found log
hygiene, and an optional default-off failed-payment containment. Built on brideo / Upturn
(MIT), with the styles-sanitiser hook corrected to `getProcessedTemplate` (the magic
`setTemplateStyles` a plugin cannot intercept). Full detail in that repository's README.

Keeping the module in one place stopped two copies drifting. Since 7 September the patch in
[`../patches/`](../patches/) is Adobe's official fix, which replaces both the module and the
old sink patch.

## Disabling GraphQL

Not a module, on purpose. A controller plugin does not fire and a front-controller preference
does not win, both verified on 2.4.8, so a GraphQL-disable module would silently fail to
disable GraphQL. Use the web-server rule (`location ^~ /graphql { return 403; }` in
[`../snippets/`](../snippets/)) or `bin/magento module:disable`.
