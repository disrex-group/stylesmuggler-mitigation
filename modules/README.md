# Magento modules

Application-layer options for stores you can deploy Magento code to. Everything here is
interim mitigation — remove it once Adobe ships an official fix.

## Disrex_StyleSmugglerGuard

Config-gated guards that run inside Magento:

- **Template-styles sanitiser** — blanks an email template's styles value if it carries a
  `{{ }}` directive, a PHP tag, or a `\Namespace\` separator. Legitimate styles are plain
  CSS, so real mail is untouched. Hooks `getProcessedTemplate` (a real method), not
  `setTemplateStyles` (a magic setter a plugin cannot intercept).
- **Block-directive allow-list** — rejects `{{block class="..."}}` naming a DI/Setup/Code
  namespace.
- **Log-poison hygiene** — strips PHP tags from the store-not-found exception before it is
  logged (one known stage-1 sink).
- **Payment-failure containment** — optional, **default off**; suppresses the failed-payment
  email whose render is the trigger. Trade-off: the merchant stops receiving those emails.

Built on brideo / Upturn's module (https://github.com/brideo/stylesmuggler-patch, MIT),
credited in each file, with the styles-sanitiser hook corrected to one that actually fires.
Verified on 2.4.8: guards fire, legitimate CSS is untouched, `setup:di:compile` and the
storefront both fine.

### Install (composer, path repository)

From your Magento root:

```bash
composer config repositories.stylesmuggler-guard path /path/to/stylesmuggler-mitigation/modules/Disrex/StyleSmugglerGuard
composer require disrex/module-stylesmuggler-guard:@dev
bin/magento module:enable Disrex_StyleSmugglerGuard
bin/magento setup:upgrade && bin/magento setup:di:compile
```

Or copy `Disrex/StyleSmugglerGuard` into `app/code/Disrex/StyleSmugglerGuard` and run the
last two commands. Toggles live under Stores → Configuration → Advanced → StyleSmuggler Guard.

### Remove (once Adobe patches)

```bash
bin/magento module:disable Disrex_StyleSmugglerGuard
composer remove disrex/module-stylesmuggler-guard
bin/magento setup:upgrade && bin/magento setup:di:compile
```

## Disabling GraphQL is not a module here — on purpose

Sansec's interim advice is to disable GraphQL where a store does not need it. We tried to
ship that as a Magento module and did not: a plugin on `Magento\GraphQl\Controller\GraphQl
::dispatch` does not fire in the graphql area, and a front-controller preference did not win
either — verified on 2.4.8, GraphQL kept serving 200. brideo reached the same conclusion and
also disables GraphQL at the web server, not in Magento. Shipping a module that silently fails
to disable GraphQL would be worse than none: the merchant would believe they were protected.

Use one of these instead, both reliable:

1. **Web server** — uncomment the GraphQL block in [`../snippets/nginx.conf`](../snippets/nginx.conf)
   or [`../snippets/apache.conf`](../snippets/apache.conf). Returns 403 for `/graphql`. Check
   first that nothing consumes GraphQL: `grep -c '"POST /graphql' <access.log>` (headless/PWA
   storefronts do; most classic and Hyvä storefronts do not).
2. **Magento native** — `bin/magento module:disable` the GraphQl modules. Heavier: it breaks
   dependent modules and needs a recompile, so prefer the web-server rule for a quick, reversible
   switch.
