# The email that surfaced it

This is the single most useful early-warning sign for a merchant, and it is the reason
one of these compromises was caught the same day rather than weeks later. It is not a
log line or a scanner alert. It is a garbled order-notification email that the store
sends to its own owner.

If you run a Magento store and one of these lands in your inbox, treat it as a possible
StyleSmuggler probe and check your server. Do not dismiss it as a broken order.

## Why it happens

When the attacker's payload passes through Magento's template filter, the same filter
that renders order-notification emails chokes on the injected directives. The store then
emails the merchant a "failed transaction" notice in which the template variables were
never resolved. So the merchant receives an email full of raw `{{var ...}}` and
`{{depend ...}}` tags, a customer address on a `.invalid` domain, and a total of zero.

It reads like a broken checkout. It is exhaust from an exploitation attempt.

## What it looked like

Received 5 September 2026, 13:10. Subject: **Herinnering mislukte betalingstransactie**
("Reminder: failed payment transaction"). Merchant-identifying headers removed.

```
Betalingstransactie mislukt          [Payment transaction failed]

  Activiteit      Transactie afgewezen         [Activity: transaction rejected]
  Kassa-Type      onepage
  Klant           Bezoeker <524e824ed66da44d468120bf@nx.invalid>
  Items
  Totaal          EUR 0.0000
  Factuuradres    A B
                  Acme
                  {{var postcode}}{{var postcode}}Er is een fout opgetreden bij
                  het genereren van deze content.
                  België
                  T: 0
  Bezorgadres     {{depend prefix}}{{var prefix}} {{/depend}} {{depend middlename}}
                  {{var middlename}} {{/depend}}{{depend suffix}} {{var suffix}}
                  {{/depend}}{{depend firstname}}{{/depend}} {{depend company}}
                  {{var company}}{{/depend}} {{if street1}}{{var street1}}{{/if}}
                  {{depend street2}}{{var street2}}{{/depend}} {{depend street3}}
                  {{var street3}}{{/depend}} {{depend street4}}{{var street4}}
                  {{/depend}} {{if city}}{{var city}}, {{/if}}{{if region}}
                  {{var region}}, {{/if}}{{if postcode}}{{var postcode}}{{/if}}

                  {{depend telephone}}T: {{var telephone}}{{/depend}} {{depend fax}}
                  F: {{var fax}}{{/depend}} {{depend vat_id}}
                  VAT: {{var vat_id}}{{/depend}}
  Verzendmethode
  Betaalmethode
  Datum & Tijd    5 sep. 2026 13:10:05
```

## The tells, in order of reliability

1. **Unresolved template tags in the body.** `{{var postcode}}`, `{{depend ...}}`,
   `{{if street1}}`. A real notification never shows these; the store renders them into
   values. Raw tags mean the template filter was fed something it could not process.
2. **`Er is een fout opgetreden bij het genereren van deze content.`** — Magento's own
   "an error occurred generating this content" fallback, sitting inside the address.
3. **A customer address ending in `.invalid`**, with a long hex local part
   (`524e824ed66da44d468120bf@nx.invalid`). `.invalid` is a reserved domain that can
   never exist; the attacker uses the value as a per-probe correlation ID.
4. **Zero total, no items, no shipping or payment method.** There was no real order.
5. **Placeholder names** like `A B` / `Acme` in the billing address.

Any one of the first three is enough to stop and look at the server.

## What to do if you receive one

Do not reply, do not delete, and do not change anything on the store yet. Forward it to
whoever runs your hosting, and run the read-only checks in [README.md](README.md) §1. In
the incident this came from, the merchant forwarded exactly this email, and that forward
is what started the investigation that found the implant within the hour.

See [HOW-IT-WORKS.md](HOW-IT-WORKS.md) for why the template filter produces this, and
[CLEANUP.md](CLEANUP.md) if the checks turn up indicators.
