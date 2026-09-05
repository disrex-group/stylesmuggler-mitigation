# Security policy

## Reporting a problem with this mitigation

Open a GitHub issue for anything that does not involve attacker-usable detail: a false
positive, a store that broke, a Magento version where the hardening script reports
`unrecognised method signature`.

For anything that would help an attacker, including a bypass of these rules, email
**support@disrex.nl** instead of filing publicly. Include the rule you bypassed and the
Magento version. Expect a reply within two working days.

## Reporting the underlying vulnerability

This repository mitigates a vulnerability it did not discover. Send new findings about
StyleSmuggler itself to the [Sansec forensics team](https://sansec.io/contact) and to
Adobe PSIRT, not here.

## Scope

These rules reduce exposure. They are not a vendor patch and they are not a guarantee.
Replace them with Adobe's official fix once it ships, and re-run the scanner afterwards
to confirm nothing arrived in the meantime.
