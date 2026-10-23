# TradingMeow license distribution

This public repository contains encrypted license grants and signed authorization metadata. It does not contain customer contact/payment details, device private keys, or the publisher root signing key.

The authoritative publisher root is embedded in the customer binary. A root key listed here is not, by itself, a new trust anchor.

Administrator setup:

1. Create this repository with a `main` branch.
2. In the local administrator tool, save a fine-grained repository token with Contents write permission. The first workflow installation also needs Workflows write permission.
3. Download the limited-purpose status key and save its text as the repository Actions Secret `TRADINGMEOW_STATUS_PRIVATE_KEY`.
4. Publish from the local administrator tool and verify the status workflow succeeds.

The scheduled workflow refreshes the signed status every six hours. GitHub schedules can be delayed or disabled; status expires at its signed deadline (at most 72 hours), never 72 hours after a client download. The local administrator tool can publish a fresh signed status if automation fails.

Do not enable public pull-request workflows that receive signing Secrets. Do not add customer enrollment files, the local administrator vault, compiler debug files, or proprietary bridge source here.
