# @hmcrum/tls-cert-expiry

Standalone TLS certificate expiry checker. Give it hostnames, get back
days-until-expiry — no external service dependency.

`@lint/cert-health` already has a TLS-probe method that does the same
handshake, but it lives behind `globalArguments` that require Nginx Proxy
Manager credentials even if you never touch NPM. This model has none of
that: just the probe, with its own configurable warn/critical thresholds.

One method, `check`. TLS-handshakes every listed host (via `openssl
s_client`/`openssl x509` — Deno has no public API for reading a peer's
certificate chain, so this shells out the same way `@lint/cert-health`
does), classifies each by days remaining, and writes one resource per host
plus a fleet-wide summary. A probe failure (unreachable host, handshake
error, timeout) degrades that one host to `status: "error"` instead of
aborting the whole batch.

Requires `openssl` on the machine running swamp. No vault, no credentials,
no third-party account.

## Quick Start

```bash
swamp extension pull @hmcrum/tls-cert-expiry
swamp model create @hmcrum/tls-cert-expiry certs \
  --global-arg warnThresholdDays=30 --global-arg criticalThresholdDays=7
swamp model method run certs check \
  --input hosts='["example.com","gateway.example.net:8443"]'
```

## Example output

A run writes one `cert` resource per host plus a `summary` resource:

```json
{
  "host": "example.com",
  "port": 443,
  "status": "warn",
  "daysRemaining": 18,
  "notBefore": "Jan  1 00:00:00 2026 GMT",
  "notAfter": "Oct  5 23:59:59 2026 GMT",
  "subject": "/CN=example.com",
  "issuer": "/C=US/O=Example CA/CN=Example CA",
  "error": null,
  "checkedAt": "2026-09-17T22:33:00.014Z"
}
```

```json
{
  "total": 2,
  "ok": 1,
  "warn": 1,
  "critical": 0,
  "error": 0,
  "closestToExpiry": [ /* sorted soonest-expiry first, capped at 10 */ ],
  "truncated": false,
  "checkedAt": "2026-09-17T22:33:00.014Z"
}
```

## Design notes

- **No shell string interpolation.** `openssl` is invoked with an argument
  array, never a shell string, so a hostname can't be interpreted as a
  shell metacharacter.
- **Per-host isolation.** One dead or slow host degrades to an `error`
  status for that host alone; it never throws away results for the rest of
  the batch.
- **Injectable probe for testing.** The `check` method accepts an optional
  `_probe` override so unit tests can stand in for `openssl` entirely —
  see `tls_cert_expiry_test.ts`.
