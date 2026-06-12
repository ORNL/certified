# How-To Guides

Practical recipes for common tasks.  Each guide covers one CLI command or
workflow; see the [CLI reference](../cli.md) for full flag listings.

| Guide | Commands |
|---|---|
| [Create a new identity](init.md) | `certified init` |
| [Inspect your certificates](inspect.md) | `certified get-ident`, `certified get-signer`, `openssl` |
| [Cross-org introduction](introduce.md) | `certified introduce`, `certified add-intro` |
| [Add a known service](add-service.md) | `certified add-service` |
| [Trust a client](add-client.md) | `certified add-client` |
| [Join an organization](set-org.md) | `certified set-org` |
| [Call an mTLS API](api-client.md) | `message`, `Certified.Client`, `Certified.ClientSession` |
| [Run an mTLS server](api-server.md) | `certified serve` |
| [Rich JSON logging](logging.md) | `certified serve --loki` |
