# Concept Guide

`certified` separates **authentication** (x509 mTLS — *who are you?*) from
**authorisation** (biscuit tokens — *what may you do?*). The pages below explain
how each layer works and why the design is split this way.

- [Key Management](keys.md) — PKI key layout, trust chains, expiry vs revocation, and comparison with GPG/SSH/myproxy
- [Cross-chain Trust](cross_chain_trust.md) — federated trust between orgs: directory layout evolution, service definitions, and connection walkthrough
- [Authorization Model](authz.md) — biscuit tokens, scope files, and how authz is kept separate from authentication
- [Certificates vs Tokens](certs_vs_tokens.md) — background on what certificates and signed tokens are, their pitfalls, and why you need both
