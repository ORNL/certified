# API Reference

This reference covers all public classes and functions in `certified`.

| Module | Contents |
|--------|----------|
| [cert](cert.md) | `Certified` — the main config/connection manager |
| [ca](ca.md) | `CA`, `LeafCert` — certificate authority and leaf cert types |
| [encode](encode.md) | Name and SAN builders, key types, certificate helpers |
| [models](models.md) | Pydantic config models (`TrustedService`, `TrustedClient`, `LokiConfig`) |
| [fast](fast.md) | FastAPI integration: auth dependencies, biscuit authz |
| [layout](layout.md) | Config directory layout, path resolution |
| [blob](blob.md) | `Blob` — safe file I/O for PEM/key material |
| [cert_info](cert_info.md) | `CertInfo` — certificate builder input |
| [cert_base](cert_base.md) | `FullCert` — shared base for CA and LeafCert |
| [serial](serial.md) | PEM / base64-DER serialization helpers |
