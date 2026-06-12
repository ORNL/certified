# certified.cert_info — CertInfo

`CertInfo` is the intermediate data structure used when constructing certificates.
It holds the subject name, subject alternative names, public key, and CA flag,
and can be loaded from a CSR or existing certificate.

Module also defines the `CA_Usage`, `EE_Usage`, and `EE_Extension` x509 extension
constants used when issuing certificates.

## CertInfo

::: certified.cert_info.CertInfo
