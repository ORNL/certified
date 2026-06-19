# certified.serial — PEM / DER / Base64 Serialization

Helpers for converting between certificate representations:
PEM (ASCII armored), DER (binary), and URL-safe base64-DER.

The `alt=True` default uses `-_` as base64 altchars, making the output
safe for use in URLs and HTTP headers without percent-encoding.

## High-level helpers

### pem_to_cert

::: certified.serial.pem_to_cert

### cert_to_pem

::: certified.serial.cert_to_pem

### b64_to_cert

::: certified.serial.b64_to_cert

### cert_to_b64

::: certified.serial.cert_to_b64

### pem_to_csr

::: certified.serial.pem_to_csr

### b64_to_csr

::: certified.serial.b64_to_csr

### serial_number

::: certified.serial.serial_number

## Low-level helpers

### b64_to_der

::: certified.serial.b64_to_der

### der_to_b64

::: certified.serial.der_to_b64
