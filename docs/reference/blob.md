# certified.blob — Blob: Safe PEM File I/O

`Blob` is a thin wrapper around `bytes` that tracks whether the data is
secret (private key) or public (certificate), and enforces appropriate
file permissions (`0o600` for secrets, `0o644` for public data) on write.

## Blob

::: certified.blob.Blob

## PublicBlob

::: certified.blob.PublicBlob

## PrivateBlob

::: certified.blob.PrivateBlob

## is_user_only

::: certified.blob.is_user_only

## new_file

::: certified.blob.new_file
