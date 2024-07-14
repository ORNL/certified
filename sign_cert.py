from typing import List, Optional

import argparse
import sys
import os
from datetime import datetime

import trustme

# ISO 8601
DATE_FORMAT = "%Y-%m-%d"


def from_list(param):
    return str(param[0]) if param else None

def main(argv : Optional[List[str]] = None) -> None:
    if argv is None:
        argv = sys.argv

    parser = argparse.ArgumentParser(prog="sign_cert")
    parser.add_argument(
        "--root",
        default="ca_root",
        help="Base name of root certificate to use for signing.",
    )
    parser.add_argument(
        "--out",
        default="cert",
        help="Base name of output signed certificate.",
    )
    parser.add_argument(
        "-i",
        "--identities",
        nargs="*",
        default=("localhost", "127.0.0.1", "::1"),
        help="Identities for the certificate. Defaults to 'localhost 127.0.0.1 ::1'.",
    )
    parser.add_argument(
        "--common-name",
        nargs=1,
        default=None,
        help="Also sets the deprecated 'commonName' field (only for the first identity passed).",
    )
    parser.add_argument(
        "-x",
        "--expires-on",
        default=None,
        help="Set the date the certificate will expire on (in YYYY-MM-DD format).",
        metavar="YYYY-MM-DD",
    )
    parser.add_argument(
        "-k",
        "--key-type",
        choices=list(t.name for t in trustme.KeyType),
        default="ECDSA",
    )

    args = parser.parse_args(argv[1:])
    identities = [str(identity) for identity in args.identities]
    common_name = from_list(args.common_name)
    expires_on = (
        None
        if args.expires_on is None
        else datetime.strptime(args.expires_on, DATE_FORMAT)
    )
    key_type = trustme.KeyType[args.key_type]

    with open(args.root + ".pem", "rb") as f:
        cert_bytes = f.read()
    with open(args.root + ".key", "rb") as f:
        private_key_bytes = f.read()
    # Load the CA certificate.
    ca = trustme.CA.from_pem(cert_bytes = cert_bytes,
                             private_key_bytes=private_key_bytes)

    cert = ca.issue_cert(
        *identities, common_name=common_name, not_after=expires_on, key_type=key_type
    )

    # Write the certificate and private key just created
    server_key = args.out + ".key"
    server_cert = args.out + ".pem"
    cert.private_key_pem.write_to_path(path=server_key)
    with open(server_cert, mode="w") as f:
        f.truncate()
    for blob in cert.cert_chain_pems:
        blob.write_to_path(path=server_cert, append=True)

    idents = "', '".join(identities)
    print(f"Generated a certificate for '{idents}'")
    print("Configure your application to use the following files:")
    print(f"  cert={server_cert}")
    print(f"  key={server_key}")

if __name__=="__main__":
    main(sys.argv)
