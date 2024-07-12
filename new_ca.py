from typing import List, Optional
import argparse
import os
import sys

import trustme

def from_list(param):
    return str(param[0]) if param else None

def main(argv: Optional[List[str]] = None) -> None:
    if argv is None:
        argv = sys.argv

    parser = argparse.ArgumentParser(prog="new_ca")
    parser.add_argument(
        "-d",
        "--dir",
        default=os.getcwd(),
        help="Directory where certificates and keys are written to. Defaults to cwd.",
    )
    parser.add_argument(
        "--organization-name",
        nargs=1,
        default=None,
        help="Organization name."
    )
    parser.add_argument(
        "--unit-name",
        nargs=1,
        default=None,
        help="Organization unit name."
    )
    parser.add_argument(
        "-k",
        "--key-type",
        choices=list(t.name for t in trustme.KeyType),
        default="ECDSA",
    )

    args = parser.parse_args(argv[1:])
    cert_dir = args.dir
    key_type = trustme.KeyType[args.key_type]

    if not os.path.isdir(cert_dir):
        raise ValueError(f"--dir={cert_dir} is not a directory")

    # Generate the CA certificate.
    ca = trustme.CA(path_length = 1,
                    organization_name = from_list(args.organization_name),
                    organization_unit_name = from_list(args.unit_name),
                    key_type=key_type)

    # Write the certificate the client should trust
    ca_cert = os.path.join(cert_dir, "ca_root.pem")
    ca_key = os.path.join(cert_dir, "ca_root-key.pem")
    ca.private_key_pem.write_to_path(path=ca_key)
    ca.cert_pem.write_to_path(path=ca_cert)
    print("Configure your client to use the following file:")
    print(f"  cert={ca_cert}")
    print("Use the following to sign cert-requests:")
    print(f"  cert={ca_key}")

if __name__=="__main__":
    main(sys.argv)
