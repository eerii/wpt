#!/usr/bin/env python3
"""Generate the WPT-CA-signed certificate matrix used by the TLS sidecar.

The sidecar selects a TLS profile by SNI, so each profile needs a server
certificate whose SAN covers the subdomain the test addresses. These are
generated once and committed under ``tools/certs/tls/``; regenerate with:

    python3 tools/tls/gen_certs.py [--openssl /path/to/openssl]

Requires OpenSSL on ``PATH`` (or via ``--openssl`` / ``$OPENSSL``). The WPT CA
key is encrypted; the passphrase is the same as the rest of the WPT test certs.
"""

import argparse
import datetime
import os
import shutil
import subprocess
import sys


WPT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
CA_CERT = os.path.join(WPT_ROOT, "tools", "certs", "cacert.pem")
CA_KEY = os.path.join(WPT_ROOT, "tools", "certs", "cacert.key")
CA_PASSPHRASE = "web-platform-tests"
DEFAULT_OUT = os.path.join(WPT_ROOT, "tools", "certs", "tls")

HOSTS = ("localhost", "web-platform.test")


def date(days_from_now):
    when = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=days_from_now)
    return when.strftime("%y%m%d%H%M%SZ")


# name -> (sans, not_before_days, not_after_days, self_signed)
PROFILES = {
    "tls13": (["localhost", "web-platform.test", "tls13.localhost",
               "tls13.web-platform.test"], 0, 365, False),
    "tls12": (["localhost", "web-platform.test", "tls12.localhost",
               "tls12.web-platform.test"], 0, 365, False),
    "cauth": (["localhost", "web-platform.test", "cauth.localhost",
               "cauth.web-platform.test"], 0, 365, False),
    "expired": (["expired.localhost", "expired.web-platform.test"], -30, -1, False),
    "notyet": (["notyet.localhost", "notyet.web-platform.test"], 1, 30, False),
    "wronghost": (["wrong.example"], 0, 365, False),
    "selfsigned": (["selfsigned.localhost", "selfsigned.web-platform.test"],
                   0, 365, True),
}


class CertGenerator:
    def __init__(self, openssl, out_dir):
        self.openssl = openssl
        self.out_dir = out_dir

    def run(self, *args):
        subprocess.check_call([self.openssl, *args])

    def san_extension(self, sans):
        return "subjectAltName=" + ",".join("DNS:" + name for name in sans)

    def generate(self, name, sans, before, after, self_signed):
        key_path = os.path.join(self.out_dir, name + ".key")
        cert_path = os.path.join(self.out_dir, name + ".pem")
        self.run("genrsa", "-out", key_path, "2048")
        if self_signed:
            self.run("req", "-x509", "-new", "-key", key_path, "-out", cert_path,
                     "-subj", "/CN=" + name,
                     "-addext", self.san_extension(sans),
                     "-addext", "extendedKeyUsage=serverAuth",
                     "-addext", "basicConstraints=CA:FALSE",
                     "-not_before", date(before), "-not_after", date(after))
            return
        csr_path = os.path.join(self.out_dir, name + ".csr")
        ext_path = os.path.join(self.out_dir, name + ".ext")
        self.run("req", "-new", "-key", key_path, "-out", csr_path,
                 "-subj", "/CN=" + name)
        with open(ext_path, "w") as ext:
            ext.write(self.san_extension(sans) + "\n")
            ext.write("extendedKeyUsage=serverAuth\n")
            ext.write("basicConstraints=CA:FALSE\n")
        self.run("x509", "-req", "-in", csr_path, "-CA", CA_CERT, "-CAkey", CA_KEY,
                 "-passin", "pass:" + CA_PASSPHRASE, "-CAcreateserial",
                 "-out", cert_path, "-extfile", ext_path,
                 "-not_before", date(before), "-not_after", date(after))
        os.unlink(csr_path)
        os.unlink(ext_path)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--openssl", default=os.environ.get("OPENSSL"),
                        help="Path to the openssl binary")
    parser.add_argument("--out", default=DEFAULT_OUT,
                        help="Output directory for the generated certificates")
    args = parser.parse_args()

    openssl = args.openssl or shutil.which("openssl")
    if openssl is None:
        print("openssl not found; pass --openssl or set $OPENSSL", file=sys.stderr)
        return 1

    os.makedirs(args.out, exist_ok=True)
    # Work in a temp dir so the CA serial file does not litter the output.
    generator = CertGenerator(openssl, args.out)
    for name, (sans, before, after, self_signed) in PROFILES.items():
        generator.generate(name, sans, before, after, self_signed)
    # Remove the serial file the CA signing step creates.
    for serial in (CA_CERT + ".srl", os.path.splitext(CA_CERT)[0] + ".srl"):
        if os.path.exists(serial):
            os.unlink(serial)
    print("wrote certificates for %d profiles to %s" % (len(PROFILES), args.out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
