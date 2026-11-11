"""certificate-blob-preserved."""
from __future__ import annotations

import datetime

CHECK = "certificate-blob-preserved"
GROUP = "representation"
SERVICES = ["transfer"]

from behavioral_harness import tags
from fidelity_tests_runner import RequiredToolMissing

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import rsa as _rsa
    from cryptography.hazmat.primitives.serialization import Encoding as _Encoding
    from cryptography.x509.oid import NameOID

    _CRYPTO_AVAILABLE = True
except ImportError:
    _CRYPTO_AVAILABLE = False


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A PEM certificate blob given to ImportCertificate round-trips byte-identically
    through DescribeCertificate."""
    if not _CRYPTO_AVAILABLE:
        raise RequiredToolMissing(["cryptography"], "module")

    transfer = ctx.client("transfer")

    pem = _generate_self_signed_cert_pem()

    certificate_id = transfer.import_certificate(
        Usage="SIGNING",
        Certificate=pem,
        Description=ctx.unique_name("sim2real-cert-"),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["CertificateId"]
    ctx.on_cleanup(lambda: transfer.delete_certificate(CertificateId=certificate_id))

    described = transfer.describe_certificate(CertificateId=certificate_id)["Certificate"]
    got = described["Certificate"]
    # AWS Transfer strips a single trailmg newline after the PEM footer when it
    # stores/returns the certificate; the certificate bytes themselves (and any
    # interior formatting) must still be preserved exactly.
    expected = pem.rstrip("\n")
    assert got == expected, (
        "certificate PEM body was altered by the round trip (beyond a trailing "
        f"newline); sent {len(pem)} bytes {pem!r}, got {len(got)} bytes {got!r}"
    )


def _generate_self_signed_cert_pem() -> str:
    key = _rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "sim2real.transfer.test")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=30))
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(_Encoding.PEM).decode()


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
