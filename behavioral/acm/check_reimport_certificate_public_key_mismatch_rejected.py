"""reimport-certificate-public-key-mismatch-rejected."""
from __future__ import annotations

import datetime

from behavioral_harness import tags

CHECK = "reimport-certificate-public-key-mismatch-rejected"
GROUP = "overly-permissive"
SERVICES = ["acm"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Importing (or reimporting) a certificate together with a PrivateKey that does not correspond to
    that certificate's public key is rejected outright, and does not mutate any existing certificate."""
    import cryptography  # noqa: F401

    from botocore.exceptions import ClientError

    acm = ctx.client("acm")
    domain = _domain(ctx, "keymismatch")

    leaf1_pem, key1_pem, _key1 = _generate_self_signed_cert(domain)
    arn = acm.import_certificate(
        Certificate=leaf1_pem, PrivateKey=key1_pem, Tags=[{"Key": "sim2real", "Value": CHECK}]
    )["CertificateArn"]
    ctx.on_cleanup(lambda: _safe_delete(acm, arn))

    # Positive control: the original import with a matching key succeeded and is retrievable.
    got_before = acm.get_certificate(CertificateArn=arn)
    before_pem = got_before["Certificate"].encode() if isinstance(got_before["Certificate"], str) else got_before["Certificate"]
    assert _cert_fingerprint(before_pem) == _cert_fingerprint(leaf1_pem), (
        "the positive-control import must be retrievable and byte-identical to what was submitted"
    )

    # A second certificate/key pair for the same domain, signed with an unrelated key.
    leaf2_pem, key2_pem, _key2 = _generate_self_signed_cert(domain)

    # The mismatch under test: submit leaf2's certificate body paired with key1 (which does NOT
    # correspond to leaf2's public key). This must be rejected regardless of the CertificateArn target.
    try:
        acm.import_certificate(Certificate=leaf2_pem, PrivateKey=key1_pem, CertificateArn=arn)
        raise AssertionError("reimport with a mismatched certificate/private-key pair must be rejected")
    except ClientError as err:
        code = err.response["Error"]["Code"]
        message = err.response["Error"].get("Message", "")
        assert code == "ValidationException", code
        # The exact message separates this from a malformed-PEM or size rejection, which also
        # raise ValidationException with a different message.
        assert message == "Key provided does not match the certificate.", message

    got_after = acm.get_certificate(CertificateArn=arn)
    after_pem = got_after["Certificate"].encode() if isinstance(got_after["Certificate"], str) else got_after["Certificate"]
    assert _cert_fingerprint(after_pem) == _cert_fingerprint(leaf1_pem), (
        "rejected reimport must not have mutated the stored certificate"
    )


def _domain(ctx, tag: str) -> str:
    label = ctx.unique_name(f"acm-{tag}-").rstrip("-").lower().replace("_", "-")
    return f"{label}.example.com"


def _generate_self_signed_cert(
    common_name: str,
    sans=None,
    key=None,
    not_after_days: int = 825,
    is_ca: bool = False,
    issuer_key=None,
    issuer_cn: str | None = None,
):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    if key is None:
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer_cn or common_name)])
    signing_key = issuer_key or key
    san_names = [common_name] + [s for s in (sans or []) if s != common_name]
    now = datetime.datetime.utcnow()
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=not_after_days))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(n) for n in san_names]), critical=False)
        .add_extension(x509.BasicConstraints(ca=is_ca, path_length=None), critical=True)
    )
    cert = builder.sign(signing_key, hashes.SHA256())
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return cert_pem, key_pem, key


def _cert_fingerprint(pem_bytes: bytes) -> str:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes

    cert = x509.load_pem_x509_certificate(pem_bytes)
    return cert.fingerprint(hashes.SHA256()).hex()


def _safe_delete(acm, arn: str) -> None:
    from botocore.exceptions import ClientError

    try:
        acm.delete_certificate(CertificateArn=arn)
    except ClientError as err:
        if err.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
