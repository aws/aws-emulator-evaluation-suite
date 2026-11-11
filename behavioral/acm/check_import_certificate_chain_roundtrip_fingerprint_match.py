"""import-certificate-chain-roundtrip-fingerprint-match."""
from __future__ import annotations

import datetime

from behavioral_harness import tags

CHECK = "import-certificate-chain-roundtrip-fingerprint-match"
GROUP = "lifecycle"
SERVICES = ["acm"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ImportCertificate with a CertificateChain stores both; GetCertificate returns each
    byte-for-byte (by fingerprint). After DeleteCertificate, the certificate is genuinely gone:
    GetCertificate and a second DeleteCertificate both fail with ResourceNotFoundException."""
    import cryptography  # noqa: F401

    acm = ctx.client("acm")
    domain = _domain(ctx, "chain")

    root_pem, root_key_pem, root_key = _generate_self_signed_cert(
        "test-root-ca", is_ca=True, sans=["test-root-ca"], not_after_days=3650
    )
    leaf_pem, leaf_key_pem, _leaf_key = _generate_self_signed_cert(
        domain, issuer_key=root_key, issuer_cn="test-root-ca"
    )

    arn = acm.import_certificate(
        Certificate=leaf_pem,
        PrivateKey=leaf_key_pem,
        CertificateChain=root_pem,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["CertificateArn"]
    ctx.on_cleanup(lambda: _safe_delete(acm, arn))

    got = acm.get_certificate(CertificateArn=arn)
    leaf_returned = got["Certificate"].encode() if isinstance(got["Certificate"], str) else got["Certificate"]
    chain_returned = (
        got["CertificateChain"].encode() if isinstance(got["CertificateChain"], str) else got["CertificateChain"]
    )
    leaf_fp, chain_fp = _cert_fingerprint(leaf_returned), _cert_fingerprint(chain_returned)
    expected_leaf_fp, expected_root_fp = _cert_fingerprint(leaf_pem), _cert_fingerprint(root_pem)
    assert leaf_fp == expected_leaf_fp, (
        f"GetCertificate's Certificate fingerprint {leaf_fp} does not match the imported leaf's "
        f"{expected_leaf_fp}"
    )
    assert chain_fp == expected_root_fp, (
        f"GetCertificate's CertificateChain fingerprint {chain_fp} does not match the imported "
        f"root's {expected_root_fp}"
    )
    assert leaf_fp != chain_fp, (
        f"the returned leaf and chain fingerprints are identical ({leaf_fp}); they must be distinct "
        "certificates"
    )

    acm.delete_certificate(CertificateArn=arn)
    not_found_code, not_found_message = _poll_error(
        lambda: acm.get_certificate(CertificateArn=arn), timeout_s=30.0
    )
    assert not_found_code == "ResourceNotFoundException", (
        f"GetCertificate on a deleted certificate must fail with ResourceNotFoundException, "
        f"got {not_found_code!r}"
    )
    expected_not_found = f"Could not find certificate {arn}."
    assert not_found_message == expected_not_found, (
        f"expected message {expected_not_found!r}, got {not_found_message!r}"
    )
    delete_again_code, delete_again_message = _error(
        lambda: acm.delete_certificate(CertificateArn=arn)
    )
    assert delete_again_code == "ResourceNotFoundException", (
        f"a second DeleteCertificate on an already-deleted certificate must fail with "
        f"ResourceNotFoundException, got {delete_again_code!r}"
    )
    expected_delete_again = f"Could not find certificate {arn}."
    assert delete_again_message == expected_delete_again, (
        f"expected message {expected_delete_again!r}, got {delete_again_message!r}"
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


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a rejection, but the call succeeded and returned {result!r}")


def _poll_error(fn, *, timeout_s: float, interval_s: float = 1.0):
    """Poll fn() through eventual consistency until it is refused; return (code, message).
    A call still succeeding at the deadline raises."""
    import time

    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
        except ClientError as exc:
            err = exc.response.get("Error", {})
            return err.get("Code"), err.get("Message")
        if time.monotonic() >= deadline:
            raise AssertionError(f"the call still succeeded after {timeout_s}s")
        time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
