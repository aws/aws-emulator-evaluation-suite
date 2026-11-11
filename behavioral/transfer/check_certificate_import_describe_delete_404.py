"""certificate-import-describe-delete-404."""
from __future__ import annotations

import datetime

from botocore.exceptions import ClientError

from behavioral_harness import tags
from fidelity_tests_runner import RequiredToolMissing

CHECK = "certificate-import-describe-delete-404"
GROUP = "state-machine"
SERVICES = ["transfer"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ImportCertificate registers a certificate visible via Describe that 404s after Delete."""
    try:
        cert_pem = _generate_self_signed_certificate_pem()
    except ImportError as exc:
        raise RequiredToolMissing(["cryptography"], "module") from exc

    transfer = ctx.client("transfer")
    description = ctx.unique_name("sim2real-cert-")

    cert_id = transfer.import_certificate(
        Usage="SIGNING",
        Certificate=cert_pem,
        Description=description,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["CertificateId"]

    def _cleanup_cert():
        try:
            transfer.delete_certificate(CertificateId=cert_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup_cert)

    desc = transfer.describe_certificate(CertificateId=cert_id)["Certificate"]
    assert desc["Usage"] == "SIGNING", f"expected Usage 'SIGNING', got {desc['Usage']!r}"
    assert desc["CertificateId"] == cert_id, f"expected CertificateId {cert_id!r}, got {desc['CertificateId']!r}"

    transfer.delete_certificate(CertificateId=cert_id)
    error = _client_error(lambda: transfer.describe_certificate(CertificateId=cert_id))
    assert error == ("ResourceNotFoundException", "Unknown certificate"), error


def _client_error(fn):
    """Call fn(); return its ClientError (code, message). An unexpected SUCCESS raises, so a target
    that accepts what AWS refuses cannot read as a plain code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _generate_self_signed_certificate_pem() -> str:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "sim2real-transfer-test")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=365))
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM).decode("ascii")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
