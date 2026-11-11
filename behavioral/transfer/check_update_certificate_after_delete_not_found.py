"""update-certificate-after-delete-not-found."""
from __future__ import annotations

import datetime

from behavioral_harness import tags

CHECK = "update-certificate-after-delete-not-found"
GROUP = "error-semantics"
SERVICES = ["transfer"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateCertificate and DescribeCertificate on a just-deleted CertificateId fail with ResourceNotFoundException
    "Unknown certificate", while a second certificate's Description updates to "still-alive"."""
    transfer = ctx.client("transfer")

    cert_pem_a = _generate_self_signed_cert_pem()
    cert_pem_b = _generate_self_signed_cert_pem()

    cert_id_a = transfer.import_certificate(
        Usage="SIGNING", Certificate=cert_pem_a, Tags=[{"Key": "sim2real", "Value": CHECK}]
    )["CertificateId"]
    cert_id_b = transfer.import_certificate(
        Usage="SIGNING", Certificate=cert_pem_b, Tags=[{"Key": "sim2real", "Value": CHECK}]
    )["CertificateId"]
    ctx.on_cleanup(lambda: transfer.delete_certificate(CertificateId=cert_id_b))

    transfer.delete_certificate(CertificateId=cert_id_a)

    code, message = _error(
        lambda: transfer.update_certificate(CertificateId=cert_id_a, Description="post-delete-update")
    )
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
    assert message == "Unknown certificate", f"expected message 'Unknown certificate', got {message!r}"

    # Effect absent: the certificate did not reappear / get updated by that call.
    describe_code, describe_message = _error(lambda: transfer.describe_certificate(CertificateId=cert_id_a))
    assert describe_code == "ResourceNotFoundException", (
        f"expected the deleted certificate to keep 404ing on an independent read, got {describe_code}"
    )
    assert describe_message == "Unknown certificate", (
        f"expected message 'Unknown certificate', got {describe_message!r}"
    )

    # Positive control: a certificate that was NOT deleted still updates normally.
    transfer.update_certificate(CertificateId=cert_id_b, Description="still-alive")
    described = transfer.describe_certificate(CertificateId=cert_id_b)["Certificate"]
    assert described["Description"] == "still-alive", (
        f"expected the live certificate's update to be visible on an independent read, got {described['Description']!r}"
    )


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"].get("Code"), err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _generate_self_signed_cert_pem() -> str:
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
