"""certificate-unicode-description-rejected."""
from __future__ import annotations

import datetime as dt

from behavioral_harness import tags
from fidelity_tests_runner import RequiredToolMissing

CHECK = "certificate-unicode-description-rejected"
GROUP = "representation"
SERVICES = ["transfer"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A Certificate Description containing multi-byte unicode is rejected
    (violates the documented printable-ASCII pattern), while a printable-ASCII
    description survives import, update, and describe unchanged."""
    try:
        cert_pem, key_pem = _self_signed_cert()
    except ImportError as exc:
        raise RequiredToolMissing(["cryptography"], "module") from exc

    transfer = ctx.client("transfer")
    unicode_description = "证书说明 – café ✅"

    def _attempt_import_with_unicode():
        transfer.import_certificate(
            Usage="SIGNING",
            Certificate=cert_pem,
            PrivateKey=key_pem,
            Description=unicode_description,
        )

    error = _client_error(_attempt_import_with_unicode)
    assert error == ("ValidationException", "1 validation error detected: Value at 'description' failed to satisfy constraint: Member must satisfy regular expression pattern: [\\u0021-\\u007E]+"), error

    all_certs = transfer.list_certificates().get("Certificates", [])
    assert not any(c.get("Description") == unicode_description for c in all_certs), (
        "a certificate with the rejected unicode description should not exist"
    )

    # The documented pattern [\u0021-\u007E]+ excludes the space (0x20).
    ascii_description = "Sig-cert-v1(2024-Q1)[ok]#42!"
    cert_id = transfer.import_certificate(
        Usage="SIGNING",
        Certificate=cert_pem,
        PrivateKey=key_pem,
        Description=ascii_description,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["CertificateId"]
    ctx.on_cleanup(lambda: transfer.delete_certificate(CertificateId=cert_id))

    described = transfer.describe_certificate(CertificateId=cert_id)["Certificate"]
    assert described["Description"] == ascii_description, (
        f"expected Description {ascii_description!r} to round-trip through import+describe, "
        f"got {described.get('Description')!r}"
    )

    updated_ascii_description = "Updated-desc<v2>{rotated}"
    transfer.update_certificate(CertificateId=cert_id, Description=updated_ascii_description)
    described_after_update = transfer.describe_certificate(CertificateId=cert_id)["Certificate"]
    assert described_after_update["Description"] == updated_ascii_description, (
        f"expected Description {updated_ascii_description!r} after update+describe, "
        f"got {described_after_update.get('Description')!r}"
    )


def _client_error(fn):
    """Call fn() and return its ClientError (code, message); an unexpected success raises
    rather than surfacing as an error-code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


def _self_signed_cert() -> tuple[str, str]:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "sim2real.transfer.test")])
    now = dt.datetime.now(dt.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=1))
        .not_valid_after(now + dt.timedelta(days=365))
        .sign(key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")
    return cert_pem, key_pem


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
