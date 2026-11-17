"""update-signing-certificate-invalid-status-value-rejected."""
from __future__ import annotations

import datetime

from botocore.exceptions import ClientError
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from behavioral_harness import tags

CHECK = "update-signing-certificate-invalid-status-value-rejected"
GROUP = "error-semantics"
SERVICES = ["iam"]


def _self_signed_cert_pem(common_name: str) -> str:
    """A minimal self-signed X.509 certificate PEM, valid for the next two days."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=2))
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM).decode("ascii")


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateSigningCertificate rejects a Status outside the modeled enum with the exact
    enum-constraint ValidationError, leaving the certificate's own status unchanged."""
    iam = ctx.client("iam")
    user_name = ctx.unique_name("sim2real-usc-")
    iam.create_user(UserName=user_name)
    ctx.on_cleanup(lambda: iam.delete_user(UserName=user_name))

    cert_pem = _self_signed_cert_pem(f"{ctx.unique_name('sim2real-usc-cert-')}.example.com")
    uploaded = iam.upload_signing_certificate(UserName=user_name, CertificateBody=cert_pem)["Certificate"]
    cert_id = uploaded["CertificateId"]
    ctx.on_cleanup(lambda: iam.delete_signing_certificate(UserName=user_name, CertificateId=cert_id))
    assert uploaded["Status"] == "Active", f"expected a freshly uploaded cert Active, got {uploaded['Status']!r}"

    code, message = _error(
        lambda: iam.update_signing_certificate(UserName=user_name, CertificateId=cert_id, Status="Disabled")
    )
    assert code == "ValidationError", f"expected ValidationError, got {code!r}: {message!r}"
    expected = (
        "1 validation error detected: Value at 'status' failed to satisfy constraint: "
        "Member must satisfy enum value set: [Expired, Active, Inactive]"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    unchanged = iam.list_signing_certificates(UserName=user_name)["Certificates"]
    unchanged_status = next(c["Status"] for c in unchanged if c["CertificateId"] == cert_id)
    assert unchanged_status == "Active", (
        f"a rejected UpdateSigningCertificate must not change status, got {unchanged_status!r}"
    )

    # positive control: a legitimate transition on the identical certificate still works
    iam.update_signing_certificate(UserName=user_name, CertificateId=cert_id, Status="Inactive")
    after = iam.list_signing_certificates(UserName=user_name)["Certificates"]
    after_status = next(c["Status"] for c in after if c["CertificateId"] == cert_id)
    assert after_status == "Inactive", f"expected the legitimate transition to apply, got {after_status!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
