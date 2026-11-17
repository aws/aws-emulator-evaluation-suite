"""upload-signing-certificate-malformed-body-rejected."""
from __future__ import annotations

import datetime

from botocore.exceptions import ClientError
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from behavioral_harness import tags

CHECK = "upload-signing-certificate-malformed-body-rejected"
GROUP = "error-semantics"
SERVICES = ["iam"]

_MALFORMED_BODY = (
    "-----BEGIN CERTIFICATE-----\n"
    "dGhpcyBpcyBub3QgYSByZWFsIGNlcnRpZmljYXRlIGJvZHkgYXQgYWxsLCBqdXN0\n"
    "YSBwaWxlIG9mIGJhc2U2NCBieXRlcyB0aGF0IGRvIG5vdCBkZWNvZGUgdG8gYW4g\n"
    "YXNuMSBzdHJ1Y3R1cmUgb2YgYW55IGtpbmQu\n"
    "-----END CERTIFICATE-----\n"
)


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
    """UploadSigningCertificate rejects a body that is not a parseable X.509 certificate with
    MalformedCertificate and its exact message, leaving no certificate behind, while a real
    self-signed certificate uploads and becomes Active."""
    iam = ctx.client("iam")
    user_name = ctx.unique_name("sim2real-uscb-")
    iam.create_user(UserName=user_name)
    ctx.on_cleanup(lambda: iam.delete_user(UserName=user_name))

    code, message = _error(
        lambda: iam.upload_signing_certificate(UserName=user_name, CertificateBody=_MALFORMED_BODY)
    )
    assert code == "MalformedCertificate", f"expected MalformedCertificate, got {code!r}: {message!r}"
    expected = f"Certificate {_MALFORMED_BODY} is malformed."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    leftover = iam.list_signing_certificates(UserName=user_name)["Certificates"]
    assert leftover == [], f"a rejected UploadSigningCertificate must leave no certificate behind, got {leftover!r}"

    # positive control: a real self-signed certificate uploads and reads back Active
    cert_pem = _self_signed_cert_pem(f"{ctx.unique_name('sim2real-uscb-cert-')}.example.com")
    uploaded = iam.upload_signing_certificate(UserName=user_name, CertificateBody=cert_pem)["Certificate"]
    cert_id = uploaded["CertificateId"]
    ctx.on_cleanup(lambda: iam.delete_signing_certificate(UserName=user_name, CertificateId=cert_id))
    assert uploaded["Status"] == "Active", f"expected the real certificate Active, got {uploaded['Status']!r}"

    certs = iam.list_signing_certificates(UserName=user_name)["Certificates"]
    assert any(c["CertificateId"] == cert_id for c in certs), (
        f"expected {cert_id!r} in ListSigningCertificates, got {certs!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
