"""list-server-certificate-tags-nonexistent-name-rejected."""
from __future__ import annotations

import datetime

from botocore.exceptions import ClientError
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from behavioral_harness import tags

CHECK = "list-server-certificate-tags-nonexistent-name-rejected"
GROUP = "error-semantics"
SERVICES = ["iam"]


def _self_signed_cert_and_key_pem(common_name: str) -> tuple[str, str]:
    """A minimal self-signed X.509 certificate PEM and its matching private key PEM."""
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
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode("ascii")
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("ascii")
    return cert_pem, key_pem


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
    """ListServerCertificateTags rejects a ServerCertificateName naming no certificate with
    NoSuchEntity and the exact message, while the same call on a real certificate succeeds."""
    iam = ctx.client("iam")

    missing_name = ctx.unique_name("sim2real-lsct-missing-")
    code, message = _error(lambda: iam.list_server_certificate_tags(ServerCertificateName=missing_name))
    assert code == "NoSuchEntity", f"expected NoSuchEntity for a nonexistent name, got {code!r}: {message!r}"
    expected = f"The Server Certificate with name {missing_name} cannot be found."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # positive control: the identical call on a real certificate succeeds
    real_name = ctx.unique_name("sim2real-lsct-real-")
    cert_pem, key_pem = _self_signed_cert_and_key_pem(f"{real_name}.example.com")
    iam.upload_server_certificate(
        ServerCertificateName=real_name,
        CertificateBody=cert_pem,
        PrivateKey=key_pem,
        Tags=[{"Key": "sim2real-k", "Value": "v1"}],
    )
    ctx.on_cleanup(lambda: iam.delete_server_certificate(ServerCertificateName=real_name))

    real_tags = iam.list_server_certificate_tags(ServerCertificateName=real_name)["Tags"]
    assert {"Key": "sim2real-k", "Value": "v1"} in real_tags, (
        f"expected the uploaded tag reflected on a real certificate, got {real_tags!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
