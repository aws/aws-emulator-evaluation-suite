"""signing-certificate-duplicate-rejected."""
from __future__ import annotations

import datetime

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "signing-certificate-duplicate-rejected"
GROUP = "error-semantics"
SERVICES = ["iam"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Uploading a signing certificate already active on another user fails with
    DuplicateCertificate and "Duplicate certificate uploaded.", leaving the second user
    with none and the owner's unchanged."""
    iam = ctx.client("iam")

    owner_user = ctx.unique_name("sim2real-signcertdup-owner-")
    other_user = ctx.unique_name("sim2real-signcertdup-other-")
    tag = [{"Key": "sim2real", "Value": CHECK}]
    iam.create_user(UserName=owner_user, Tags=tag)
    ctx.on_cleanup(lambda: iam.delete_user(UserName=owner_user))
    iam.create_user(UserName=other_user, Tags=tag)
    ctx.on_cleanup(lambda: iam.delete_user(UserName=other_user))

    cert_pem = _self_signed_cert_pem(owner_user)
    first = iam.upload_signing_certificate(UserName=owner_user, CertificateBody=cert_pem)["Certificate"]
    cert_id = first["CertificateId"]
    ctx.on_cleanup(lambda: _best_effort_delete_cert(iam, owner_user, cert_id))

    code, message = _error_code(
        lambda: iam.upload_signing_certificate(UserName=other_user, CertificateBody=cert_pem))
    assert code == "DuplicateCertificate", f"expected DuplicateCertificate, got {code}"
    assert message == "Duplicate certificate uploaded.", message

    owner_listed = iam.list_signing_certificates(UserName=owner_user)["Certificates"]
    assert len(owner_listed) == 1 and owner_listed[0]["CertificateId"] == cert_id, (
        f"expected owning user's certificate unaffected, got {owner_listed}"
    )

    other_listed = iam.list_signing_certificates(UserName=other_user)["Certificates"]
    assert other_listed == [], (
        f"expected other user to have no certificates after rejected duplicate upload, got {other_listed}"
    )


def _error_code(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


def _self_signed_cert_pem(common_name: str) -> str:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=365))
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def _best_effort_delete_cert(iam, user_name, cert_id) -> None:
    from botocore.exceptions import ClientError

    try:
        iam.delete_signing_certificate(UserName=user_name, CertificateId=cert_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
