"""duplicate-upload-returns-specific-duplicate-errors."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "duplicate-upload-returns-specific-duplicate-errors"
GROUP = 'errors'
SERVICES = ['iam']


def _error(fn):
    """Call fn(); return its (Code, Message). An unexpected SUCCESS raises rather than returning a
    falsy sentinel."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED: {result!r}")


def _ignore_no_such_entity(fn):
    """Teardown-only: the body deletes some of its own resources, so tolerate one already gone."""
    try:
        fn()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "NoSuchEntity":
            raise


def _gen_ssh_rsa_public_key(key_bits=2048):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    key = rsa.generate_private_key(public_exponent=65537, key_size=key_bits)
    public_bytes = key.public_key().public_bytes(
        encoding=serialization.Encoding.OpenSSH,
        format=serialization.PublicFormat.OpenSSH,
    )
    return public_bytes.decode("ascii") + " sim2real-generated-key"


def _gen_self_signed_cert(common_name, days=3650):
    import datetime

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=days))
        .sign(key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode("ascii")
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("ascii")
    return cert_pem, key_pem


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Duplicate SSH key, signing certificate (other user) and server certificate name uploads
    return DuplicateSSHPublicKey / DuplicateCertificate / EntityAlreadyExists without mutating
    the original, and each identical re-upload succeeds once the conflicting entity is removed."""
    iam = ctx.client("iam")
    user_name = ctx.unique_name("sim2real-behav-user-")
    iam.create_user(UserName=user_name)
    ctx.on_cleanup(lambda: iam.delete_user(UserName=user_name))

    # SSH public key: same body twice, same user -> DuplicateSSHPublicKey
    ssh_key_body = _gen_ssh_rsa_public_key()
    key_id = iam.upload_ssh_public_key(UserName=user_name, SSHPublicKeyBody=ssh_key_body)[
        "SSHPublicKey"
    ]["SSHPublicKeyId"]
    ctx.on_cleanup(
        lambda: _ignore_no_such_entity(
            lambda: iam.delete_ssh_public_key(UserName=user_name, SSHPublicKeyId=key_id)
        )
    )
    code_ssh, msg_ssh = _error(
        lambda: iam.upload_ssh_public_key(UserName=user_name, SSHPublicKeyBody=ssh_key_body)
    )
    assert code_ssh == "DuplicateSSHPublicKey", f"expected DuplicateSSHPublicKey, got {code_ssh}"
    expected_ssh = "Duplicate SSH public key uploaded."
    assert msg_ssh == expected_ssh, f"expected message {expected_ssh!r}, got {msg_ssh!r}"
    listed_keys = iam.list_ssh_public_keys(UserName=user_name)["SSHPublicKeys"]
    assert len(listed_keys) == 1, f"duplicate upload must not add a second key: {listed_keys}"

    # Restore: the rejection is a consequence of the first key's continued existence, not of the
    # body being permanently invalid -- once it is deleted, the identical body uploads cleanly.
    iam.delete_ssh_public_key(UserName=user_name, SSHPublicKeyId=key_id)
    assert iam.list_ssh_public_keys(UserName=user_name)["SSHPublicKeys"] == [], (
        "expected no keys left after deleting the original"
    )
    restored_key_id = iam.upload_ssh_public_key(UserName=user_name, SSHPublicKeyBody=ssh_key_body)[
        "SSHPublicKey"
    ]["SSHPublicKeyId"]
    ctx.on_cleanup(
        lambda: iam.delete_ssh_public_key(UserName=user_name, SSHPublicKeyId=restored_key_id)
    )
    listed_after_restore = iam.list_ssh_public_keys(UserName=user_name)["SSHPublicKeys"]
    assert (
        len(listed_after_restore) == 1 and listed_after_restore[0]["SSHPublicKeyId"] == restored_key_id
    ), f"expected the identical body to upload once the original key was removed, got {listed_after_restore}"

    # Signing certificate: same body, uploaded to a SECOND (different) user -> DuplicateCertificate.
    other_user_name = ctx.unique_name("sim2real-behav-user-")
    iam.create_user(UserName=other_user_name)
    ctx.on_cleanup(lambda: iam.delete_user(UserName=other_user_name))

    cert_pem, _ = _gen_self_signed_cert("sim2real-behav-signing-cert")
    cert_id = iam.upload_signing_certificate(UserName=user_name, CertificateBody=cert_pem)[
        "Certificate"
    ]["CertificateId"]
    ctx.on_cleanup(
        lambda: _ignore_no_such_entity(
            lambda: iam.delete_signing_certificate(UserName=user_name, CertificateId=cert_id)
        )
    )
    code_cert, msg_cert = _error(
        lambda: iam.upload_signing_certificate(UserName=other_user_name, CertificateBody=cert_pem)
    )
    assert code_cert == "DuplicateCertificate", f"expected DuplicateCertificate, got {code_cert}"
    expected_cert = "Duplicate certificate uploaded."
    assert msg_cert == expected_cert, f"expected message {expected_cert!r}, got {msg_cert!r}"
    listed_certs_other = iam.list_signing_certificates(UserName=other_user_name)["Certificates"]
    assert listed_certs_other == [], (
        f"the rejected cross-user duplicate upload must not add a cert to the other user: "
        f"{listed_certs_other}"
    )

    # Restore: the rejection is keyed on the body already being in use by ANOTHER user, not on
    # the body being permanently invalid -- once the owner's certificate is removed, the second
    # user's identical upload succeeds.
    iam.delete_signing_certificate(UserName=user_name, CertificateId=cert_id)
    restored_cert_id = iam.upload_signing_certificate(UserName=other_user_name, CertificateBody=cert_pem)[
        "Certificate"
    ]["CertificateId"]
    ctx.on_cleanup(
        lambda: iam.delete_signing_certificate(UserName=other_user_name, CertificateId=restored_cert_id)
    )
    listed_after_restore = iam.list_signing_certificates(UserName=other_user_name)["Certificates"]
    assert (
        len(listed_after_restore) == 1
        and listed_after_restore[0]["CertificateId"] == restored_cert_id
    ), (
        "expected the identical body to upload once the owning user's certificate was removed, "
        f"got {listed_after_restore}"
    )

    # Server certificate: re-using the same NAME -> EntityAlreadyExists (keyed by name, not content).
    server_name = ctx.unique_name("sim2real-behav-servercert-")
    cert1_pem, key1_pem = _gen_self_signed_cert("sim2real-behav-server-cert-1")
    iam.upload_server_certificate(
        ServerCertificateName=server_name, CertificateBody=cert1_pem, PrivateKey=key1_pem
    )
    ctx.on_cleanup(lambda: iam.delete_server_certificate(ServerCertificateName=server_name))
    cert2_pem, key2_pem = _gen_self_signed_cert("sim2real-behav-server-cert-2")
    code_srv, msg_srv = _error(
        lambda: iam.upload_server_certificate(
            ServerCertificateName=server_name, CertificateBody=cert2_pem, PrivateKey=key2_pem
        )
    )
    assert code_srv == "EntityAlreadyExists", f"expected EntityAlreadyExists, got {code_srv}"
    expected_srv = f"The Server Certificate with name {server_name} already exists."
    assert msg_srv == expected_srv, f"expected message {expected_srv!r}, got {msg_srv!r}"
    got_srv = iam.get_server_certificate(ServerCertificateName=server_name)
    assert got_srv["ServerCertificate"]["CertificateBody"].strip() == cert1_pem.strip(), (
        "rejected re-upload under the same name must not overwrite the original certificate body"
    )

    # Restore: the rejection is keyed on the NAME already being in use, not on the name being
    # permanently unusable -- once the original is deleted, the same name accepts a new upload.
    iam.delete_server_certificate(ServerCertificateName=server_name)
    iam.upload_server_certificate(
        ServerCertificateName=server_name, CertificateBody=cert2_pem, PrivateKey=key2_pem
    )
    got_srv_restored = iam.get_server_certificate(ServerCertificateName=server_name)
    assert got_srv_restored["ServerCertificate"]["CertificateBody"].strip() == cert2_pem.strip(), (
        "expected the same name to accept a new certificate once the original was removed"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
