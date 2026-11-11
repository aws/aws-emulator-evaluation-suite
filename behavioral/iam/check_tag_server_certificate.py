"""tag-server-certificate."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-server-certificate"
GROUP = 'tags'
SERVICES = ['iam']


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. An unexpected SUCCESS
    raises, because an emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _self_signed_cert(common_name, days=3650):
    """Generate a self-signed RSA X.509 cert (PEM) + private key (PEM). IAM validates certificate
    STRUCTURE (parses the X.509 DER) but not the chain of trust / expiration, so a locally generated
    self-signed cert is accepted identically to a "real" one."""
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


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagServerCertificate persists tags that ListServerCertificateTags then reflects exactly;
    tagging a nonexistent ServerCertificateName is rejected NoSuchEntity."""
    iam = ctx.client("iam")
    name = ctx.unique_name("certtag-")
    cert_pem, key_pem = _self_signed_cert("sim2real-behav-certtag")
    iam.upload_server_certificate(
        ServerCertificateName=name, CertificateBody=cert_pem, PrivateKey=key_pem
    )
    ctx.on_cleanup(lambda: iam.delete_server_certificate(ServerCertificateName=name))

    iam.tag_server_certificate(ServerCertificateName=name, Tags=[{"Key": "sim2real-k", "Value": "v1"}])
    ctx.on_cleanup(
        lambda: iam.untag_server_certificate(ServerCertificateName=name, TagKeys=["sim2real-k"])
    )

    tags = iam.list_server_certificate_tags(ServerCertificateName=name)["Tags"]
    assert {"Key": "sim2real-k", "Value": "v1"} in tags, f"tag missing: {tags}"

    missing = ctx.unique_name("missing-")
    code, message = _error(
        lambda: iam.tag_server_certificate(
            ServerCertificateName=missing, Tags=[{"Key": "k", "Value": "v"}]
        )
    )
    assert code == "NoSuchEntity", (
        f"expected NoSuchEntity for a nonexistent ServerCertificateName, got {code}"
    )
    expected = f"The Server Certificate with name {missing} cannot be found."
    assert message == expected, f"expected message {expected!r}, got {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
