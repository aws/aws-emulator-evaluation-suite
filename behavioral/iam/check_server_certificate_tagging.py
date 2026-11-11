"""server-certificate-tagging."""
from __future__ import annotations

import datetime

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "server-certificate-tagging"
GROUP = "state-machine"
SERVICES = ["iam"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagServerCertificate adds tags visible via ListServerCertificateTags;
    UntagServerCertificate removes them."""
    iam = ctx.client("iam")

    name = ctx.unique_name("sim2real-servercerttag-")
    cert_pem, key_pem = _self_signed_cert_and_key(name)
    iam.upload_server_certificate(ServerCertificateName=name, CertificateBody=cert_pem, PrivateKey=key_pem)
    ctx.on_cleanup(lambda: _best_effort_delete_server_cert(iam, name))

    before = iam.list_server_certificate_tags(ServerCertificateName=name)["Tags"]
    assert before == [], f"expected no tags on fresh certificate, got {before}"

    iam.tag_server_certificate(
        ServerCertificateName=name,
        Tags=[{"Key": "env", "Value": "behavioral"}, {"Key": "owner", "Value": "sim2real"}],
    )
    tags = {t["Key"]: t["Value"] for t in iam.list_server_certificate_tags(ServerCertificateName=name)["Tags"]}
    assert tags == {"env": "behavioral", "owner": "sim2real"}, f"unexpected tags after tagging: {tags}"

    iam.untag_server_certificate(ServerCertificateName=name, TagKeys=["env"])
    tags_after = {t["Key"]: t["Value"] for t in iam.list_server_certificate_tags(ServerCertificateName=name)["Tags"]}
    assert tags_after == {"owner": "sim2real"}, f"unexpected tags after partial untag: {tags_after}"

    iam.untag_server_certificate(ServerCertificateName=name, TagKeys=["owner"])
    tags_final = iam.list_server_certificate_tags(ServerCertificateName=name)["Tags"]
    assert tags_final == [], f"expected no tags after full untag, got {tags_final}"


def _self_signed_cert_and_key(common_name: str) -> tuple[str, str]:
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
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    return cert_pem, key_pem


def _best_effort_delete_server_cert(iam, name) -> None:
    from botocore.exceptions import ClientError

    try:
        iam.delete_server_certificate(ServerCertificateName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
