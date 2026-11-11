"""server-certificate-tag-lifecycle."""
from __future__ import annotations

import datetime
import os
import subprocess
import tempfile
import time

from behavioral_harness import tags
from fidelity_tests_runner import require_tools
from botocore.exceptions import ClientError

CHECK = "server-certificate-tag-lifecycle"
GROUP = "state-machine"
SERVICES = ["iam"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Tags attach to a server certificate via TagServerCertificate, are visible
    via ListServerCertificateTags, and a targeted key disappears after
    UntagServerCertificate while an untouched key survives."""
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-cert-")
    cert_pem, key_pem = _generate_self_signed_cert(ctx)

    iam.upload_server_certificate(
        ServerCertificateName=name, CertificateBody=cert_pem, PrivateKey=key_pem
    )
    ctx.on_cleanup(lambda: iam.delete_server_certificate(ServerCertificateName=name))

    _retry_until_success(
        lambda: iam.tag_server_certificate(
            ServerCertificateName=name,
            Tags=[
                {"Key": "Environment", "Value": "sim2real-test"},
                {"Key": "Owner", "Value": "behavioral-suite"},
            ],
        )
    )

    tags = _tagmap(iam.list_server_certificate_tags(ServerCertificateName=name)["Tags"])
    assert tags.get("Environment") == "sim2real-test", (
        f"expected tag Environment=sim2real-test after TagServerCertificate, got {tags}"
    )
    assert tags.get("Owner") == "behavioral-suite", (
        f"expected tag Owner=behavioral-suite after TagServerCertificate, got {tags}"
    )

    iam.untag_server_certificate(ServerCertificateName=name, TagKeys=["Environment"])

    tags_after = _tagmap(iam.list_server_certificate_tags(ServerCertificateName=name)["Tags"])
    assert "Environment" not in tags_after, (
        f"expected Environment removed after UntagServerCertificate, still present: {tags_after}"
    )
    assert tags_after.get("Owner") == "behavioral-suite", (
        f"expected untouched tag Owner=behavioral-suite to survive untag, got {tags_after}"
    )


def _tagmap(tags):
    return {t["Key"]: t["Value"] for t in tags}


def _retry_until_success(fn, *, timeout_s=15.0, interval_s=1.0):
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code != "NoSuchEntityException" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _generate_self_signed_cert(ctx) -> tuple[str, str]:
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "sim2real.example.com")])
        now = datetime.datetime.utcnow()
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=365))
            .sign(key, hashes.SHA256())
        )
        cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode("ascii")
        key_pem = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        ).decode("ascii")
        return cert_pem, key_pem
    except ImportError:
        pass

    require_tools("openssl")
    with tempfile.TemporaryDirectory() as tmp:
        key_path = os.path.join(tmp, "key.pem")
        cert_path = os.path.join(tmp, "cert.pem")
        try:
            subprocess.run(
                [
                    "openssl",
                    "req",
                    "-x509",
                    "-newkey",
                    "rsa:2048",
                    "-days",
                    "365",
                    "-nodes",
                    "-subj",
                    "/CN=sim2real.example.com",
                    "-keyout",
                    key_path,
                    "-out",
                    cert_path,
                ],
                check=True,
                capture_output=True,
                env=ctx.subprocess_env(),
            )
        except subprocess.CalledProcessError as exc:
            raise AssertionError(f"cannot generate self-signed certificate: {exc}") from exc
        with open(cert_path) as f:
            cert_pem = f.read()
        with open(key_path) as f:
            key_pem = f.read()
        return cert_pem, key_pem


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
