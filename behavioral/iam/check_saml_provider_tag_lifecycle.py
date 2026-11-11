"""saml-provider-tag-lifecycle."""
from __future__ import annotations

import datetime
import os
import subprocess
import tempfile
import time

from behavioral_harness import tags
from fidelity_tests_runner import require_tools
from botocore.exceptions import ClientError

CHECK = "saml-provider-tag-lifecycle"
GROUP = "state-machine"
SERVICES = ["iam"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Tags attach to a SAML provider via TagSAMLProvider, are visible via
    ListSAMLProviderTags, and a targeted key disappears after UntagSAMLProvider
    while an untouched key survives."""
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-saml-")
    cert_pem, _key_pem = _generate_self_signed_cert(ctx)
    metadata = _build_saml_metadata(name, cert_pem)

    arn = iam.create_saml_provider(SAMLMetadataDocument=metadata, Name=name)["SAMLProviderArn"]
    ctx.on_cleanup(lambda: iam.delete_saml_provider(SAMLProviderArn=arn))

    _retry_until_success(
        lambda: iam.tag_saml_provider(
            SAMLProviderArn=arn,
            Tags=[
                {"Key": "Environment", "Value": "sim2real-test"},
                {"Key": "Owner", "Value": "behavioral-suite"},
            ],
        )
    )

    tags = _tagmap(iam.list_saml_provider_tags(SAMLProviderArn=arn)["Tags"])
    assert tags.get("Environment") == "sim2real-test", f"expected Environment=sim2real-test, got {tags}"
    assert tags.get("Owner") == "behavioral-suite", f"expected Owner=behavioral-suite, got {tags}"

    iam.untag_saml_provider(SAMLProviderArn=arn, TagKeys=["Environment"])

    tags_after = _tagmap(iam.list_saml_provider_tags(SAMLProviderArn=arn)["Tags"])
    assert "Environment" not in tags_after, f"expected Environment removed, still present: {tags_after}"
    assert tags_after.get("Owner") == "behavioral-suite", f"untouched Owner tag lost: {tags_after}"


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


def _strip_pem(pem_text: str) -> str:
    lines = [ln for ln in pem_text.strip().splitlines() if "BEGIN" not in ln and "END" not in ln]
    return "".join(lines)


def _build_saml_metadata(name: str, cert_pem: str) -> str:
    cert_b64 = _strip_pem(cert_pem)
    return (
        '<?xml version="1.0"?>'
        f'<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" '
        f'entityID="https://sim2real.example.com/{name}">'
        '<IDPSSODescriptor WantAuthnRequestsSigned="false" '
        'protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">'
        '<KeyDescriptor use="signing">'
        '<ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">'
        "<ds:X509Data>"
        f"<ds:X509Certificate>{cert_b64}</ds:X509Certificate>"
        "</ds:X509Data>"
        "</ds:KeyInfo>"
        "</KeyDescriptor>"
        '<SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" '
        f'Location="https://sim2real.example.com/{name}/sso"/>'
        "</IDPSSODescriptor>"
        "</EntityDescriptor>"
    )


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
