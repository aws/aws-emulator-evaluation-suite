"""list-saml-provider-tags-nonexistent-arn-rejected."""
from __future__ import annotations

import datetime

from botocore.exceptions import ClientError
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from behavioral_harness import tags

CHECK = "list-saml-provider-tags-nonexistent-arn-rejected"
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


def _idp_metadata_xml(entity_id: str, sso_host: str, cert_pem: str) -> str:
    """A minimal, well-formed SAML 2.0 IdP EntityDescriptor embedding cert_pem's DER, base64."""
    cert_b64 = "".join(line for line in cert_pem.strip().splitlines() if "-----" not in line)
    return (
        '<?xml version="1.0" encoding="UTF-8"?>'
        f'<EntityDescriptor entityID="{entity_id}" xmlns="urn:oasis:names:tc:SAML:2.0:metadata">'
        '<IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">'
        '<KeyDescriptor use="signing"><KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">'
        f"<X509Data><X509Certificate>{cert_b64}</X509Certificate></X509Data>"
        "</KeyInfo></KeyDescriptor>"
        '<SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" '
        f'Location="https://{sso_host}/sso"/>'
        "</IDPSSODescriptor></EntityDescriptor>"
    )


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
    """ListSAMLProviderTags rejects a SAMLProviderArn naming no provider with NoSuchEntity and
    the exact message, while the same call on a real provider reflects its own tags."""
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    account = sts.get_caller_identity()["Account"]

    missing_name = ctx.unique_name("sim2real-lspt-missing-")
    missing_arn = f"arn:aws:iam::{account}:saml-provider/{missing_name}"
    code, message = _error(lambda: iam.list_saml_provider_tags(SAMLProviderArn=missing_arn))
    assert code == "NoSuchEntity", f"expected NoSuchEntity for a nonexistent provider ARN, got {code!r}: {message!r}"
    expected = f"Manifest not found for arn {missing_arn}"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # positive control: the identical call on a real provider reflects its own tags
    provider_name = ctx.unique_name("sim2real-lspt-real-")
    host = ctx.unique_name("sim2real-lspt-host-") + ".example.com"
    cert_pem = _self_signed_cert_pem(host)
    metadata = _idp_metadata_xml(f"https://{host}/entity", host, cert_pem)
    created = iam.create_saml_provider(
        SAMLMetadataDocument=metadata, Name=provider_name, Tags=[{"Key": "sim2real-k", "Value": "v1"}]
    )
    real_arn = created["SAMLProviderArn"]
    ctx.on_cleanup(lambda: iam.delete_saml_provider(SAMLProviderArn=real_arn))

    real_tags = iam.list_saml_provider_tags(SAMLProviderArn=real_arn)["Tags"]
    assert {"Key": "sim2real-k", "Value": "v1"} in real_tags, (
        f"expected the created tag reflected on a real provider, got {real_tags!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
