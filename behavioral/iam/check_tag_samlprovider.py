"""tag-samlprovider."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-samlprovider"
GROUP = 'tags'
SERVICES = ['iam']


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. An unexpected SUCCESS
    raises, because an emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


def _self_signed_cert(common_name, days=3650):
    """Generate a self-signed RSA X.509 cert (PEM) + private key (PEM). IAM validates certificate
    STRUCTURE (parses the X.509 DER) but not the chain of trust / expiration on SAML metadata, so a
    locally generated self-signed cert is accepted identically to a "real" one."""
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


def _saml_metadata_document(entity_id, sso_host, cert_pem):
    """A minimal, well-formed SAML 2.0 IdP EntityDescriptor XML embedding the given cert's base64
    body, suitable for CreateSAMLProvider (SAMLMetadataDocumentType requires >=1000 chars, which a
    real cert body comfortably clears)."""
    cert_b64 = "".join(
        line for line in cert_pem.strip().splitlines() if not line.startswith("-----")
    )
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        f'<EntityDescriptor entityID="{entity_id}" '
        'xmlns="urn:oasis:names:tc:SAML:2.0:metadata">\n'
        '  <IDPSSODescriptor WantAuthnRequestsSigned="false" '
        'protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">\n'
        '    <KeyDescriptor use="signing">\n'
        '      <KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">\n'
        "        <X509Data>\n"
        f"          <X509Certificate>{cert_b64}</X509Certificate>\n"
        "        </X509Data>\n"
        "      </KeyInfo>\n"
        "    </KeyDescriptor>\n"
        "    <NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</NameIDFormat>\n"
        '    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" '
        f'Location="https://{sso_host}/sso"/>\n'
        "  </IDPSSODescriptor>\n"
        "</EntityDescriptor>\n"
    )


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagSAMLProvider persists tags that GetSAMLProvider / ListSAMLProviderTags then reflect
    exactly; tagging a nonexistent provider ARN is rejected NoSuchEntity."""
    iam = ctx.client("iam")
    provider_name = ctx.unique_name("samltag-")
    host = ctx.unique_name("samltaghost-") + ".example.com"
    cert_pem, _ = _self_signed_cert(host)
    metadata = _saml_metadata_document(f"https://{host}/entity", host, cert_pem)
    created = iam.create_saml_provider(SAMLMetadataDocument=metadata, Name=provider_name)
    arn = created["SAMLProviderArn"]
    ctx.on_cleanup(lambda: iam.delete_saml_provider(SAMLProviderArn=arn))

    iam.tag_saml_provider(SAMLProviderArn=arn, Tags=[{"Key": "sim2real-k", "Value": "v1"}])
    ctx.on_cleanup(lambda: iam.untag_saml_provider(SAMLProviderArn=arn, TagKeys=["sim2real-k"]))

    tags = iam.list_saml_provider_tags(SAMLProviderArn=arn)["Tags"]
    assert {"Key": "sim2real-k", "Value": "v1"} in tags, f"tag missing: {tags}"
    got_tags = iam.get_saml_provider(SAMLProviderArn=arn).get("Tags", [])
    assert {"Key": "sim2real-k", "Value": "v1"} in got_tags, f"GetSAMLProvider omitted the tag: {got_tags}"

    account = ctx.client("sts").get_caller_identity()["Account"]
    fake_arn = f"arn:aws:iam::{account}:saml-provider/{ctx.unique_name('missing-')}"
    code, message = _error(
        lambda: iam.tag_saml_provider(SAMLProviderArn=fake_arn, Tags=[{"Key": "k", "Value": "v"}])
    )
    assert code == "NoSuchEntity", f"expected NoSuchEntity for a nonexistent provider ARN, got {code}"
    expected = f"Manifest not found for arn {fake_arn}"
    assert message == expected, f"expected message {expected!r}, got {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
