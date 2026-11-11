"""saml-provider-tagging."""
from __future__ import annotations

import base64
import datetime

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "saml-provider-tagging"
GROUP = "state-machine"
SERVICES = ["iam"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagSAMLProvider adds tags visible via ListSAMLProviderTags; UntagSAMLProvider
    removes them."""
    iam = ctx.client("iam")

    provider_name = ctx.unique_name("sim2real-samltag-")
    entity_id = "https://sim2real.example.com/idp/tagging"
    cert_b64 = _self_signed_cert_der_b64(entity_id)
    metadata = _saml_metadata_xml(entity_id, cert_b64)

    arn = iam.create_saml_provider(SAMLMetadataDocument=metadata, Name=provider_name)["SAMLProviderArn"]
    ctx.on_cleanup(lambda: _best_effort_delete_saml(iam, arn))

    before = iam.list_saml_provider_tags(SAMLProviderArn=arn)["Tags"]
    assert before == [], f"expected no tags on fresh provider, got {before}"

    iam.tag_saml_provider(
        SAMLProviderArn=arn,
        Tags=[{"Key": "env", "Value": "behavioral"}, {"Key": "owner", "Value": "sim2real"}],
    )
    tags = {t["Key"]: t["Value"] for t in iam.list_saml_provider_tags(SAMLProviderArn=arn)["Tags"]}
    assert tags == {"env": "behavioral", "owner": "sim2real"}, f"unexpected tags after tagging: {tags}"

    iam.untag_saml_provider(SAMLProviderArn=arn, TagKeys=["env"])
    tags_after = {t["Key"]: t["Value"] for t in iam.list_saml_provider_tags(SAMLProviderArn=arn)["Tags"]}
    assert tags_after == {"owner": "sim2real"}, f"unexpected tags after partial untag: {tags_after}"

    iam.untag_saml_provider(SAMLProviderArn=arn, TagKeys=["owner"])
    tags_final = iam.list_saml_provider_tags(SAMLProviderArn=arn)["Tags"]
    assert tags_final == [], f"expected no tags after full untag, got {tags_final}"


def _self_signed_cert_der_b64(common_name: str) -> str:
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
    der = cert.public_bytes(serialization.Encoding.DER)
    return base64.b64encode(der).decode()


def _saml_metadata_xml(entity_id: str, cert_b64: str) -> str:
    return (
        '<?xml version="1.0"?>'
        f'<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="{entity_id}">'
        '<IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">'
        '<KeyDescriptor use="signing">'
        '<ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">'
        f'<ds:X509Data><ds:X509Certificate>{cert_b64}</ds:X509Certificate></ds:X509Data>'
        '</ds:KeyInfo>'
        '</KeyDescriptor>'
        '<SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" '
        f'Location="{entity_id}/sso"/>'
        '</IDPSSODescriptor>'
        '</EntityDescriptor>'
    )


def _best_effort_delete_saml(iam, arn) -> None:
    from botocore.exceptions import ClientError

    try:
        iam.delete_saml_provider(SAMLProviderArn=arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
