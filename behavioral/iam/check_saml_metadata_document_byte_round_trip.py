"""saml-metadata-document-byte-round-trip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "saml-metadata-document-byte-round-trip"
GROUP = "error-semantics"
SERVICES = ["iam"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """The SAMLMetadataDocument bytes supplied to CreateSAMLProvider are returned
    byte-identical (no re-encoding/whitespace loss) from GetSAMLProvider."""
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-samlrt-")

    cert_b64 = _generate_self_signed_cert_b64()
    entity_id = f"https://sim2real.example.com/{name}"
    metadata_xml = _valid_saml_metadata_xml(entity_id, cert_b64)

    resp = iam.create_saml_provider(
        SAMLMetadataDocument=metadata_xml,
        Name=name,
        Tags=[{"Key": "env", "Value": "behavioral"}, {"Key": "owner", "Value": "sim2real"}],
    )
    arn = resp["SAMLProviderArn"]
    ctx.on_cleanup(lambda: iam.delete_saml_provider(SAMLProviderArn=arn))

    fetched = iam.get_saml_provider(SAMLProviderArn=arn)["SAMLMetadataDocument"]
    assert fetched == metadata_xml, (
        "SAMLMetadataDocument must round-trip byte-identical: "
        f"uploaded {len(metadata_xml)} bytes, got back {len(fetched)} bytes"
    )


def _generate_self_signed_cert_b64():
    import base64
    import datetime

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "sim2real-test-idp")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=3650))
        .sign(key, hashes.SHA256())
    )
    der = cert.public_bytes(serialization.Encoding.DER)
    return base64.b64encode(der).decode("ascii")


def _valid_saml_metadata_xml(entity_id, cert_b64):
    return (
        '<?xml version="1.0" encoding="UTF-8"?>'
        f'<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="{entity_id}">'
        '<IDPSSODescriptor xmlns:ds="http://www.w3.org/2000/09/xmldsig#" '
        'protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">'
        '<KeyDescriptor use="signing"><ds:KeyInfo><ds:X509Data>'
        f"<ds:X509Certificate>{cert_b64}</ds:X509Certificate>"
        "</ds:X509Data></ds:KeyInfo></KeyDescriptor>"
        '<SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" '
        f'Location="{entity_id}/sso"/>'
        "</IDPSSODescriptor></EntityDescriptor>"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
