"""saml-provider-invalid-metadata-document-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "saml-provider-invalid-metadata-document-rejected"
GROUP = "error-semantics"
SERVICES = ["iam"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateSAMLProvider rejects a length-valid but non-XML metadata document with InvalidInput
    and creates nothing; a valid SAML metadata document succeeds and is listed afterwards."""
    iam = ctx.client("iam")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    name = ctx.unique_name("sim2real-samlbad-")
    expected_arn = f"arn:aws:iam::{account_id}:saml-provider/{name}"
    ctx.on_cleanup(
        lambda: _ignore_no_such_entity(lambda: iam.delete_saml_provider(SAMLProviderArn=expected_arn))
    )

    # >=1000 chars (the modeled minimum length) but not XML at all
    garbage = ("this-is-not-a-valid-saml-metadata-document " * 40)[:1500]
    assert len(garbage) >= 1000, f"test garbage document is only {len(garbage)} chars, need >=1000"

    code, message = _error(
        lambda: iam.create_saml_provider(SAMLMetadataDocument=garbage, Name=name)
    )
    assert code == "InvalidInput", f"expected InvalidInput, got {code!r}"
    want = "Invalid SAML metadata document"
    assert message == want, f"InvalidInput message: expected {want!r}, got {message!r}"

    providers = iam.list_saml_providers()["SAMLProviderList"]
    assert not any(p["Arn"].endswith(f"/{name}") for p in providers), (
        f"provider {name!r} should not exist after the rejected call, but appears in {providers!r}"
    )

    # positive control: a well-formed SAML metadata document with a real certificate succeeds
    cert_b64 = _generate_self_signed_cert_b64()
    entity_id = f"https://sim2real.example.com/{name}"
    valid_xml = _valid_saml_metadata_xml(entity_id, cert_b64)
    resp = iam.create_saml_provider(
        SAMLMetadataDocument=valid_xml,
        Name=name,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    arn = resp["SAMLProviderArn"]
    assert arn.endswith(f"/{name}"), f"expected an ARN ending in /{name}, got {arn!r}"

    providers_after = iam.list_saml_providers()["SAMLProviderList"]
    assert any(p["Arn"] == arn for p in providers_after), (
        f"created SAML provider {arn!r} not visible via ListSAMLProviders: {providers_after!r}"
    )


def _error(fn):
    """The ClientError's (code, message); a successful call fails the refusal claim."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _ignore_no_such_entity(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


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
