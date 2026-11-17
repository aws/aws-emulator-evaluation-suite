"""saml-provider-identity-providers-quota-exceeded-rejected."""
from __future__ import annotations

import base64
import datetime as _dt

from botocore.exceptions import ClientError
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID

from behavioral_harness import tags

CHECK = "saml-provider-identity-providers-quota-exceeded-rejected"
GROUP = "error-semantics"
SERVICES = ["iam"]


def _signing_cert_b64(common_name: str) -> str:
    """A self-signed X.509 certificate's DER bytes, base64-encoded for a SAML ``X509Certificate`` element."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = _dt.datetime.now(_dt.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - _dt.timedelta(minutes=5))
        .not_valid_after(now + _dt.timedelta(days=2))
        .sign(key, hashes.SHA256())
    )
    return base64.b64encode(cert.public_bytes(Encoding.DER)).decode("ascii")


def _entity_descriptor(entity_id: str, cert_b64: str) -> str:
    return (
        f'  <EntityDescriptor entityID="{entity_id}">\n'
        '    <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol" '
        'WantAuthnRequestsSigned="false">\n'
        '      <KeyDescriptor use="signing">\n'
        '        <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">\n'
        f"          <ds:X509Data><ds:X509Certificate>{cert_b64}</ds:X509Certificate></ds:X509Data>\n"
        "        </ds:KeyInfo>\n"
        "      </KeyDescriptor>\n"
        '      <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" '
        f'Location="{entity_id}/sso/redirect"/>\n'
        "    </IDPSSODescriptor>\n"
        "  </EntityDescriptor>\n"
    )


def _metadata_document(group_label: str, entity_ids: list[str], certs_b64: list[str]) -> str:
    valid_until = (_dt.datetime.now(_dt.timezone.utc) + _dt.timedelta(days=365)).strftime("%Y-%m-%dT%H:%M:%SZ")
    entities_xml = "".join(_entity_descriptor(e, c) for e, c in zip(entity_ids, certs_b64))
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        f'<EntitiesDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" '
        f'Name="sim2real-behav-samlidps-{group_label}" validUntil="{valid_until}">\n'
        f"{entities_xml}"
        "</EntitiesDescriptor>\n"
    )


def _error(fn):
    """``(code, message)`` of the ClientError ``fn`` raises; an unexpected success raises instead."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected this call to be refused, but it succeeded: {result!r}")


def _ignore_no_such_entity(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A SAML provider's metadata may describe at most 10 identity providers; an 11th via
    UpdateSAMLProvider is refused LimitExceeded and leaves the 10-IdP document in place."""
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-samlidps-")

    entity_ids_10 = [f"https://sim2real-behav-samlidps.example.com/idp/{i}" for i in range(10)]
    certs_10 = [_signing_cert_b64(f"sim2real-behav-samlidps-{i}.example.com") for i in range(10)]
    metadata_v1 = _metadata_document("v1", entity_ids_10, certs_10)

    created = iam.create_saml_provider(
        SAMLMetadataDocument=metadata_v1, Name=name, Tags=[{"Key": "sim2real", "Value": CHECK}]
    )
    arn = created["SAMLProviderArn"]
    ctx.on_cleanup(lambda: _ignore_no_such_entity(lambda: iam.delete_saml_provider(SAMLProviderArn=arn)))

    got_v1 = iam.get_saml_provider(SAMLProviderArn=arn)
    for entity_id in entity_ids_10:
        assert entity_id in got_v1["SAMLMetadataDocument"], (
            f"GetSAMLProvider for {arn} must return all 10 identity providers just created, "
            f"missing {entity_id!r}"
        )

    entity_ids_11 = entity_ids_10 + ["https://sim2real-behav-samlidps.example.com/idp/overflow"]
    certs_11 = certs_10 + [_signing_cert_b64("sim2real-behav-samlidps-overflow.example.com")]
    metadata_overflow = _metadata_document("overflow", entity_ids_11, certs_11)

    code, message = _error(
        lambda: iam.update_saml_provider(SAMLProviderArn=arn, SAMLMetadataDocument=metadata_overflow)
    )
    assert code == "LimitExceeded", f"expected LimitExceeded updating to 11 identity providers, got {code!r}"
    want = "Cannot exceed quota for SamlIdpsPerSamlProvider: 10"
    assert message == want, f"expected the exact quota message {want!r}, got {message!r}"

    got_after_refusal = iam.get_saml_provider(SAMLProviderArn=arn)
    for entity_id in entity_ids_10:
        assert entity_id in got_after_refusal["SAMLMetadataDocument"], (
            f"the rejected 11-IdP update must not have replaced the 10-IdP document, missing {entity_id!r}"
        )
    assert entity_ids_11[-1] not in got_after_refusal["SAMLMetadataDocument"], (
        "the rejected 11th identity provider must not have been persisted"
    )

    entity_ids_v2 = [f"https://sim2real-behav-samlidps.example.com/idp-v2/{i}" for i in range(10)]
    certs_v2 = [_signing_cert_b64(f"sim2real-behav-samlidps-v2-{i}.example.com") for i in range(10)]
    iam.update_saml_provider(
        SAMLProviderArn=arn, SAMLMetadataDocument=_metadata_document("v2", entity_ids_v2, certs_v2)
    )

    got_v2 = iam.get_saml_provider(SAMLProviderArn=arn)
    assert entity_ids_v2[0] in got_v2["SAMLMetadataDocument"], (
        f"a fresh 10-IdP UpdateSAMLProvider must still succeed after the quota refusal, "
        f"got {got_v2['SAMLMetadataDocument'][:200]!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
