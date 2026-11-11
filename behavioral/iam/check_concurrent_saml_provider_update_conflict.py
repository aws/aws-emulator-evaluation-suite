"""concurrent-saml-provider-update-conflict."""
from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags

CHECK = "concurrent-saml-provider-update-conflict"
GROUP = "concurrency"
SERVICES = ["iam"]

RACER_COUNT = 6

METADATA_TEMPLATE = """<?xml version="1.0"?>
<EntityDescriptor entityID="{entity_id}" xmlns="urn:oasis:names:tc:SAML:2.0:metadata">
  <IDPSSODescriptor WantAuthnRequestsSigned="false" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <KeyDescriptor use="signing">
      <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
        <ds:X509Data>
          <ds:X509Certificate>{cert_b64}</ds:X509Certificate>
        </ds:X509Data>
      </ds:KeyInfo>
    </KeyDescriptor>
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.com/sso"/>
  </IDPSSODescriptor>
</EntityDescriptor>"""


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Racing UpdateSAMLProvider calls each succeed or fail with
    ConcurrentModification, and the metadata GetSAMLProvider then returns carries the
    entityID of one winning writer's document."""
    cert_b64 = _generate_self_signed_cert_b64()
    if cert_b64 is None:
        _raise_skip("cryptography package unavailable to generate a SAML signing certificate")

    iam = ctx.client("iam")
    initial_doc = METADATA_TEMPLATE.format(
        entity_id="https://sim2real.example.com/idp/initial", cert_b64=cert_b64
    )
    provider_arn = iam.create_saml_provider(
        SAMLMetadataDocument=initial_doc,
        Name=ctx.unique_name("sim2real-behav-saml-"),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["SAMLProviderArn"]
    ctx.on_cleanup(lambda: iam.delete_saml_provider(SAMLProviderArn=provider_arn))

    racer_docs = [
        METADATA_TEMPLATE.format(
            entity_id=f"https://sim2real.example.com/idp/racer-{i}", cert_b64=cert_b64
        )
        for i in range(RACER_COUNT)
    ]
    barrier = threading.Barrier(RACER_COUNT)

    def _racer(doc: str):
        barrier.wait(timeout=10)
        iam.update_saml_provider(SAMLProviderArn=provider_arn, SAMLMetadataDocument=doc)
        return doc

    results = []
    with ThreadPoolExecutor(max_workers=RACER_COUNT) as ex:
        futures = [ex.submit(_racer, doc) for doc in racer_docs]
        for f in futures:
            results.append(_outcome(f))

    successes = [r for r in results if r[0] == "ok"]
    failures = [r for r in results if r[0] == "error"]

    assert len(successes) >= 1, f"expected at least one winner, got results={results}"
    for _, code in failures:
        assert code == "ConcurrentModification", (
            f"expected only ConcurrentModification on losers, got {code!r} in {results}"
        )

    final_doc = iam.get_saml_provider(SAMLProviderArn=provider_arn)["SAMLMetadataDocument"]
    winning_docs = {doc for _, doc in successes}
    winning_entity_ids = {_extract_entity_id(doc) for doc in winning_docs}
    final_entity_id = _extract_entity_id(final_doc)
    assert final_entity_id in winning_entity_ids, (
        f"final entityID {final_entity_id!r} was not among the reported winners {winning_entity_ids!r}"
    )


def _outcome(future):
    from botocore.exceptions import ClientError

    try:
        return ("ok", future.result())
    except ClientError as e:
        return ("error", e.response["Error"]["Code"])


def _extract_entity_id(metadata_doc: str) -> str:
    import re

    match = re.search(r'entityID="([^"]+)"', metadata_doc)
    assert match, f"could not find entityID in metadata document: {metadata_doc!r}"
    return match.group(1)


def _generate_self_signed_cert_b64():
    """Generate a throwaway self-signed X.509 certificate (base64 DER) suitable for
    embedding in SAML IdP metadata. Returns None if the cryptography package is missing."""
    import base64
    import datetime

    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID
    except ImportError:
        return None

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "sim2real-saml-behavioral-check")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=3650))
        .sign(key, hashes.SHA256())
    )
    der = cert.public_bytes(serialization.Encoding.DER)
    return base64.b64encode(der).decode("ascii")


def _raise_skip(reason: str) -> None:

    raise AssertionError(reason)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
