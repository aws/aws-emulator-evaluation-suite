"""concurrent-update-saml-provider-race-accepted."""
from __future__ import annotations

import datetime
import threading
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-update-saml-provider-race-accepted"
GROUP = "concurrency"
SERVICES = ["iam"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Concurrent UpdateSAMLProvider calls: one or more succeed, losers get ConcurrentModification,
    and the stored SAMLMetadataDocument equals exactly one successful writer's document.
    """
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-samlrace-")
    cert_b64 = _generate_self_signed_cert_b64()
    initial_entity_id = f"https://sim2real.example.com/{name}/initial"
    initial_doc = _valid_saml_metadata_xml(initial_entity_id, cert_b64)

    created = iam.create_saml_provider(SAMLMetadataDocument=initial_doc, Name=name)
    arn = created["SAMLProviderArn"]
    ctx.on_cleanup(lambda: iam.delete_saml_provider(SAMLProviderArn=arn))

    racer_count = 6
    racer_docs = [
        _valid_saml_metadata_xml(f"https://sim2real.example.com/{name}/racer-{i}", cert_b64)
        for i in range(racer_count)
    ]
    barrier = threading.Barrier(racer_count)
    outcomes: list[tuple[str, int]] = [("", -1)] * racer_count

    def racer(i: int) -> None:
        barrier.wait()
        try:
            iam.update_saml_provider(SAMLProviderArn=arn, SAMLMetadataDocument=racer_docs[i])
            outcomes[i] = ("ok", i)
        except ClientError as exc:
            outcomes[i] = (exc.response["Error"]["Code"], i)

    with ThreadPoolExecutor(max_workers=racer_count) as pool:
        list(pool.map(racer, range(racer_count)))

    successes = [i for status, i in outcomes if status == "ok"]
    failures = [status for status, i in outcomes if status != "ok"]

    for code in failures:
        assert code == "ConcurrentModification", (
            f"expected only ConcurrentModification for a losing racer, got {code!r}"
        )
    assert len(successes) == racer_count or len(successes) >= 1, (
        "at least one concurrent UpdateSAMLProvider writer must succeed; "
        f"got {len(successes)}/{racer_count} successes, "
        f"failures={failures}"
    )

    final_doc = iam.get_saml_provider(SAMLProviderArn=arn)["SAMLMetadataDocument"]
    successful_docs = [racer_docs[i] for i in successes]
    assert final_doc in successful_docs, (
        "final SAMLMetadataDocument does not match any successful writer's document "
        "-- indicates corruption or a silent lost update under contention"
    )


def _generate_self_signed_cert_b64():
    import base64

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
