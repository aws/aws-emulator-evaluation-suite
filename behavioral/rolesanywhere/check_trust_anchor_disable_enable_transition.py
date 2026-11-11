"""trust-anchor-disable-enable-transition."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "trust-anchor-disable-enable-transition"
GROUP = "state"
SERVICES = ["rolesanywhere"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DisableTrustAnchor/EnableTrustAnchor flip trustAnchor.enabled and GetTrustAnchor reflects it."""
    ca_pem = _generate_ca_pem(ctx.unique_name("sim2real-ra-ca-"))

    ra = ctx.client("rolesanywhere")
    created = ra.create_trust_anchor(
        name=ctx.unique_name("sim2real-ra-ta-"),
        source={"sourceType": "CERTIFICATE_BUNDLE", "sourceData": {"x509CertificateData": ca_pem}},
        enabled=True,
        tags=[{"key": "sim2real", "value": "true"}],
    )["trustAnchor"]
    ta_id = created["trustAnchorId"]
    ctx.on_cleanup(lambda: _delete_ta_ignore_missing(ra, ta_id))

    assert created["enabled"] is True, f"expected CreateTrustAnchor(enabled=True) to echo enabled=True, got {created['enabled']!r}"
    got = ra.get_trust_anchor(trustAnchorId=ta_id)["trustAnchor"]
    assert got["enabled"] is True, f"expected GetTrustAnchor to reflect enabled=True right after create, got {got['enabled']!r}"

    disabled = ra.disable_trust_anchor(trustAnchorId=ta_id)["trustAnchor"]
    assert disabled["enabled"] is False, f"expected DisableTrustAnchor to return enabled=False, got {disabled['enabled']!r}"
    got = ra.get_trust_anchor(trustAnchorId=ta_id)["trustAnchor"]
    assert got["enabled"] is False, f"expected GetTrustAnchor to reflect enabled=False after DisableTrustAnchor, got {got['enabled']!r}"

    enabled = ra.enable_trust_anchor(trustAnchorId=ta_id)["trustAnchor"]
    assert enabled["enabled"] is True, f"expected EnableTrustAnchor to return enabled=True, got {enabled['enabled']!r}"
    got = ra.get_trust_anchor(trustAnchorId=ta_id)["trustAnchor"]
    assert got["enabled"] is True, f"expected GetTrustAnchor to reflect enabled=True after EnableTrustAnchor, got {got['enabled']!r}"


def _generate_ca_pem(common_name: str) -> str:
    import datetime

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.datetime.utcnow()
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=2))
        .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM).decode("ascii")


def _delete_ta_ignore_missing(ra, ta_id: str) -> None:
    from botocore.exceptions import ClientError

    try:
        ra.delete_trust_anchor(trustAnchorId=ta_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
