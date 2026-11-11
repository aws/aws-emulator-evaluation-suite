"""update-trust-anchor-replaces-source."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "update-trust-anchor-replaces-source"
GROUP = "data-plane"
SERVICES = ["rolesanywhere"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateTrustAnchor replaces source.sourceData in place; GetTrustAnchor reflects
    the new certificate bundle and no longer the old one."""
    ca1_pem = _generate_ca_pem(ctx.unique_name("sim2real-ra-ca1-"))
    ca2_pem = _generate_ca_pem(ctx.unique_name("sim2real-ra-ca2-"))

    ra = ctx.client("rolesanywhere")
    created = ra.create_trust_anchor(
        name=ctx.unique_name("sim2real-ra-ta-"),
        source={"sourceType": "CERTIFICATE_BUNDLE", "sourceData": {"x509CertificateData": ca1_pem}},
        tags=[{"key": "sim2real", "value": "true"}],
    )["trustAnchor"]
    ta_id = created["trustAnchorId"]
    ctx.on_cleanup(lambda: ra.delete_trust_anchor(trustAnchorId=ta_id))

    before = ra.get_trust_anchor(trustAnchorId=ta_id)["trustAnchor"]
    before_stored = _norm(before["source"]["sourceData"]["x509CertificateData"])
    assert before_stored == _norm(ca1_pem), (
        f"GetTrustAnchor after CreateTrustAnchor: expected the ca1 bundle "
        f"({_norm(ca1_pem)[:40]}...), got {before_stored[:40]}..."
    )

    ra.update_trust_anchor(
        trustAnchorId=ta_id,
        source={"sourceType": "CERTIFICATE_BUNDLE", "sourceData": {"x509CertificateData": ca2_pem}},
    )

    after = ra.get_trust_anchor(trustAnchorId=ta_id)["trustAnchor"]
    stored = _norm(after["source"]["sourceData"]["x509CertificateData"])
    assert stored == _norm(ca2_pem), (
        f"GetTrustAnchor after UpdateTrustAnchor: expected the new ca2 bundle "
        f"({_norm(ca2_pem)[:40]}...), got {stored[:40]}..."
    )
    assert stored != _norm(ca1_pem), (
        "GetTrustAnchor after UpdateTrustAnchor: stored sourceData still matches "
        "the original ca1 bundle; UpdateTrustAnchor did not replace it"
    )


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


def _norm(pem: str) -> str:
    return "".join(pem.split())


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
