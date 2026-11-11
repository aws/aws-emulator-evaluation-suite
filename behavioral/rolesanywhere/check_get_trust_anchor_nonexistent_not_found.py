"""get-trust-anchor-nonexistent-not-found."""
from __future__ import annotations

import uuid

from behavioral_harness import tags

CHECK = "get-trust-anchor-nonexistent-not-found"
GROUP = "error-semantics"
SERVICES = ["rolesanywhere"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetTrustAnchor on a well-formed but nonexistent trustAnchorId raises
    ResourceNotFoundException -- distinct from a blanket rejection of every
    GetTrustAnchor call, proven by a positive control on the same client."""
    ca_pem = _generate_ca_pem(ctx.unique_name("sim2real-ra-ca-"))

    ra = ctx.client("rolesanywhere")
    ta = ra.create_trust_anchor(
        name=ctx.unique_name("sim2real-ra-ta-"),
        source={"sourceType": "CERTIFICATE_BUNDLE", "sourceData": {"x509CertificateData": ca_pem}},
        tags=[{"key": "sim2real", "value": "get-trust-anchor-nonexistent-not-found"}],
    )["trustAnchor"]
    ta_id = ta["trustAnchorId"]
    ctx.on_cleanup(lambda: ra.delete_trust_anchor(trustAnchorId=ta_id))

    # Positive control: the same client + same call shape, a real id, succeeds.
    got = ra.get_trust_anchor(trustAnchorId=ta_id)["trustAnchor"]
    assert got["trustAnchorId"] == ta_id, (
        f"positive control: expected GetTrustAnchor({ta_id}) to return that id, "
        f"got {got.get('trustAnchorId')!r}"
    )

    bogus_id = str(uuid.uuid4())
    err = _client_error(lambda: ra.get_trust_anchor(trustAnchorId=bogus_id))
    assert err.get("Code") == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for well-formed but nonexistent "
        f"trustAnchorId {bogus_id}, got {err.get('Code')!r}"
    )
    assert err.get("Message") == "TrustAnchor not found", (
        f"expected message 'TrustAnchor not found', got {err.get('Message')!r}"
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


def _client_error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
