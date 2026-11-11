"""trust-anchor-delete-removes-resource."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "trust-anchor-delete-removes-resource"
GROUP = "state"
SERVICES = ["rolesanywhere"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteTrustAnchor is irreversible: GetTrustAnchor 404s, it vanishes from ListTrustAnchors, and a
    mutation on the dead id also fails not-found."""
    ca_pem = _generate_ca_pem(ctx.unique_name("sim2real-ra-ca-"))

    ra = ctx.client("rolesanywhere")
    sim2real_tags = [{"key": "sim2real", "value": "trust-anchor-delete-removes-resource"}]
    created = ra.create_trust_anchor(
        name=ctx.unique_name("sim2real-ra-ta-"),
        source={"sourceType": "CERTIFICATE_BUNDLE", "sourceData": {"x509CertificateData": ca_pem}},
        tags=sim2real_tags,
    )["trustAnchor"]
    ta_id = created["trustAnchorId"]
    ctx.on_cleanup(lambda: _delete_ta_ignore_missing(ra, ta_id))

    ra.get_trust_anchor(trustAnchorId=ta_id)
    assert _ta_id_in_list(ra, ta_id), f"expected {ta_id} in ListTrustAnchors before delete, was absent"

    ra.delete_trust_anchor(trustAnchorId=ta_id)

    error = _client_error(lambda: ra.get_trust_anchor(trustAnchorId=ta_id))
    assert error["Code"] == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException from GetTrustAnchor on a deleted id, got {error['Code']!r}"
    )
    assert error.get("Message") == "TrustAnchor not found", (
        f"expected GetTrustAnchor message 'TrustAnchor not found', got {error.get('Message')!r}"
    )
    assert not _ta_id_in_list(ra, ta_id), f"expected {ta_id} absent from ListTrustAnchors after delete, still present"

    mutation_error = _client_error(lambda: ra.enable_trust_anchor(trustAnchorId=ta_id))
    assert mutation_error["Code"] == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException from EnableTrustAnchor on a deleted id, got {mutation_error['Code']!r}"
    )
    assert mutation_error.get("Message") == "TrustAnchor not found", (
        f"expected EnableTrustAnchor message 'TrustAnchor not found', got {mutation_error.get('Message')!r}"
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
    """Call fn(); return its botocore error dict. An unexpected SUCCESS raises, because a target
    accepting a call real AWS refuses must not read as an error-code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _ta_id_in_list(ra, ta_id: str) -> bool:
    next_token = None
    while True:
        kwargs = {"nextToken": next_token} if next_token else {}
        resp = ra.list_trust_anchors(**kwargs)
        if any(t["trustAnchorId"] == ta_id for t in resp.get("trustAnchors", [])):
            return True
        next_token = resp.get("nextToken")
        if not next_token:
            return False


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
