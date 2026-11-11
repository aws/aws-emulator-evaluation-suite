"""create-trust-anchor-malformed-certificate-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-trust-anchor-malformed-certificate-rejected"
GROUP = "overly-permissive"
SERVICES = ["rolesanywhere"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateTrustAnchor with CERTIFICATE_BUNDLE sourceData that is not a PEM X.509 certificate is
    refused with ValidationException and creates no trust anchor, while the same call with a real CA
    certificate succeeds and GetTrustAnchor reads it back.
    """
    ca_pem = _generate_ca_pem(ctx.unique_name("sim2real-ra-ca-"))

    ra = ctx.client("rolesanywhere")
    rejected_name = ctx.unique_name("sim2real-ra-badcert-")

    error = _client_error(
        lambda: ra.create_trust_anchor(
            name=rejected_name,
            source={
                "sourceType": "CERTIFICATE_BUNDLE",
                "sourceData": {"x509CertificateData": "not a valid PEM certificate"},
            },
        )
    )
    assert error["Code"] == "ValidationException", (
        f"expected ValidationException for malformed cert, got {error['Code']!r}"
    )
    expected_message = "Error creating TrustAnchor. Bad certificate data"
    assert error.get("Message") == expected_message, (
        f"expected message {expected_message!r}, got {error.get('Message')!r}"
    )
    assert not _trust_anchor_name_in_list(ra, rejected_name), (
        f"trust anchor {rejected_name!r} must not exist after a rejected create"
    )

    # Positive control: same shape, genuine certificate bundle, succeeds.
    accepted_name = ctx.unique_name("sim2real-ra-goodcert-")
    created = ra.create_trust_anchor(
        name=accepted_name,
        source={"sourceType": "CERTIFICATE_BUNDLE", "sourceData": {"x509CertificateData": ca_pem}},
        tags=[{"key": "sim2real", "value": "true"}],
    )["trustAnchor"]
    created_id = created["trustAnchorId"]
    ctx.on_cleanup(lambda: ra.delete_trust_anchor(trustAnchorId=created_id))

    # Terminal assertion is an independent read (GetTrustAnchor), not the create
    # call's own response, and confirms the anchor is discoverable at the destination.
    fetched = ra.get_trust_anchor(trustAnchorId=created_id)["trustAnchor"]
    assert fetched["name"] == accepted_name, (
        f"expected GetTrustAnchor to reflect name {accepted_name!r}, got {fetched['name']!r}"
    )
    assert _trust_anchor_name_in_list(ra, accepted_name), (
        f"trust anchor {accepted_name!r} must be visible in ListTrustAnchors after a successful create"
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


def _trust_anchor_name_in_list(ra, name: str) -> bool:
    next_token = None
    while True:
        kwargs = {"nextToken": next_token} if next_token else {}
        resp = ra.list_trust_anchors(**kwargs)
        if any(t["name"] == name for t in resp.get("trustAnchors", [])):
            return True
        next_token = resp.get("nextToken")
        if not next_token:
            return False


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
