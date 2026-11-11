"""get-trust-anchor-malformed-id-validation-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-trust-anchor-malformed-id-validation-rejected"
GROUP = "overly-permissive"
SERVICES = ["rolesanywhere"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetTrustAnchor with a trustAnchorId that is not a UUID is refused with ValidationException,
    while the same call with a real trust anchor's id succeeds.
    """
    ca_pem = _generate_ca_pem(ctx.unique_name("sim2real-ra-ca-"))

    ra = ctx.client("rolesanywhere")
    ta = ra.create_trust_anchor(
        name=ctx.unique_name("sim2real-ra-ta-"),
        source={"sourceType": "CERTIFICATE_BUNDLE", "sourceData": {"x509CertificateData": ca_pem}},
        tags=[{"key": "sim2real", "value": CHECK}],
    )["trustAnchor"]
    ta_id = ta["trustAnchorId"]
    ctx.on_cleanup(lambda: ra.delete_trust_anchor(trustAnchorId=ta_id))

    malformed_id = "zzzzzzzz-zzzz-zzzz-zzzz-zzzzzzzzzzzz"
    error = _client_error(lambda: ra.get_trust_anchor(trustAnchorId=malformed_id))
    assert error["Code"] == "ValidationException", f"expected ValidationException, got {error['Code']!r}"
    expected_message = (
        f"1 validation error detected: Value '{malformed_id}' at 'trustAnchorId' failed to satisfy "
        "constraint: Member must satisfy regular expression pattern: "
        "([a-f0-9]{8}-([a-z0-9]{4}-){3}[a-z0-9]{12}|arn:aws(-[^:]+)?:rolesanywhere(:.*){2}:"
        "(trust-anchor|alias/trust-anchor)/.*)"
    )
    assert error.get("Message") == expected_message, (
        f"expected message {expected_message!r}, got {error.get('Message')!r}"
    )

    # Positive control: the same client + same call shape, valid id, succeeds.
    got = ra.get_trust_anchor(trustAnchorId=ta_id)["trustAnchor"]
    assert got["trustAnchorId"] == ta_id, f"expected trustAnchorId {ta_id!r}, got {got['trustAnchorId']!r}"


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
    """Call fn(); return its botocore error dict. An unexpected SUCCESS raises, because an emulator
    ACCEPTING an id real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"real AWS rejects this trustAnchorId, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
