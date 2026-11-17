"""create-keys-and-certificate-sign-verify-and-active-state."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError


CHECK = "create-keys-and-certificate-sign-verify-and-active-state"
GROUP = "certificate-lifecycle"
SERVICES = ["iot"]

_MESSAGE = b"sim2real-behavioral-check-signing-payload"


def _delete_certificate(iot, cert_id):
    """Teardown: deactivate then force-delete; a missing certificate is clean."""
    try:
        iot.update_certificate(certificateId=cert_id, newStatus="INACTIVE")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
    try:
        iot.delete_certificate(certificateId=cert_id, forceDelete=True)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _sign_and_verify(private_key, cert_public_key):
    """Sign with the private key and verify with the certificate's public key.

    Returns nothing; raises if the signature does not verify, or if a signature
    over a different message is wrongly accepted (which would make the check vacuous).
    """
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

    if isinstance(private_key, rsa.RSAPrivateKey):
        signature = private_key.sign(_MESSAGE, padding.PKCS1v15(), hashes.SHA256())
        cert_public_key.verify(signature, _MESSAGE, padding.PKCS1v15(), hashes.SHA256())
        tampered = _MESSAGE + b"x"
        try:
            cert_public_key.verify(signature, tampered, padding.PKCS1v15(), hashes.SHA256())
        except InvalidSignature:
            pass
        else:
            raise AssertionError("signature over the original message wrongly verified against a different one")
    elif isinstance(private_key, ec.EllipticCurvePrivateKey):
        signature = private_key.sign(_MESSAGE, ec.ECDSA(hashes.SHA256()))
        cert_public_key.verify(signature, _MESSAGE, ec.ECDSA(hashes.SHA256()))
        tampered = _MESSAGE + b"x"
        try:
            cert_public_key.verify(signature, tampered, ec.ECDSA(hashes.SHA256()))
        except InvalidSignature:
            pass
        else:
            raise AssertionError("signature over the original message wrongly verified against a different one")
    else:
        raise AssertionError(f"unexpected private key type: {type(private_key)!r}")


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A signature made with the private key CreateKeysAndCertificate returns verifies against the
    public key of the certificate it returns; DescribeCertificate returns that PEM with status
    ACTIVE when setAsActive is true and INACTIVE when it is omitted.
    """
    from cryptography.hazmat.primitives import serialization
    from cryptography.x509 import load_pem_x509_certificate

    iot = ctx.client("iot")

    active = iot.create_keys_and_certificate(setAsActive=True)
    active_id = active["certificateId"]
    ctx.on_cleanup(lambda _n=active_id: _delete_certificate(iot, _n))

    private_key = serialization.load_pem_private_key(
        active["keyPair"]["PrivateKey"].encode(), password=None
    )
    cert = load_pem_x509_certificate(active["certificatePem"].encode())
    _sign_and_verify(private_key, cert.public_key())

    described_active = iot.describe_certificate(certificateId=active_id)["certificateDescription"]
    assert described_active["status"] == "ACTIVE", (
        f"expected ACTIVE after create(setAsActive=True), got {described_active['status']!r}"
    )
    described_active_pem = described_active["certificatePem"]
    if isinstance(described_active_pem, bytes):
        described_active_pem = described_active_pem.decode()
    assert described_active_pem == active["certificatePem"], (
        "DescribeCertificate's PEM does not match the certificate CreateKeysAndCertificate returned"
    )

    inactive = iot.create_keys_and_certificate()
    inactive_id = inactive["certificateId"]
    ctx.on_cleanup(lambda _n=inactive_id: _delete_certificate(iot, _n))

    described_inactive = iot.describe_certificate(certificateId=inactive_id)["certificateDescription"]
    assert described_inactive["status"] == "INACTIVE", (
        f"expected INACTIVE when setAsActive is omitted, got {described_inactive['status']!r}"
    )
    described_inactive_pem = described_inactive["certificatePem"]
    if isinstance(described_inactive_pem, bytes):
        described_inactive_pem = described_inactive_pem.decode()
    assert described_inactive_pem == inactive["certificatePem"], (
        "DescribeCertificate's PEM does not match the certificate CreateKeysAndCertificate returned"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
