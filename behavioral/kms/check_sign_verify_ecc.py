"""sign-verify-ecc."""
from __future__ import annotations

import hashlib

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils

from behavioral_harness import tags

CHECK = "sign-verify-ecc"
GROUP = 'sign_verify'
SERVICES = ['kms']


def _local_verify(public_key, signature: bytes, digest: bytes) -> bool:
    """Verify a KMS ECDSA_SHA_256 signature over a pre-computed digest, off AWS."""
    try:
        public_key.verify(signature, digest, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
        return True
    except InvalidSignature:
        return False


@tags("axis:happy-path", "cap:c1", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """An ECC_NIST_P256 Sign result verifies locally against GetPublicKey's DER key and via KMS
    Verify; a one-bit digest tamper fails local verification, so the local check is not vacuous."""
    kms = ctx.client("kms")
    resp = kms.create_key(
        Description=ctx.unique_name("sim2real-behav-kms-ecc-sign-"),
        KeyUsage="SIGN_VERIFY",
        KeySpec="ECC_NIST_P256",
        Tags=[{"TagKey": "sim2real", "TagValue": "kms-sign-verify-ecc"}],
    )
    key_id = resp["KeyMetadata"]["KeyId"]
    ctx.on_cleanup(lambda _k=key_id: kms.schedule_key_deletion(KeyId=_k, PendingWindowInDays=7))

    message = b"ecc-sign-verify-data"
    digest = hashlib.sha256(message).digest()
    tampered_digest = digest[:-1] + bytes([digest[-1] ^ 1])

    sign_resp = kms.sign(
        KeyId=key_id,
        Message=digest,
        MessageType="DIGEST",
        SigningAlgorithm="ECDSA_SHA_256",
    )
    signature = sign_resp["Signature"]

    pub = kms.get_public_key(KeyId=key_id)
    assert pub["KeySpec"] == "ECC_NIST_P256", (
        f"GetPublicKey advertises KeySpec {pub['KeySpec']!r}, the key was created as "
        f"ECC_NIST_P256"
    )
    loaded = serialization.load_der_public_key(pub["PublicKey"])

    assert _local_verify(loaded, signature, digest) is True, (
        f"the ECDSA_SHA_256 signature KMS produced for {key_id} does not verify locally "
        f"against the public key KMS published for it — the two halves are not a key pair"
    )
    assert _local_verify(loaded, signature, tampered_digest) is False, (
        "a one-bit digest change must break local ECDSA verification — the local "
        "verifier is not checking anything"
    )

    verify_resp = kms.verify(
        KeyId=key_id,
        Message=digest,
        MessageType="DIGEST",
        Signature=signature,
        SigningAlgorithm="ECDSA_SHA_256",
    )
    assert verify_resp["SignatureValid"] is True, (
        f"KMS Verify disagrees with the local verifier on its own signature: {verify_resp!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
