"""generate-data-key-pair-without-plaintext."""
from __future__ import annotations

from cryptography.hazmat.primitives import serialization
from behavioral_harness import tags

CHECK = "generate-data-key-pair-without-plaintext"
GROUP = 'data_keys'
SERVICES = ['kms']


@tags("axis:happy-path", "cap:c1", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """GenerateDataKeyPairWithoutPlaintext omits PrivateKeyPlaintext but the wrapped private key it
    returns is a genuine mathematical pair with the published public key, not two independently
    well-formed DER blobs with no relation to each other.
    """
    kms = ctx.client("kms")
    meta = kms.create_key(
        Description=ctx.unique_name("kms-gdkpnp-"),
        KeyUsage="ENCRYPT_DECRYPT",
        KeySpec="SYMMETRIC_DEFAULT",
        Tags=[{"TagKey": "sim2real", "TagValue": CHECK}],
    )["KeyMetadata"]
    ctx.on_cleanup(lambda _k=meta["KeyId"]: kms.schedule_key_deletion(KeyId=_k, PendingWindowInDays=7))

    resp = kms.generate_data_key_pair_without_plaintext(
        KeyId=meta["KeyId"], KeyPairSpec="ECC_NIST_P256"
    )
    assert "PrivateKeyPlaintext" not in resp, "response must not leak the plaintext private key"
    assert resp["KeyId"] == meta["Arn"], f"KeyId must echo the CMK ARN, got {resp['KeyId']!r}"
    assert resp["KeyPairSpec"] == "ECC_NIST_P256", resp["KeyPairSpec"]
    assert resp["PrivateKeyCiphertextBlob"], "PrivateKeyCiphertextBlob must not be empty"
    assert resp["PublicKey"][:1] == b"\x30", "public key must be DER encoded"

    unwrapped = kms.decrypt(CiphertextBlob=resp["PrivateKeyCiphertextBlob"])["Plaintext"]
    assert unwrapped[:1] == b"\x30", "unwrapped private key must be DER encoded"

    # --- The independent proof: the unwrapped private key must derive the SAME public key KMS
    # published, not merely be some other well-formed EC private key. Without this, a target could
    # satisfy every assertion above by pairing any valid EC public key with any valid EC private
    # key ciphertext, with no mathematical relation between the two.
    derived_public_der = (
        serialization.load_der_private_key(unwrapped, password=None)
        .public_key()
        .public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    )
    assert derived_public_der == resp["PublicKey"], (
        "the unwrapped private key does not derive the public key GenerateDataKeyPairWithoutPlaintext "
        "published — PrivateKeyCiphertextBlob and PublicKey are not a matching pair"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
