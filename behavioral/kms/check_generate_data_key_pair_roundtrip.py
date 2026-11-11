"""generate-data-key-pair-roundtrip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "generate-data-key-pair-roundtrip"
GROUP = 'data_keys'
SERVICES = ['kms']


@tags("axis:happy-path", "cap:c1", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """GenerateDataKeyPair returns a DER private key whose wrapped form decrypts back byte-identically."""
    kms = ctx.client("kms")
    meta = kms.create_key(
        Description=ctx.unique_name("kms-gdkp-"),
        KeyUsage="ENCRYPT_DECRYPT",
        KeySpec="SYMMETRIC_DEFAULT",
        Tags=[{"TagKey": "sim2real", "TagValue": CHECK}],
    )["KeyMetadata"]
    ctx.on_cleanup(lambda _k=meta["KeyId"]: kms.schedule_key_deletion(KeyId=_k, PendingWindowInDays=7))

    resp = kms.generate_data_key_pair(KeyId=meta["KeyId"], KeyPairSpec="ECC_NIST_P256")
    assert resp["KeyPairSpec"] == "ECC_NIST_P256", resp["KeyPairSpec"]
    assert resp["KeyId"] == meta["Arn"], f"expected KeyId to be the key's ARN {meta['Arn']!r}, got {resp['KeyId']!r}"
    assert resp["PrivateKeyPlaintext"][:1] == b"\x30", "private key must be DER encoded"
    assert resp["PublicKey"][:1] == b"\x30", "public key must be DER encoded"

    from cryptography.hazmat.primitives import serialization

    private = serialization.load_der_private_key(resp["PrivateKeyPlaintext"], password=None)
    derived = private.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    assert resp["PublicKey"] == derived, "PublicKey must be the SPKI of the returned private key"

    unwrapped = kms.decrypt(CiphertextBlob=resp["PrivateKeyCiphertextBlob"])["Plaintext"]
    assert unwrapped == resp["PrivateKeyPlaintext"], "wrapped private key must decrypt to the plaintext one"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
