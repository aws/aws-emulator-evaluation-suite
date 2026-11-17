"""ml-kem-encapsulate-decapsulate-round-trip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "ml-kem-encapsulate-decapsulate-round-trip"
GROUP = "sign_verify"
SERVICES = ["kms"]


@tags("axis:happy-path", "cap:c1", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Encapsulate on an ML-KEM key returns a shared secret and its ciphertext, and Decapsulate
    on the matching ciphertext with the same key recovers the identical shared secret."""
    kms = ctx.client("kms")
    key_meta = kms.create_key(
        Description=ctx.unique_name("kms-ml-kem-"),
        KeyUsage="ENCAPSULATE_DECAPSULATE",
        KeySpec="ML_KEM_768",
        Tags=[{"TagKey": "sim2real", "TagValue": "kms-ml-kem-encapsulate-decapsulate-round-trip"}],
    )["KeyMetadata"]
    key_id, key_arn = key_meta["KeyId"], key_meta["Arn"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7))

    encapsulated = kms.encapsulate(KeyId=key_id, EncapsulationAlgorithm="ML_KEM")
    assert encapsulated["KeyId"] == key_arn, f"expected KeyId {key_arn!r}, got {encapsulated['KeyId']!r}"
    assert encapsulated["EncapsulationAlgorithm"] == "ML_KEM", encapsulated["EncapsulationAlgorithm"]
    assert len(encapsulated["SharedSecret"]) == 32, f"expected a 32-byte shared secret, got {len(encapsulated['SharedSecret'])}"
    ciphertext = encapsulated["SharedSecretCiphertextBlob"]

    decapsulated = kms.decapsulate(
        KeyId=key_id, SharedSecretCiphertextBlob=ciphertext, EncapsulationAlgorithm="ML_KEM"
    )
    assert decapsulated["KeyId"] == key_arn, f"expected KeyId {key_arn!r}, got {decapsulated['KeyId']!r}"
    assert decapsulated["EncapsulationAlgorithm"] == "ML_KEM", decapsulated["EncapsulationAlgorithm"]
    assert decapsulated["SharedSecret"] == encapsulated["SharedSecret"], (
        "decapsulating the matching ciphertext must recover the identical shared secret"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
