"""decapsulate-cross-key-ciphertext-implicit-rejection."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "decapsulate-cross-key-ciphertext-implicit-rejection"
GROUP = "sign_verify"
SERVICES = ["kms"]


@tags("axis:happy-path", "cap:c1", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Decapsulate accepts a correctly-sized ciphertext encapsulated under a different ML-KEM
    key: it returns 200 with a 32-byte shared secret that does not match the originator's,
    rather than an error (ML-KEM implicit rejection), while the matching key still recovers it."""
    kms = ctx.client("kms")
    key_a = kms.create_key(
        Description=ctx.unique_name("kms-ml-kem-a-"),
        KeyUsage="ENCAPSULATE_DECAPSULATE",
        KeySpec="ML_KEM_768",
        Tags=[{"TagKey": "sim2real", "TagValue": "kms-decapsulate-cross-key-implicit-rejection"}],
    )["KeyMetadata"]
    ctx.on_cleanup(lambda _k=key_a["KeyId"]: kms.schedule_key_deletion(KeyId=_k, PendingWindowInDays=7))
    key_b = kms.create_key(
        Description=ctx.unique_name("kms-ml-kem-b-"),
        KeyUsage="ENCAPSULATE_DECAPSULATE",
        KeySpec="ML_KEM_768",
        Tags=[{"TagKey": "sim2real", "TagValue": "kms-decapsulate-cross-key-implicit-rejection"}],
    )["KeyMetadata"]
    ctx.on_cleanup(lambda _k=key_b["KeyId"]: kms.schedule_key_deletion(KeyId=_k, PendingWindowInDays=7))

    encapsulated_a = kms.encapsulate(KeyId=key_a["KeyId"], EncapsulationAlgorithm="ML_KEM")
    ciphertext_a = encapsulated_a["SharedSecretCiphertextBlob"]

    # positive control: the originating key recovers the identical shared secret
    control = kms.decapsulate(
        KeyId=key_a["KeyId"], SharedSecretCiphertextBlob=ciphertext_a, EncapsulationAlgorithm="ML_KEM"
    )
    assert control["SharedSecret"] == encapsulated_a["SharedSecret"], (
        "positive control: the originating key must recover the identical shared secret"
    )

    cross = kms.decapsulate(
        KeyId=key_b["KeyId"], SharedSecretCiphertextBlob=ciphertext_a, EncapsulationAlgorithm="ML_KEM"
    )
    assert len(cross["SharedSecret"]) == 32, f"expected a 32-byte shared secret, got {len(cross['SharedSecret'])}"
    assert cross["SharedSecret"] != encapsulated_a["SharedSecret"], (
        "a ciphertext decapsulated under the wrong key must not recover the originator's shared secret"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
