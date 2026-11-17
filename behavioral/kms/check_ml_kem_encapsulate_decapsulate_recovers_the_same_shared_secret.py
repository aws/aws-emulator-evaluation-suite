"""ml-kem-encapsulate-decapsulate-recovers-the-same-shared-secret."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "ml-kem-encapsulate-decapsulate-recovers-the-same-shared-secret"
GROUP = "key_agreement"
SERVICES = ["kms"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """An ML-KEM key pair's GetPublicKey, Encapsulate and Decapsulate round trip: Decapsulate
    recovers the exact 32-byte shared secret Encapsulate generated for that ciphertext.
    """
    kms = ctx.client("kms")

    created = kms.create_key(
        Description=ctx.unique_name("sim2real-behav-mlkem-"),
        KeyUsage="ENCAPSULATE_DECAPSULATE",
        KeySpec="ML_KEM_512",
        Tags=[{"TagKey": "sim2real-behav", "TagValue": CHECK}],
    )["KeyMetadata"]
    key_id = created["KeyId"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7))
    assert created["KeySpec"] == "ML_KEM_512", f"KeySpec: {created['KeySpec']!r}"
    assert created["KeyUsage"] == "ENCAPSULATE_DECAPSULATE", f"KeyUsage: {created['KeyUsage']!r}"

    pub = kms.get_public_key(KeyId=key_id)
    assert pub["KeySpec"] == "ML_KEM_512", f"GetPublicKey KeySpec: {pub['KeySpec']!r}"
    assert pub["KeyUsage"] == "ENCAPSULATE_DECAPSULATE", (
        f"GetPublicKey KeyUsage: {pub['KeyUsage']!r}"
    )
    assert pub["EncapsulationAlgorithms"] == ["ML_KEM"], (
        f"GetPublicKey EncapsulationAlgorithms: {pub['EncapsulationAlgorithms']!r}"
    )
    assert len(pub["PublicKey"]) > 0, "GetPublicKey returned an empty public key"

    encapsulated = kms.encapsulate(KeyId=key_id, EncapsulationAlgorithm="ML_KEM")
    assert encapsulated["KeyId"] == created["Arn"], (
        f"Encapsulate KeyId: {encapsulated['KeyId']!r}, expected {created['Arn']!r}"
    )
    assert encapsulated["EncapsulationAlgorithm"] == "ML_KEM", (
        f"Encapsulate EncapsulationAlgorithm: {encapsulated['EncapsulationAlgorithm']!r}"
    )
    shared_secret = encapsulated["SharedSecret"]
    ciphertext = encapsulated["SharedSecretCiphertextBlob"]
    assert len(shared_secret) == 32, f"Encapsulate SharedSecret length: {len(shared_secret)}"
    assert len(ciphertext) > 0, "Encapsulate returned an empty SharedSecretCiphertextBlob"

    decapsulated = kms.decapsulate(
        KeyId=key_id,
        SharedSecretCiphertextBlob=ciphertext,
        EncapsulationAlgorithm="ML_KEM",
    )
    assert decapsulated["KeyId"] == created["Arn"], (
        f"Decapsulate KeyId: {decapsulated['KeyId']!r}, expected {created['Arn']!r}"
    )
    assert decapsulated["EncapsulationAlgorithm"] == "ML_KEM", (
        f"Decapsulate EncapsulationAlgorithm: {decapsulated['EncapsulationAlgorithm']!r}"
    )
    recovered_secret = decapsulated["SharedSecret"]
    assert recovered_secret == shared_secret, (
        "Decapsulate must recover the same shared secret Encapsulate generated for this "
        f"ciphertext, got {recovered_secret!r} instead of {shared_secret!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
