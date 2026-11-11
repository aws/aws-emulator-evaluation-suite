"""derive-shared-secret-is-symmetric."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "derive-shared-secret-is-symmetric"
GROUP = 'sign_verify'
SERVICES = ['kms']


@tags("axis:happy-path", "cap:c1", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """ECDH DeriveSharedSecret is symmetric across the pair and deterministic for fixed inputs."""
    kms = ctx.client("kms")
    alice = kms.create_key(
        Description=ctx.unique_name("kms-ecdh-a-"),
        KeyUsage="KEY_AGREEMENT",
        KeySpec="ECC_NIST_P256",
        Tags=[{"TagKey": "sim2real", "TagValue": "kms-derive-shared-secret-is-symmetric"}],
    )["KeyMetadata"]
    ctx.on_cleanup(lambda _k=alice["KeyId"]: kms.schedule_key_deletion(KeyId=_k, PendingWindowInDays=7))
    bob = kms.create_key(
        Description=ctx.unique_name("kms-ecdh-b-"),
        KeyUsage="KEY_AGREEMENT",
        KeySpec="ECC_NIST_P256",
        Tags=[{"TagKey": "sim2real", "TagValue": "kms-derive-shared-secret-is-symmetric"}],
    )["KeyMetadata"]
    ctx.on_cleanup(lambda _k=bob["KeyId"]: kms.schedule_key_deletion(KeyId=_k, PendingWindowInDays=7))

    alice_pub = kms.get_public_key(KeyId=alice["KeyId"])
    bob_pub = kms.get_public_key(KeyId=bob["KeyId"])
    assert "ECDH" in alice_pub["KeyAgreementAlgorithms"], alice_pub.get("KeyAgreementAlgorithms")

    s_ab = kms.derive_shared_secret(
        KeyId=alice["KeyId"], KeyAgreementAlgorithm="ECDH", PublicKey=bob_pub["PublicKey"]
    )
    s_ba = kms.derive_shared_secret(
        KeyId=bob["KeyId"], KeyAgreementAlgorithm="ECDH", PublicKey=alice_pub["PublicKey"]
    )

    assert s_ab["KeyAgreementAlgorithm"] == "ECDH", s_ab.get("KeyAgreementAlgorithm")
    assert s_ab["KeyId"] == alice["Arn"], (s_ab["KeyId"], alice["Arn"])
    assert len(s_ab["SharedSecret"]) == 32, len(s_ab["SharedSecret"])
    assert s_ab["SharedSecret"] == s_ba["SharedSecret"], "ECDH shared secret must be symmetric"

    repeat = kms.derive_shared_secret(
        KeyId=alice["KeyId"], KeyAgreementAlgorithm="ECDH", PublicKey=bob_pub["PublicKey"]
    )
    assert repeat["SharedSecret"] == s_ab["SharedSecret"], "ECDH must be deterministic for fixed inputs"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
