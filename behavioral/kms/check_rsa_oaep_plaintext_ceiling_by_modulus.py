"""rsa-oaep-plaintext-ceiling-by-modulus."""
from __future__ import annotations

import hashlib

from botocore.exceptions import ClientError
from behavioral_harness import tags

CHECK = "rsa-oaep-plaintext-ceiling-by-modulus"
GROUP = 'encrypt_decrypt'
SERVICES = ['kms']

ERR_VALIDATION = "ValidationException"
ALG_SHA256 = "RSAES_OAEP_SHA_256"
ALG_SHA1 = "RSAES_OAEP_SHA_1"

MODULUS_BYTES = 256                     # RSA_2048
# RFC 8017 OAEP: the message may be at most k - 2*hLen - 2 bytes.
MAX_SHA256 = MODULUS_BYTES - 2 * hashlib.sha256().digest_size - 2   # 190
MAX_SHA1 = MODULUS_BYTES - 2 * hashlib.sha1().digest_size - 2       # 214



def _client_error(fn):
    """Return the botocore Error if fn() raises ClientError. An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected rejection, but the call SUCCEEDED and returned {result!r}")


def _teardown_key(kms, key_arn: str) -> None:
    """Schedule deletion of a CMK this check minted (7-day minimum window; bills until then)."""
    assert key_arn.startswith("arn:") and ":key/" in key_arn, key_arn
    assert "alias/" not in key_arn, key_arn
    kms.schedule_key_deletion(KeyId=key_arn, PendingWindowInDays=7)


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """The RSAES_OAEP plaintext ceiling on an RSA_2048 key depends on the OAEP hash: 190 bytes for
    SHA-256 and 214 for SHA-1, exact to the byte; one byte over, or 4096 bytes, is refused.
    """
    kms = ctx.client("kms")
    assert (MAX_SHA256, MAX_SHA1) == (190, 214), (MAX_SHA256, MAX_SHA1)
    meta = kms.create_key(
        Description=ctx.unique_name("sim2real-behav-kms-oaepmax-"),
        KeyUsage="ENCRYPT_DECRYPT",
        KeySpec="RSA_2048",
    )["KeyMetadata"]
    key_arn = meta["Arn"]
    ctx.on_cleanup(lambda _a=key_arn: _teardown_key(kms, _a))
    assert meta["KeySpec"] == "RSA_2048", meta["KeySpec"]
    assert sorted(meta["EncryptionAlgorithms"]) == [ALG_SHA1, ALG_SHA256], (
        meta["EncryptionAlgorithms"]
    )

    def _roundtrip(size: int, alg: str) -> None:
        """Encrypt/Decrypt `size` bytes under `alg` and assert byte-identical recovery."""
        pt = bytes((i % 251) + 1 for i in range(size))
        assert len(pt) == size
        enc = kms.encrypt(KeyId=key_arn, Plaintext=pt, EncryptionAlgorithm=alg)
        assert enc["EncryptionAlgorithm"] == alg, enc["EncryptionAlgorithm"]
        dec = kms.decrypt(
            CiphertextBlob=enc["CiphertextBlob"], KeyId=key_arn, EncryptionAlgorithm=alg
        )
        assert dec["Plaintext"] == pt, f"{size}-byte round trip under {alg} must be exact"

    def _rejected(size: int, alg: str) -> None:
        """Assert `size` bytes under `alg` is refused with the specific validation error."""
        pt = b"x" * size
        err = _client_error(
            lambda: kms.encrypt(KeyId=key_arn, Plaintext=pt, EncryptionAlgorithm=alg)
        )
        ceiling = MAX_SHA256 if alg == ALG_SHA256 else MAX_SHA1
        # ValidationException is not a modelled KMS error shape, but KMS returns it for input-size
        # violations.
        assert err["Code"] == ERR_VALIDATION, (
            f"{size} bytes under {alg} (max {ceiling}) must raise {ERR_VALIDATION}, got {err!r}"
        )
        expected = (
            f"Algorithm {alg} and key spec RSA_2048 cannot encrypt data larger than {ceiling} bytes."
        )
        assert err["Message"] == expected, (
            f"{size} bytes under {alg}: expected message {expected!r}, got {err['Message']!r}"
        )

    # Both ceilings, exactly at the limit, must round-trip.
    _roundtrip(MAX_SHA256, ALG_SHA256)          # 190
    _roundtrip(MAX_SHA1, ALG_SHA1)              # 214

    # One byte over each ceiling.
    _rejected(MAX_SHA256 + 1, ALG_SHA256)       # 191
    _rejected(MAX_SHA1 + 1, ALG_SHA1)           # 215

    # 214 bytes is legal under SHA-1 and illegal under SHA-256 on this same key.
    _rejected(MAX_SHA1, ALG_SHA256)             # 214 under SHA-256

    # 4096 bytes is inside PlaintextType's modelled max, so it reaches the server; the symmetric
    # ceiling must not apply to an asymmetric key.
    _rejected(4096, ALG_SHA256)

    after = kms.describe_key(KeyId=key_arn)["KeyMetadata"]
    assert after["KeyState"] == "Enabled", after["KeyState"]
    assert after["Enabled"] is True, after
    _roundtrip(MAX_SHA256, ALG_SHA256)
    _roundtrip(1, ALG_SHA256)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
