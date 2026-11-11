"""sep-kms-key-scope-cross-key-decrypt-fails-while-keyless-decrypt-names-the-wrapping-key."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sep-kms-key-scope-cross-key-decrypt-fails-while-keyless-decrypt-names-the-wrapping-key"
GROUP = "key-separation"
SERVICES = ["kms"]


@tags(
    "axis:rejection",
    "cap:c1",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """Keyless Decrypt routes each of two keys' blobs to the key that wrapped it, while Decrypt
    pinned to the other key is refused with IncorrectKeyException, in both directions.
    """
    kms = ctx.client("kms")
    key_a = _new_key(ctx, kms, "a")
    key_b = _new_key(ctx, kms, "b")
    assert key_a != key_b, f"two CreateKey calls must mint two keys; both returned {key_a!r}"

    same = b"sep-identical-plaintext-under-two-keys"
    ct_a = kms.encrypt(KeyId=key_a, Plaintext=same)["CiphertextBlob"]
    ct_b = kms.encrypt(KeyId=key_b, Plaintext=same)["CiphertextBlob"]
    assert ct_a != ct_b, "the same plaintext under two different keys must not yield the same blob"
    assert same not in ct_a and same not in ct_b, (
        f"the plaintext must not appear inside the ciphertext; ct_a={ct_a!r} ct_b={ct_b!r}"
    )

    # The same plaintext under both keys, so only the blob can route a keyless decrypt.
    for label, blob, owner in (("A", ct_a, key_a), ("B", ct_b, key_b)):
        out = kms.decrypt(CiphertextBlob=blob)
        assert out["Plaintext"] == same, (
            f"keyless Decrypt of key {label}'s blob must return {same!r}, got {out['Plaintext']!r}"
        )
        assert out["KeyId"] == owner, (
            f"keyless Decrypt must attribute key {label}'s blob to {owner!r} (the key that wrapped "
            f"it), got {out['KeyId']!r}"
        )
        pinned = kms.decrypt(CiphertextBlob=blob, KeyId=owner)
        assert pinned["Plaintext"] == same, (
            f"Decrypt pinned to the wrapping key {label} must succeed, got {pinned['Plaintext']!r}"
        )

    code_ab = _rejected(lambda: kms.decrypt(CiphertextBlob=ct_a, KeyId=key_b))
    assert code_ab == ("IncorrectKeyException", _INCORRECT_KEY_MESSAGE), (
        f"Decrypt of key A's blob pinned to key B must raise IncorrectKeyException, got {code_ab!r}"
    )
    code_ba = _rejected(lambda: kms.decrypt(CiphertextBlob=ct_b, KeyId=key_a))
    assert code_ba == ("IncorrectKeyException", _INCORRECT_KEY_MESSAGE), (
        f"Decrypt of key B's blob pinned to key A must raise IncorrectKeyException, got {code_ba!r}"
    )

    after_a = kms.decrypt(CiphertextBlob=ct_a)
    after_b = kms.decrypt(CiphertextBlob=ct_b)
    assert (after_a["KeyId"], after_a["Plaintext"]) == (key_a, same), (
        f"after the refused cross-key decrypt, key A's blob must still decrypt under A; got "
        f"{(after_a['KeyId'], after_a['Plaintext'])!r}"
    )
    assert (after_b["KeyId"], after_b["Plaintext"]) == (key_b, same), (
        f"after the refused cross-key decrypt, key B's blob must still decrypt under B; got "
        f"{(after_b['KeyId'], after_b['Plaintext'])!r}"
    )


_INCORRECT_KEY_MESSAGE = (
    "The key ID in the request does not identify a CMK that can perform this operation."
)


def _new_key(ctx, kms, label):
    """A fresh symmetric key; its 7-day scheduled deletion is registered before it is returned."""
    meta = kms.create_key(
        Description=ctx.unique_name(f"sim2real-sep-{label}-"),
        KeyUsage="ENCRYPT_DECRYPT",
        KeySpec="SYMMETRIC_DEFAULT",
        Tags=[{"TagKey": "sim2real", "TagValue": CHECK[:200]}],
    )["KeyMetadata"]
    arn = meta["Arn"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=arn, PendingWindowInDays=7))
    return arn


def _rejected(fn):
    """The AWS error code and message of a call real AWS refuses; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code") or "NO_ERROR_CODE", err.get("Message")
    raise AssertionError(f"real AWS refuses this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
