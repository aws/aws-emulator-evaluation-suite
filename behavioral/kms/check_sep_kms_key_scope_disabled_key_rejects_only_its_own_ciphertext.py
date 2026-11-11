"""sep-kms-key-scope-disabled-key-rejects-only-its-own-ciphertext."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sep-kms-key-scope-disabled-key-rejects-only-its-own-ciphertext"
GROUP = "key-separation"
SERVICES = ["kms"]


@tags(
    "axis:rejection",
    "cap:c1",
    "cap:c4",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """Disabling key A makes keyless Decrypt of A's blob fail with DisabledException while key B's
    blob still decrypts; re-enabling A restores the exact original bytes.
    """
    kms = ctx.client("kms")
    key_a = _new_key(ctx, kms, "a")
    key_b = _new_key(ctx, kms, "b")
    payload = b"sep-disable-scope-payload"
    ct_a = kms.encrypt(KeyId=key_a, Plaintext=payload)["CiphertextBlob"]
    ct_b = kms.encrypt(KeyId=key_b, Plaintext=payload)["CiphertextBlob"]

    for blob, owner in ((ct_a, key_a), (ct_b, key_b)):
        out = kms.decrypt(CiphertextBlob=blob)
        assert (out["KeyId"], out["Plaintext"]) == (owner, payload), (
            f"before any key is disabled, keyless Decrypt must return ({owner!r}, {payload!r}); "
            f"got {(out['KeyId'], out['Plaintext'])!r}"
        )

    # Re-enable is registered so a failing assert cannot leave the key disabled.
    kms.disable_key(KeyId=key_a)
    ctx.on_cleanup(lambda: kms.enable_key(KeyId=key_a))
    state = kms.describe_key(KeyId=key_a)["KeyMetadata"]["KeyState"]
    assert state == "Disabled", f"DescribeKey must report key A as Disabled, got {state!r}"

    refused = _poll(
        lambda: _outcome(lambda: kms.decrypt(CiphertextBlob=ct_a)),
        lambda o: o["Code"] == "DisabledException",
        timeout_s=60,
        interval_s=2,
        description="Decrypt of key A's blob refused after DisableKey",
    )
    assert refused["Code"] == "DisabledException", (
        f"keyless Decrypt of a blob wrapped by the disabled key A must raise DisabledException, "
        f"got {refused!r}"
    )
    expected = f"{key_a} is disabled."
    assert refused["Message"] == expected, (
        f"expected message {expected!r}, got {refused['Message']!r}"
    )

    sib = kms.decrypt(CiphertextBlob=ct_b)
    assert (sib["KeyId"], sib["Plaintext"]) == (key_b, payload), (
        f"disabling key A must not affect key B's ciphertext; keyless Decrypt returned "
        f"{(sib['KeyId'], sib['Plaintext'])!r}"
    )
    fresh_b = kms.encrypt(KeyId=key_b, Plaintext=payload)["CiphertextBlob"]
    assert kms.decrypt(CiphertextBlob=fresh_b)["Plaintext"] == payload, (
        "key B must keep encrypting and decrypting while key A is disabled"
    )

    kms.enable_key(KeyId=key_a)
    restored = _poll(
        lambda: _outcome(lambda: kms.decrypt(CiphertextBlob=ct_a)),
        lambda o: o["Code"] == "OK",
        timeout_s=60,
        interval_s=2,
        description="Decrypt of key A's blob restored after EnableKey",
    )
    assert restored["Code"] == "OK", f"after EnableKey, Decrypt of key A's blob must succeed, got {restored!r}"
    back = kms.decrypt(CiphertextBlob=ct_a)
    assert (back["KeyId"], back["Plaintext"]) == (key_a, payload), (
        f"after re-enabling key A its original blob must decrypt to ({key_a!r}, {payload!r}); got "
        f"{(back['KeyId'], back['Plaintext'])!r}"
    )


def _new_key(ctx, kms, label):
    """A fresh symmetric key; its 7-day scheduled deletion is registered before it is returned."""
    meta = kms.create_key(
        Description=ctx.unique_name(f"sim2real-sep-{label}-"),
        Tags=[{"TagKey": "sim2real", "TagValue": CHECK}],
    )["KeyMetadata"]
    arn = meta["Arn"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=arn, PendingWindowInDays=7))
    return arn


def _outcome(fn):
    """``{"Code": "OK"}`` on success, else the AWS error."""
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]
    return {"Code": "OK"}


def _poll(probe, predicate, *, timeout_s, interval_s, description):
    """Bounded poll to an observable condition; raises on timeout."""
    deadline = time.monotonic() + timeout_s
    last = probe()
    while not predicate(last):
        if time.monotonic() >= deadline:
            raise AssertionError(f"{description} not observed within {timeout_s}s; last {last!r}")
        time.sleep(interval_s)
        last = probe()
    return last


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
