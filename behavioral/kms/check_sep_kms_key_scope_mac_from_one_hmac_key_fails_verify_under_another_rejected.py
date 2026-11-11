"""sep-kms-key-scope-mac-from-one-hmac-key-fails-verify-under-another-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sep-kms-key-scope-mac-from-one-hmac-key-fails-verify-under-another-rejected"
GROUP = "key-separation"
SERVICES = ["kms"]

_ALG = "HMAC_SHA_256"


@tags(
    "axis:rejection",
    "cap:c1",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """HMAC key A's MAC verifies under A but fails under a second HMAC key B with
    KMSInvalidMacException (and vice versa), and the two keys' MACs differ, so each key holds
    independent material.
    """
    kms = ctx.client("kms")
    key_a = _new_hmac_key(ctx, kms, "a")
    key_b = _new_hmac_key(ctx, kms, "b")
    message = b"sep-message-authenticated-by-key-a"

    mac_a = kms.generate_mac(KeyId=key_a, Message=message, MacAlgorithm=_ALG)["Mac"]
    mac_b = kms.generate_mac(KeyId=key_b, Message=message, MacAlgorithm=_ALG)["Mac"]
    assert len(mac_a) == 32 and len(mac_b) == 32, (
        f"HMAC_SHA_256 MACs must be 32 bytes; got {len(mac_a)} and {len(mac_b)}"
    )
    assert mac_a != mac_b, (
        "two HMAC keys must hold independent material: their MACs over the same message must "
        f"differ, both were {mac_a.hex()!r}"
    )

    # Positive controls: each MAC verifies under its own key.
    for label, key, mac in (("A", key_a, mac_a), ("B", key_b, mac_b)):
        ok = kms.verify_mac(KeyId=key, Message=message, Mac=mac, MacAlgorithm=_ALG)
        assert ok["MacValid"] is True and ok["KeyId"] == key, (
            f"key {label}'s MAC must verify under key {label}; got MacValid={ok.get('MacValid')!r} "
            f"KeyId={ok.get('KeyId')!r}"
        )

    # KMS sends KMSInvalidMacException with no message at all.
    err = _rejected(
        lambda: kms.verify_mac(KeyId=key_b, Message=message, Mac=mac_a, MacAlgorithm=_ALG)
    )
    assert err["Code"] == "KMSInvalidMacException", (
        f"key A's MAC verified under key B must raise KMSInvalidMacException, got {err!r}"
    )
    assert err["Message"] == "", f"KMSInvalidMacException carries no message, got {err!r}"
    err_rev = _rejected(
        lambda: kms.verify_mac(KeyId=key_a, Message=message, Mac=mac_b, MacAlgorithm=_ALG)
    )
    assert err_rev["Code"] == "KMSInvalidMacException", (
        f"key B's MAC verified under key A must raise KMSInvalidMacException, got {err_rev!r}"
    )
    assert err_rev["Message"] == "", f"KMSInvalidMacException carries no message, got {err_rev!r}"

    # Determinism under the right key, so the refusal is not randomness.
    again = kms.generate_mac(KeyId=key_a, Message=message, MacAlgorithm=_ALG)["Mac"]
    assert again == mac_a, "HMAC under the same key over the same message must be deterministic"


def _new_hmac_key(ctx, kms, label):
    """Create an HMAC_256 key and register its scheduled deletion."""
    meta = kms.create_key(
        Description=ctx.unique_name(f"sim2real-sep-hmac-{label}-"),
        KeySpec="HMAC_256",
        KeyUsage="GENERATE_VERIFY_MAC",
        Tags=[{"TagKey": "sim2real", "TagValue": CHECK}],
    )["KeyMetadata"]
    arn = meta["Arn"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=arn, PendingWindowInDays=7))
    return arn


def _rejected(fn):
    """Return the Code and Message of the expected ClientError; raise if the call succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return {"Code": err.get("Code"), "Message": err.get("Message")}
    raise AssertionError(f"real AWS refuses this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
