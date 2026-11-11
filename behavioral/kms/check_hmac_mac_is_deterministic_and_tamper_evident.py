"""hmac-mac-is-deterministic-and-tamper-evident."""
from __future__ import annotations

from botocore.exceptions import ClientError
from behavioral_harness import tags

CHECK = "hmac-mac-is-deterministic-and-tamper-evident"
GROUP = 'hmac'
SERVICES = ['kms']

ERR_INVALID_MAC = "KMSInvalidMacException"
MAC_ALG = "HMAC_SHA_256"
# AWS sends KMSInvalidMacException with an empty message.
INVALID_MAC_MESSAGE = ""


def _error(fn):
    """Call fn(); return its (Error.Code, Error.Message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _teardown_key(kms, key_arn: str) -> None:
    """Schedule deletion of a CMK this check minted (7-day minimum window)."""
    assert key_arn.startswith("arn:") and ":key/" in key_arn, key_arn
    assert "alias/" not in key_arn, key_arn
    kms.schedule_key_deletion(KeyId=key_arn, PendingWindowInDays=7)


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """GenerateMac is deterministic (same key, message and algorithm give the same 32-byte MAC),
    and a failed VerifyMac raises KMSInvalidMacException rather than returning MacValid: false.

    Reference: https://docs.aws.amazon.com/kms/latest/APIReference/API_VerifyMac.html
    """
    kms = ctx.client("kms")
    meta = kms.create_key(
        Description=ctx.unique_name("sim2real-behav-kms-macdet-"),
        KeyUsage="GENERATE_VERIFY_MAC",
        KeySpec="HMAC_256",
        Tags=[{"TagKey": "sim2real", "TagValue": CHECK}],
    )["KeyMetadata"]
    key_arn = meta["Arn"]
    ctx.on_cleanup(lambda _a=key_arn: _teardown_key(kms, _a))
    assert meta["KeySpec"] == "HMAC_256", meta["KeySpec"]
    assert meta["KeyUsage"] == "GENERATE_VERIFY_MAC", meta["KeyUsage"]
    assert meta["MacAlgorithms"] == [MAC_ALG], meta["MacAlgorithms"]

    message = b"mac-me-deterministically"

    first = kms.generate_mac(KeyId=key_arn, Message=message, MacAlgorithm=MAC_ALG)
    second = kms.generate_mac(KeyId=key_arn, Message=message, MacAlgorithm=MAC_ALG)
    mac = first["Mac"]
    assert second["Mac"] == mac, (
        "HMAC is deterministic: the same key/message/algorithm must produce the identical MAC"
    )
    assert len(mac) == 32, f"HMAC_SHA_256 must be 32 bytes, got {len(mac)}"
    assert first["MacAlgorithm"] == MAC_ALG, first["MacAlgorithm"]
    assert first["KeyId"] == key_arn, first["KeyId"]

    # A one-byte-longer message must produce a completely different MAC.
    other = kms.generate_mac(KeyId=key_arn, Message=message + b" ", MacAlgorithm=MAC_ALG)["Mac"]
    assert other != mac, "a different message must produce a different MAC"
    assert len(other) == 32, len(other)

    ok = kms.verify_mac(KeyId=key_arn, Message=message, MacAlgorithm=MAC_ALG, Mac=mac)
    assert ok["MacValid"] is True, ok
    assert ok["MacAlgorithm"] == MAC_ALG, ok["MacAlgorithm"]
    assert ok["KeyId"] == key_arn, ok["KeyId"]

    tampered = bytearray(message)
    tampered[0] ^= 0x01
    code, err_message = _error(lambda: kms.verify_mac(
        KeyId=key_arn, Message=bytes(tampered), MacAlgorithm=MAC_ALG, Mac=mac))
    assert code == ERR_INVALID_MAC, (
        f"VerifyMac on a tampered message must RAISE {ERR_INVALID_MAC}, not return "
        f"MacValid: false; got {code!r}"
    )
    assert err_message == INVALID_MAC_MESSAGE, f"unexpected message: {err_message!r}"

    bad_mac = bytearray(mac)
    bad_mac[-1] ^= 0x01
    code, err_message = _error(lambda: kms.verify_mac(
        KeyId=key_arn, Message=message, MacAlgorithm=MAC_ALG, Mac=bytes(bad_mac)))
    assert code == ERR_INVALID_MAC, (
        f"VerifyMac with a bit-flipped MAC must raise {ERR_INVALID_MAC}, got {code!r}"
    )
    assert err_message == INVALID_MAC_MESSAGE, f"unexpected message: {err_message!r}"

    # A truncated tag must not verify (no prefix comparison).
    code, err_message = _error(lambda: kms.verify_mac(
        KeyId=key_arn, Message=message, MacAlgorithm=MAC_ALG, Mac=mac[:16]))
    assert code == ERR_INVALID_MAC, (
        f"VerifyMac with a truncated (16-byte) MAC must raise {ERR_INVALID_MAC}, got {code!r}"
    )
    assert err_message == INVALID_MAC_MESSAGE, f"unexpected message: {err_message!r}"

    code, err_message = _error(lambda: kms.verify_mac(
        KeyId=key_arn, Message=message, MacAlgorithm=MAC_ALG, Mac=other))
    assert code == ERR_INVALID_MAC, (
        f"VerifyMac with another message's MAC must raise {ERR_INVALID_MAC}, got {code!r}"
    )
    assert err_message == INVALID_MAC_MESSAGE, f"unexpected message: {err_message!r}"

    # The refusals changed nothing.
    again = kms.verify_mac(KeyId=key_arn, Message=message, MacAlgorithm=MAC_ALG, Mac=mac)
    assert again["MacValid"] is True, again
    assert kms.generate_mac(
        KeyId=key_arn, Message=message, MacAlgorithm=MAC_ALG
    )["Mac"] == mac, "GenerateMac must remain deterministic after failed verifications"
    after = kms.describe_key(KeyId=key_arn)["KeyMetadata"]
    assert after["KeyState"] == "Enabled", after["KeyState"]
    assert after["Enabled"] is True, after
    # The other message's MAC verifies against the other message — so the refusals above were
    # about the pairing, not about the key having been invalidated.
    assert kms.verify_mac(
        KeyId=key_arn, Message=message + b" ", MacAlgorithm=MAC_ALG, Mac=other
    )["MacValid"] is True


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
