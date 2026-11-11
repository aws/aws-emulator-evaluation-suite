"""verify-mac-wrong-message."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "verify-mac-wrong-message"
GROUP = 'hmac'
SERVICES = ['kms']

ERR_INVALID_MAC = "KMSInvalidMacException"


def _err(fn):
    """Return the botocore Error (Code and Message) if fn() raises ClientError. An unexpected
    SUCCESS raises, so a target that accepts the call cannot read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return {"Code": err.get("Code"), "Message": err.get("Message")}
    raise AssertionError(f"expected VerifyMac to be rejected, but it SUCCEEDED: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """VerifyMac on a wrong message must RAISE KMSInvalidMacException, never return MacValid: false
    — real AWS never returns the latter.
    """
    kms = ctx.client("kms")
    key_id = kms.create_key(KeyUsage="GENERATE_VERIFY_MAC", KeySpec="HMAC_256")["KeyMetadata"]["KeyId"]
    ctx.on_cleanup(lambda _k=key_id: kms.schedule_key_deletion(KeyId=_k, PendingWindowInDays=7))

    message = b"correct-message"
    mac = kms.generate_mac(
        KeyId=key_id,
        Message=message,
        MacAlgorithm="HMAC_SHA_256",
    )["Mac"]

    # Positive control: the account, key and algorithm are healthy before we break anything.
    ok = kms.verify_mac(KeyId=key_id, Message=message, MacAlgorithm="HMAC_SHA_256", Mac=mac)
    assert ok["MacValid"] is True, ok

    err = _err(lambda: kms.verify_mac(
        KeyId=key_id,
        Message=b"wrong-message",
        MacAlgorithm="HMAC_SHA_256",
        Mac=mac,
    ))
    assert err["Code"] == ERR_INVALID_MAC, f"VerifyMac on a wrong message must raise {ERR_INVALID_MAC}, got {err!r}"
    # KMS sends KMSInvalidMacException with no message at all.
    assert err["Message"] == "", f"{ERR_INVALID_MAC} carries no message, got {err!r}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
