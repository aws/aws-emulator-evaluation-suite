"""generate-mac-verify-mac."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "generate-mac-verify-mac"
GROUP = 'hmac'
SERVICES = ['kms']

ERR_INVALID_MAC = "KMSInvalidMacException"


@tags("axis:happy-path", "cap:c1", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """GenerateMac/VerifyMac roundtrip for HMAC_SHA_256."""
    kms = ctx.client("kms")
    key_id = kms.create_key(
        Description=ctx.unique_name("sim2real-behav-kms-macgen-"),
        KeyUsage="GENERATE_VERIFY_MAC",
        KeySpec="HMAC_256",
    )["KeyMetadata"]["KeyId"]
    ctx.on_cleanup(lambda _k=key_id: kms.schedule_key_deletion(KeyId=_k, PendingWindowInDays=7))

    message = b"sim2real-hmac-test-message"
    gen_resp = kms.generate_mac(
        KeyId=key_id,
        Message=message,
        MacAlgorithm="HMAC_SHA_256",
    )
    mac = gen_resp["Mac"]
    assert len(mac) == 32, f"HMAC_SHA_256 must be a 32-byte MAC, got {len(mac)}"

    verify_resp = kms.verify_mac(
        KeyId=key_id,
        Message=message,
        MacAlgorithm="HMAC_SHA_256",
        Mac=mac,
    )
    assert verify_resp["MacValid"] is True, verify_resp

    # A stub that always answers MacValid: True regardless of input passes the roundtrip
    # above. Tamper one bit of the MAC and demand the specific rejection, so the positive
    # result above is proven to depend on the actual bytes, not on the call succeeding.
    tampered_mac = bytearray(mac)
    tampered_mac[-1] ^= 0x01
    try:
        kms.verify_mac(
            KeyId=key_id,
            Message=message,
            MacAlgorithm="HMAC_SHA_256",
            Mac=bytes(tampered_mac),
        )
        raise AssertionError("VerifyMac accepted a bit-flipped MAC")
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        assert code == ERR_INVALID_MAC, f"expected {ERR_INVALID_MAC}, got {code}"
        # AWS sends this refusal with an empty message.
        message = exc.response["Error"]["Message"]
        assert message == "", f"expected an empty message, got {message!r}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
