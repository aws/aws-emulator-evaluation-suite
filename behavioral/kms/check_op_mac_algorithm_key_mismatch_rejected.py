"""op-mac-algorithm-key-mismatch-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-mac-algorithm-key-mismatch-rejected"
GROUP = 'hmac'
SERVICES = ['kms']


def _error(fn):
    """Call fn(); return its botocore (Error.Code, Error.Message). An unexpected SUCCESS raises,
    because an emulator ACCEPTING a call real AWS refuses must not read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message", "")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """MAC algorithms incompatible with the key spec/usage must be rejected -- proven against a
    positive control on the same key, so the rejection is attributable to the specific mismatch
    and not to GenerateMac being refused outright."""
    kms = ctx.client("kms")
    hmac_key = kms.create_key(
        Description=ctx.unique_name("kms-op-macmismatch-"),
        KeyUsage="GENERATE_VERIFY_MAC",
        KeySpec="HMAC_256",
        Tags=[{"TagKey": "sim2real", "TagValue": CHECK}],
    )["KeyMetadata"]["KeyId"]
    ctx.on_cleanup(lambda _k=hmac_key: kms.schedule_key_deletion(KeyId=_k, PendingWindowInDays=7))

    control = kms.generate_mac(KeyId=hmac_key, Message=b"msg", MacAlgorithm="HMAC_SHA_256")
    assert len(control["Mac"]) > 0, f"positive control returned an empty MAC: {control!r}"

    code, message = _error(
        lambda: kms.generate_mac(
            KeyId=hmac_key, Message=b"msg", MacAlgorithm="HMAC_SHA_512"
        )
    )
    assert code == "InvalidKeyUsageException", f"HMAC_256 key + HMAC_SHA_512 -> got {code}"
    assert message == "Algorithm HMAC_SHA_512 is incompatible with key spec HMAC_256.", message

    symmetric_meta = kms.create_key(
        Description=ctx.unique_name("kms-op-macsym-"),
        KeyUsage="ENCRYPT_DECRYPT",
        KeySpec="SYMMETRIC_DEFAULT",
        Tags=[{"TagKey": "sim2real", "TagValue": CHECK}],
    )["KeyMetadata"]
    symmetric = symmetric_meta["KeyId"]
    ctx.on_cleanup(lambda _k=symmetric: kms.schedule_key_deletion(KeyId=_k, PendingWindowInDays=7))
    code2, message2 = _error(
        lambda: kms.generate_mac(
            KeyId=symmetric, Message=b"msg", MacAlgorithm="HMAC_SHA_256"
        )
    )
    assert code2 == "InvalidKeyUsageException", f"ENCRYPT_DECRYPT key + GenerateMac -> got {code2}"
    assert message2 == (
        f"{symmetric_meta['Arn']} key usage is ENCRYPT_DECRYPT which is not valid for GenerateMac."
    ), message2


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
