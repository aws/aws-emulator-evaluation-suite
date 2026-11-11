"""op-tampered-ciphertext-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-tampered-ciphertext-rejected"
GROUP = 'overly-permissive'
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


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Modified or truncated ciphertext must fail authentication instead of decrypting."""
    kms = ctx.client("kms")
    meta = kms.create_key(
        Description=ctx.unique_name("sim2real-behav-kms-op-tamperct-"),
        Tags=[{"TagKey": "sim2real", "TagValue": CHECK}],
    )["KeyMetadata"]
    ctx.on_cleanup(
        lambda: kms.schedule_key_deletion(KeyId=meta["KeyId"], PendingWindowInDays=7)
    )
    ct = kms.encrypt(KeyId=meta["KeyId"], Plaintext=b"authentic-payload")["CiphertextBlob"]

    plaintext = kms.decrypt(CiphertextBlob=ct)["Plaintext"]
    assert plaintext == b"authentic-payload", (
        f"positive control failed: expected authentic-payload, got {plaintext!r}"
    )

    tampered = bytearray(ct)
    tampered[-1] ^= 0xFF
    # AWS sends both refusals with no message text.
    code, message = _error(lambda: kms.decrypt(CiphertextBlob=bytes(tampered)))
    assert code == "InvalidCiphertextException", (
        f"expected InvalidCiphertextException, got {code}"
    )
    assert message == "", f"tampered blob -> unexpected message {message!r}"

    code2, message2 = _error(lambda: kms.decrypt(CiphertextBlob=ct[: len(ct) // 2]))
    assert code2 == "InvalidCiphertextException", f"truncated blob -> got {code2}"
    assert message2 == "", f"truncated blob -> unexpected message {message2!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
