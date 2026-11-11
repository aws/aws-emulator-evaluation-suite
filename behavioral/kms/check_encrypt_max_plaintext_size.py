"""encrypt-max-plaintext-size."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "encrypt-max-plaintext-size"
GROUP = 'encrypt_decrypt'
SERVICES = ['kms']

def _error(fn):
    """Call fn(); return its botocore (Error Code, Error Message). An unexpected SUCCESS raises, because
    an emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected rejection, but the call SUCCEEDED and returned {result!r}")

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Encrypt accepts exactly 4096 plaintext bytes (the documented symmetric ceiling) and
    rejects 4097 with the specific ValidationException real AWS returns."""
    kms = ctx.client("kms")
    key_id = kms.create_key(
        KeyUsage="ENCRYPT_DECRYPT",
        KeySpec="SYMMETRIC_DEFAULT",
        Tags=[{"TagKey": "sim2real", "TagValue": "kms-encrypt-max-plaintext-size"}],
    )["KeyMetadata"]["KeyId"]
    ctx.on_cleanup(lambda _k=key_id: kms.schedule_key_deletion(KeyId=_k, PendingWindowInDays=7))

    at_limit = kms.encrypt(KeyId=key_id, Plaintext=b"x" * 4096)
    assert at_limit["CiphertextBlob"], "4096 bytes is exactly at the documented limit and must succeed"
    plaintext_back = kms.decrypt(KeyId=key_id, CiphertextBlob=at_limit["CiphertextBlob"])["Plaintext"]
    assert plaintext_back == b"x" * 4096, "decrypt of the at-limit ciphertext did not round-trip"

    big_plaintext = b"x" * 4097
    code, message = _error(lambda: kms.encrypt(KeyId=key_id, Plaintext=big_plaintext))
    assert code == "ValidationException", f"expected ValidationException for >4096 byte plaintext, got {code}"
    assert message == (
        "1 validation error detected: Value at 'plaintext' failed to satisfy constraint: "
        "Member must have length less than or equal to 4096"
    ), f"unexpected message {message!r}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
