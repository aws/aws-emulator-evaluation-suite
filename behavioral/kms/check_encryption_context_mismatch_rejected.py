"""encryption-context-mismatch-rejected."""
from __future__ import annotations

from typing import Any

from behavioral_harness import tags

CHECK = "encryption-context-mismatch-rejected"
GROUP = "error-semantics"
SERVICES = ["kms"]


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Decrypt with an EncryptionContext different from the one used at Encrypt, or with none, fails with
    InvalidCiphertextException and an empty message, while the original context decrypts the same ciphertext."""
    kms = ctx.client("kms")
    key_id = kms.create_key(
        Description=ctx.unique_name("sim2real-behav-"),
        KeyUsage="ENCRYPT_DECRYPT",
        KeySpec="SYMMETRIC_DEFAULT",
        Tags=[{"TagKey": "sim2real-check", "TagValue": CHECK}],
    )["KeyMetadata"]["KeyId"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7))

    plaintext = b"context-must-match-exactly"
    original_context = {"purpose": "\u8ab2\u984c-invoice", "tenant": "acme-\U0001f3e2"}
    wrong_context = {"purpose": "\u8ab2\u984c-invoice", "tenant": "acme-\U0001f3e2-x"}

    ciphertext = kms.encrypt(
        KeyId=key_id, Plaintext=plaintext, EncryptionContext=original_context
    )["CiphertextBlob"]

    # Positive control: decrypting with the exact original context still works.
    good = kms.decrypt(CiphertextBlob=ciphertext, EncryptionContext=original_context)
    assert good["Plaintext"] == plaintext, (
        f"positive control: decrypt with the original context must return the original "
        f"plaintext {plaintext!r}, got {good['Plaintext']!r}"
    )

    # Break exactly one thing: a slightly different context value.
    code, message = _error(
        lambda: kms.decrypt(CiphertextBlob=ciphertext, EncryptionContext=wrong_context)
    )
    assert code == "InvalidCiphertextException", (
        f"decrypt with a mismatched EncryptionContext {wrong_context!r} must raise "
        f"InvalidCiphertextException, got {code!r}"
    )
    assert message == "", f"mismatched context: unexpected message {message!r}"

    # And omitting the context entirely must also be rejected the same way.
    code_missing, message_missing = _error(lambda: kms.decrypt(CiphertextBlob=ciphertext))
    assert code_missing == "InvalidCiphertextException", (
        f"decrypt with the EncryptionContext omitted must raise InvalidCiphertextException, "
        f"got {code_missing!r}"
    )
    assert message_missing == "", f"omitted context: unexpected message {message_missing!r}"


def _error(fn) -> Any:
    """Call fn(); return the botocore (Error.Code, Error.Message) it raises. An unexpected SUCCESS
    raises."""
    try:
        result = fn()
    except Exception as exc:  # noqa: BLE001
        response = getattr(exc, "response", None)
        if response is not None:
            err = response.get("Error", {})
            return err.get("Code"), err.get("Message")
        raise
    raise AssertionError(
        f"expected InvalidCiphertextException, but decrypt SUCCEEDED and returned "
        f"Plaintext={result.get('Plaintext')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
