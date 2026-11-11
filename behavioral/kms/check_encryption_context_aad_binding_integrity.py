"""encryption-context-aad-binding-integrity."""
from __future__ import annotations

from botocore.exceptions import ClientError
from behavioral_harness import tags

CHECK = "encryption-context-aad-binding-integrity"
GROUP = 'encrypt_decrypt'
SERVICES = ['kms']

ERR_INVALID_CIPHERTEXT = "InvalidCiphertextException"
ERR_VALIDATION = "ValidationException"
MSG_INVALID_CONTEXT = "Invalid EncryptionContext"
MSG_INVALID_CIPHERTEXT = ""


def _err(fn):
    """Return (Code, Message) if fn() raises ClientError; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _teardown_key(kms, key_arn: str) -> None:
    """Schedule deletion of a CMK this check minted.

    KMS has no prompt delete: the minimum PendingWindowInDays is 7. The ARN guard keeps this
    teardown off AWS-managed keys and aliases.
    """
    assert key_arn.startswith("arn:") and ":key/" in key_arn, key_arn
    assert "alias/" not in key_arn, key_arn
    kms.schedule_key_deletion(KeyId=key_arn, PendingWindowInDays=7)


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """EncryptionContext is AAD: every non-identical context is refused, yet the ciphertext
    stays intact and decryptable with the exact context.
    """
    kms = ctx.client("kms")
    meta = kms.create_key(
        Description=ctx.unique_name("sim2real-behav-kms-aadctx-"),
        KeyUsage="ENCRYPT_DECRYPT",
        KeySpec="SYMMETRIC_DEFAULT",
    )["KeyMetadata"]
    key_arn = meta["Arn"]
    ctx.on_cleanup(lambda _a=key_arn: _teardown_key(kms, _a))

    plaintext = b"aad-bound-payload"
    context = {"tenant": "acme", "purpose": "invoice"}
    enc = kms.encrypt(KeyId=key_arn, Plaintext=plaintext, EncryptionContext=context)
    ciphertext = enc["CiphertextBlob"]
    assert enc["KeyId"] == key_arn, enc["KeyId"]

    # --- Every deviation from the exact context must be refused with the SAME specific code.
    # Each case breaks exactly one thing about the context and nothing else.
    deviations = {
        "wrong value": {"tenant": "evil", "purpose": "invoice"},
        "proper subset": {"tenant": "acme"},
        "extra key": {"tenant": "acme", "purpose": "invoice", "extra": "x"},
        "key-name case flipped": {"Tenant": "acme", "purpose": "invoice"},
        "value case flipped": {"tenant": "ACME", "purpose": "invoice"},
    }
    for label, bad in deviations.items():
        code, message = _err(
            lambda _b=bad: kms.decrypt(
                CiphertextBlob=ciphertext, KeyId=key_arn, EncryptionContext=_b
            )
        )
        assert code == ERR_INVALID_CIPHERTEXT, (
            f"context deviation {label!r} ({bad!r}) must raise "
            f"{ERR_INVALID_CIPHERTEXT}, got {code!r}"
        )
        assert message == MSG_INVALID_CIPHERTEXT, (
            f"context deviation {label!r}: unexpected message {message!r}"
        )

    # Omitting the context entirely is a distinct input from any wrong context.
    code_absent, message_absent = _err(
        lambda: kms.decrypt(CiphertextBlob=ciphertext, KeyId=key_arn)
    )
    assert code_absent == ERR_INVALID_CIPHERTEXT, (
        f"Decrypt with the encryption context omitted must raise "
        f"{ERR_INVALID_CIPHERTEXT}, got {code_absent!r}"
    )
    assert message_absent == MSG_INVALID_CIPHERTEXT, (
        f"Decrypt with the encryption context omitted: unexpected message {message_absent!r}"
    )

    # --- An empty-string VALUE is not an AAD mismatch at all: it is not a legal encryption
    # context, so it never reaches the authentication step.
    #
    # {"tenant": "acme", "purpose": ""} is ValidationException / "Invalid EncryptionContext",
    # refused identically by Encrypt, where there is no ciphertext to authenticate against.
    empty_value = {"tenant": "acme", "purpose": ""}
    for op, call in (
        ("Decrypt", lambda: kms.decrypt(
            CiphertextBlob=ciphertext, KeyId=key_arn, EncryptionContext=empty_value)),
        ("Encrypt", lambda: kms.encrypt(
            KeyId=key_arn, Plaintext=plaintext, EncryptionContext=empty_value)),
    ):
        empty_code, empty_msg = _err(call)
        assert empty_code == ERR_VALIDATION, (
            f"{op} with an empty-string context value must raise {ERR_VALIDATION} (the context "
            f"is malformed, not merely mismatched), got {empty_code!r}"
        )
        assert empty_msg == MSG_INVALID_CONTEXT, (
            f"{op}: expected the message {MSG_INVALID_CONTEXT!r}, got {empty_msg!r}"
        )

    # --- Positive: the context is a MAP, so serialisation order must not matter. Same pairs,
    # opposite insertion order. An emulator that hashes a concatenated string fails here.
    reordered = {"purpose": "invoice", "tenant": "acme"}
    assert list(reordered) != list(context), "the reordered context must differ in key order"
    dec_reordered = kms.decrypt(
        CiphertextBlob=ciphertext, KeyId=key_arn, EncryptionContext=reordered
    )
    assert dec_reordered["Plaintext"] == plaintext, "context key order must not affect Decrypt"

    # --- Effect absent / integrity: the seven refusals above authenticated, they did not
    # corrupt. The very same ciphertext still yields byte-identical plaintext.
    dec = kms.decrypt(CiphertextBlob=ciphertext, KeyId=key_arn, EncryptionContext=context)
    assert dec["Plaintext"] == plaintext, "ciphertext must survive failed context attempts"
    assert dec["KeyId"] == key_arn, dec["KeyId"]
    assert dec["EncryptionAlgorithm"] == "SYMMETRIC_DEFAULT", dec["EncryptionAlgorithm"]

    # --- Control: the key was never mutated by the refusals.
    after = kms.describe_key(KeyId=key_arn)["KeyMetadata"]
    assert after["KeyState"] == "Enabled", after["KeyState"]
    assert after["Enabled"] is True, after

    # --- And the binding is per-ciphertext, not per-key: a fresh Encrypt under a DIFFERENT
    # context on the same key succeeds and is refused under the first context.
    other_context = {"tenant": "acme", "purpose": "receipt"}
    ct2 = kms.encrypt(
        KeyId=key_arn, Plaintext=plaintext, EncryptionContext=other_context
    )["CiphertextBlob"]
    code_cross, message_cross = _err(
        lambda: kms.decrypt(CiphertextBlob=ct2, KeyId=key_arn, EncryptionContext=context)
    )
    assert code_cross == ERR_INVALID_CIPHERTEXT, (
        f"ciphertext bound to {other_context!r} must not decrypt under {context!r}, "
        f"got {code_cross!r}"
    )
    assert message_cross == MSG_INVALID_CIPHERTEXT, (
        f"cross-context Decrypt: unexpected message {message_cross!r}"
    )
    dec_ct2 = kms.decrypt(
        CiphertextBlob=ct2, KeyId=key_arn, EncryptionContext=other_context
    )["Plaintext"]
    assert dec_ct2 == plaintext, (
        f"ciphertext bound to {other_context!r} must still decrypt under its own context, "
        f"got {dec_ct2!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
