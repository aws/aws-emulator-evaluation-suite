"""encryption-context-unicode-round-trip."""
from __future__ import annotations

import unicodedata
from typing import Any

from behavioral_harness import tags

CHECK = "encryption-context-unicode-round-trip"
GROUP = "error-semantics"
SERVICES = ["kms"]


@tags("axis:happy-path", "cap:c1", "concern:data-plane", "concern:representation", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A ciphertext encrypted under a unicode EncryptionContext decrypts with the identical context, while an
    NFD-decomposed variant of the accented value fails with InvalidCiphertextException and an empty message
    (KMS does not normalize context values), and the original context still decrypts afterwards."""
    kms = ctx.client("kms")
    key_id = kms.create_key(
        Description=ctx.unique_name("sim2real-behav-"),
        KeyUsage="ENCRYPT_DECRYPT",
        KeySpec="SYMMETRIC_DEFAULT",
    )["KeyMetadata"]["KeyId"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7))

    context = {
        "\u90e8\u9580": "\u55b6\u696d\u90e8",  # 部門: 営業部 (Japanese)
        "emoji": "\U0001f512\U0001f511",  # 🔒🔑
        "accented": "Caf\u00e9 \u00d1o\u00f1o",  # Café Ñoño (NFC: precomposed é, Ñ, ñ)
    }
    plaintext = "unicode-secret-\U0001f512-\u65e5\u672c\u8a9e".encode("utf-8")

    enc = kms.encrypt(KeyId=key_id, Plaintext=plaintext, EncryptionContext=context)
    ciphertext = enc["CiphertextBlob"]
    assert enc["KeyId"].endswith(key_id)

    dec = kms.decrypt(CiphertextBlob=ciphertext, EncryptionContext=context)
    assert dec["Plaintext"] == plaintext, "decrypted plaintext must match original bytes exactly"
    assert dec["KeyId"].endswith(key_id)

    # Break exactly one thing: swap the accented value for its NFD decomposition (same
    # rendered text, different codepoints/bytes).
    nfd_value = unicodedata.normalize("NFD", context["accented"])
    assert nfd_value != context["accented"], "NFD decomposition must differ byte-for-byte from the NFC original"
    nfd_context = {**context, "accented": nfd_value}

    code, message = _error(lambda: kms.decrypt(CiphertextBlob=ciphertext, EncryptionContext=nfd_context))
    assert code == "InvalidCiphertextException", (
        f"a Unicode-normalized (NFD) variant of the context value must be treated as a "
        f"different context and rejected, got {code!r}"
    )
    assert message == "", f"unexpected message {message!r}"

    # Restore: the exact original context still decrypts — the failed NFD attempt did not
    # corrupt the ciphertext or the key.
    dec_restored = kms.decrypt(CiphertextBlob=ciphertext, EncryptionContext=context)
    assert dec_restored["Plaintext"] == plaintext, "ciphertext must survive the failed NFD-context attempt"


def _error(fn) -> Any:
    """Return the botocore (Error.Code, Error.Message) of the refused call; a success raises."""
    try:
        fn()
    except Exception as exc:  # noqa: BLE001
        response = getattr(exc, "response", None)
        if response is not None:
            err = response.get("Error", {})
            return err.get("Code"), err.get("Message")
        raise
    raise AssertionError("expected the call to raise, but it succeeded")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
