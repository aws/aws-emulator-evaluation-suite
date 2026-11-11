"""sep-kms-key-scope-data-key-halves-correspond-and-rewrap-moves-key-scope."""
from __future__ import annotations

import os

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sep-kms-key-scope-data-key-halves-correspond-and-rewrap-moves-key-scope"
GROUP = "key-separation"
SERVICES = ["kms"]

_CONTEXT = {"tenant": "acme", "object": "ledger-2026"}


@tags(
    "axis:happy-path",
    "cap:c1",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """GenerateDataKey's CiphertextBlob decrypts to its Plaintext half (a working AES-GCM key);
    ReEncrypt to key B keeps those bytes; the rewrapped blob pinned to A is IncorrectKeyException.
    """
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    kms = ctx.client("kms")
    key_a = _new_key(ctx, kms, "a")
    key_b = _new_key(ctx, kms, "b")

    gdk = kms.generate_data_key(KeyId=key_a, KeySpec="AES_256", EncryptionContext=_CONTEXT)
    data_key, wrapped = gdk["Plaintext"], gdk["CiphertextBlob"]
    assert gdk["KeyId"] == key_a, f"GenerateDataKey must report key A, got {gdk['KeyId']!r}"
    assert len(data_key) == 32, f"an AES_256 data key must be 32 bytes, got {len(data_key)}"
    assert data_key not in wrapped, "the plaintext data key must not appear inside its wrapped blob"
    second = kms.generate_data_key(KeyId=key_a, KeySpec="AES_256", EncryptionContext=_CONTEXT)
    assert second["Plaintext"] != data_key, "two GenerateDataKey calls must return different keys"

    unwrapped = kms.decrypt(CiphertextBlob=wrapped, EncryptionContext=_CONTEXT)
    assert unwrapped["KeyId"] == key_a and unwrapped["Plaintext"] == data_key, (
        f"Decrypt(CiphertextBlob) must return the Plaintext half of the same GenerateDataKey "
        f"response under key A; KeyId={unwrapped['KeyId']!r}, bytes equal="
        f"{unwrapped['Plaintext'] == data_key}"
    )

    nonce = os.urandom(12)
    document = b"sep-envelope-document-body"
    sealed = AESGCM(data_key).encrypt(nonce, document, b"sep-aad")
    opened = AESGCM(unwrapped["Plaintext"]).decrypt(nonce, sealed, b"sep-aad")
    assert opened == document, f"the recovered data key must open the envelope, got {opened!r}"

    rewrap = kms.re_encrypt(
        CiphertextBlob=wrapped,
        SourceEncryptionContext=_CONTEXT,
        DestinationKeyId=key_b,
        DestinationEncryptionContext=_CONTEXT,
    )
    assert (rewrap["SourceKeyId"], rewrap["KeyId"]) == (key_a, key_b), (
        f"ReEncrypt must report source A and destination B; got "
        f"{(rewrap['SourceKeyId'], rewrap['KeyId'])!r}"
    )
    moved = rewrap["CiphertextBlob"]
    assert moved != wrapped, "the rewrapped blob must differ from the original"

    under_b = kms.decrypt(CiphertextBlob=moved, EncryptionContext=_CONTEXT)
    assert under_b["KeyId"] == key_b and under_b["Plaintext"] == data_key, (
        f"the rewrapped blob must decrypt keylessly under key B to the SAME 32 data-key bytes; "
        f"KeyId={under_b['KeyId']!r}, bytes equal={under_b['Plaintext'] == data_key}"
    )
    reopened = AESGCM(under_b["Plaintext"]).decrypt(nonce, sealed, b"sep-aad")
    assert reopened == document, "the data key recovered via key B must open the original envelope"

    code = _rejected(
        lambda: kms.decrypt(CiphertextBlob=moved, KeyId=key_a, EncryptionContext=_CONTEXT)
    )
    assert code == (
        "IncorrectKeyException",
        "The key ID in the request does not identify a CMK that can perform this operation.",
    ), (
        f"the blob rewrapped under key B, pinned to key A, must raise IncorrectKeyException; got "
        f"{code!r}"
    )
    # ReEncrypt does not consume its input.
    still_a = kms.decrypt(CiphertextBlob=wrapped, KeyId=key_a, EncryptionContext=_CONTEXT)
    assert still_a["Plaintext"] == data_key, "ReEncrypt must not invalidate the original A-wrapped blob"


def _new_key(ctx, kms, label):
    """A fresh symmetric key; its 7-day scheduled deletion is registered before it is returned."""
    meta = kms.create_key(
        Description=ctx.unique_name(f"sim2real-sep-dk-{label}-"),
        Tags=[{"TagKey": "sim2real", "TagValue": CHECK}],
    )["KeyMetadata"]
    arn = meta["Arn"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=arn, PendingWindowInDays=7))
    return arn


def _rejected(fn):
    """The AWS error code and message of a call real AWS refuses; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code") or "NO_ERROR_CODE", err.get("Message")
    raise AssertionError(f"real AWS refuses this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
