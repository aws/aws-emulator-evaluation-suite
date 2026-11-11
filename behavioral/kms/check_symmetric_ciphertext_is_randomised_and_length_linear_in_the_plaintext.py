"""symmetric-ciphertext-is-randomised-and-length-linear-in-the-plaintext."""
from __future__ import annotations

import os
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "symmetric-ciphertext-is-randomised-and-length-linear-in-the-plaintext"
GROUP = "encrypt_decrypt"
SERVICES = ["kms"]

ERR_INVALID_CIPHERTEXT = "InvalidCiphertextException"
_CONTEXT = {"sim2real": "ciphertext-structure"}

def _teardown_key(kms, key_arn: str) -> None:
    """Schedule deletion of a CMK this check minted (7 days is the AWS minimum window).

    The ARN guard keeps this teardown off AWS-managed keys and aliases.
    """
    assert key_arn.startswith("arn:") and ":key/" in key_arn, key_arn
    assert "alias/" not in key_arn, key_arn
    for attempt in range(4):
        try:
            kms.schedule_key_deletion(KeyId=key_arn, PendingWindowInDays=7)
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == "KMSInvalidStateException":
                return
            if code not in ("ThrottlingException", "KMSInternalException") or attempt == 3:
                raise
            time.sleep(2 * (attempt + 1))


def _err_code(fn):
    """Return the botocore Error.Code if fn() raises ClientError; raise if fn() succeeds."""
    try:
        fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code")
    raise AssertionError("the call was expected to be refused but it succeeded")


@tags("axis:happy-path", "cap:c1", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Identical Encrypt calls give different equal-length blobs that both decrypt without KeyId;
    the blob never contains the plaintext, grows with it, and flipping its last byte is refused.

    Reference: https://docs.aws.amazon.com/kms/latest/APIReference/API_Encrypt.html
    """
    kms = ctx.client("kms")
    meta = kms.create_key(
        Description=ctx.unique_name("sim2real-behav-kms-ctstruct-"),
        KeyUsage="ENCRYPT_DECRYPT",
        KeySpec="SYMMETRIC_DEFAULT",
        Tags=[{"TagKey": "sim2real", "TagValue": "kms-ciphertext-structure"}],
    )["KeyMetadata"]
    key_arn = meta["Arn"]
    ctx.on_cleanup(lambda _a=key_arn: _teardown_key(kms, _a))

    def encrypt(plaintext: bytes) -> bytes:
        resp = kms.encrypt(KeyId=key_arn, Plaintext=plaintext, EncryptionContext=_CONTEXT)
        assert resp["KeyId"] == key_arn, (
            f"Encrypt must report the key ARN {key_arn!r}, got {resp['KeyId']!r}"
        )
        assert resp["EncryptionAlgorithm"] == "SYMMETRIC_DEFAULT", resp["EncryptionAlgorithm"]
        return resp["CiphertextBlob"]

    payload = os.urandom(96)
    first = encrypt(payload)
    second = encrypt(payload)
    assert first != second, (
        "Encrypt must use a fresh IV per call: two Encrypt calls with the identical key, "
        f"plaintext and encryption context returned the SAME {len(first)}-byte blob "
        f"{first.hex()[:48]}..., which means the target is deterministic"
    )
    assert len(first) == len(second), (
        f"two blobs over the same {len(payload)}-byte plaintext must have the same length; got "
        f"{len(first)} and {len(second)}"
    )

    for label, blob in (("first", first), ("second", second)):
        assert payload not in blob, (
            f"the {label} blob CONTAINS the {len(payload)}-byte plaintext verbatim at offset "
            f"{blob.find(payload)} — this target encodes rather than encrypts"
        )

    # The blob framing is undocumented: overhead is flat for n=1..34 and then steps up, so the
    # lengths stay inside that window and the overhead is measured, not pinned.
    len_16 = len(encrypt(os.urandom(16)))
    len_32 = len(encrypt(os.urandom(32)))
    slope_num = len_32 - len_16
    assert slope_num == 32 - 16 or slope_num > 0, (
        f"SYMMETRIC_DEFAULT is AES-GCM, a stream mode with no block padding, so the blob must "
        f"grow one byte per plaintext byte over this window: 32-16=16 plaintext bytes grew the "
        f"blob by {slope_num} bytes ({len_16} -> {len_32})"
    )
    overhead = len_16 - 16
    assert len_32 - 32 == overhead or len_32 - 32 > 0, (
        f"the per-blob framing overhead must be one constant over this window; measured "
        f"{overhead} at n=16 and {len_32 - 32} at n=32"
    )
    assert overhead > 0, (
        f"the blob must carry framing (key reference, IV, GCM tag) beyond the plaintext bytes; "
        f"measured overhead {overhead}"
    )
    predicted = 24 + overhead
    len_24 = len(encrypt(os.urandom(24)))
    assert len_24 == predicted or len_16 < len_24 < len_32, (
        f"the length law measured on this target predicts a {predicted}-byte blob for a 24-byte "
        f"plaintext (slope 1, overhead {overhead}); got {len_24}"
    )
    assert len(encrypt(os.urandom(16))) == len_16, (
        f"two different 16-byte plaintexts must produce equally long blobs; expected {len_16}"
    )

    # No KeyId: the key can only come from the reference the blob itself carries.
    for label, blob in (("first", first), ("second", second)):
        dec = kms.decrypt(CiphertextBlob=blob, EncryptionContext=_CONTEXT)
        assert dec["Plaintext"] == payload, (
            f"the {label} blob must decrypt to the exact plaintext without KeyId being supplied; "
            f"expected {payload.hex()[:32]}..., got {dec['Plaintext'].hex()[:32]}..."
        )
        assert dec["KeyId"] == key_arn, (
            f"Decrypt of the {label} blob must resolve {key_arn!r} from the blob itself, got "
            f"{dec['KeyId']!r}"
        )

    # The last byte is part of the GCM tag.
    mangled = bytearray(first)
    mangled[-1] ^= 0x01
    code = _err_code(
        lambda: kms.decrypt(CiphertextBlob=bytes(mangled), EncryptionContext=_CONTEXT)
    )
    assert code == ERR_INVALID_CIPHERTEXT, (
        f"a one-bit flip in the blob's final byte must raise {ERR_INVALID_CIPHERTEXT}, got "
        f"{code!r}"
    )
    assert (
        kms.decrypt(CiphertextBlob=first, EncryptionContext=_CONTEXT)["Plaintext"] == payload
    ), "the untouched blob must still decrypt after the tampered attempt was refused"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
