"""sep-kms-key-scope-bit-flipped-ciphertext-never-yields-different-plaintext-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sep-kms-key-scope-bit-flipped-ciphertext-never-yields-different-plaintext-rejected"
GROUP = "key-separation"
SERVICES = ["kms"]

# The trailing bytes of a symmetric KMS blob are the AEAD ciphertext + authentication tag. A GCM
# tag is 16 bytes; every flip inside it must fail authentication.
_TAG_BYTES = 16


@tags(
    "axis:rejection",
    "cap:c1",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """No single-bit flip of a ciphertext makes Decrypt return other plaintext; flips in the 16-byte
    tag, and appending or dropping a byte, fail with InvalidCiphertextException.
    """
    # On AWS a few header bits are not authenticated and still decrypt to the original bytes, and
    # key-identifier flips fail with AccessDeniedException, so "every flip fails" is not asserted.
    kms = ctx.client("kms")
    meta = kms.create_key(
        Description=ctx.unique_name("sim2real-sep-bitflip-"),
        Tags=[{"TagKey": "sim2real", "TagValue": CHECK}],
    )["KeyMetadata"]
    key = meta["Arn"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key, PendingWindowInDays=7))

    payload = b"sep-authenticated-payload-0123456789"
    blob = kms.encrypt(KeyId=key, Plaintext=payload)["CiphertextBlob"]
    control = kms.decrypt(CiphertextBlob=blob)
    assert (control["KeyId"], control["Plaintext"]) == (key, payload), (
        f"positive control: the untampered blob must decrypt to ({key!r}, {payload!r}); got "
        f"{(control['KeyId'], control['Plaintext'])!r}"
    )
    assert len(blob) > _TAG_BYTES + len(payload), (
        f"a {len(blob)}-byte blob cannot hold a {len(payload)}-byte payload plus a "
        f"{_TAG_BYTES}-byte tag -- it is not an AEAD ciphertext"
    )

    different_plaintexts = []
    refused = 0
    tag_codes = {}
    for i in range(len(blob)):
        flipped = bytearray(blob)
        flipped[i] ^= 0x01
        try:
            out = kms.decrypt(CiphertextBlob=bytes(flipped))
        except ClientError as exc:
            refused += 1
            if i >= len(blob) - _TAG_BYTES:
                err = exc.response.get("Error", {})
                tag_codes[i] = (err.get("Code"), err.get("Message"))
            continue
        if out["Plaintext"] != payload or out["KeyId"] != key:
            different_plaintexts.append((i, out["KeyId"], out["Plaintext"]))
        if i >= len(blob) - _TAG_BYTES:
            tag_codes[i] = ("DECRYPTED", None)

    assert different_plaintexts == [], (
        f"a single-bit flip must never make Decrypt return anything but the original plaintext "
        f"under the original key; these flips did (offset, KeyId, Plaintext): "
        f"{different_plaintexts[:5]!r}"
    )
    bad_tag = {i: c for i, c in tag_codes.items() if c != ("InvalidCiphertextException", "")}
    assert len(tag_codes) == _TAG_BYTES and bad_tag == {}, (
        f"every flip in the trailing {_TAG_BYTES} authentication bytes must raise "
        f"InvalidCiphertextException with an empty message; offsets that did not: {bad_tag!r}"
    )
    assert refused > len(blob) // 2, (
        f"authentication must cover most of the blob; only {refused} of {len(blob)} single-bit "
        f"flips were refused"
    )

    extended = _rejected(lambda: kms.decrypt(CiphertextBlob=blob + b"\x00"))
    assert extended == ("InvalidCiphertextException", ""), (
        f"the blob with one byte appended must raise InvalidCiphertextException with an empty "
        f"message, got {extended!r}"
    )
    shortened = _rejected(lambda: kms.decrypt(CiphertextBlob=blob[:-1]))
    assert shortened == ("InvalidCiphertextException", ""), (
        f"the blob with its last byte dropped must raise InvalidCiphertextException with an empty "
        f"message, got {shortened!r}"
    )

    again = kms.decrypt(CiphertextBlob=blob)
    assert again["Plaintext"] == payload, (
        f"after the tampering sweep the original blob must still decrypt to {payload!r}, got "
        f"{again['Plaintext']!r}"
    )


def _rejected(fn):
    """The AWS error code and message of a call real AWS refuses; an unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code") or "NO_ERROR_CODE", err.get("Message")
    raise AssertionError(f"real AWS refuses this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
