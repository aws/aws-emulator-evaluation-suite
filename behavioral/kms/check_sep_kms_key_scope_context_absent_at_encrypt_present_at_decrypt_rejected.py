"""sep-kms-key-scope-context-absent-at-encrypt-present-at-decrypt-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sep-kms-key-scope-context-absent-at-encrypt-present-at-decrypt-rejected"
GROUP = "key-separation"
SERVICES = ["kms"]


@tags(
    "axis:rejection",
    "cap:c1",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """A blob encrypted with no context is refused (InvalidCiphertextException) when Decrypt
    supplies one, for Encrypt and GenerateDataKey blobs; omitting it or an empty map still decrypts.
    """
    kms = ctx.client("kms")
    meta = kms.create_key(
        Description=ctx.unique_name("sim2real-sep-ctxrev-"),
        Tags=[{"TagKey": "sim2real", "TagValue": CHECK}],
    )["KeyMetadata"]
    key = meta["Arn"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key, PendingWindowInDays=7))

    payload = b"sep-context-free-ciphertext"
    blob = kms.encrypt(KeyId=key, Plaintext=payload)["CiphertextBlob"]
    supplied = {"tenant": "acme", "purpose": "invoice"}

    # Real AWS treats an empty context map as absent.
    omitted = kms.decrypt(CiphertextBlob=blob)
    assert (omitted["KeyId"], omitted["Plaintext"]) == (key, payload), (
        f"Decrypt with the context omitted must return ({key!r}, {payload!r}); got "
        f"{(omitted['KeyId'], omitted['Plaintext'])!r}"
    )
    empty = kms.decrypt(CiphertextBlob=blob, EncryptionContext={})
    assert empty["Plaintext"] == payload, (
        f"Decrypt with an EMPTY EncryptionContext map is equivalent to omitting it and must return "
        f"{payload!r}; got {empty['Plaintext']!r}"
    )

    code = _rejected(
        lambda: kms.decrypt(CiphertextBlob=blob, EncryptionContext=supplied)
    )
    assert code == ("InvalidCiphertextException", ""), (
        f"Decrypt supplying {supplied!r} for a blob encrypted with NO context must raise "
        f"InvalidCiphertextException with an empty message, got {code!r}"
    )
    one_pair = {"tenant": "acme"}
    code_one = _rejected(
        lambda: kms.decrypt(CiphertextBlob=blob, EncryptionContext=one_pair)
    )
    assert code_one == ("InvalidCiphertextException", ""), (
        f"a single supplied pair {one_pair!r} must be refused just the same, got {code_one!r}"
    )

    # The same binding on the data-key path.
    dk = kms.generate_data_key(KeyId=key, KeySpec="AES_256")
    dk_code = _rejected(
        lambda: kms.decrypt(CiphertextBlob=dk["CiphertextBlob"], EncryptionContext=supplied)
    )
    assert dk_code == ("InvalidCiphertextException", ""), (
        f"a GenerateDataKey blob minted without context must be refused when Decrypt supplies "
        f"{supplied!r}; got {dk_code!r}"
    )
    dk_ok = kms.decrypt(CiphertextBlob=dk["CiphertextBlob"])
    assert dk_ok["Plaintext"] == dk["Plaintext"], (
        "the context-free data-key blob must decrypt, with no context, to the Plaintext half of the "
        f"same GenerateDataKey response; got {len(dk_ok['Plaintext'])} bytes that differ"
    )

    again = kms.decrypt(CiphertextBlob=blob)
    assert again["Plaintext"] == payload, (
        f"after the refused decrypts the blob must still decrypt to {payload!r}, got "
        f"{again['Plaintext']!r}"
    )


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
