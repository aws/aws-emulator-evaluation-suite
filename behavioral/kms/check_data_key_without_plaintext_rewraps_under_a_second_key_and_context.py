"""data-key-without-plaintext-rewraps-under-a-second-key-and-context."""

from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "data-key-without-plaintext-rewraps-under-a-second-key-and-context"
GROUP = "e2e_workflows"
SERVICES = ["kms"]

#: KMS key-state changes are eventually consistent; each converges within this bound.
_CONVERGE_S = 40.0


@tags(
    "axis:happy-path",
    "cap:c1",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """A data key minted without plaintext and re-wrapped by ReEncrypt under a second key and
    context decrypts to the same 16 bytes only under the new key and context; each wrapping then
    depends on its own key's state alone (disabled source, second key pending deletion)."""
    kms = ctx.client("kms")
    tag_spec = [{"TagKey": "sim2real-check", "TagValue": CHECK}]
    partition = _partition(ctx)
    arns = {}
    for label in ("source", "destination"):
        key_id = kms.create_key(
            KeyUsage="ENCRYPT_DECRYPT", KeySpec="SYMMETRIC_DEFAULT", Tags=tag_spec
        )["KeyMetadata"]["KeyId"]
        ctx.on_cleanup(lambda _k=key_id: _schedule_deletion(kms, _k))
        arns[label] = (key_id, f"arn:{partition}:kms:{ctx.region}:{ctx.account}:key/{key_id}")
    src_id, src_arn = arns["source"]
    dst_id, dst_arn = arns["destination"]

    src_context = {"bucket": ctx.unique_name("b-")}
    dst_context = {"archive": ctx.unique_name("a-"), "tier": "cold"}
    minted = kms.generate_data_key_without_plaintext(
        KeyId=src_id, KeySpec="AES_128", EncryptionContext=src_context
    )
    assert "Plaintext" not in minted, "GenerateDataKeyWithoutPlaintext returned a Plaintext field"
    assert minted["KeyId"] == src_arn, (
        f"GenerateDataKeyWithoutPlaintext KeyId {minted['KeyId']!r}, expected {src_arn!r}"
    )
    old_blob = minted["CiphertextBlob"]
    data_key = kms.decrypt(CiphertextBlob=old_blob, EncryptionContext=src_context)["Plaintext"]
    assert len(data_key) == 16, (
        f"an AES_128 data key decrypts to {len(data_key)} bytes, expected 16"
    )

    rewrapped = kms.re_encrypt(
        CiphertextBlob=old_blob,
        SourceEncryptionContext=src_context,
        DestinationKeyId=dst_id,
        DestinationEncryptionContext=dst_context,
    )
    assert (rewrapped["SourceKeyId"], rewrapped["KeyId"]) == (src_arn, dst_arn), (
        f"ReEncrypt (SourceKeyId, KeyId) {(rewrapped['SourceKeyId'], rewrapped['KeyId'])!r}, expected the two key ARNs"
    )
    new_blob = rewrapped["CiphertextBlob"]
    assert new_blob != old_blob and data_key not in new_blob, (
        "ReEncrypt returned the old blob or the key in the clear"
    )
    dec = kms.decrypt(CiphertextBlob=new_blob, EncryptionContext=dst_context)
    assert (dec["Plaintext"], dec["KeyId"]) == (data_key, dst_arn), (
        f"the re-wrapped blob decrypts to {len(dec['Plaintext'])} bytes under {dec['KeyId']!r}, expected the "
        f"same 16-byte data key under {dst_arn!r}"
    )

    # The re-wrapped blob carries only the destination context and key.
    got = _refusal(
        lambda: kms.decrypt(CiphertextBlob=new_blob, EncryptionContext=src_context),
        "Decrypt of the re-wrapped blob with the source context",
    )
    assert got == ("InvalidCiphertextException", ""), (
        f"Decrypt with the source context: got {got!r}"
    )
    got = _refusal(
        lambda: kms.decrypt(CiphertextBlob=new_blob, KeyId=src_id, EncryptionContext=dst_context),
        "Decrypt of the re-wrapped blob naming the source key",
    )
    assert got == (
        "IncorrectKeyException",
        "The key ID in the request does not identify a CMK that can perform this operation.",
    ), f"Decrypt naming the source key: got {got!r}"

    # Disabling the source key refuses only the old wrapping; the new one still decrypts.
    kms.disable_key(KeyId=src_id)
    got = _refusal(
        lambda: kms.decrypt(CiphertextBlob=old_blob, EncryptionContext=src_context),
        "Decrypt of the old blob under a disabled source key",
        converge=True,
    )
    assert got == ("DisabledException", f"{src_arn} is disabled."), (
        f"Decrypt under the disabled source key: got {got!r}"
    )
    assert (
        kms.decrypt(CiphertextBlob=new_blob, EncryptionContext=dst_context)["Plaintext"] == data_key
    ), "the re-wrapped blob stopped decrypting when only the source key was disabled"
    kms.enable_key(KeyId=src_id)
    again = _converge(lambda: kms.decrypt(CiphertextBlob=old_blob, EncryptionContext=src_context))
    assert again["Plaintext"] == data_key, (
        "the old blob does not decrypt after the source key is re-enabled"
    )

    # The destination key pending deletion refuses the new wrapping; the old one still decrypts.
    kms.schedule_key_deletion(KeyId=dst_id, PendingWindowInDays=7)
    got = _refusal(
        lambda: kms.decrypt(CiphertextBlob=new_blob, EncryptionContext=dst_context),
        "Decrypt of the re-wrapped blob under a key pending deletion",
        converge=True,
    )
    assert got == ("KMSInvalidStateException", f"{dst_arn} is pending deletion."), (
        f"Decrypt under the destination key pending deletion: got {got!r}"
    )
    assert (
        kms.decrypt(CiphertextBlob=old_blob, EncryptionContext=src_context)["Plaintext"] == data_key
    ), "the old blob stopped decrypting when only the destination key was scheduled for deletion"


def _refusal(fn, what, *, converge=False):
    """(code, message) of the refusal fn raises, after grading its HTTP 4xx; a success raises.
    With converge, a success is retried until the key-state change propagates, then raises at
    the bound."""
    deadline = time.monotonic() + (_CONVERGE_S if converge else 0.0)
    while True:
        try:
            result = fn()
        except ClientError as exc:
            err = exc.response.get("Error", {})
            status = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
            assert isinstance(status, int) and 400 <= status < 500, (
                f"{what} was refused with HTTP {status!r}, expected 4xx"
            )
            return err.get("Code"), err.get("Message")
        if time.monotonic() >= deadline:
            raise AssertionError(f"{what} should have been rejected, but it SUCCEEDED: {result!r}")
        time.sleep(1.0)


def _converge(fn):
    """fn() once the key-state change propagates: a DisabledException meanwhile is retried, and
    the last one raises at the bound."""
    deadline = time.monotonic() + _CONVERGE_S
    while True:
        try:
            return fn()
        except ClientError as exc:
            if (
                exc.response.get("Error", {}).get("Code") != "DisabledException"
                or time.monotonic() >= deadline
            ):
                raise
        time.sleep(1.0)


def _partition(ctx) -> str:
    """The caller's partition, taken from its own ARN — never a literal 'aws'."""
    arn = ctx.client("sts").get_caller_identity()["Arn"]
    parts = arn.split(":")
    assert len(parts) > 2 and parts[0] == "arn" and parts[1], (
        f"GetCallerIdentity returned Arn {arn!r}, from which no partition can be read"
    )
    return parts[1]


def _schedule_deletion(kms, key_id):
    """Teardown: schedule the key's deletion; a key the body already scheduled is left as is,
    any other refusal raises."""
    try:
        kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "KMSInvalidStateException":
            raise
        state = kms.describe_key(KeyId=key_id)["KeyMetadata"]["KeyState"]
        if state != "PendingDeletion":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
