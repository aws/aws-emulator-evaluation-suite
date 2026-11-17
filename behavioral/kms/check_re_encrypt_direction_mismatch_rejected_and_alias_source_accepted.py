"""re-encrypt-direction-mismatch-rejected-and-alias-source-accepted."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "re-encrypt-direction-mismatch-rejected-and-alias-source-accepted"
GROUP = 're_encrypt'
SERVICES = ['kms']

ERR_INCORRECT_KEY = "IncorrectKeyException"
MSG_INCORRECT_KEY = (
    "The key ID in the request does not identify a CMK that can perform this operation."
)


def _err(fn):
    """Return (Code, Message) of the ClientError fn() raises; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded: {result!r}")


def _alias_resolves_to(kms, alias: str, key_arn: str) -> bool:
    try:
        resolved = kms.describe_key(KeyId=alias)["KeyMetadata"]["Arn"]
    except kms.exceptions.NotFoundException:
        return False
    return resolved == key_arn


def _poll_until(probe, *, timeout_s=60, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if probe():
            return
        time.sleep(interval_s)
    raise AssertionError(f"timed out after {timeout_s}s waiting for {description}")


def _teardown(undo, *not_found: str):
    """A cleanup running undo() where a failed delete raises; the resource's own not-found
    codes mean it is already gone."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """ReEncrypt accepts the wrapping key as SourceKeyId by id and by alias, echoes both keys' ARNs
    as SourceKeyId and KeyId, and its blob decrypts without a KeyId under the destination key; the
    swapped direction is refused with IncorrectKeyException and the source blob still decrypts.
    """
    kms = ctx.client("kms")
    key_a = kms.create_key(
        Description=ctx.unique_name("sim2real-behav-kms-reencrypt-a-"),
        KeyUsage="ENCRYPT_DECRYPT", KeySpec="SYMMETRIC_DEFAULT",
    )["KeyMetadata"]["Arn"]
    ctx.on_cleanup(lambda _k=key_a: kms.schedule_key_deletion(KeyId=_k, PendingWindowInDays=7))
    key_b = kms.create_key(
        Description=ctx.unique_name("sim2real-behav-kms-reencrypt-b-"),
        KeyUsage="ENCRYPT_DECRYPT", KeySpec="SYMMETRIC_DEFAULT",
    )["KeyMetadata"]["Arn"]
    ctx.on_cleanup(lambda _k=key_b: kms.schedule_key_deletion(KeyId=_k, PendingWindowInDays=7))
    assert key_a != key_b, "the two minted CMKs must be distinct"

    alias = "alias/" + ctx.unique_name("sim2real-behav-kms-reencrypt-")
    assert not alias.startswith("alias/aws/"), alias
    kms.create_alias(AliasName=alias, TargetKeyId=key_a)
    ctx.on_cleanup(_teardown(lambda: kms.delete_alias(AliasName=alias), "NotFoundException"))
    _poll_until(
        lambda: _alias_resolves_to(kms, alias, key_a),
        description="the new alias to resolve to key A",
    )

    plaintext = b"re-encrypt-direction-mismatch-plaintext"
    ciphertext = kms.encrypt(KeyId=key_a, Plaintext=plaintext)["CiphertextBlob"]

    # --- Legal neighbour 1: SourceKeyId named by id. The response echoes A's ARN as SourceKeyId
    # and B's ARN as KeyId, and a keyless Decrypt of the rewrapped blob reports KeyId=B and the
    # original plaintext.
    re1 = kms.re_encrypt(CiphertextBlob=ciphertext, SourceKeyId=key_a, DestinationKeyId=key_b)
    assert re1["SourceKeyId"] == key_a, f"expected SourceKeyId {key_a!r}, got {re1['SourceKeyId']!r}"
    assert re1["KeyId"] == key_b, f"expected KeyId {key_b!r}, got {re1['KeyId']!r}"
    dec1 = kms.decrypt(CiphertextBlob=re1["CiphertextBlob"])
    assert dec1["Plaintext"] == plaintext, f"expected {plaintext!r}, got {dec1['Plaintext']!r}"
    assert dec1["KeyId"] == key_b, f"expected keyless Decrypt to report KeyId {key_b!r}, got {dec1['KeyId']!r}"

    # --- Legal neighbour 2: SourceKeyId named by A's alias. Same echoed ARNs and same keyless
    # decrypt, proving the alias resolves exactly like the id for this operation.
    re2 = kms.re_encrypt(CiphertextBlob=ciphertext, SourceKeyId=alias, DestinationKeyId=key_b)
    assert re2["SourceKeyId"] == key_a, f"expected SourceKeyId {key_a!r}, got {re2['SourceKeyId']!r}"
    assert re2["KeyId"] == key_b, f"expected KeyId {key_b!r}, got {re2['KeyId']!r}"
    dec2 = kms.decrypt(CiphertextBlob=re2["CiphertextBlob"])
    assert dec2["Plaintext"] == plaintext, f"expected {plaintext!r}, got {dec2['Plaintext']!r}"
    assert dec2["KeyId"] == key_b, f"expected keyless Decrypt to report KeyId {key_b!r}, got {dec2['KeyId']!r}"

    # Swapping source and destination names B, which never wrapped this blob, as its source.
    got = _err(lambda: kms.re_encrypt(CiphertextBlob=ciphertext, SourceKeyId=key_b, DestinationKeyId=key_a))
    assert got == (ERR_INCORRECT_KEY, MSG_INCORRECT_KEY), (
        f"expected {(ERR_INCORRECT_KEY, MSG_INCORRECT_KEY)!r}, got {got!r}"
    )

    # The original blob still decrypts under A after the refusal.
    dec3 = kms.decrypt(CiphertextBlob=ciphertext, KeyId=key_a)
    assert dec3["Plaintext"] == plaintext, (
        f"the refused ReEncrypt must leave the source ciphertext decryptable under A, got {dec3['Plaintext']!r}"
    )
    assert dec3["KeyId"] == key_a, f"expected KeyId {key_a!r}, got {dec3['KeyId']!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
