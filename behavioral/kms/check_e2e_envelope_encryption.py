"""e2e-envelope-encryption."""
from __future__ import annotations

import secrets
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-envelope-encryption"
GROUP = 'e2e_workflows'
SERVICES = ['kms']

#: KMS key-state changes are eventually consistent; each converges within this bound.
_CONVERGE_S = 60.0

@tags(
    "axis:happy-path",
    "cap:c1",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """Envelope encryption: a data key round-trips through a self-describing ciphertext bound to
    its context and CMK; a disabled key refuses Decrypt until re-enabled, and a key pending
    deletion refuses Encrypt."""
    kms = ctx.client("kms")
    tag_spec = [{"TagKey": "sim2real-check", "TagValue": CHECK}]
    key_id = kms.create_key(
        KeyUsage="ENCRYPT_DECRYPT", KeySpec="SYMMETRIC_DEFAULT", Tags=tag_spec
    )["KeyMetadata"]["KeyId"]
    ctx.on_cleanup(lambda _k=key_id: _schedule_deletion(kms, _k))

    context = {"purpose": ctx.unique_name("envelope-")}

    # GenerateDataKey — returns both plaintext and encrypted data key, bound to this context
    gen_resp = kms.generate_data_key(KeyId=key_id, KeySpec="AES_256", EncryptionContext=context)
    plaintext_key = gen_resp["Plaintext"]
    ciphertext_blob = gen_resp["CiphertextBlob"]

    assert len(plaintext_key) == 32, f"Expected 32-byte AES-256 key, got {len(plaintext_key)}"
    # A real wrapped key carries algorithm/key-id metadata beyond the 32 raw bytes — a stub that
    # just handed back the plaintext (or a trivial encoding of it) as "ciphertext" fails this.
    assert len(ciphertext_blob) > len(plaintext_key), (
        f"CiphertextBlob ({len(ciphertext_blob)} bytes) should carry more than the raw "
        f"{len(plaintext_key)}-byte key material"
    )

    # Simulate "discarding" the plaintext — in real code, you'd encrypt local data with it.
    # Store only the ciphertext blob (as you would in a database or file header).
    stored_ciphertext = ciphertext_blob

    # Later: Decrypt the CiphertextBlob to recover the plaintext data key. No KeyId is passed —
    # the ciphertext is self-describing, which is what lets a real application store only the
    # blob and not the key id alongside it.
    dec_resp = kms.decrypt(CiphertextBlob=stored_ciphertext, EncryptionContext=context)
    recovered_key = dec_resp["Plaintext"]
    assert recovered_key == plaintext_key, (
        "Decrypted data key does not match original plaintext from GenerateDataKey"
    )
    # Decrypt reports KeyId as the full key ARN, not the bare id CreateKey returned.
    assert dec_resp["KeyId"].endswith(f"/{key_id}"), (
        f"Decrypt reported KeyId {dec_resp['KeyId']!r}, expected it to identify the "
        f"originating key {key_id!r}"
    )

    # Negative: the encryption context is authenticated associated data, not an advisory label —
    # a mismatched context must be refused outright, by construction it can never be made valid.
    # AWS sends InvalidCiphertextException with an empty message.
    got = _refusal(
        lambda: kms.decrypt(CiphertextBlob=stored_ciphertext, EncryptionContext={"purpose": "wrong"}),
        "Decrypt with a mismatched EncryptionContext",
    )
    assert got == ("InvalidCiphertextException", ""), f"Decrypt with a mismatched EncryptionContext: got {got!r}"

    # Negative: the CMK identity is bound into the ciphertext itself — a ciphertext minted under
    # one CMK is never valid under another, by construction it can never be made valid.
    other_key_id = kms.create_key(
        KeyUsage="ENCRYPT_DECRYPT", KeySpec="SYMMETRIC_DEFAULT", Tags=tag_spec
    )["KeyMetadata"]["KeyId"]
    ctx.on_cleanup(lambda _k=other_key_id: _schedule_deletion(kms, _k))
    got = _refusal(
        lambda: kms.decrypt(
            CiphertextBlob=stored_ciphertext, KeyId=other_key_id, EncryptionContext=context
        ),
        "Decrypt against a different CMK",
    )
    assert got == (
        "IncorrectKeyException",
        "The key ID in the request does not identify a CMK that can perform this operation.",
    ), f"Decrypt against a different CMK: got {got!r}"

    # Direct Encrypt/Decrypt on the same key: random 4 KiB plaintext, byte-exact recovery, and
    # Decrypt reports the key ARN built from the caller's own partition, region and account.
    plaintext = secrets.token_bytes(4096)
    direct_context = {"leg": ctx.unique_name("direct-")}
    blob = kms.encrypt(KeyId=key_id, Plaintext=plaintext, EncryptionContext=direct_context)["CiphertextBlob"]
    assert plaintext not in blob, "the Encrypt CiphertextBlob carries the plaintext in the clear"
    direct = kms.decrypt(CiphertextBlob=blob, EncryptionContext=direct_context)
    assert direct["Plaintext"] == plaintext, "Decrypt did not recover the 4 KiB plaintext byte-exact"
    expected_arn = f"arn:{_partition(ctx)}:kms:{ctx.region}:{ctx.account}:key/{key_id}"
    assert direct["KeyId"] == expected_arn, (
        f"Decrypt reported KeyId {direct['KeyId']!r}, expected {expected_arn!r}"
    )

    # Key-state tail: a disabled key refuses to decrypt its own earlier ciphertext, re-enabling
    # restores it, and a key pending deletion refuses new encryption.
    kms.disable_key(KeyId=key_id)
    got = _refusal(
        lambda: kms.decrypt(CiphertextBlob=blob, EncryptionContext=direct_context),
        "Decrypt under a disabled key", converge=True,
    )
    assert got == ("DisabledException", f"{expected_arn} is disabled."), f"Decrypt under a disabled key: got {got!r}"
    kms.enable_key(KeyId=key_id)
    reenabled = _converge(lambda: kms.decrypt(CiphertextBlob=blob, EncryptionContext=direct_context))
    assert reenabled["Plaintext"] == plaintext, "Decrypt after EnableKey did not recover the plaintext byte-exact"

    kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7)
    state = _converge_value(lambda: kms.describe_key(KeyId=key_id)["KeyMetadata"]["KeyState"],
                            lambda v: v == "PendingDeletion")
    assert state == "PendingDeletion", f"DescribeKey KeyState {state!r} after ScheduleKeyDeletion, expected 'PendingDeletion'"
    got = _refusal(
        lambda: kms.encrypt(KeyId=key_id, Plaintext=b"after-schedule"),
        "Encrypt under a key pending deletion", converge=True,
    )
    assert got == ("KMSInvalidStateException", f"{expected_arn} is pending deletion."), (
        f"Encrypt under a key pending deletion: got {got!r}"
    )


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
            assert isinstance(status, int) and 400 <= status < 500, f"{what} was refused with HTTP {status!r}, expected 4xx"
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
            if exc.response.get("Error", {}).get("Code") != "DisabledException" or time.monotonic() >= deadline:
                raise
        time.sleep(1.0)


def _converge_value(probe, ok):
    """Re-read until ok(value) holds or the bound passes; return the last value read."""
    deadline = time.monotonic() + _CONVERGE_S
    while True:
        value = probe()
        if ok(value) or time.monotonic() >= deadline:
            return value
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
