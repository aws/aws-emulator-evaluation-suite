"""server-side-kms-encryption-transparent-decryption."""
from __future__ import annotations

import time

import botocore.exceptions

from behavioral_harness import tags

CHECK = "server-side-kms-encryption-transparent-decryption"
GROUP = "server-side"
SERVICES = ["secretsmanager"]


def _budget_s(ctx, cap_s: float) -> float:
    """A poll's timeout: cap_s, bounded by the runner's remaining time when it has one."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


@tags(
    "axis:happy-path",
    "cap:c2",
    "concern:data-plane",
    "concern:representation",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """A secret under a customer-managed KMS key decrypts transparently on GetSecretValue for both
    versions; disabling the key makes GetSecretValue fail with DecryptionFailure while
    DescribeSecret still works, and re-enabling it restores the read."""
    kms = ctx.client("kms")
    sm = ctx.client("secretsmanager")

    key = kms.create_key(
        Description=ctx.unique_name("sim2real-behav-smkey-"),
        KeyUsage="ENCRYPT_DECRYPT",
        KeySpec="SYMMETRIC_DEFAULT",
    )["KeyMetadata"]
    key_arn = key["Arn"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_arn, PendingWindowInDays=7))

    name = ctx.unique_name("sim2real-behav-smkms-")
    original_value = "kms-round-trip-value-v1"
    sm.create_secret(Name=name, SecretString=original_value, KmsKeyId=key_arn)
    ctx.on_cleanup(lambda: sm.delete_secret(SecretId=name, ForceDeleteWithoutRecovery=True))

    description = sm.describe_secret(SecretId=name)
    assert description["KmsKeyId"] == key_arn, (
        f"expected DescribeSecret to echo the CMK ARN {key_arn!r}, got "
        f"{description.get('KmsKeyId')!r}"
    )

    fetched = sm.get_secret_value(SecretId=name)["SecretString"]
    assert fetched == original_value, (
        f"expected transparent server-side decrypt to return {original_value!r}, "
        f"got {fetched!r}"
    )

    updated_value = "kms-round-trip-value-v2"
    sm.put_secret_value(SecretId=name, SecretString=updated_value)
    fetched_v2 = sm.get_secret_value(SecretId=name, VersionStage="AWSCURRENT")["SecretString"]
    assert fetched_v2 == updated_value, (
        f"expected the re-encrypted version to decrypt to {updated_value!r}, got "
        f"{fetched_v2!r}"
    )

    # Disabling the key proves the CMK is actually used for decryption. A KMS key-state change is
    # eventually consistent, so the read is polled every 2 s while it still succeeds; throttling is
    # retried and the first other refusal is graded.
    kms.disable_key(KeyId=key_arn)
    deadline = time.monotonic() + _budget_s(ctx, 120.0)
    refusal = None
    while refusal is None and time.monotonic() < deadline:
        try:
            sm.get_secret_value(SecretId=name, VersionStage="AWSCURRENT")
        except botocore.exceptions.ClientError as exc:
            if exc.response["Error"]["Code"] != "ThrottlingException":
                refusal = exc
                break
        time.sleep(2)
    if refusal is None:
        raise AssertionError(
            "GetSecretValue succeeded with the CMK disabled -- the secret is not "
            "actually depending on this key for decryption"
        )
    code = refusal.response["Error"]["Code"]
    assert code == "DecryptionFailure", (
        f"expected GetSecretValue to fail with DecryptionFailure once the CMK "
        f"is disabled, got {code!r}"
    )
    # The message embeds the downstream KMS call's per-request Request ID, so only its fixed
    # prefix and suffix are pinned.
    message = refusal.response["Error"].get("Message", "")
    prefix = (
        f"Secrets Manager can't decrypt the secret value: {key_arn} is disabled. (Service: AWSKMS; "
        "Status Code: 400; Error Code: DisabledException; Request ID: "
    )
    assert message.startswith(prefix) and message.endswith("; Proxy: null)"), (
        f"expected {prefix!r}<request id>'; Proxy: null)', got {message!r}"
    )

    description_while_disabled = sm.describe_secret(SecretId=name)
    assert description_while_disabled["KmsKeyId"] == key_arn, (
        "expected the secret's own metadata to be unaffected by the disabled CMK, "
        f"got KmsKeyId={description_while_disabled.get('KmsKeyId')!r}"
    )

    kms.enable_key(KeyId=key_arn)
    # The re-enable is eventually consistent too: DecryptionFailure is retried every 2 s.
    deadline = time.monotonic() + _budget_s(ctx, 120.0)
    while True:
        try:
            restored = sm.get_secret_value(SecretId=name, VersionStage="AWSCURRENT")["SecretString"]
            break
        except botocore.exceptions.ClientError as exc:
            if exc.response["Error"]["Code"] != "DecryptionFailure" or time.monotonic() >= deadline:
                raise
        time.sleep(2)
    assert restored == updated_value, (
        f"expected GetSecretValue to succeed again with {updated_value!r} once the "
        f"CMK was re-enabled, got {restored!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
