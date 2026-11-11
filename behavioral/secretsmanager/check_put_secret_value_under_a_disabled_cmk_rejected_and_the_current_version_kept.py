"""put-secret-value-under-a-disabled-cmk-rejected-and-the-current-version-kept."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-secret-value-under-a-disabled-cmk-rejected-and-the-current-version-kept"
GROUP = "server-side"
SERVICES = ["secretsmanager"]


def _error(fn):
    """(code, message) of the ClientError fn() raised. An unexpected success RAISES."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _key(ctx, kms):
    """A fresh symmetric CMK, scheduled for deletion at teardown."""
    arn = kms.create_key(
        Description=ctx.unique_name("sim2real-behav-smkey-"),
        KeyUsage="ENCRYPT_DECRYPT",
        KeySpec="SYMMETRIC_DEFAULT",
    )["KeyMetadata"]["Arn"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=arn, PendingWindowInDays=7))
    return arn


def _secret(ctx, sm, **kwargs):
    name = ctx.unique_name("sim2real-behav-secret-")
    arn = sm.create_secret(Name=name, Tags=[{"Key": "sim2real-check", "Value": CHECK}], **kwargs)["ARN"]
    ctx.on_cleanup(lambda: sm.delete_secret(SecretId=arn, ForceDeleteWithoutRecovery=True))
    return arn


@tags("axis:rejection", "cap:c4", "concern:negative-classes", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """PutSecretValue under a disabled CMK fails with EncryptionFailure and mints no version or
    AWSPENDING label; after the key is re-enabled the same put succeeds and becomes AWSCURRENT.
    """
    kms = ctx.client("kms")
    sm = ctx.client("secretsmanager")
    key = _key(ctx, kms)
    arn = _secret(ctx, sm, KmsKeyId=key, SecretString="v1")
    before = sorted(v["VersionId"] for v in sm.list_secret_version_ids(SecretId=arn)["Versions"])

    kms.disable_key(KeyId=key)
    ctx.on_cleanup(lambda: kms.enable_key(KeyId=key))
    _await_key_unusable(sm, arn)
    code, _ = _error(lambda: sm.put_secret_value(SecretId=arn, SecretString="v2"))
    assert code == "EncryptionFailure", f"PutSecretValue under a disabled key: got {code!r}"
    # message varies: it embeds the downstream KMS call's request id.
    after = sorted(v["VersionId"] for v in sm.list_secret_version_ids(SecretId=arn)["Versions"])
    assert after == before, f"the refused put changed the versions: {before!r} -> {after!r}"
    code, message = _error(lambda: sm.get_secret_value(SecretId=arn, VersionStage="AWSPENDING"))
    assert code == "ResourceNotFoundException", f"the refused put left an AWSPENDING version: {code!r}"
    assert message == (
        "Secrets Manager can't find the specified secret value for staging label: AWSPENDING"
    ), f"unexpected message {message!r}"

    kms.enable_key(KeyId=key)
    put = sm.put_secret_value(SecretId=arn, SecretString="v2")
    current = sm.get_secret_value(SecretId=arn)
    assert (current["SecretString"], current["VersionId"]) == ("v2", put["VersionId"]), (
        f"after re-enabling the key the put must be AWSCURRENT: {current['VersionId']!r}"
    )



def _await_key_unusable(sm, arn, timeout_s=120.0):
    """Poll a read that needs the key until it fails: disabling a key propagates, it is not instant."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            sm.get_secret_value(SecretId=arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "DecryptionFailure":
                return
            raise
        assert time.monotonic() < deadline, f"the disabled key still decrypts after {timeout_s}s"
        time.sleep(2.0)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

