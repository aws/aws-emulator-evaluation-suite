"""create-secret-under-a-cmk-pending-deletion-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-secret-under-a-cmk-pending-deletion-rejected"
GROUP = "server-side"
SERVICES = ["secretsmanager"]


def _error(fn):
    """(code, message) of the ClientError fn() raised; an unexpected success raises."""
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


@tags("axis:rejection", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateSecret under a CMK pending deletion is refused and leaves no secret; once the deletion
    is cancelled and the key re-enabled, the same CreateSecret succeeds and the value reads back.
    """
    kms = ctx.client("kms")
    sm = ctx.client("secretsmanager")
    key = _key(ctx, kms)
    kms.schedule_key_deletion(KeyId=key, PendingWindowInDays=7)
    name = ctx.unique_name("sim2real-behav-secret-")

    code, message = _error(lambda: sm.create_secret(
        Name=name, KmsKeyId=key, SecretString="v1", Tags=[{"Key": "sim2real-check", "Value": CHECK}]
    ))
    assert code == "PreconditionNotMetException", (
        f"CreateSecret under a pending-deletion key: got {code}: {message!r}"
    )
    # message varies: it embeds the downstream KMS call's request id.
    code, message = _error(lambda: sm.describe_secret(SecretId=name))
    assert code == "ResourceNotFoundException", f"the refused CreateSecret left a secret: {code!r}"
    assert message == "Secrets Manager can't find the specified secret.", f"message {message!r}"

    kms.cancel_key_deletion(KeyId=key)
    kms.enable_key(KeyId=key)
    arn = sm.create_secret(
        Name=name, KmsKeyId=key, SecretString="v1", Tags=[{"Key": "sim2real-check", "Value": CHECK}]
    )["ARN"]
    ctx.on_cleanup(lambda: sm.delete_secret(SecretId=arn, ForceDeleteWithoutRecovery=True))
    assert sm.get_secret_value(SecretId=arn)["SecretString"] == "v1", "the restored key's secret"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

