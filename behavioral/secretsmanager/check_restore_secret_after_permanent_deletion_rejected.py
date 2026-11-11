"""restore-secret-after-permanent-deletion-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "restore-secret-after-permanent-deletion-rejected"
GROUP = "concurrency"
SERVICES = ["secretsmanager"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """RestoreSecret rejects a secret that was permanently deleted (an irreversible state
    transition) with ResourceNotFoundException and the secret stays gone, while a positive
    control secret scheduled for deletion with a recovery window is restored successfully."""
    sm = ctx.client("secretsmanager")

    # positive control: schedule-for-deletion -> restore succeeds
    control_name = ctx.unique_name("sim2real-restorectl-")
    control = sm.create_secret(
        Name=control_name, SecretString="control", Tags=[{"Key": "sim2real-check", "Value": CHECK}]
    )
    control_arn = control["ARN"]
    ctx.on_cleanup(lambda: sm.delete_secret(SecretId=control_arn, ForceDeleteWithoutRecovery=True))

    sm.delete_secret(SecretId=control_arn)
    restored = sm.restore_secret(SecretId=control_arn)
    assert restored["ARN"] == control_arn, f"expected ARN {control_arn}, got {restored['ARN']}"
    desc = sm.describe_secret(SecretId=control_arn)
    assert "DeletedDate" not in desc, f"expected DeletedDate absent after restore, got {desc.get('DeletedDate')}"

    # negative: a permanently deleted secret can never be restored
    gone_name = ctx.unique_name("sim2real-restoregone-")
    gone = sm.create_secret(
        Name=gone_name, SecretString="gone", Tags=[{"Key": "sim2real-check", "Value": CHECK}]
    )
    gone_arn = gone["ARN"]
    sm.delete_secret(SecretId=gone_arn, ForceDeleteWithoutRecovery=True)

    # bounded poll: force-deletion may take a moment to fully propagate before
    # DescribeSecret consistently reports the secret gone.
    deadline = time.monotonic() + 30
    while True:
        try:
            sm.describe_secret(SecretId=gone_arn)
        except ClientError as exc:
            deleted_error = exc.response["Error"]
            if deleted_error["Code"] == "ResourceNotFoundException":
                break
            raise
        if time.monotonic() >= deadline:
            raise AssertionError("secret was not fully gone 30s after ForceDeleteWithoutRecovery")
        time.sleep(2)
    assert deleted_error.get("Message") == "Secrets Manager can't find the specified secret.", (
        f"unexpected not-found message: {deleted_error.get('Message')!r}"
    )

    code, message = _rejected_code(lambda: sm.restore_secret(SecretId=gone_arn))
    assert code == "ResourceNotFoundException", f"unexpected RestoreSecret rejection code: {code}"
    assert message == "Secrets Manager can't find the specified secret.", f"unexpected RestoreSecret rejection message: {message!r}"

    # effect absent: the secret is still gone, not resurrected by the failed restore
    code2, message2 = _rejected_code(lambda: sm.describe_secret(SecretId=gone_arn))
    assert code2 == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code2}"
    assert message2 == "Secrets Manager can't find the specified secret.", f"unexpected not-found message: {message2!r}"


def _rejected_code(fn):
    """Call fn(); return its (error code, error message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
