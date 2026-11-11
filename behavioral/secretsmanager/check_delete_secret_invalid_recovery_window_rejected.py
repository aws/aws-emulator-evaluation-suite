"""delete-secret-invalid-recovery-window-rejected."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "delete-secret-invalid-recovery-window-rejected"
GROUP = "visibility-timeout-ttl"
SERVICES = ["secretsmanager"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteSecret rejects a RecoveryWindowInDays outside the documented [7, 30] range instead
    of silently clamping it, and leaves the secret untouched."""
    sm = ctx.client("secretsmanager")

    broken_name = ctx.unique_name("sim2real-behav-badwindow-")
    control_name = ctx.unique_name("sim2real-behav-goodwindow-")

    sm.create_secret(Name=broken_name, SecretString="v")
    ctx.on_cleanup(lambda: sm.delete_secret(SecretId=broken_name, ForceDeleteWithoutRecovery=True))

    code, message = _refusal(lambda: sm.delete_secret(SecretId=broken_name, RecoveryWindowInDays=5))
    assert code == "InvalidParameterException", (
        f"expected InvalidParameterException, got {code!r}"
    )
    assert message == "The RecoveryWindowInDays value must be between 7 and 30 days (inclusive).", (
        f"unexpected refusal message: {message!r}"
    )

    # Effect absent: the secret is still fully active, not partially/incorrectly scheduled.
    desc = sm.describe_secret(SecretId=broken_name)
    assert "DeletedDate" not in desc, "rejected DeleteSecret call still scheduled the secret for deletion"

    # Positive control in the same file: a valid recovery window on a sibling secret succeeds.
    sm.create_secret(Name=control_name, SecretString="v")

    def _cleanup_control():
        try:
            sm.restore_secret(SecretId=control_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
        sm.delete_secret(SecretId=control_name, ForceDeleteWithoutRecovery=True)

    ctx.on_cleanup(_cleanup_control)

    before = datetime.now(timezone.utc)
    del_resp = sm.delete_secret(SecretId=control_name, RecoveryWindowInDays=7)
    assert del_resp["DeletionDate"] > before
    assert del_resp["DeletionDate"] < before + timedelta(days=8)

    # Independent read at the destination: the control secret's own successful DeleteSecret
    # response is not enough, since a target could echo a plausible DeletionDate without ever
    # transitioning the secret's state. Confirm via a different operation that the secret is
    # now actually pending deletion.
    control_desc = sm.describe_secret(SecretId=control_name)
    assert "DeletedDate" in control_desc, (
        "DescribeSecret did not report DeletedDate for the control secret after a valid "
        "recovery-window DeleteSecret call succeeded"
    )


def _refusal(fn):
    """Call fn(); return (Error.Code, Error.Message). An unexpected SUCCESS raises, so a target
    that clamps the window instead of refusing it fails loudly instead of as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be refused, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
