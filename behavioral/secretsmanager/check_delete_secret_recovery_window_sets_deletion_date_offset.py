"""delete-secret-recovery-window-sets-deletion-date-offset."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "delete-secret-recovery-window-sets-deletion-date-offset"
GROUP = "visibility-timeout-ttl"
SERVICES = ["secretsmanager"]

_MARKED_FOR_DELETION = (
    "You can't perform this operation on the secret because it was marked for deletion."
)


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteSecret's DeletionDate is now+RecoveryWindowInDays, while DescribeSecret's DeletedDate is
    ~now, so the two differ by ~the window; the value stays unreadable during the window."""
    sm = ctx.client("secretsmanager")
    name = ctx.unique_name("sim2real-behav-recoverywindow-")

    sm.create_secret(Name=name, SecretString="v")

    positive_control = sm.get_secret_value(SecretId=name)
    assert positive_control["SecretString"] == "v", (
        "positive control failed -- GetSecretValue did not return the just-created secret's "
        f"value before any delete, got {positive_control.get('SecretString')!r}"
    )

    def _cleanup():
        try:
            sm.restore_secret(SecretId=name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
        sm.delete_secret(SecretId=name, ForceDeleteWithoutRecovery=True)

    ctx.on_cleanup(_cleanup)

    recovery_window_days = 10
    before = datetime.now(timezone.utc)
    del_resp = sm.delete_secret(SecretId=name, RecoveryWindowInDays=recovery_window_days)
    after = datetime.now(timezone.utc)

    deletion_date = del_resp["DeletionDate"]
    assert deletion_date > after, "DeletionDate was not in the future -- deletion was not deferred"

    expected = before + timedelta(days=recovery_window_days)
    delta_seconds = abs((deletion_date - expected).total_seconds())
    assert delta_seconds < 300, (
        f"DeletionDate {deletion_date} is not within 5 minutes of now+{recovery_window_days}d "
        f"{expected} (delta={delta_seconds}s)"
    )

    desc = sm.describe_secret(SecretId=name)
    assert "DeletedDate" in desc, "DescribeSecret did not report DeletedDate for a pending-deletion secret"

    # DescribeSecret's DeletedDate marks when deletion was scheduled (~now), not the future
    # permanent-purge-eligible date -- verify it's close to the request time and that the gap
    # between it and DeleteSecret's DeletionDate is ~RecoveryWindowInDays, not zero/immediate.
    deleted_date = desc["DeletedDate"]
    assert abs((deleted_date - before).total_seconds()) < 300, (
        f"DescribeSecret DeletedDate {deleted_date} is not close to the delete-request time {before}"
    )
    window_gap_seconds = (deletion_date - deleted_date).total_seconds()
    expected_window_seconds = recovery_window_days * 86400
    assert abs(window_gap_seconds - expected_window_seconds) < 300, (
        f"gap between DeletionDate and DeletedDate ({window_gap_seconds}s) does not match the "
        f"configured {recovery_window_days}-day recovery window ({expected_window_seconds}s)"
    )

    # Per AWS docs: "When a secret is scheduled for deletion, you cannot retrieve the secret
    # value" -- this must hold throughout the recovery window, not just at permanent deletion.
    from botocore.exceptions import ClientError

    try:
        sm.get_secret_value(SecretId=name)
        raise AssertionError("GetSecretValue unexpectedly succeeded on a secret pending deletion")
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        assert code == "InvalidRequestException", (
            f"expected InvalidRequestException for GetSecretValue on a pending-deletion secret, got {code}"
        )
        message = exc.response["Error"].get("Message")
        assert message == _MARKED_FOR_DELETION, (
            f"expected message {_MARKED_FOR_DELETION!r}, got {message!r}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

