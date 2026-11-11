"""delete-secret-recovery-window-sets-exact-deletion-date."""
from __future__ import annotations

import datetime as dt

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "delete-secret-recovery-window-sets-exact-deletion-date"
GROUP = "visibility-timeout-ttl"
SERVICES = ["secretsmanager"]

_RECOVERY_WINDOW_DAYS = 7
_TOLERANCE_SECONDS = 600  # generous allowance for clock skew / request latency


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteSecret with RecoveryWindowInDays=N returns DeletionDate ~now + N days, while
    DescribeSecret's DeletedDate is populated immediately with the deletion-request time."""
    sm = ctx.client("secretsmanager")
    secret_name = ctx.unique_name("sim2real-behav-delwindow-")
    secret = sm.create_secret(Name=secret_name, SecretString="to-be-deleted")
    secret_arn = secret["ARN"]

    def _cleanup():
        try:
            sm.restore_secret(SecretId=secret_arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
        sm.delete_secret(SecretId=secret_arn, ForceDeleteWithoutRecovery=True)

    ctx.on_cleanup(_cleanup)

    before = dt.datetime.now(dt.timezone.utc)
    delete_resp = sm.delete_secret(SecretId=secret_arn, RecoveryWindowInDays=_RECOVERY_WINDOW_DAYS)
    after = dt.datetime.now(dt.timezone.utc)
    expected = before + dt.timedelta(days=_RECOVERY_WINDOW_DAYS)

    # DeleteSecret's own response computes the real scheduled-deletion date.
    deletion_date = delete_resp["DeletionDate"]
    delta = abs((deletion_date - expected).total_seconds())
    assert delta < _TOLERANCE_SECONDS, f"DeleteSecret response DeletionDate off by {delta}s from now+{_RECOVERY_WINDOW_DAYS}d"

    # DescribeSecret's DeletedDate is populated immediately (not eventually) but
    # tracks the deletion-request time, not the N-day-out scheduled date.
    described = sm.describe_secret(SecretId=secret_arn)
    described_date = described["DeletedDate"]
    request_window_delta = (described_date - before).total_seconds()
    assert -_TOLERANCE_SECONDS < request_window_delta < (after - before).total_seconds() + _TOLERANCE_SECONDS, (
        f"DescribeSecret DeletedDate ({described_date}) is not close to the deletion "
        f"request time ({before} .. {after})"
    )
    far_from_schedule = abs((described_date - expected).total_seconds())
    assert far_from_schedule > (_RECOVERY_WINDOW_DAYS - 1) * 86400, (
        "DescribeSecret DeletedDate unexpectedly matches the N-day-out scheduled date "
        f"({described_date} vs expected {expected}) -- real-AWS semantics changed?"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
