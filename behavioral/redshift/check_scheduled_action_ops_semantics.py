"""scheduled-action-ops-semantics."""

from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags


_THROTTLE = (
    "Throttling",
    "ThrottlingException",
    "RequestLimitExceeded",
    "TooManyRequestsException",
    "SlowDown",
)


def _code_of(exc):
    if isinstance(exc, ClientError):
        return exc.response["Error"]["Code"]
    return f"EXC:{type(exc).__name__}"


def _retrying(fn, attempts=6, delay_s=5.0):
    """Call *fn*, retrying only on API throttling (a rate limit is infrastructure
    noise under parallel runs, not a behavioral observation)."""
    last = None
    for attempt in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            if _code_of(exc) not in _THROTTLE:
                raise
            last = exc
            time.sleep(delay_s * (attempt + 1))
    raise last


def _err(fn):
    """Call *fn*; return the AWS error code, or "OK" if it succeeded."""
    try:
        _retrying(fn)
    except Exception as exc:  # noqa: BLE001 - behavioral probe of error semantics
        return _code_of(exc)
    return "OK"


def _probe_codes(cases):
    """{label: callable} -> {label: error-code-or-"OK"}; never raises."""
    return {label: _err(fn) for label, fn in cases.items()}

CHECK = "scheduled-action-ops-semantics"
GROUP = 'scheduling'
SERVICES = ['redshift']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Scheduled actions: unknown-name operations agree on ScheduledActionNotFound, and creation
    validates the cron/rate expression before anything else."""
    rs = ctx.client("redshift")
    missing = ctx.unique_name("sim2real-behav-rs-sa-")
    missing_cluster = ctx.unique_name("sim2real-behav-rs-sa-cluster-")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    role_arn = f"arn:aws:iam::{account_id}:role/sim2real-behav-missing-role"
    cases = {
        "DescribeScheduledActions": lambda: rs.describe_scheduled_actions(ScheduledActionName=missing),
        "ModifyScheduledAction": lambda: rs.modify_scheduled_action(
            ScheduledActionName=missing, Enable=False
        ),
        "DeleteScheduledAction": lambda: rs.delete_scheduled_action(ScheduledActionName=missing),
        "CreateScheduledAction(bad-schedule)": lambda: rs.create_scheduled_action(
            ScheduledActionName=ctx.unique_name("sim2real-behav-rs-sa-bad-"),
            TargetAction={"PauseCluster": {"ClusterIdentifier": missing_cluster}},
            Schedule="every 5 minutes",
            IamRole=role_arn,
        ),
    }
    observed = _probe_codes(cases)
    expected = dict.fromkeys(cases, "ScheduledActionNotFound")
    expected["CreateScheduledAction(bad-schedule)"] = "InvalidParameterValue"
    assert observed == expected, f"scheduled-action contract drift:\n expected={expected}\n observed={observed}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
