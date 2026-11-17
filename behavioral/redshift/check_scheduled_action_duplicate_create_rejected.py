"""scheduled-action-duplicate-create-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "scheduled-action-duplicate-create-rejected"
GROUP = "scheduling"
SERVICES = ["redshift", "iam"]


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _code_of(exc):
    return exc.response.get("Error", {}).get("Code") if isinstance(exc, ClientError) else None


def _delete_unless_gone(delete, gone_code):
    try:
        delete()
    except ClientError as exc:
        if _code_of(exc) != gone_code:
            raise


def _create_with_role_propagation(fn, deadline_s=90.0):
    """IAM exposes no condition to poll for role propagation; retry the exact transient
    rejection a brand-new trust policy can produce at first use, bounded."""
    deadline = time.monotonic() + deadline_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            message = exc.response.get("Error", {}).get("Message", "")
            if _code_of(exc) != "InvalidParameterValue" or "delegate access" not in message:
                raise
            if time.monotonic() >= deadline:
                raise
            time.sleep(5)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateScheduledAction on a name already in use is rejected with ScheduledActionAlreadyExists
    and leaves the original action's schedule unchanged."""
    rs = ctx.client("redshift")
    iam = ctx.client("iam")
    account = ctx.client("sts").get_caller_identity()["Account"]

    role_name = ctx.unique_name("sim2real-behav-rs-sarole-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "scheduler.redshift.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))
    ctx.on_cleanup(
        lambda: _delete_unless_gone(lambda: iam.delete_role(RoleName=role_name), "NoSuchEntity")
    )
    role_arn = f"arn:aws:iam::{account}:role/{role_name}"

    action_name = ctx.unique_name("sim2real-behav-rs-sadup-")
    target_cluster = ctx.unique_name("sim2real-behav-rs-sadup-cl-")
    ctx.on_cleanup(
        lambda: _delete_unless_gone(
            lambda: rs.delete_scheduled_action(ScheduledActionName=action_name),
            "ScheduledActionNotFound",
        )
    )
    created = _create_with_role_propagation(
        lambda: rs.create_scheduled_action(
            ScheduledActionName=action_name,
            TargetAction={"PauseCluster": {"ClusterIdentifier": target_cluster}},
            Schedule="cron(0 10 * * ? *)",
            IamRole=role_arn,
        )
    )
    assert created["Schedule"] == "cron(0 10 * * ? *)", created
    assert created["State"] == "ACTIVE", created

    code, message = _error(
        lambda: rs.create_scheduled_action(
            ScheduledActionName=action_name,
            TargetAction={"PauseCluster": {"ClusterIdentifier": target_cluster}},
            Schedule="cron(0 11 * * ? *)",
            IamRole=role_arn,
        )
    )
    assert code == "ScheduledActionAlreadyExists", f"expected ScheduledActionAlreadyExists, got {code}: {message!r}"
    expected = f"The scheduled action {action_name} already exists."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    unchanged = rs.describe_scheduled_actions(ScheduledActionName=action_name)["ScheduledActions"]
    assert len(unchanged) == 1, unchanged
    assert unchanged[0]["Schedule"] == "cron(0 10 * * ? *)", (
        f"a rejected duplicate create must not have overwritten the original schedule: {unchanged[0]!r}"
    )

    rs.delete_scheduled_action(ScheduledActionName=action_name)
    code, message = _error(lambda: rs.describe_scheduled_actions(ScheduledActionName=action_name))
    assert code == "ScheduledActionNotFound", f"expected ScheduledActionNotFound, got {code}: {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
