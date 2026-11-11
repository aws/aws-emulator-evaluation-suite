"""metrics-states-version-and-alias-count-increase-on-publish-and-alias-create."""
from __future__ import annotations

import json
import time
from datetime import datetime, timedelta, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "metrics-states-version-and-alias-count-increase-on-publish-and-alias-create"
GROUP = "metric-emission"
SERVICES = ["cloudwatch", "stepfunctions"]

_UP_BUDGET_S = 90.0
_POLL_S = 2.0


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


# timing:real-time — metric: 30 s https://docs.aws.amazon.com/step-functions/latest/dg/procedure-cw-metrics.html
@tags(
    "axis:happy-path",
    "concern:data-plane",
    "concern:metrics",
    "dp:api",
    "plane:data",
    "cap:c3",
    "timing:real-time",
)
def run(ctx) -> None:
    """VersionCount under [ResourceArn] rises by one per publish-on-create, publish-on-update and
    PublishStateMachineVersion; AliasCount rises by one on CreateStateMachineAlias.

    Reference: https://docs.aws.amazon.com/step-functions/latest/dg/procedure-cw-metrics.html
    """
    sfn = ctx.client("stepfunctions")
    cw = ctx.client("cloudwatch")

    role_arn = _states_role(ctx)
    name = ctx.unique_name("sim2real-behav-obs-sfn-vacount-up-")
    created = _create_published(ctx, sfn, name, role_arn, _definition("v1"))
    sm_arn, v1 = created["stateMachineArn"], created["stateMachineVersionArn"]
    ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=sm_arn))
    ctx.on_cleanup(lambda: sfn.delete_state_machine_version(stateMachineVersionArn=v1))

    res_d = [{"Name": "ResourceArn", "Value": sm_arn}]
    _poll_metric(ctx, cw, "VersionCount", res_d, 1.0, "publish-on-create")

    v2 = sfn.update_state_machine(
        stateMachineArn=sm_arn, definition=_definition("v2"), publish=True,
    )["stateMachineVersionArn"]
    ctx.on_cleanup(lambda: sfn.delete_state_machine_version(stateMachineVersionArn=v2))
    assert v2 != v1, f"publish-on-update must mint a new version, got the same ARN {v2!r}"
    _poll_metric(ctx, cw, "VersionCount", res_d, 2.0, "publish-on-update")

    # A fresh PublishStateMachineVersion call needs a changed revision; only UpdateStateMachine
    # with a new definition advances it, so bump the definition first with no publish.
    sfn.update_state_machine(stateMachineArn=sm_arn, definition=_definition("v3"))
    v3 = sfn.publish_state_machine_version(stateMachineArn=sm_arn)["stateMachineVersionArn"]
    ctx.on_cleanup(lambda: sfn.delete_state_machine_version(stateMachineVersionArn=v3))
    assert v3 not in (v1, v2), f"PublishStateMachineVersion must mint a new version, got {v3!r}"
    _poll_metric(ctx, cw, "VersionCount", res_d, 3.0, "PublishStateMachineVersion")

    alias_arn = sfn.create_state_machine_alias(
        name="live", description="sim2real vacount-up",
        routingConfiguration=[{"stateMachineVersionArn": v3, "weight": 100}],
    )["stateMachineAliasArn"]
    ctx.on_cleanup(lambda: sfn.delete_state_machine_alias(stateMachineAliasArn=alias_arn))
    _poll_metric(ctx, cw, "AliasCount", res_d, 1.0, "CreateStateMachineAlias")


def _definition(result: str) -> str:
    return json.dumps({"StartAt": "Mark", "States": {
        "Mark": {"Type": "Pass", "Result": result, "End": True}}})


def _states_role(ctx) -> str:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-obs-sfn-role-")
    arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Principal": {"Service": "states.amazonaws.com"},
            "Action": "sts:AssumeRole"}]}),
        Description="sim2real obs-sfn metrics ledger", Tags=[{"Key": "sim2real", "Value": "1"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    return arn


def _create_published(ctx, sfn, name: str, role_arn: str, definition: str) -> dict:
    deadline = time.monotonic() + _budget_s(ctx, 120.0)
    last = None
    while time.monotonic() < deadline:
        try:
            return sfn.create_state_machine(
                name=name, definition=definition, roleArn=role_arn, type="STANDARD",
                publish=True, tags=[{"key": "sim2real", "value": "1"}],
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException":
                raise
            last = exc
            time.sleep(2.0)  # IAM propagation of the fresh role: no observable to poll
    if _budget_spent(ctx):
        raise TimeoutError("CreateStateMachine past the fresh role's AccessDenied: the run budget ended first; not graded")
    raise AssertionError(f"CreateStateMachine AccessDenied for up to 120s after role create: {last}")


def _latest(cw, metric: str, dims: list) -> float | None:
    now = datetime.now(timezone.utc)
    pts = cw.get_metric_statistics(
        Namespace="AWS/States", MetricName=metric, Dimensions=dims,
        StartTime=now - timedelta(minutes=15), EndTime=now + timedelta(minutes=2),
        Period=60, Statistics=["Maximum"],
    )["Datapoints"]
    if not pts:
        return None
    return max(pts, key=lambda p: p["Timestamp"])["Maximum"]


def _poll_metric(ctx, cw, metric: str, dims: list, want: float, action: str) -> None:
    """Poll ``metric[dims]`` to its latest published value until it reaches ``want``."""
    deadline = time.monotonic() + _budget_s(ctx, _UP_BUDGET_S)
    last = None
    while True:
        last = _latest(cw, metric, dims)
        if last == want:
            return
        if time.monotonic() > deadline:
            if _budget_spent(ctx):
                raise TimeoutError(
                    f"{metric} to reach {want!r} after {action}: the run budget ended first; not graded")
            raise AssertionError(
                f"{metric}{dims!r} did not reach {want!r} within {_UP_BUDGET_S:.0f}s after "
                f"{action}; last read {last!r}")
        time.sleep(_POLL_S)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
