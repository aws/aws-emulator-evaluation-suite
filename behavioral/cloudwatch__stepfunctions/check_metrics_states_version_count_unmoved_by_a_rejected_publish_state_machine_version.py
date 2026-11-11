"""metrics-states-version-count-unmoved-by-a-rejected-publish-state-machine-version."""
from __future__ import annotations

import json
import time
from datetime import datetime, timedelta, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "metrics-states-version-count-unmoved-by-a-rejected-publish-state-machine-version"
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


# timing:real-time — metric: 33 s https://docs.aws.amazon.com/step-functions/latest/dg/procedure-cw-metrics.html
@tags(
    "axis:rejection",
    "concern:data-plane",
    "concern:metrics",
    "concern:negative-classes",
    "dp:api",
    "plane:control",
    "plane:data",
    "cap:c3",
    "timing:real-time",
)
def run(ctx) -> None:
    """A PublishStateMachineVersion rejected for a stale revisionId leaves VersionCount under
    [ResourceArn] unchanged; publishing with the current revisionId then raises it by one, both
    before and after the rejection.

    Reference: https://docs.aws.amazon.com/step-functions/latest/dg/procedure-cw-metrics.html
    """
    sfn = ctx.client("stepfunctions")
    cw = ctx.client("cloudwatch")

    role_arn = _states_role(ctx)
    name = ctx.unique_name("sim2real-behav-obs-sfn-vc-reject-")
    sm_arn = _create_state_machine(ctx, sfn, name, role_arn, _definition("v0"))
    ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=sm_arn))
    res_d = [{"Name": "ResourceArn", "Value": sm_arn}]

    # A new state machine has no revisionId; only a definition-changing update populates one.
    sfn.update_state_machine(stateMachineArn=sm_arn, definition=_definition("v1"))
    stale_revision = _wait_for_revision_id(ctx, sfn, sm_arn)

    v1 = sfn.publish_state_machine_version(
        stateMachineArn=sm_arn, revisionId=stale_revision,
    )["stateMachineVersionArn"]
    ctx.on_cleanup(lambda: sfn.delete_state_machine_version(stateMachineVersionArn=v1))
    latency = _poll_metric(ctx, cw, "VersionCount", res_d, 1.0, _UP_BUDGET_S, "the first publish")

    # A concurrent update bumps the revisionId forward, so the first revision is now stale.
    sfn.update_state_machine(stateMachineArn=sm_arn, definition=_definition("v2"))
    current_revision = _wait_for_revision_id(ctx, sfn, sm_arn, differs_from=stale_revision)
    assert current_revision != stale_revision, "revisionId did not change after the second update"

    code, message = _refusal(
        lambda: sfn.publish_state_machine_version(stateMachineArn=sm_arn, revisionId=stale_revision)
    )
    assert code == "ConflictException", f"expected ConflictException, got {code!r}"
    expected_message = (
        f"Failed to publish the State Machine version for revision {stale_revision}. "
        f"The current State Machine revision is {current_revision}."
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # The effect is absent: hold VersionCount at its pre-rejection value over a window derived
    # from how long the earlier, accepted publish took to move it.
    hold_s = max(10.0, 3.0 * latency)
    hold_deadline = time.monotonic() + _budget_s(ctx, hold_s)
    while time.monotonic() < hold_deadline:
        now = _latest(cw, "VersionCount", res_d)
        assert now == 1.0, f"VersionCount moved to {now!r} after a rejected publish"
        time.sleep(_POLL_S)
    if _budget_spent(ctx):
        raise TimeoutError(
            f"VersionCount held for {hold_s:.0f}s after the rejected publish: the run budget "
            "ended first; not graded"
        )

    v2 = sfn.publish_state_machine_version(
        stateMachineArn=sm_arn, revisionId=current_revision,
    )["stateMachineVersionArn"]
    ctx.on_cleanup(lambda: sfn.delete_state_machine_version(stateMachineVersionArn=v2))
    assert v2 != v1, f"the accepted publish must mint a new version, got the same ARN {v2!r}"
    _poll_metric(ctx, cw, "VersionCount", res_d, 2.0, _UP_BUDGET_S, "the accepted publish")


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


def _create_state_machine(ctx, sfn, name: str, role_arn: str, definition: str) -> str:
    deadline = time.monotonic() + _budget_s(ctx, 120.0)
    last = None
    while time.monotonic() < deadline:
        try:
            return sfn.create_state_machine(
                name=name, definition=definition, roleArn=role_arn, type="STANDARD",
                tags=[{"key": "sim2real", "value": "1"}],
            )["stateMachineArn"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException":
                raise
            last = exc
            time.sleep(2.0)  # IAM propagation of the fresh role: no observable to poll
    if _budget_spent(ctx):
        raise TimeoutError("CreateStateMachine past the fresh role's AccessDenied: the run budget ended first; not graded")
    raise AssertionError(f"CreateStateMachine AccessDenied for up to 120s after role create: {last}")


def _wait_for_revision_id(ctx, sfn, sm_arn: str, *, differs_from=None):
    """Poll for revisionId, which DescribeStateMachine may briefly omit or report stale right
    after an UpdateStateMachine that changed the definition."""
    deadline = time.monotonic() + _budget_s(ctx, 60.0)
    last = None
    while True:
        last = sfn.describe_state_machine(stateMachineArn=sm_arn).get("revisionId")
        if last is not None and (differs_from is None or last != differs_from):
            return last
        if time.monotonic() > deadline:
            if _budget_spent(ctx):
                raise TimeoutError("revisionId to settle: the run budget ended first; not graded")
            raise AssertionError(
                f"revisionId on {sm_arn} did not settle within 60s: last saw {last!r}, "
                f"waiting to differ from {differs_from!r}")
        time.sleep(_POLL_S)


def _refusal(fn):
    """Call fn(); return the (code, message) it is refused with, raising if it succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, it succeeded with {result!r}")


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


def _poll_metric(ctx, cw, metric: str, dims: list, want: float, budget_s: float, action: str) -> float:
    """Poll ``metric[dims]`` until it reaches ``want``; returns the elapsed seconds."""
    start = time.monotonic()
    deadline = start + _budget_s(ctx, budget_s)
    last = None
    while True:
        last = _latest(cw, metric, dims)
        if last == want:
            return time.monotonic() - start
        if time.monotonic() > deadline:
            if _budget_spent(ctx):
                raise TimeoutError(
                    f"{metric} to reach {want!r} after {action}: the run budget ended first; not graded")
            raise AssertionError(
                f"{metric}{dims!r} did not reach {want!r} within {budget_s:.0f}s after "
                f"{action}; last read {last!r}")
        time.sleep(_POLL_S)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
