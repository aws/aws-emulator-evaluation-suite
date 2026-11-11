"""get-metric-statistics-with-end-time-before-start-time-rejected."""
from __future__ import annotations

import datetime as dt
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-metric-statistics-with-end-time-before-start-time-rejected"
GROUP = "metric-emission"
SERVICES = ["cloudwatch", "stepfunctions"]


@tags("axis:rejection", "cap:c3", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetMetricStatistics rejects a window whose EndTime precedes StartTime for an AWS/States
    metric's StateMachineArn dimension, and the identical window with the times the right way
    round is accepted.
    """
    iam = ctx.client("iam")
    sfn = ctx.client("stepfunctions")
    cw = ctx.client("cloudwatch")

    role_arn = _create_sfn_role(ctx, iam)
    sm_arn = _create_state_machine(ctx, sfn, role_arn)
    dims = [{"Name": "StateMachineArn", "Value": sm_arn}]

    now = dt.datetime.now(dt.timezone.utc)
    earlier, later = now - dt.timedelta(minutes=10), now

    code, message = _error(
        lambda: cw.get_metric_statistics(
            Namespace="AWS/States", MetricName="ExecutionsStarted", Dimensions=dims,
            StartTime=later, EndTime=earlier, Period=60, Statistics=["Sum"],
        )
    )
    assert code == "InvalidParameterValue", (
        f"EndTime before StartTime must be rejected with Error.Code 'InvalidParameterValue'; "
        f"got {code!r}"
    )
    assert message == "The parameter StartTime must be less than the parameter EndTime.", (
        f"the rejection must carry this exact message; got {message!r}"
    )

    # Positive control: the identical call with the times the right way round is accepted, for a
    # state machine that has never executed, so it returns no datapoints.
    resp = cw.get_metric_statistics(
        Namespace="AWS/States", MetricName="ExecutionsStarted", Dimensions=dims,
        StartTime=earlier, EndTime=later, Period=60, Statistics=["Sum"],
    )
    assert resp["Datapoints"] == [], (
        f"a freshly created, never-executed state machine must carry no ExecutionsStarted "
        f"datapoints; got {resp['Datapoints']!r}"
    )


def _error(fn) -> tuple[str, str]:
    """The Error (Code, Message) ``fn`` raises. An unexpected success raises too."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err["Message"]
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


_TRUST = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Principal": {"Service": "states.amazonaws.com"},
                   "Action": "sts:AssumeRole"}],
})


def _create_sfn_role(ctx, iam) -> str:
    name = ctx.unique_name("sim2real-behav-cwsfnneg-role-")
    arn = iam.create_role(
        RoleName=name, AssumeRolePolicyDocument=_TRUST,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=name), "NoSuchEntity"))
    return arn


_SM_CREATE_TIMEOUT_S = 120


def _create_state_machine(ctx, sfn, role_arn: str) -> str:
    name = ctx.unique_name("sim2real-behav-cwsfnneg-")
    definition = json.dumps({
        "StartAt": "Mark", "States": {"Mark": {"Type": "Pass", "Result": "ok", "End": True}},
    })
    deadline = time.monotonic() + _SM_CREATE_TIMEOUT_S
    last = None
    while time.monotonic() < deadline:
        try:
            arn = sfn.create_state_machine(
                name=name, definition=definition, roleArn=role_arn, type="STANDARD",
                tags=[{"key": "sim2real", "value": CHECK}],
            )["stateMachineArn"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException":
                raise
            last = exc.response["Error"]
            time.sleep(2.0)
            continue
        ctx.on_cleanup(_teardown(lambda: sfn.delete_state_machine(stateMachineArn=arn),
                                 "StateMachineDoesNotExist"))
        return arn
    raise AssertionError(
        f"CreateStateMachine still AccessDenied {_SM_CREATE_TIMEOUT_S}s after role creation; "
        f"last error {last!r}"
    )


def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
