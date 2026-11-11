"""activity-task-failure-flow."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "activity-task-failure-flow"
GROUP = 'activities'
SERVICES = ['stepfunctions']


_SFN_TRUST_POLICY = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "states.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
)


def _swallow(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _create_sfn_role(ctx):
    """An execution role this check creates for its own state machine."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-sfn-role-")
    arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=_SFN_TRUST_POLICY,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _swallow(lambda: iam.delete_role(RoleName=role_name)))
    return arn


def _create_state_machine(ctx, definition, *, name=None, sm_type="STANDARD"):
    sfn = ctx.client("stepfunctions")
    name = name or ctx.unique_name("sim2real-behav-sm-")
    role_arn = _create_sfn_role(ctx)
    # A fresh role takes a few seconds before Step Functions may assume it.
    deadline = time.monotonic() + 90.0
    while True:
        try:
            arn = sfn.create_state_machine(
                name=name,
                definition=json.dumps(definition),
                roleArn=role_arn,
                type=sm_type,
                tags=[{"key": "sim2real", "value": CHECK}],
            )["stateMachineArn"]
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException":
                raise
            if time.monotonic() > deadline:
                raise
            time.sleep(5)
    ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
    return arn


def _start_execution(ctx, sm_arn, *, input_data=None, name=None):
    sfn = ctx.client("stepfunctions")
    kwargs = {"stateMachineArn": sm_arn}
    if input_data is not None:
        kwargs["input"] = json.dumps(input_data)
    if name is not None:
        kwargs["name"] = name
    exec_arn = sfn.start_execution(**kwargs)["executionArn"]
    ctx.on_cleanup(lambda: sfn.stop_execution(executionArn=exec_arn))
    return exec_arn


def _wait_execution_complete(ctx, exec_arn, *, timeout_s=30):
    sfn = ctx.client("stepfunctions")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = sfn.describe_execution(executionArn=exec_arn)
        if last["status"] in ("SUCCEEDED", "FAILED", "TIMED_OUT", "ABORTED"):
            return last
        time.sleep(0.5)
    raise AssertionError(f"execution {exec_arn} not terminal within {timeout_s}s: {last!r}")


def _create_activity(ctx, *, name=None):
    sfn = ctx.client("stepfunctions")
    name = name or ctx.unique_name("sim2real-behav-act-")
    arn = sfn.create_activity(name=name, tags=[{"key": "sim2real", "value": CHECK}])["activityArn"]
    ctx.on_cleanup(lambda: sfn.delete_activity(activityArn=arn))
    return {"name": name, "arn": arn}


def _asl_activity_task(activity_arn, timeout_seconds=300):
    return {
        "Comment": "behavioral-activity",
        "StartAt": "T",
        "States": {
            "T": {
                "Type": "Task",
                "Resource": activity_arn,
                "TimeoutSeconds": timeout_seconds,
                "End": True,
            }
        },
    }


def _poll_activity_task(ctx, activity_arn, *, timeout_s=65):
    """GetActivityTask long-polls up to ~60s server-side; retry the call if it comes back empty."""
    client = ctx.client("stepfunctions")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = client.get_activity_task(activityArn=activity_arn)
        if last.get("taskToken"):
            return last
        time.sleep(0.5)
    raise AssertionError(f"activity task not scheduled within {timeout_s}s: {last!r}")


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """SendTaskFailure on an outstanding activity task drives the parent execution to FAILED
    with the supplied error/cause verbatim.
    """
    sfn = ctx.client("stepfunctions")
    act = _create_activity(ctx)
    sm_arn = _create_state_machine(ctx, _asl_activity_task(act["arn"]))
    exec_arn = _start_execution(ctx, sm_arn)

    task = _poll_activity_task(ctx, act["arn"])
    sfn.send_task_failure(taskToken=task["taskToken"], error="MyError", cause="my cause")

    result = _wait_execution_complete(ctx, exec_arn, timeout_s=60)
    assert result["status"] == "FAILED", f"expected FAILED, got {result['status']}"
    assert result.get("error") == "MyError", f"expected error 'MyError', got {result.get('error')!r}"
    assert result.get("cause") == "my cause", f"expected cause 'my cause', got {result.get('cause')!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
