"""catch-matches-256-char-errorequals-against-activity-sendtaskfailure."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "catch-matches-256-char-errorequals-against-activity-sendtaskfailure"
GROUP = "activities"
SERVICES = ["stepfunctions"]

_ERROR = "E" * 256
_CAUSE = "C" * 10000


def _create_sfn_role(ctx):
    """Create an execution role Step Functions may assume, deleted at cleanup."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-sfnrole-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "states.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return arn


def _call_once_role_assumable(create, **kwargs):
    """Call ``create``, retrying while a just-created role is not yet assumable."""
    deadline = time.monotonic() + 60.0
    while True:
        try:
            return create(**kwargs)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException" or time.monotonic() > deadline:
                raise
            time.sleep(3)


def _create_activity(ctx):
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name("sim2real-behav-act-")
    arn = sfn.create_activity(name=name)["activityArn"]
    ctx.on_cleanup(lambda: sfn.delete_activity(activityArn=arn))
    return arn


def _create_state_machine(ctx, role_arn, definition):
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name("sim2real-behav-sm-")
    arn = _call_once_role_assumable(
        sfn.create_state_machine,
        name=name,
        definition=json.dumps(definition),
        roleArn=role_arn,
    )["stateMachineArn"]
    ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
    return arn


def _get_activity_task_token(ctx, activity_arn, *, timeout_s=30):
    sfn = ctx.client("stepfunctions")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        task = sfn.get_activity_task(activityArn=activity_arn)
        token = task.get("taskToken")
        if token:
            return token
        time.sleep(1.0)
    raise AssertionError(f"no activity task token arrived on {activity_arn} within {timeout_s}s")


def _wait_execution_complete(ctx, exec_arn, *, timeout_s=30):
    sfn = ctx.client("stepfunctions")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = sfn.describe_execution(executionArn=exec_arn)
        if last["status"] != "RUNNING":
            return last
        time.sleep(1.0)
    raise AssertionError(f"execution {exec_arn} not terminal within {timeout_s}s: {last!r}")


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Catch whose ErrorEquals names a 256-character string matches an activity
    SendTaskFailure carrying that exact 256-char error and a 10,000-char cause; its ResultPath
    merges both verbatim into the state's input instead of replacing that input.

    Reference: https://docs.aws.amazon.com/step-functions/latest/apireference/API_SendTaskFailure.html
    """
    role_arn = _create_sfn_role(ctx)
    activity_arn = _create_activity(ctx)

    definition = {
        "StartAt": "T",
        "States": {
            "T": {
                "Type": "Task",
                "Resource": activity_arn,
                "Catch": [{"ErrorEquals": [_ERROR], "ResultPath": "$.err", "Next": "Caught"}],
                "End": True,
            },
            "Caught": {"Type": "Pass", "End": True},
        },
    }
    sm_arn = _create_state_machine(ctx, role_arn, definition)
    sfn = ctx.client("stepfunctions")
    exec_arn = sfn.start_execution(
        stateMachineArn=sm_arn, input=json.dumps({"orig": "untouched"})
    )["executionArn"]
    ctx.on_cleanup(lambda: sfn.stop_execution(executionArn=exec_arn))

    token = _get_activity_task_token(ctx, activity_arn)
    sfn.send_task_failure(taskToken=token, error=_ERROR, cause=_CAUSE)

    result = _wait_execution_complete(ctx, exec_arn)
    assert result["status"] == "SUCCEEDED", (
        f"a Catch whose 256-char ErrorEquals matches the activity's SendTaskFailure "
        f"error must route to the handler; got status={result['status']!r} "
        f"error={result.get('error')!r} cause={result.get('cause')!r}"
    )
    output = json.loads(result["output"])
    assert output.get("orig") == "untouched", (
        f"a Catch ResultPath must merge into the state's original input, not replace "
        f"it; expected 'orig' to survive as 'untouched', got {output.get('orig')!r}"
    )
    err = output.get("err")
    assert isinstance(err, dict), (
        f"expected the error info to be merged in at ResultPath '$.err' as an object, "
        f"got {err!r}"
    )
    assert err.get("Error") == _ERROR, (
        f"expected the merged error info to carry the 256-char Error verbatim, got a "
        f"value of length {len(err.get('Error', ''))}"
    )
    assert err.get("Cause") == _CAUSE, (
        f"expected the merged error info to carry the 10,000-char Cause verbatim, got "
        f"a value of length {len(err.get('Cause', ''))}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
