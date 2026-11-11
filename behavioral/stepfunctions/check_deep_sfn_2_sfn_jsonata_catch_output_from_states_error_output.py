"""deep-sfn-2-sfn-jsonata-catch-output-from-states-error-output."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deep-sfn-2-sfn-jsonata-catch-output-from-states-error-output"
GROUP = 'jsonata'
SERVICES = ['stepfunctions']


@tags(
    "axis:happy-path",
    "concern:data-plane",
    "concern:representation",
    "dp:api",
    "plane:data",
    "cap:c3",
)
def run(ctx) -> None:
    """A JSONata Catch builds its Output from `$states.errorOutput.Error` and `.Cause` of an aws-sdk
    DynamoDB GetItem failure: the exact error name, a Cause equal to the TaskFailed event's, and
    the fallback state entered once."""
    account = ctx.client("sts").get_caller_identity()["Account"]
    missing_table = ctx.unique_name("sim2real-behav-sfnj-absent-")
    role_arn = _create_role(ctx, [{
        "Effect": "Allow", "Action": ["dynamodb:GetItem"],
        "Resource": f"arn:aws:dynamodb:{ctx.region}:{account}:table/{missing_table}",
    }])

    definition = {
        "QueryLanguage": "JSONata",
        "StartAt": "Lookup",
        "States": {
            "Lookup": {
                "Type": "Task",
                "Resource": "arn:aws:states:::aws-sdk:dynamodb:getItem",
                "Arguments": {
                    "TableName": "{% $states.input.table %}",
                    "Key": {"pk": {"S": "k"}},
                },
                "Catch": [{
                    "ErrorEquals": ["DynamoDb.ResourceNotFoundException"],
                    "Output": {
                        "error": "{% $states.errorOutput.Error %}",
                        "cause": "{% $states.errorOutput.Cause %}",
                        "marker": "{% $states.input.marker %}",
                    },
                    "Next": "Handled",
                }],
                "Next": "NeverHere",
            },
            "NeverHere": {"Type": "Pass", "Output": {"wrong": True}, "End": True},
            "Handled": {
                "Type": "Pass",
                "Output": "{% $merge([$states.input, {'handled': true}]) %}",
                "End": True,
            },
        },
    }
    sm_arn = _create_state_machine(ctx, definition, role_arn)

    marker = ctx.unique_name("m-")
    exe = _run_to_terminal(ctx, sm_arn, {"table": missing_table, "marker": marker}, timeout_s=90)
    assert exe["status"] == "SUCCEEDED", (
        f"the Catch did not recover the execution: {exe['status']!r} "
        f"error={exe.get('error')!r} cause={exe.get('cause')!r}"
    )
    out = json.loads(exe["output"])
    assert set(out) == {"error", "cause", "marker", "handled"}, f"output keys {sorted(out)!r}"
    assert out["error"] == "DynamoDb.ResourceNotFoundException", (
        f"$states.errorOutput.Error in the Catch Output was {out['error']!r}"
    )
    assert out["marker"] == marker and out["handled"] is True, (
        f"$states.input inside the Catch Output, or the next state's input, was lost: {out!r}"
    )

    events = _history(ctx, exe["executionArn"])
    failed = [e["taskFailedEventDetails"] for e in events if e["type"] == "TaskFailed"]
    assert len(failed) == 1, f"expected one TaskFailed event, got {failed!r}"
    assert failed[0]["error"] == out["error"], (
        f"TaskFailed error {failed[0]['error']!r} != Catch-observed {out['error']!r}"
    )
    assert failed[0]["cause"] == out["cause"] and isinstance(out["cause"], str) and out["cause"], (
        f"$states.errorOutput.Cause {out['cause']!r} is not the TaskFailed cause {failed[0]['cause']!r}"
    )
    entered = [e["stateEnteredEventDetails"]["name"] for e in events if e["type"] == "PassStateEntered"]
    assert entered == ["Handled"], f"Pass states entered after the failure: {entered!r}"


# ===== helpers =====
_TERMINAL = ("SUCCEEDED", "FAILED", "TIMED_OUT", "ABORTED")
_PROPAGATION_MARKERS = ("not authorized", "AccessDenied", "cannot be assumed", "States.Permissions")


def _tags_kv():
    return [{"Key": "sim2real", "Value": CHECK}]


def _create_role(ctx, statements):
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-sfnj-")
    trust = {"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow", "Principal": {"Service": "states.amazonaws.com"},
        "Action": "sts:AssumeRole"}]}
    arn = iam.create_role(
        RoleName=name, AssumeRolePolicyDocument=json.dumps(trust),
        Description="sim2real-behav sfn jsonata execution role", Tags=_tags_kv(),
    )["Role"]["Arn"]

    def _delete_role():
        for pname in iam.list_role_policies(RoleName=name).get("PolicyNames", []):
            iam.delete_role_policy(RoleName=name, PolicyName=pname)
        iam.delete_role(RoleName=name)

    ctx.on_cleanup(_delete_role)
    iam.put_role_policy(
        RoleName=name, PolicyName=f"{name}-policy",
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
    )
    return arn


def _create_state_machine(ctx, definition, role_arn):
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name("sim2real-behav-sfnj-")

    def _attempt():
        try:
            return True, sfn.create_state_machine(
                name=name, definition=json.dumps(definition), roleArn=role_arn, type="STANDARD",
                tags=[{"key": "sim2real", "value": CHECK}],
            )["stateMachineArn"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException":
                raise
            return False, exc

    arn = _until_propagated(ctx, _attempt, what="CreateStateMachine with the fresh role")
    ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
    return arn


def _until_propagated(ctx, attempt, *, what, window_s=90.0):
    """Repeat attempt() every 2 s while it returns (False, last) for the IAM-propagation race."""
    deadline = time.monotonic() + window_s
    left = ctx.time_left()
    if left is not None:
        deadline = min(deadline, time.monotonic() + left)
    while True:
        done, value = attempt()
        if done:
            return value
        if time.monotonic() >= deadline:
            raise AssertionError(f"{what} still hit IAM propagation at the deadline: {value!r}")
        time.sleep(2)


def _run_to_terminal(ctx, sm_arn, input_data, *, timeout_s):
    """Start an execution and poll it to terminal; restart only on the IAM-propagation race."""
    sfn = ctx.client("stepfunctions")

    def _attempt():
        exec_arn = sfn.start_execution(
            stateMachineArn=sm_arn, name=ctx.unique_name("sim2real-behav-exec-"),
            input=json.dumps(input_data),
        )["executionArn"]
        ctx.on_cleanup(lambda a=exec_arn: _best_effort_stop(ctx, a))
        desc = _wait_terminal(ctx, exec_arn, timeout_s=timeout_s)
        blob = (desc.get("cause") or "") + (desc.get("error") or "")
        return desc["status"] != "FAILED" or not any(m in blob for m in _PROPAGATION_MARKERS), desc

    return _until_propagated(ctx, _attempt, what="the execution")


def _wait_terminal(ctx, exec_arn, *, timeout_s, interval_s=1.0):
    sfn = ctx.client("stepfunctions")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = sfn.describe_execution(executionArn=exec_arn)
        if last["status"] in _TERMINAL:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"execution {exec_arn} was not terminal within {timeout_s}s: {last!r}")


def _best_effort_stop(ctx, exec_arn):
    try:
        ctx.client("stepfunctions").stop_execution(
            executionArn=exec_arn, error="cleanup", cause="sim2real cleanup")
    except ClientError as exc:
        # StopExecution is a no-op on a terminal execution; only a vanished one is not an error.
        if exc.response["Error"]["Code"] != "ExecutionDoesNotExist":
            raise


def _history(ctx, exec_arn):
    sfn = ctx.client("stepfunctions")
    events, token = [], None
    while True:
        kwargs = {"executionArn": exec_arn, "maxResults": 1000}
        if token:
            kwargs["nextToken"] = token
        page = sfn.get_execution_history(**kwargs)
        events.extend(page["events"])
        token = page.get("nextToken")
        if not token:
            return events


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
