"""deep-sfn-2-sfn-jsonata-context-retry-count-increments-per-attempt."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deep-sfn-2-sfn-jsonata-context-retry-count-increments-per-attempt"
GROUP = 'context-object'
SERVICES = ['stepfunctions']

_MAX_ATTEMPTS = 2


@tags(
    "axis:happy-path",
    "concern:data-plane",
    "concern:representation",
    "dp:api",
    "plane:data",
    "cap:c3",
)
def run(ctx) -> None:
    """$$.State.RetryCount of a retried Parallel reads 0, 1, 2 across attempts (recorded in a
    DynamoDB side channel) while its never-retried inner Task reads 0 each time; the history
    has one ParallelStateStarted per attempt."""
    ddb = ctx.client("dynamodb")
    table, table_arn = _create_table(ctx)
    role_arn = _create_role(ctx, [{
        "Effect": "Allow", "Action": ["dynamodb:UpdateItem"], "Resource": table_arn,
    }])

    definition = {
        "StartAt": "Attempt",
        "States": {
            "Attempt": {
                "Type": "Parallel",
                "Parameters": {"run.$": "$.run", "rc.$": "$$.State.RetryCount"},
                "Branches": [{
                    "StartAt": "Log",
                    "States": {
                        # This write survives the failed attempt, so each RetryCount is kept.
                        "Log": {
                            "Type": "Task",
                            "Resource": "arn:aws:states:::dynamodb:updateItem",
                            "Parameters": {
                                "TableName": table,
                                "Key": {"pk": {"S.$": "$.run"}},
                                "UpdateExpression": (
                                    "SET outer_rc = list_append(if_not_exists(outer_rc, :empty), :o), "
                                    "inner_rc = list_append(if_not_exists(inner_rc, :empty), :i)"
                                ),
                                "ExpressionAttributeValues": {
                                    ":empty": {"L": []},
                                    ":o": {"L": [{"N.$": "States.Format('{}', $.rc)"}]},
                                    ":i": {"L": [{"N.$": "States.Format('{}', $$.State.RetryCount)"}]},
                                },
                            },
                            "ResultPath": None,
                            "Next": "Boom",
                        },
                        "Boom": {"Type": "Fail", "Error": "SimRetryProbe", "Cause": "induced"},
                    },
                }],
                "Retry": [{
                    "ErrorEquals": ["SimRetryProbe"], "IntervalSeconds": 1,
                    "MaxAttempts": _MAX_ATTEMPTS, "BackoffRate": 1.0,
                }],
                "Catch": [{"ErrorEquals": ["SimRetryProbe"], "ResultPath": "$.err", "Next": "Exhausted"}],
                "End": True,
            },
            "Exhausted": {"Type": "Pass", "End": True},
        },
    }
    sm_arn = _create_state_machine(ctx, definition, role_arn)

    exe, run_tag = _run_to_terminal(ctx, sm_arn, timeout_s=120)
    assert exe["status"] == "SUCCEEDED", (
        f"execution {exe['status']!r}: error={exe.get('error')!r} cause={exe.get('cause')!r}"
    )
    out = json.loads(exe["output"])
    assert out.get("run") == run_tag and out.get("err", {}).get("Error") == "SimRetryProbe", (
        f"the Catch did not deliver the exhausted retrier's error: {out!r}"
    )

    item = ddb.get_item(TableName=table, Key={"pk": {"S": run_tag}}, ConsistentRead=True).get("Item")
    assert item is not None, f"no side-channel row for run {run_tag!r}: the branch never wrote"
    outer = [int(v["N"]) for v in item["outer_rc"]["L"]]
    inner = [int(v["N"]) for v in item["inner_rc"]["L"]]
    assert outer == list(range(_MAX_ATTEMPTS + 1)), (
        f"$$.State.RetryCount across the Parallel's attempts was {outer!r}, expected "
        f"{list(range(_MAX_ATTEMPTS + 1))!r}"
    )
    assert inner == [0] * (_MAX_ATTEMPTS + 1), (
        f"the never-retried inner Task saw RetryCount {inner!r}; the counter is per retried state"
    )

    starts = [e for e in _history(ctx, exe["executionArn"]) if e["type"] == "ParallelStateStarted"]
    assert len(starts) == _MAX_ATTEMPTS + 1, (
        f"{len(starts)!r} ParallelStateStarted events, expected one per attempt "
        f"({_MAX_ATTEMPTS + 1!r})"
    )


# ===== helpers =====
_TERMINAL = ("SUCCEEDED", "FAILED", "TIMED_OUT", "ABORTED")
_PROPAGATION_MARKERS = ("not authorized", "AccessDenied", "cannot be assumed", "States.Permissions")


def _tags_kv():
    return [{"Key": "sim2real", "Value": CHECK}]


def _create_table(ctx):
    ddb = ctx.client("dynamodb")
    name = ctx.unique_name("sim2real-behav-sfnj-")
    arn = ddb.create_table(
        TableName=name,
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=_tags_kv(),
    )["TableDescription"]["TableArn"]
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=name))
    ddb.get_waiter("table_exists").wait(TableName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 60})
    return name, arn


def _create_role(ctx, statements):
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-sfnj-")
    trust = {"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow", "Principal": {"Service": "states.amazonaws.com"},
        "Action": "sts:AssumeRole"}]}
    arn = iam.create_role(
        RoleName=name, AssumeRolePolicyDocument=json.dumps(trust),
        Description="sim2real-behav sfn context-object execution role", Tags=_tags_kv(),
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
    arn = sfn.create_state_machine(
        name=name, definition=json.dumps(definition), roleArn=role_arn, type="STANDARD",
        tags=[{"key": "sim2real", "value": CHECK}],
    )["stateMachineArn"]
    ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
    return arn


def _run_to_terminal(ctx, sm_arn, *, timeout_s, propagation_s=120.0):
    """Start an execution under a fresh run tag and poll it to terminal.

    A fresh execution is started only for the IAM-propagation race (an AccessDenied
    UpdateItem is not the Retrier's error, so it fails the execution outright). Every attempt
    writes under its own run tag, so a discarded attempt's rows can never be counted.
    """
    sfn = ctx.client("stepfunctions")
    desc = run_tag = None
    deadline = _deadline(ctx, propagation_s)
    while True:
        run_tag = ctx.unique_name("run-")
        exec_arn = sfn.start_execution(
            stateMachineArn=sm_arn, name=ctx.unique_name("sim2real-behav-exec-"),
            input=json.dumps({"run": run_tag}),
        )["executionArn"]
        ctx.on_cleanup(lambda a=exec_arn: _best_effort_stop(ctx, a))
        desc = _wait_terminal(ctx, exec_arn, timeout_s=timeout_s)
        blob = (desc.get("cause") or "") + (desc.get("error") or "")
        if desc["status"] != "FAILED" or not any(m in blob for m in _PROPAGATION_MARKERS):
            return desc, run_tag
        if time.monotonic() >= deadline:
            return desc, run_tag
        time.sleep(2)


def _wait_terminal(ctx, exec_arn, *, timeout_s, interval_s=1.0):
    sfn = ctx.client("stepfunctions")
    deadline = _deadline(ctx, timeout_s)
    last = None
    while time.monotonic() < deadline:
        last = sfn.describe_execution(executionArn=exec_arn)
        if last["status"] in _TERMINAL:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"execution {exec_arn} was not terminal within {timeout_s}s: {last!r}")


def _deadline(ctx, timeout_s):
    """A monotonic deadline ``timeout_s`` away, capped by the check's remaining run time."""
    left = ctx.time_left()
    return time.monotonic() + (timeout_s if left is None else min(timeout_s, left))


def _best_effort_stop(ctx, exec_arn):
    try:
        ctx.client("stepfunctions").stop_execution(
            executionArn=exec_arn, error="cleanup", cause="sim2real cleanup")
    except ClientError as exc:
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
