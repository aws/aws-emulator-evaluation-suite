"""deep-sfn-language-retry-first-matching-retrier-and-catch-order."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deep-sfn-language-retry-first-matching-retrier-and-catch-order"
GROUP = 'error_handling'
SERVICES = ['stepfunctions']


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Retry uses only the first matching retrier (1 + MaxAttempts runs, counted by a DynamoDB
    tally) and Catch routes to the first matching catcher, with States.ALL listed last.
    """
    table, table_arn = _create_tally_table(ctx)
    role = _create_sfn_role(ctx, [{"Effect": "Allow", "Action": ["dynamodb:UpdateItem"],
                                   "Resource": table_arn}])
    _wait_role_can_write(ctx, table, role)
    definition = {
        "StartAt": "Attempt",
        "States": {
            "Attempt": {
                "Type": "Parallel",
                "Branches": [{"StartAt": "Tally", "States": {
                    "Tally": _tally_task(table, "Boom"),
                    "Boom": {"Type": "Fail", "ErrorPath": "$.raise", "Cause": "sim2real"},
                }}],
                "Retry": [
                    {"ErrorEquals": ["Other.Err"], "IntervalSeconds": 1, "MaxAttempts": 4,
                     "BackoffRate": 1.0},
                    {"ErrorEquals": ["Tally.Boom"], "IntervalSeconds": 1, "MaxAttempts": 2,
                     "BackoffRate": 2.0},
                    {"ErrorEquals": ["States.ALL"], "IntervalSeconds": 1, "MaxAttempts": 5,
                     "BackoffRate": 1.0},
                ],
                "Catch": [
                    {"ErrorEquals": ["Other.Err"], "ResultPath": "$.err", "Next": "CatchOther"},
                    {"ErrorEquals": ["Tally.Boom", "Another.Err"], "ResultPath": "$.err",
                     "Next": "CatchBoom"},
                    {"ErrorEquals": ["States.ALL"], "ResultPath": "$.err", "Next": "CatchAll"},
                ],
                "Next": "NeverReached",
            },
            "CatchOther": {"Type": "Pass", "End": True},
            "CatchBoom": {"Type": "Pass", "End": True},
            "CatchAll": {"Type": "Pass", "End": True},
            "NeverReached": {"Type": "Pass", "End": True},
        },
    }
    sm_arn = _create_state_machine(ctx, definition, role)

    for raised, want_tally, want_catcher in (("Tally.Boom", 3, "CatchBoom"),
                                             ("Other.Err", 5, "CatchOther")):
        pk = ctx.unique_name("tally-")
        desc = _run_execution(ctx, sm_arn, {"pk": pk, "raise": raised}, timeout_s=240.0)
        assert desc["status"] == "SUCCEEDED", (
            f"[{raised}] the catcher must recover the execution, got {desc['status']!r} "
            f"error={desc.get('error')!r} cause={desc.get('cause')!r}"
        )
        attempts = _tally(ctx, table, pk)
        assert attempts == want_tally, (
            f"[{raised}] the branch ran {attempts} times; the first matching retrier allows "
            f"exactly {want_tally} (1 + MaxAttempts) and later matching retriers must not add more"
        )
        out = json.loads(desc["output"])
        assert out.get("err", {}).get("Error") == raised and out.get("pk") == pk, (
            f"[{raised}] Catch ResultPath '$.err' must graft the error beside the input, got {out!r}"
        )
        entered = _entered(_history(ctx, desc["executionArn"]))
        others = {"CatchOther", "CatchBoom", "CatchAll", "NeverReached"} - {want_catcher}
        assert want_catcher in entered and not (others & set(entered)), (
            f"[{raised}] the FIRST matching catcher {want_catcher!r} must be the only one "
            f"entered; entered={entered!r}"
        )


_TERMINAL = ("SUCCEEDED", "FAILED", "TIMED_OUT", "ABORTED")


def _create_sfn_role(ctx, statements=None):
    """An execution role this check owns. Pass/Choice/Wait/Fail machines need no permissions,
    but CreateStateMachine still requires a role Step Functions can assume."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-sfnlang-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "states.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Description="sim2real-behav sfn language check role",
        Tags=[{"Key": "sim2real", "Value": "sfn-language"}],
    )["Role"]["Arn"]

    def _delete_role():
        for pname in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            iam.delete_role_policy(RoleName=role_name, PolicyName=pname)
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_delete_role)
    if statements:
        iam.put_role_policy(
            RoleName=role_name,
            PolicyName=f"{role_name}-policy",
            PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
        )
    return role_arn


def _create_state_machine(ctx, definition, role_arn):
    """Create a STANDARD machine, absorbing IAM trust propagation with a bounded retry."""
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name("sim2real-behav-sfnlang-sm-")
    deadline = time.monotonic() + 90.0
    last = None
    while time.monotonic() < deadline:
        try:
            arn = sfn.create_state_machine(
                name=name,
                definition=json.dumps(definition),
                roleArn=role_arn,
                type="STANDARD",
                tags=[{"key": "sim2real", "value": "sfn-language"}],
            )["stateMachineArn"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException":
                raise
            last = exc
            time.sleep(3)
            continue
        ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
        return arn
    raise AssertionError(f"CreateStateMachine kept refusing the freshly created role: {last!r}")


def _stop_if_running(sfn, exec_arn):
    if sfn.describe_execution(executionArn=exec_arn)["status"] == "RUNNING":
        sfn.stop_execution(executionArn=exec_arn, error="sim2real.cleanup")


def _run_execution(ctx, sm_arn, payload, *, timeout_s=150.0):
    """Start one execution and poll DescribeExecution until it is terminal."""
    sfn = ctx.client("stepfunctions")
    exec_arn = sfn.start_execution(
        stateMachineArn=sm_arn, name=ctx.unique_name("sim2real-x-"), input=json.dumps(payload)
    )["executionArn"]
    ctx.on_cleanup(lambda: _stop_if_running(sfn, exec_arn))
    deadline = time.monotonic() + timeout_s
    desc = None
    while time.monotonic() < deadline:
        desc = sfn.describe_execution(executionArn=exec_arn)
        if desc["status"] in _TERMINAL:
            return desc
        time.sleep(1)
    raise AssertionError(f"execution {exec_arn} not terminal within {timeout_s}s: {desc!r}")


def _history(ctx, exec_arn):
    sfn = ctx.client("stepfunctions")
    events = []
    for page in sfn.get_paginator("get_execution_history").paginate(executionArn=exec_arn):
        events.extend(page["events"])
    return events


def _entered(events):
    """Names of every state entered, in history order."""
    return [e["stateEnteredEventDetails"]["name"] for e in events
            if e["type"].endswith("StateEntered")]


def _exited(events):
    return [e["stateExitedEventDetails"]["name"] for e in events
            if e["type"].endswith("StateExited")]


def _create_tally_table(ctx):
    """A pay-per-request table this check owns; each attempt ADDs 1 to an item's counter."""
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-sfntally-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": "sfn-language"}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 60})
    account = ctx.client("sts").get_caller_identity()["Account"]
    return table, f"arn:aws:dynamodb:{ctx.region}:{account}:table/{table}"


def _tally_task(table, next_state):
    return {
        "Type": "Task",
        "Resource": "arn:aws:states:::dynamodb:updateItem",
        "Parameters": {
            "TableName": table,
            "Key": {"pk": {"S.$": "$.pk"}},
            "UpdateExpression": "ADD n :one",
            "ExpressionAttributeValues": {":one": {"N": "1"}},
        },
        "ResultPath": None,
        "Next": next_state,
    }


def _tally(ctx, table, pk):
    item = ctx.client("dynamodb").get_item(
        TableName=table, Key={"pk": {"S": pk}}, ConsistentRead=True
    ).get("Item")
    return int(item["n"]["N"]) if item else 0


def _wait_role_can_write(ctx, table, role_arn):
    """Run the same updateItem in a warm-up machine until two executions in a row succeed.

    The machine under test retries on States.ALL, so an unpropagated grant would inflate the tally.
    """
    sm_arn = _create_state_machine(ctx, {
        "StartAt": "Tally",
        "States": {"Tally": dict(_tally_task(table, "Done")), "Done": {"Type": "Succeed"}},
    }, role_arn)
    streak, attempts, last = 0, 0, None
    while streak < 2 and attempts < 20:
        attempts += 1
        last = _run_execution(ctx, sm_arn, {"pk": ctx.unique_name("warmup-")}, timeout_s=60.0)
        streak = streak + 1 if last["status"] == "SUCCEEDED" else 0
        if streak == 0:
            time.sleep(3)
    assert streak >= 2, (
        f"the execution role never became able to UpdateItem on {table!r} after {attempts} "
        f"warm-up executions; last={last.get('error')!r} {last.get('cause')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
