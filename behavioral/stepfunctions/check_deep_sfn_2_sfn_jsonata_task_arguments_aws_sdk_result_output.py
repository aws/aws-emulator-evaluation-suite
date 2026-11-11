"""deep-sfn-2-sfn-jsonata-task-arguments-aws-sdk-result-output."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deep-sfn-2-sfn-jsonata-task-arguments-aws-sdk-result-output"
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
    """A JSONata Task evaluates `{% %}` in `Arguments` before its aws-sdk call and computes `Output`
    from `$states.result`; the stored item and TaskScheduled parameters hold the evaluated values.
    """
    sfn = ctx.client("stepfunctions")
    ddb = ctx.client("dynamodb")

    table, table_arn = _create_table(ctx)
    role_arn = _create_role(ctx, [{
        "Effect": "Allow", "Action": ["dynamodb:PutItem", "dynamodb:GetItem"],
        "Resource": table_arn,
    }])

    definition = {
        "QueryLanguage": "JSONata",
        "StartAt": "Put",
        "States": {
            "Put": {
                "Type": "Task",
                "Resource": "arn:aws:states:::aws-sdk:dynamodb:putItem",
                "Arguments": {
                    "TableName": table,
                    "Item": {
                        "pk": {"S": "{% $states.input.id %}"},
                        "qty": {"N": "{% $string($states.input.qty * 3) %}"},
                        "tag": {"S": "{% $uppercase($states.input.tag) %}"},
                    },
                },
                "Output": "{% $states.input %}",
                "Next": "Get",
            },
            "Get": {
                "Type": "Task",
                "Resource": "arn:aws:states:::aws-sdk:dynamodb:getItem",
                "Arguments": {
                    "TableName": table,
                    "Key": {"pk": {"S": "{% $states.input.id %}"}},
                    "ConsistentRead": True,
                },
                "Output": {
                    "qty": "{% $number($states.result.Item.qty.N) %}",
                    "tag": "{% $states.result.Item.tag.S %}",
                    "attrs": "{% $sort($keys($states.result.Item)) %}",
                    "echo": "{% $states.input.id %}",
                },
                "End": True,
            },
        },
    }
    sm_arn = _create_state_machine(ctx, definition, role_arn)

    item_id = ctx.unique_name("item-")
    exe = _run_to_terminal(ctx, sm_arn, {"id": item_id, "qty": 7, "tag": "widget"}, timeout_s=90)
    assert exe["status"] == "SUCCEEDED", (
        f"execution {exe['status']!r}: error={exe.get('error')!r} cause={exe.get('cause')!r}"
    )
    out = json.loads(exe["output"])
    expected = {"qty": 21, "tag": "WIDGET", "attrs": ["pk", "qty", "tag"], "echo": item_id}
    assert out == expected, (
        f"the Get state's Output over $states.result was {out!r}, expected {expected!r} "
        f"(raw GetItem passthrough means Output was ignored; '{{%' strings mean Arguments were not evaluated)"
    )

    stored = ddb.get_item(TableName=table, Key={"pk": {"S": item_id}}, ConsistentRead=True).get("Item")
    assert stored == {"pk": {"S": item_id}, "qty": {"N": "21"}, "tag": {"S": "WIDGET"}}, (
        f"the item PutItem wrote, read out-of-band, is {stored!r}: the Arguments were not evaluated "
        f"before the SDK call"
    )

    scheduled = [e["taskScheduledEventDetails"] for e in _history(ctx, exe["executionArn"])
                 if e["type"] == "TaskScheduled"]
    assert [(d["resourceType"], d["resource"]) for d in scheduled] == [
        ("aws-sdk:dynamodb", "putItem"), ("aws-sdk:dynamodb", "getItem")], (
        f"TaskScheduled events name {[(d['resourceType'], d['resource']) for d in scheduled]!r}"
    )
    put_params = json.loads(scheduled[0]["parameters"])
    assert put_params == {"TableName": table, "Item": stored}, (
        f"the PutItem parameters the service recorded are {put_params!r}, expected the evaluated "
        f"item {stored!r}"
    )


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
    arn = sfn.create_state_machine(
        name=name, definition=json.dumps(definition), roleArn=role_arn, type="STANDARD",
        tags=[{"key": "sim2real", "value": CHECK}],
    )["stateMachineArn"]
    ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
    return arn


def _run_to_terminal(ctx, sm_arn, input_data, *, timeout_s, propagation_s=120.0):
    """Start an execution and poll it to terminal; restart only on the IAM-propagation race."""
    sfn = ctx.client("stepfunctions")
    desc = None
    deadline = _deadline(ctx, propagation_s)
    while True:
        exec_arn = sfn.start_execution(
            stateMachineArn=sm_arn, name=ctx.unique_name("sim2real-behav-exec-"),
            input=json.dumps(input_data),
        )["executionArn"]
        ctx.on_cleanup(lambda a=exec_arn: _best_effort_stop(ctx, a))
        desc = _wait_terminal(ctx, exec_arn, timeout_s=timeout_s)
        blob = (desc.get("cause") or "") + (desc.get("error") or "")
        if desc["status"] != "FAILED" or not any(m in blob for m in _PROPAGATION_MARKERS):
            return desc
        if time.monotonic() >= deadline:
            return desc
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
