"""delete-item-task-removes-the-item-and-a-failed-condition-leaves-it-untouched."""
from __future__ import annotations

import json
import re
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-item-task-removes-the-item-and-a-failed-condition-leaves-it-untouched"
GROUP = "task_integrations"
SERVICES = ["dynamodb", "stepfunctions"]


@tags("axis:rejection", "cap:c2", "cap:c3", "concern:data-plane", "concern:negative-classes",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """A dynamodb:deleteItem task removes the item it targets, while a sibling task whose
    ConditionExpression fails is caught as DynamoDB.ConditionalCheckFailedException and leaves
    its item untouched.
    """
    ddb = ctx.client("dynamodb")
    sfn = ctx.client("stepfunctions")

    table = _create_table(ctx)
    pk1 = f"victim-{uuid.uuid4().hex[:8]}"
    pk2 = f"survivor-{uuid.uuid4().hex[:8]}"
    ddb.put_item(TableName=table["name"], Item={"pk": {"S": pk1}, "count": {"N": "5"}})
    ddb.put_item(TableName=table["name"], Item={"pk": {"S": pk2}, "count": {"N": "5"}})

    role_arn = _create_sfn_role(ctx, table["arn"])
    sm_arn = _create_state_machine(ctx, table["name"], role_arn)

    exec_arn, desc = _run_to_terminal(ctx, sm_arn, {"pk1": pk1, "pk2": pk2})
    assert desc["status"] == "SUCCEEDED", (
        f"execution ended {desc['status']!r}: {desc.get('error')!r} {desc.get('cause')!r}"
    )

    history = _history(ctx, exec_arn)
    failed = [e["taskFailedEventDetails"] for e in history if e["type"] == "TaskFailed"]
    assert len(failed) == 1, f"expected exactly one TaskFailed event, got {failed!r}"
    assert failed[0]["error"] == "DynamoDB.ConditionalCheckFailedException", (
        f"the conditional delete's caught error was {failed[0]['error']!r}, expected "
        "'DynamoDB.ConditionalCheckFailedException'"
    )
    # AWS relays DynamoDB's error text, which embeds a per-call request id: mask only that id.
    masked = re.sub(r"Request ID: [0-9A-Z]+;", "Request ID: <id>;", failed[0]["cause"])
    assert masked == (
        "The conditional request failed (Service: AmazonDynamoDBv2; Status Code: 400; "
        "Error Code: ConditionalCheckFailedException; Request ID: <id>; Proxy: null)"
    ), f"the caught cause was {failed[0]['cause']!r}"

    # Positive control: the unconditional delete actually removed its item.
    gone = ddb.get_item(TableName=table["name"], Key={"pk": {"S": pk1}}, ConsistentRead=True)
    assert "Item" not in gone, f"pk {pk1!r} should be gone, GetItem returned {gone.get('Item')!r}"

    # Negative: the item behind the failed conditional delete is untouched.
    still_there = ddb.get_item(
        TableName=table["name"], Key={"pk": {"S": pk2}}, ConsistentRead=True
    )
    assert still_there.get("Item") == {"pk": {"S": pk2}, "count": {"N": "5"}}, (
        f"pk {pk2!r} must survive the failed conditional delete, got {still_there.get('Item')!r}"
    )


# ===== helpers =====

def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _create_table(ctx) -> dict:
    ddb = ctx.client("dynamodb")
    name = ctx.unique_name("sim2real-behav-tbl-")
    ddb.create_table(
        TableName=name,
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK[:200]}],
    )
    ctx.on_cleanup(_teardown(lambda: ddb.delete_table(TableName=name), "ResourceNotFoundException"))
    ddb.get_waiter("table_exists").wait(
        TableName=name, WaiterConfig={"Delay": 1, "MaxAttempts": 60}
    )
    arn = ddb.describe_table(TableName=name)["Table"]["TableArn"]
    return {"name": name, "arn": arn}


def _create_role(ctx, trust_service, statements):
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-role-")
    arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Principal": {"Service": trust_service},
                           "Action": "sts:AssumeRole"}],
        }),
        Tags=[{"Key": "sim2real", "Value": CHECK[:200]}],
    )["Role"]["Arn"]
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=name), "NoSuchEntity"))
    iam.put_role_policy(
        RoleName=name, PolicyName="inline",
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
    )
    ctx.on_cleanup(_teardown(
        lambda: iam.delete_role_policy(RoleName=name, PolicyName="inline"), "NoSuchEntity"))
    return arn


def _create_sfn_role(ctx, table_arn):
    return _create_role(ctx, "states.amazonaws.com", [
        {"Effect": "Allow", "Action": "dynamodb:DeleteItem", "Resource": table_arn},
    ])


def _create_state_machine(ctx, table_name, role_arn):
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name("sim2real-behav-sm-")
    definition = {
        "Comment": "sim2real: an unconditional deleteItem, then one whose condition fails",
        "StartAt": "DeleteUnconditional",
        "States": {
            "DeleteUnconditional": {
                "Type": "Task",
                "Resource": "arn:aws:states:::dynamodb:deleteItem",
                "Parameters": {
                    "TableName": table_name,
                    "Key": {"pk": {"S.$": "$.pk1"}},
                },
                "ResultPath": "$.unconditional",
                "Next": "DeleteConditional",
            },
            "DeleteConditional": {
                "Type": "Task",
                "Resource": "arn:aws:states:::dynamodb:deleteItem",
                "Parameters": {
                    "TableName": table_name,
                    "Key": {"pk": {"S.$": "$.pk2"}},
                    "ConditionExpression": "#c = :wrong",
                    "ExpressionAttributeNames": {"#c": "count"},
                    "ExpressionAttributeValues": {":wrong": {"N": "999"}},
                },
                "ResultPath": "$.conditional",
                "Catch": [{
                    "ErrorEquals": ["DynamoDB.ConditionalCheckFailedException"],
                    "ResultPath": "$.conditionalError",
                    "Next": "ConditionFailedHandled",
                }],
                "End": True,
            },
            "ConditionFailedHandled": {"Type": "Succeed"},
        },
    }
    deadline = time.monotonic() + 90.0
    last = None
    while time.monotonic() < deadline:
        try:
            arn = sfn.create_state_machine(
                name=name, definition=json.dumps(definition), roleArn=role_arn,
                type="STANDARD", tags=[{"key": "sim2real", "value": CHECK[:200]}],
            )["stateMachineArn"]
            ctx.on_cleanup(_teardown(
                lambda: sfn.delete_state_machine(stateMachineArn=arn), "StateMachineDoesNotExist"))
            return arn
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException":
                raise
            last = exc
            time.sleep(3)
    raise AssertionError(f"CreateStateMachine never stopped denying the fresh role: {last!r}")


_PROPAGATION_MARKERS = (
    "not authorized to assume",
    "cannot be assumed",
    "UnrecognizedClientException",
    "InvalidClientTokenId",
    "security token included in the request is invalid",
    "is not authorized to perform: dynamodb:DeleteItem",
)


def _start(ctx, sm_arn, payload):
    sfn = ctx.client("stepfunctions")
    arn = sfn.start_execution(
        stateMachineArn=sm_arn, name=ctx.unique_name("sim2real-behav-exec-"),
        input=json.dumps(payload),
    )["executionArn"]
    ctx.on_cleanup(lambda: _best_effort_stop(ctx, arn))
    return arn


def _best_effort_stop(ctx, exec_arn):
    sfn = ctx.client("stepfunctions")
    try:
        sfn.stop_execution(executionArn=exec_arn, error="sim2real-cleanup", cause="cleanup")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ExecutionDoesNotExist":
            raise


def _wait_terminal(ctx, exec_arn, *, timeout_s=60.0, interval_s=1.0):
    sfn = ctx.client("stepfunctions")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = sfn.describe_execution(executionArn=exec_arn)
        if last["status"] in ("SUCCEEDED", "FAILED", "TIMED_OUT", "ABORTED"):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"execution {exec_arn} was not terminal within {timeout_s}s: {last!r}")


def _run_to_terminal(ctx, sm_arn, payload, *, propagation_s=90.0):
    retry_until = time.monotonic() + propagation_s
    while True:
        exec_arn = _start(ctx, sm_arn, payload)
        desc = _wait_terminal(ctx, exec_arn)
        blob = (desc.get("cause") or "") + (desc.get("error") or "")
        if desc["status"] != "FAILED" or not any(m in blob for m in _PROPAGATION_MARKERS):
            return exec_arn, desc
        if time.monotonic() >= retry_until:
            return exec_arn, desc
        time.sleep(3)


def _history(ctx, exec_arn):
    sfn = ctx.client("stepfunctions")
    out, token = [], None
    while True:
        kwargs = {"executionArn": exec_arn, "maxResults": 200}
        if token:
            kwargs["nextToken"] = token
        resp = sfn.get_execution_history(**kwargs)
        out.extend(resp["events"])
        token = resp.get("nextToken")
        if not token:
            return out


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
