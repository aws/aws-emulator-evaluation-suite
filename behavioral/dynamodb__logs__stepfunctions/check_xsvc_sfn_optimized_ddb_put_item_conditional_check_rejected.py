"""xsvc-sfn-optimized-ddb-put-item-conditional-check-rejected."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "xsvc-sfn-optimized-ddb-put-item-conditional-check-rejected"
GROUP = "task_integrations"
SERVICES = ["dynamodb", "logs", "stepfunctions"]


@tags("axis:rejection", "dp:api", "plane:data", "cap:c3", "concern:negative-classes",
      "concern:data-plane")
def run(ctx) -> None:
    """The optimized dynamodb:putItem integration surfaces a failed ConditionExpression as
    DynamoDB.ConditionalCheckFailedException and leaves the existing item untouched; the same
    machine running once against a fresh id succeeds, proving the integration otherwise works."""
    table = _table(ctx)
    role_arn = _role(ctx, table)
    sm_arn = _state_machine(ctx, role_arn, table)

    fresh_id = ctx.unique_name("sim2real-fresh-")
    ok_d = _run_until_role_ready(ctx, sm_arn, fresh_id)
    assert ok_d["status"] == "SUCCEEDED", (
        f"positive control: the first put of a fresh id ended {ok_d['status']!r}: {ok_d!r}")
    item = ctx.client("dynamodb").get_item(TableName=table, Key={"id": {"S": fresh_id}})["Item"]
    assert item == {"id": {"S": fresh_id}, "kind": {"S": "v1"}}, f"stored item: {item!r}"

    dupe_exec = _start(ctx, sm_arn, fresh_id)
    dupe_d = _wait_terminal(ctx, dupe_exec)
    assert dupe_d["status"] == "FAILED", f"the second put of the same id ended {dupe_d['status']!r}"
    assert dupe_d.get("error") == "DynamoDB.ConditionalCheckFailedException", (
        f"expected DynamoDB.ConditionalCheckFailedException, got {dupe_d.get('error')!r}: "
        f"{dupe_d.get('cause')!r}")
    cause = dupe_d.get("cause") or ""
    # The relayed DynamoDB text embeds a per-call request id: mask only that id.
    masked = re.sub(r"Request ID: [0-9A-Z]+;", "Request ID: <id>;", cause)
    assert masked == (
        "The conditional request failed (Service: AmazonDynamoDBv2; Status Code: 400; "
        "Error Code: ConditionalCheckFailedException; Request ID: <id>; Proxy: null)"
    ), f"the execution's cause was {cause!r}"

    item = ctx.client("dynamodb").get_item(TableName=table, Key={"id": {"S": fresh_id}})["Item"]
    assert item == {"id": {"S": fresh_id}, "kind": {"S": "v1"}}, (
        f"the rejected conditional write must leave the item unchanged: {item!r}")


_TRUST = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Principal": {"Service": "states.amazonaws.com"},
                   "Action": "sts:AssumeRole"}],
})


def _definition(table: str) -> str:
    return json.dumps({
        "StartAt": "Put",
        "States": {
            "Put": {
                "Type": "Task",
                "Resource": "arn:aws:states:::dynamodb:putItem",
                "Parameters": {
                    "TableName": table,
                    "Item": {"id": {"S.$": "$.id"}, "kind": {"S": "v1"}},
                    "ConditionExpression": "attribute_not_exists(id)",
                },
                "End": True,
            },
        },
    })


def _table(ctx) -> str:
    ddb = ctx.client("dynamodb")
    name = ctx.unique_name("sim2real-xsvc-sfn-ddbneg-")
    ddb.create_table(
        TableName=name,
        AttributeDefinitions=[{"AttributeName": "id", "AttributeType": "S"}],
        KeySchema=[{"AttributeName": "id", "KeyType": "HASH"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK[:250]}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=name))
    ddb.get_waiter("table_exists").wait(TableName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 150})
    return name


def _role(ctx, table: str) -> str:
    iam = ctx.client("iam")
    table_arn = ctx.client("dynamodb").describe_table(TableName=table)["Table"]["TableArn"]
    name = ctx.unique_name("sim2real-xsvc-sfn-ddbneg-")[:64]
    arn = iam.create_role(
        RoleName=name, AssumeRolePolicyDocument=_TRUST, Path="/sim2real/",
        Description="sim2real-xsvc: sfn optimized dynamodb conditional-check rejection",
        Tags=[{"Key": "sim2real", "Value": CHECK[:250]}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    iam.put_role_policy(
        RoleName=name, PolicyName="allow",
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "Action": "dynamodb:PutItem", "Resource": table_arn}]}),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=name, PolicyName="allow"))
    return arn


def _state_machine(ctx, role_arn: str, table: str) -> str:
    """CreateStateMachine, retrying only the AccessDeniedException raised while the new role's
    trust propagates (IAM exposes no condition to poll)."""
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name("sim2real-xsvc-sfn-ddbneg-")[:80]
    deadline = time.monotonic() + 120.0
    last = None
    while time.monotonic() < deadline:
        try:
            arn = sfn.create_state_machine(
                name=name, definition=_definition(table), roleArn=role_arn, type="STANDARD",
                tags=[{"key": "sim2real", "value": CHECK[:250]}],
            )["stateMachineArn"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException":
                raise
            last = exc
            time.sleep(5.0)
            continue
        ctx.on_cleanup(lambda a=arn: sfn.delete_state_machine(stateMachineArn=a))
        return arn
    raise AssertionError(f"CreateStateMachine still AccessDenied after 120s: {last}")


def _start(ctx, sm_arn: str, item_id: str) -> str:
    sfn = ctx.client("stepfunctions")
    arn = sfn.start_execution(stateMachineArn=sm_arn, input=json.dumps({"id": item_id}))["executionArn"]
    ctx.on_cleanup(lambda: _stop_if_running(sfn, arn))
    return arn


def _stop_if_running(sfn, arn: str) -> None:
    if sfn.describe_execution(executionArn=arn)["status"] == "RUNNING":
        sfn.stop_execution(executionArn=arn)


def _wait_terminal(ctx, arn: str) -> dict:
    sfn = ctx.client("stepfunctions")
    deadline = time.monotonic() + 120.0
    last = None
    while time.monotonic() < deadline:
        last = sfn.describe_execution(executionArn=arn)
        if last["status"] != "RUNNING":
            return last
        time.sleep(1.0)
    raise AssertionError(f"execution {arn} still RUNNING after 120s: {last!r}")


_IAM_RACE_MARKER = "is not authorized to assume the provided role"


def _run_until_role_ready(ctx, sm_arn: str, item_id: str, *, attempts: int = 8) -> dict:
    """Retry the first execution while the fresh role's trust has not yet propagated to
    states.amazonaws.com — IAM exposes no condition to poll for that."""
    desc = None
    for _ in range(attempts):
        arn = _start(ctx, sm_arn, item_id)
        desc = _wait_terminal(ctx, arn)
        if desc["status"] != "FAILED" or _IAM_RACE_MARKER not in (desc.get("cause") or ""):
            return desc
        time.sleep(5.0)
    raise AssertionError(f"the role never propagated after {attempts} attempts: {desc!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
