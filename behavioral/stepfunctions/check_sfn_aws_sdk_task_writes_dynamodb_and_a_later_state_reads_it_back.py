"""sfn-aws-sdk-task-writes-dynamodb-and-a-later-state-reads-it-back."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sfn-aws-sdk-task-writes-dynamodb-and-a-later-state-reads-it-back"
GROUP = 'task_integrations'
SERVICES = ['stepfunctions']


@tags("axis:happy-path", "concern:data-plane", "concern:e2e", "dp:api", "plane:data", "cap:c3")
def run(ctx) -> None:
    """One execution writes a DynamoDB item through an aws-sdk task and a later state reads it
    back consistently, so the item's own values arrive in the execution output.
    """
    sfn = ctx.client("stepfunctions")
    ddb = ctx.client("dynamodb")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    table = ctx.unique_name("sim2real-behav-sfnddb-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter("table_exists").wait(
        TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 40}
    )

    table_arn = f"arn:aws:dynamodb:{ctx.region}:{account_id}:table/{table}"
    _role_name, role_arn = _create_sfn_role(ctx, [{
        "Effect": "Allow",
        "Action": ["dynamodb:PutItem", "dynamodb:GetItem"],
        "Resource": table_arn,
    }])

    definition = {
        "Comment": "write then consistently read the same item back in one execution",
        "StartAt": "Put",
        "States": {
            "Put": {
                "Type": "Task",
                "Resource": "arn:aws:states:::aws-sdk:dynamodb:putItem",
                "Parameters": {
                    "TableName": table,
                    "Item": {"pk": {"S.$": "$.key"}, "payload": {"S.$": "$.payload"}},
                    "ReturnConsumedCapacity": "TOTAL",
                },
                "ResultPath": "$.put",
                "Next": "Read",
            },
            "Read": {
                "Type": "Task",
                "Resource": "arn:aws:states:::aws-sdk:dynamodb:getItem",
                "Parameters": {
                    "TableName": table,
                    "Key": {"pk": {"S.$": "$.key"}},
                    "ConsistentRead": True,
                },
                "ResultPath": "$.read",
                "End": True,
            },
        },
    }
    sm_arn = _create_state_machine(ctx, definition, role_arn)

    key = ctx.unique_name("sim2real-pk-")
    payload = ctx.unique_name("sim2real-payload-")
    exe = _run_to_terminal(ctx, sm_arn, {"key": key, "payload": payload}, timeout_s=180.0)
    assert exe["status"] == "SUCCEEDED", (
        f'execution was {exe["status"]!r}: {exe.get("error")!r} {exe.get("cause")!r}'
    )

    output = json.loads(exe["output"])
    assert output["read"]["Item"]["payload"]["S"] == payload, (
        f"the read-back item's payload was "
        f'{output["read"]["Item"].get("payload")!r}, expected {payload!r}. '
        f"full output was {output!r}"
    )
    assert output["read"]["Item"]["pk"]["S"] == key, (
        f'the read-back key was {output["read"]["Item"]["pk"]!r}, expected {key!r} — the key '
        f"the first state was given in the execution input"
    )
    # The write really consumed capacity against THIS table, which is what proves the SDK task
    # called DynamoDB rather than returning a shape.
    assert output["put"]["ConsumedCapacity"]["TableName"] == table, (
        f'the putItem task reported capacity against {output["put"]["ConsumedCapacity"]!r}, '
        f"expected table {table!r}"
    )
    assert output["put"]["ConsumedCapacity"]["CapacityUnits"] >= 1, (
        f'the putItem task consumed {output["put"]["ConsumedCapacity"]["CapacityUnits"]!r} '
        f"capacity units, so no write reached DynamoDB"
    )

    direct = ddb.get_item(TableName=table, Key={"pk": {"S": key}}, ConsistentRead=True)
    assert direct.get("Item", {}).get("payload", {}).get("S") == payload, (
        f'a direct GetItem returned {direct.get("Item")!r}, expected payload {payload!r} — the '
        f"execution output claimed a write that is not in the table"
    )

    task_states = [
        e["stateEnteredEventDetails"]["name"]
        for e in _full_history(ctx, exe["executionArn"])
        if e["type"] == "TaskStateEntered"
    ]
    assert task_states == ["Put", "Read"], (
        f"the task states were entered as {task_states!r}, expected ['Put', 'Read'] — the read "
        f"must follow the write for the round trip to mean anything"
    )


def _create_sfn_role(ctx, statements):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-sfnrole-")
    trust = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "states.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    })
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=trust,
        Description="sim2real-behav sfn execution role",
    )["Role"]["Arn"]
    policy_name = f"{role_name}-policy"

    def _delete_role():
        for pname in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            try:
                iam.delete_role_policy(RoleName=role_name, PolicyName=pname)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NoSuchEntity":
                    raise
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_delete_role)
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
    )
    # IAM propagation exposes no condition to poll; the bounded retries in _create_state_machine
    # and _run_to_terminal absorb it.
    return role_name, role_arn


def _create_state_machine(ctx, definition, role_arn, *, sm_type="STANDARD",
                          name_prefix="sim2real-behav-sm-"):
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name(name_prefix)
    deadline = time.monotonic() + 90.0
    last = None
    while time.monotonic() < deadline:
        try:
            arn = sfn.create_state_machine(
                name=name, definition=json.dumps(definition), roleArn=role_arn, type=sm_type
            )["stateMachineArn"]
            ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
            return arn
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException":
                raise
            last = exc
            time.sleep(3)
    raise AssertionError(f"CreateStateMachine never stopped denying the role: {last!r}")


_TRUST_RACE_MARKERS = (
    "not authorized to assume",
    "cannot be assumed",
    "is not authorized to perform: sts:AssumeRole",
    "States.Permissions",
    "AccessDeniedException",
)


def _run_to_terminal(ctx, sm_arn, input_payload, *, timeout_s=120.0, max_attempts=6):
    """Start an execution and poll to terminal, retrying with a fresh execution (bounded) while
    the role's just-attached DynamoDB grant has not yet propagated."""
    sfn = ctx.client("stepfunctions")
    desc = None
    for _ in range(max_attempts):
        exec_arn = sfn.start_execution(
            stateMachineArn=sm_arn,
            name=ctx.unique_name("sim2real-behav-exec-"),
            input=json.dumps(input_payload),
        )["executionArn"]
        ctx.on_cleanup(lambda a=exec_arn: _best_effort_stop(ctx, a))
        desc = _wait_terminal(ctx, exec_arn, timeout_s=timeout_s)
        blob = (desc.get("cause") or "") + (desc.get("error") or "")
        if desc["status"] != "FAILED" or not any(m in blob for m in _TRUST_RACE_MARKERS):
            return desc
        time.sleep(5)
    return desc


def _wait_terminal(ctx, exec_arn, *, timeout_s=120.0, interval_s=1.5):
    sfn = ctx.client("stepfunctions")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = sfn.describe_execution(executionArn=exec_arn)
        if last["status"] in ("SUCCEEDED", "FAILED", "TIMED_OUT", "ABORTED"):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"execution {exec_arn} was not terminal within {timeout_s}s: {last!r}")


def _best_effort_stop(ctx, exec_arn):
    sfn = ctx.client("stepfunctions")
    try:
        sfn.stop_execution(executionArn=exec_arn, error="cleanup", cause="sim2real cleanup")
    except ClientError as exc:
        # StopExecution is a no-op on a terminal execution; only a vanished one is not an error.
        if exc.response["Error"]["Code"] != "ExecutionDoesNotExist":
            raise


def _full_history(ctx, exec_arn):
    sfn = ctx.client("stepfunctions")
    events, token = [], None
    while True:
        kwargs = {"executionArn": exec_arn, "maxResults": 100}
        if token:
            kwargs["nextToken"] = token
        resp = sfn.get_execution_history(**kwargs)
        events.extend(resp["events"])
        token = resp.get("nextToken")
        if not token:
            return events


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
