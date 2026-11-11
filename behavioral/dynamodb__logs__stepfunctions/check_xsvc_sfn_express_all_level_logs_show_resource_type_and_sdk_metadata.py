"""xsvc-sfn-express-all-level-logs-show-resource-type-and-sdk-metadata."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "xsvc-sfn-express-all-level-logs-show-resource-type-and-sdk-metadata"
GROUP = "express_execution_logging"
SERVICES = ["dynamodb", "logs", "stepfunctions"]


@tags("axis:happy-path", "dp:api", "plane:data", "cap:c3", "concern:e2e", "concern:data-plane")
def run(ctx) -> None:
    """An EXPRESS run's ALL-level logs carry TaskSucceeded resource/resourceType per integration
    style; the optimized dynamodb:putItem output includes Sdk*Metadata while the aws-sdk
    integration's PutItem output is the empty response {}.
    """
    table = _table(ctx)
    role_arn = _role(ctx, table)
    group, group_arn = _log_group(ctx)
    sm_arn = _state_machine(ctx, role_arn, table, group_arn)

    _warm_up(ctx, sm_arn, group, {"id1": "warm1", "id2": "warm2"})

    id1 = ctx.unique_name("sim2real-opt-")
    id2 = ctx.unique_name("sim2real-sdk-")
    resp = ctx.client("stepfunctions").start_execution(
        stateMachineArn=sm_arn, input=json.dumps({"id1": id1, "id2": id2}))
    exec_arn = resp["executionArn"]
    assert ":express:" in exec_arn, f"an EXPRESS machine must mint an express ARN; got {exec_arn!r}"

    events = _await(ctx, group, exec_arn, "ExecutionSucceeded")
    succeeded = [e for e in events if e["type"] == "TaskSucceeded"]
    assert len(succeeded) == 2, f"expected two TaskSucceeded events, got {succeeded!r}"

    optimized = _task_entered_for(events, "Optimized")
    sdk = _task_entered_for(events, "Sdk")
    opt_succ = _succeeded_after(events, optimized)
    sdk_succ = _succeeded_after(events, sdk)

    assert opt_succ["details"].get("resource") == "putItem", (
        f"optimized TaskSucceeded.resource: {opt_succ['details']!r}")
    assert opt_succ["details"].get("resourceType") == "dynamodb", (
        f"optimized TaskSucceeded.resourceType must be the bare service name: {opt_succ['details']!r}")
    opt_out = json.loads(opt_succ["details"]["output"])
    assert "SdkHttpMetadata" in opt_out and "SdkResponseMetadata" in opt_out, (
        f"the optimized dynamodb:putItem integration's raw output carries Sdk*Metadata: {opt_out!r}")

    assert sdk_succ["details"].get("resource") == "putItem", (
        f"aws-sdk TaskSucceeded.resource: {sdk_succ['details']!r}")
    assert sdk_succ["details"].get("resourceType") == "aws-sdk:dynamodb", (
        f"aws-sdk TaskSucceeded.resourceType must be prefixed aws-sdk:<service>: {sdk_succ['details']!r}")
    sdk_out = json.loads(sdk_succ["details"]["output"])
    assert sdk_out == {}, (
        f"the aws-sdk dynamodb:putItem integration's PutItem response has no attributes or "
        f"consumed capacity requested, so its raw output is empty: {sdk_out!r}")

    got1 = ctx.client("dynamodb").get_item(TableName=table, Key={"id": {"S": id1}})["Item"]
    got2 = ctx.client("dynamodb").get_item(TableName=table, Key={"id": {"S": id2}})["Item"]
    assert got1 == {"id": {"S": id1}, "kind": {"S": "optimized"}}, f"optimized item: {got1!r}"
    assert got2 == {"id": {"S": id2}, "kind": {"S": "sdk"}}, f"sdk item: {got2!r}"


_LOG_BUDGET_S = 240.0
_POLL_S = 4.0
_VALIDATION_STREAM = "log_stream_created_by_aws_to_validate_log_delivery_subscriptions"

_TRUST = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Principal": {"Service": "states.amazonaws.com"},
                   "Action": "sts:AssumeRole"}],
})

_LOG_ACTIONS = [
    "logs:CreateLogDelivery", "logs:GetLogDelivery", "logs:UpdateLogDelivery",
    "logs:DeleteLogDelivery", "logs:ListLogDeliveries", "logs:PutResourcePolicy",
    "logs:DescribeResourcePolicies", "logs:DescribeLogGroups",
    "logs:CreateLogStream", "logs:PutLogEvents",
]


def _definition(table: str) -> str:
    """Optimized dynamodb:putItem then the generic aws-sdk:dynamodb:putItem integration."""
    return json.dumps({
        "StartAt": "Optimized",
        "States": {
            "Optimized": {
                "Type": "Task",
                "Resource": "arn:aws:states:::dynamodb:putItem",
                "Parameters": {
                    "TableName": table,
                    "Item": {"id": {"S.$": "$.id1"}, "kind": {"S": "optimized"}},
                },
                "ResultPath": "$.r1",
                "Next": "Sdk",
            },
            "Sdk": {
                "Type": "Task",
                "Resource": "arn:aws:states:::aws-sdk:dynamodb:putItem",
                "Parameters": {
                    "TableName": table,
                    "Item": {"id": {"S.$": "$.id2"}, "kind": {"S": "sdk"}},
                },
                "ResultPath": "$.r2",
                "End": True,
            },
        },
    })


def _table(ctx) -> str:
    ddb = ctx.client("dynamodb")
    name = ctx.unique_name("sim2real-xsvc-sfn-ddblog-")
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
    ddb = ctx.client("dynamodb")
    table_arn = ddb.describe_table(TableName=table)["Table"]["TableArn"]
    name = ctx.unique_name("sim2real-xsvc-sfn-ddblog-")[:64]
    arn = iam.create_role(
        RoleName=name, AssumeRolePolicyDocument=_TRUST, Path="/sim2real/",
        Description="sim2real-xsvc: sfn express dynamodb logging",
        Tags=[{"Key": "sim2real", "Value": CHECK[:250]}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    iam.put_role_policy(
        RoleName=name, PolicyName="allow",
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "Action": "dynamodb:PutItem", "Resource": table_arn},
            {"Effect": "Allow", "Action": _LOG_ACTIONS, "Resource": "*"},
        ]}),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=name, PolicyName="allow"))
    return arn


def _log_group(ctx) -> tuple[str, str]:
    logs = ctx.client("logs")
    account = ctx.client("sts").get_caller_identity()["Account"]
    name = ctx.unique_name("/aws/vendedlogs/states/sim2real-xsvc-sfn-ddblog-")
    logs.create_log_group(logGroupName=name, tags={"sim2real": CHECK[:250]})
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=name))
    return name, f"arn:aws:logs:{ctx.region}:{account}:log-group:{name}:*"


def _state_machine(ctx, role_arn: str, table: str, group_arn: str) -> str:
    """CreateStateMachine (EXPRESS), retrying only the AccessDeniedException raised while
    the new role's trust propagates — IAM exposes no condition to poll."""
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name("sim2real-xsvc-sfn-ddblog-")[:80]
    logging = {"level": "ALL", "includeExecutionData": True,
               "destinations": [{"cloudWatchLogsLogGroup": {"logGroupArn": group_arn}}]}
    deadline = time.monotonic() + 120.0
    last = None
    while time.monotonic() < deadline:
        try:
            arn = sfn.create_state_machine(
                name=name, definition=_definition(table), roleArn=role_arn, type="EXPRESS",
                loggingConfiguration=logging,
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


def _read_group(ctx, group: str) -> list[dict]:
    logs = ctx.client("logs")
    out, kwargs = [], {"logGroupName": group, "limit": 10000}
    while True:
        try:
            resp = logs.filter_log_events(**kwargs)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                return out
            raise
        for event in resp["events"]:
            if event["logStreamName"] == _VALIDATION_STREAM:
                continue
            try:
                out.append(json.loads(event["message"]))
            except ValueError:
                raise AssertionError(
                    f"non-JSON message in {group}/{event['logStreamName']}: "
                    f"{event['message'][:300]!r}") from None
        if not resp.get("nextToken"):
            return out
        kwargs["nextToken"] = resp["nextToken"]


def _of(events: list[dict], exec_arn: str) -> list[dict]:
    return sorted((e for e in events if e.get("execution_arn") == exec_arn),
                  key=lambda e: int(e["id"]))


def _task_entered_for(events: list[dict], state_name: str) -> dict:
    hits = [e for e in events if e["type"] == "TaskStateEntered"
            and e["details"].get("name") == state_name]
    assert len(hits) == 1, f"expected one TaskStateEntered for {state_name!r}: {hits!r}"
    return hits[0]


def _succeeded_after(events: list[dict], entered: dict) -> dict:
    """The TaskSucceeded immediately following entered's id, before the next TaskStateEntered."""
    after = [e for e in events if int(e["id"]) > int(entered["id"])]
    for e in after:
        if e["type"] == "TaskStateEntered":
            break
        if e["type"] == "TaskSucceeded":
            return e
    raise AssertionError(f"no TaskSucceeded found after {entered!r}")


def _await(ctx, group: str, exec_arn: str, until_type: str) -> list[dict]:
    deadline = time.monotonic() + _LOG_BUDGET_S
    events: list[dict] = []
    while time.monotonic() < deadline:
        events = _of(_read_group(ctx, group), exec_arn)
        if any(e["type"] == until_type for e in events):
            return events
        time.sleep(_POLL_S)
    raise AssertionError(
        f"{exec_arn}: {until_type} not delivered to {group} within {_LOG_BUDGET_S}s; held "
        f"{[(e.get('id'), e.get('type')) for e in events]}")


def _warm_up(ctx, sm_arn: str, group: str, payload: dict) -> None:
    """Start executions until one is fully delivered; executions started in the first seconds
    after the log delivery is created are never delivered, while later ones are."""
    sfn = ctx.client("stepfunctions")
    deadline = time.monotonic() + _LOG_BUDGET_S
    started: list[str] = []
    while time.monotonic() < deadline:
        started.append(sfn.start_execution(
            stateMachineArn=sm_arn, input=json.dumps(payload))["executionArn"])
        until = time.monotonic() + 12.0
        while time.monotonic() < until:
            events = _read_group(ctx, group)
            if any(any(e.get("execution_arn") == arn and e["type"] == "ExecutionSucceeded"
                       for e in events) for arn in started):
                return
            time.sleep(_POLL_S)
    raise AssertionError(
        f"log delivery to {group} never delivered one complete warm-up execution within "
        f"{_LOG_BUDGET_S}s across {len(started)} async executions")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
