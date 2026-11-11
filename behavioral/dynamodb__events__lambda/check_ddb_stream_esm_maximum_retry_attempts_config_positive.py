"""ddb-stream-esm-maximum-retry-attempts-config-positive."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "ddb-stream-esm-maximum-retry-attempts-config-positive"
GROUP = "event-propagation"
SERVICES = ["dynamodb", "events", "lambda"]

_FAILING_HANDLER = """
import os
import boto3

TABLE = os.environ["OBS_TABLE"]
RUN_ID = os.environ.get("RUN_ID", "run")

ddb = boto3.client("dynamodb")


def handler(event, context):
    ddb.update_item(
        TableName=TABLE,
        Key={"pk": {"S": "batch-" + RUN_ID}},
        UpdateExpression="SET attempts = if_not_exists(attempts, :zero) + :one",
        ExpressionAttributeValues={":zero": {"N": "0"}, ":one": {"N": "1"}},
    )
    raise RuntimeError("intentional failure for retry-behavior test")
"""


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """With MaximumRetryAttempts=1 a stream mapping invokes an always-failing single-record batch exactly twice
    (the first attempt plus one retry) and then stops.
    """
    run_id = ctx.unique_name("run")
    obs_table = _create_obs_table(ctx)
    stream_table, stream_arn = _create_stream_table(ctx)

    role_arn = _create_lambda_role(
        ctx,
        [
            {
                "Effect": "Allow",
                "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
                "Resource": "*",
            },
            {
                "Effect": "Allow",
                "Action": [
                    "dynamodb:GetRecords",
                    "dynamodb:GetShardIterator",
                    "dynamodb:DescribeStream",
                    "dynamodb:ListStreams",
                ],
                "Resource": "*",
            },
            {"Effect": "Allow", "Action": "dynamodb:UpdateItem", "Resource": "*"},
        ],
    )
    fn_name = ctx.unique_name("sim2real-fn-")
    _create_function(
        ctx, fn_name, role_arn, _FAILING_HANDLER, env={"OBS_TABLE": obs_table, "RUN_ID": run_id}
    )

    _create_esm(
        ctx,
        fn_name,
        stream_arn,
        BatchSize=1,
        StartingPosition="TRIM_HORIZON",
        MaximumRetryAttempts=1,
        MaximumBatchingWindowInSeconds=0,
    )

    ddb = ctx.client("dynamodb")
    ddb.put_item(TableName=stream_table, Item={"id": {"S": "retry-target"}})

    final_value = _poll_stable(lambda: _get_attempts(ctx, obs_table, run_id), timeout_s=240.0, interval_s=6.0)
    assert final_value == 2, f"expected exactly 2 invocation attempts (1 retry), observed {final_value}"


def _poll_stable(probe, stable_reads: int = 3, interval_s: float = 6.0, timeout_s: float = 240.0):
    deadline = time.monotonic() + timeout_s
    history: list[int] = []
    while time.monotonic() < deadline:
        history.append(probe())
        if len(history) >= stable_reads and len(set(history[-stable_reads:])) == 1 and history[-1] > 0:
            return history[-1]
        time.sleep(interval_s)
    raise AssertionError(f"attempt count never stabilized; history={history}")


def _get_attempts(ctx, table_name: str, run_id: str) -> int:
    ddb = ctx.client("dynamodb")
    resp = ddb.get_item(TableName=table_name, Key={"pk": {"S": f"batch-{run_id}"}})
    item = resp.get("Item")
    if not item:
        return 0
    return int(item["attempts"]["N"])


def _make_zip(code: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", code)
    return buf.getvalue()


def _create_lambda_role(ctx, statements: list[dict[str, Any]], suffix: str = "role") -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name(f"sim2real-{suffix}-")
    trust = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
            ],
        }
    )
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=trust)["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="inline",
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="inline"))
    return role_arn


def _create_function(ctx, name: str, role_arn: str, code: str, env=None, timeout=30) -> str:
    lam = ctx.client("lambda")
    zip_bytes = _make_zip(code)
    deadline = time.monotonic() + 90
    resp = None
    while True:
        try:
            ctx.on_cleanup(lambda _n=name: _delete_lambda_log_group(ctx, _n))
            resp = lam.create_function(
                FunctionName=name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="index.handler",
                Code={"ZipFile": zip_bytes},
                Timeout=timeout,
                Environment={"Variables": env or {}},
                Publish=True,
            )
            break
        except ClientError as e:
            if e.response["Error"]["Code"] == "InvalidParameterValueException" and time.monotonic() < deadline:
                time.sleep(3)
                continue
            raise
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
    lam.get_waiter("function_active_v2").wait(FunctionName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 150})
    return resp["FunctionArn"]


def _create_stream_table(ctx) -> tuple[str, str]:
    ddb = ctx.client("dynamodb")
    name = ctx.unique_name("sim2real-ddbtbl-")
    ddb.create_table(
        TableName=name,
        AttributeDefinitions=[{"AttributeName": "id", "AttributeType": "S"}],
        KeySchema=[{"AttributeName": "id", "KeyType": "HASH"}],
        BillingMode="PAY_PER_REQUEST",
        StreamSpecification={"StreamEnabled": True, "StreamViewType": "NEW_AND_OLD_IMAGES"},
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=name))
    ddb.get_waiter("table_exists").wait(TableName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    stream_arn = ddb.describe_table(TableName=name)["Table"]["LatestStreamArn"]
    return name, stream_arn


def _create_obs_table(ctx) -> str:
    ddb = ctx.client("dynamodb")
    name = ctx.unique_name("sim2real-obs-")
    ddb.create_table(
        TableName=name,
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        BillingMode="PAY_PER_REQUEST",
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=name))
    ddb.get_waiter("table_exists").wait(TableName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    return name


def _create_esm(ctx, function_name: str, stream_arn: str, **kwargs) -> str:
    lam = ctx.client("lambda")
    uuid_ = lam.create_event_source_mapping(FunctionName=function_name, EventSourceArn=stream_arn, **kwargs)[
        "UUID"
    ]
    ctx.on_cleanup(lambda: lam.delete_event_source_mapping(UUID=uuid_))
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        state = lam.get_event_source_mapping(UUID=uuid_)["State"]
        if state == "Enabled":
            return uuid_
        time.sleep(3)
    raise AssertionError("event source mapping never became Enabled")


def _delete_lambda_log_group(ctx, function_name: str) -> None:
    """Delete the log group Lambda creates on a function's first log line; one never created is fine."""
    try:
        ctx.client("logs").delete_log_group(logGroupName=f"/aws/lambda/{function_name}")
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
