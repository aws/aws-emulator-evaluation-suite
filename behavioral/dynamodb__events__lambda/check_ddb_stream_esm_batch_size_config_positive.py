"""ddb-stream-esm-batch-size-config-positive."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "ddb-stream-esm-batch-size-config-positive"
GROUP = "event-propagation"
SERVICES = ["dynamodb", "events", "lambda"]

_OBS_HANDLER = """
import os
import boto3

TABLE = os.environ["OBS_TABLE"]
RUN_ID = os.environ.get("RUN_ID", "run")

ddb = boto3.client("dynamodb")


def handler(event, context):
    records = event.get("Records", [])
    ddb.update_item(
        TableName=TABLE,
        Key={"pk": {"S": "batch-" + RUN_ID}},
        UpdateExpression="SET attempts = if_not_exists(attempts, :zero) + :one",
        ExpressionAttributeValues={":zero": {"N": "0"}, ":one": {"N": "1"}},
    )
    for r in records:
        keys = r.get("dynamodb", {}).get("Keys", {})
        rec_id = r.get("eventID", "")
        ddb.put_item(
            TableName=TABLE,
            Item={
                "pk": {"S": "rec-" + RUN_ID + "-" + rec_id},
                "batch_size": {"N": str(len(records))},
                "key_id": {"S": keys.get("id", {}).get("S", "")},
            },
        )
    return {"ok": True}
"""


@tags("axis:happy-path", "cap:c2", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """A DynamoDB stream event source mapping with BatchSize=3 eventually delivers every written
    record, and no Lambda invocation receives more records than the configured BatchSize."""
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
            {"Effect": "Allow", "Action": ["dynamodb:PutItem", "dynamodb:UpdateItem"], "Resource": "*"},
        ],
    )

    fn_name = ctx.unique_name("sim2real-fn-")
    _create_function(ctx, fn_name, role_arn, _OBS_HANDLER, env={"OBS_TABLE": obs_table, "RUN_ID": run_id})

    batch_size = 3
    _create_esm(
        ctx,
        fn_name,
        stream_arn,
        BatchSize=batch_size,
        MaximumBatchingWindowInSeconds=5,
        StartingPosition="TRIM_HORIZON",
    )

    ddb = ctx.client("dynamodb")
    written_ids = [f"item-{i}" for i in range(15)]
    with_requests = [
        {"PutRequest": {"Item": {"id": {"S": item_id}}}} for item_id in written_ids
    ]
    ddb.batch_write_item(RequestItems={stream_table: with_requests})

    def _observed_key_ids():
        items = _scan_obs_records(ctx, obs_table, f"rec-{run_id}-")
        return {i["key_id"]["S"] for i in items if i.get("key_id", {}).get("S")}

    observed = _poll_until(
        _observed_key_ids,
        lambda ids: set(written_ids).issubset(ids),
        timeout_s=150.0,
        interval_s=5.0,
    )
    missing = set(written_ids) - observed
    assert not missing, f"records never observed at destination: {sorted(missing)}"

    all_items = _scan_obs_records(ctx, obs_table, f"rec-{run_id}-")
    max_batch_size = max(int(i["batch_size"]["N"]) for i in all_items)
    assert max_batch_size <= batch_size, f"observed batch of {max_batch_size} > configured {batch_size}"


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


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
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=trust,
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )["Role"]["Arn"]
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
                Tags={"sim2real:managed": "true"},
            )
            break
        except ClientError as e:
            # A new IAM role is briefly not assumable by Lambda (IAM eventual consistency).
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
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
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
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=name))
    ddb.get_waiter("table_exists").wait(TableName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    return name


def _create_esm(ctx, function_name: str, stream_arn: str, **kwargs) -> str:
    lam = ctx.client("lambda")
    uuid_ = lam.create_event_source_mapping(
        FunctionName=function_name,
        EventSourceArn=stream_arn,
        Tags={"sim2real:managed": "true"},
        **kwargs,
    )["UUID"]
    ctx.on_cleanup(lambda: lam.delete_event_source_mapping(UUID=uuid_))
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        state = lam.get_event_source_mapping(UUID=uuid_)["State"]
        if state == "Enabled":
            return uuid_
        time.sleep(3)
    raise AssertionError("event source mapping never became Enabled")


def _scan_obs_records(ctx, table_name: str, prefix: str) -> list[dict[str, Any]]:
    ddb = ctx.client("dynamodb")
    items: list[dict[str, Any]] = []
    kwargs: dict[str, Any] = {
        "TableName": table_name,
        "FilterExpression": "begins_with(pk, :p)",
        "ExpressionAttributeValues": {":p": {"S": prefix}},
    }
    while True:
        resp = ddb.scan(**kwargs)
        items.extend(resp.get("Items", []))
        if "LastEvaluatedKey" not in resp:
            return items
        kwargs["ExclusiveStartKey"] = resp["LastEvaluatedKey"]


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
