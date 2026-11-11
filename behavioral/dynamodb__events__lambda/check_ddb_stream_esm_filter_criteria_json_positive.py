"""ddb-stream-esm-filter-criteria-json-positive."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "ddb-stream-esm-filter-criteria-json-positive"
GROUP = "data-format"
SERVICES = ["dynamodb", "events", "lambda"]

_MANAGED_TAG_KEY = "sim2real:managed"


def _managed_tags_kv() -> list[dict[str, str]]:
    return [{"Key": _MANAGED_TAG_KEY, "Value": "true"}]


def _managed_tags_dict() -> dict[str, str]:
    return {_MANAGED_TAG_KEY: "true"}


_OBS_HANDLER = """
import os
import boto3

TABLE = os.environ["OBS_TABLE"]
RUN_ID = os.environ.get("RUN_ID", "run")

ddb = boto3.client("dynamodb")


def handler(event, context):
    records = event.get("Records", [])
    for r in records:
        keys = r.get("dynamodb", {}).get("Keys", {})
        rec_id = r.get("eventID", "")
        ddb.put_item(
            TableName=TABLE,
            Item={
                "pk": {"S": "rec-" + RUN_ID + "-" + rec_id},
                "key_id": {"S": keys.get("id", {}).get("S", "")},
            },
        )
    return {"ok": True}
"""


@tags("axis:happy-path", "cap:c2", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """A stream mapping's FilterCriteria forwards only records whose NewImage matches the pattern: id-keep reaches
    the function and id-skip, written to the same table, never does.
    """
    run_id = ctx.unique_name("run")
    stream_table, stream_arn = _create_stream_table(ctx)
    obs_table = _create_obs_table(ctx)

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
            {"Effect": "Allow", "Action": "dynamodb:PutItem", "Resource": "*"},
        ],
    )
    fn_name = ctx.unique_name("sim2real-fn-")
    _create_function(ctx, fn_name, role_arn, _OBS_HANDLER, env={"OBS_TABLE": obs_table, "RUN_ID": run_id})

    filter_pattern = json.dumps({"dynamodb": {"NewImage": {"kind": {"S": ["keep"]}}}})
    _create_esm(
        ctx,
        fn_name,
        stream_arn,
        StartingPosition="TRIM_HORIZON",
        FilterCriteria={"Filters": [{"Pattern": filter_pattern}]},
    )

    ddb = ctx.client("dynamodb")
    ddb.put_item(TableName=stream_table, Item={"id": {"S": "id-keep"}, "kind": {"S": "keep"}})
    ddb.put_item(TableName=stream_table, Item={"id": {"S": "id-skip"}, "kind": {"S": "skip"}})

    def _observed_key_ids():
        items = _scan_obs_records(ctx, obs_table, f"rec-{run_id}-")
        return {i["key_id"]["S"] for i in items if i.get("key_id", {}).get("S")}

    t0 = time.monotonic()
    observed = _poll_until(
        _observed_key_ids,
        lambda ids: "id-keep" in ids,
        timeout_s=150.0,
        interval_s=5.0,
    )
    positive_latency_s = time.monotonic() - t0
    assert "id-keep" in observed, f"expected id-keep among observed keys, got {observed!r}"
    assert "id-skip" not in observed, f"filtered-out record was delivered to Lambda anyway: {observed!r}"

    # A single snapshot taken the instant id-keep first appears cannot distinguish "filtered
    # out" from "delayed" -- hold the absence for a window calibrated off how long the positive
    # control itself took to arrive on this same wiring, and keep re-observing through it.
    window_s = min(max(3 * positive_latency_s, 15.0), 60.0)
    deadline = time.monotonic() + window_s
    while time.monotonic() < deadline:
        time.sleep(5.0)
        observed = _observed_key_ids()
        assert "id-skip" not in observed, (
            f"filtered-out record appeared {time.monotonic() - t0:.1f}s after the matching record: "
            f"{observed!r}"
        )


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
        RoleName=role_name, AssumeRolePolicyDocument=trust, Tags=_managed_tags_kv()
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="inline",
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="inline"))
    # IAM eventual consistency before Lambda can assume the new role is handled by
    # _create_function's own bounded retry on InvalidParameterValueException, not by a sleep here.
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
                Tags=_managed_tags_dict(),
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
        Tags=_managed_tags_kv(),
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
        Tags=_managed_tags_kv(),
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
