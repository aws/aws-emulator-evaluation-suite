"""ddb-stream-esm-destination-missing-permission-rejected."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "ddb-stream-esm-destination-missing-permission-rejected"
GROUP = "overly-permissive"
SERVICES = ["dynamodb", "events", "lambda"]

_FAILING_HANDLER = "def handler(event, context):\n    raise RuntimeError('boom')\n"


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "concern:eventing", "concern:negative-classes", "concern:representation", "dp:api", "plane:control", "plane:data")
def run(ctx) -> None:
    """A stream mapping whose role lacks sqs:SendMessage on its OnFailure queue is refused at create with
    InvalidParameterValueException and its exact message, or never delivers a failure record; the same mapping
    with the permission delivers a RetryAttemptsExhausted record carrying DDBStreamBatchInfo.streamArn.
    """
    bad_table, bad_stream_arn = _create_stream_table(ctx)
    bad_queue_url, bad_queue_arn = _create_queue(ctx)

    bad_role_arn = _create_lambda_role(
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
            # deliberately NO sqs:SendMessage here
        ],
        suffix="bad-role",
    )
    bad_fn = ctx.unique_name("sim2real-fn-bad-")
    _create_function(ctx, bad_fn, bad_role_arn, _FAILING_HANDLER)

    # Lambda may check at CreateEventSourceMapping that the role can reach the OnFailure destination
    # and refuse a role without sqs:SendMessage; either that refusal or no delivery shows the block.
    esm_rejected_upfront = False
    try:
        _create_esm(
            ctx,
            bad_fn,
            bad_stream_arn,
            BatchSize=1,
            StartingPosition="TRIM_HORIZON",
            MaximumRetryAttempts=0,
            DestinationConfig={"OnFailure": {"Destination": bad_queue_arn}},
        )
    except ClientError as e:
        assert e.response["Error"]["Code"] == "InvalidParameterValueException", e
        assert e.response["Error"].get("Message") == (
            "The function execution role does not have permissions to call SendMessage on SQS"
        ), e
        esm_rejected_upfront = True

    ddb = ctx.client("dynamodb")
    if not esm_rejected_upfront:
        ddb.put_item(TableName=bad_table, Item={"id": {"S": "trigger-bad"}})

        deadline = time.monotonic() + 60.0
        while time.monotonic() < deadline:
            body = _receive_one(ctx, bad_queue_url)
            assert body is None, f"unexpected failure-destination delivery despite missing sqs:SendMessage: {body}"
            time.sleep(4.0)

    # --- positive control: same shape, role HAS sqs:SendMessage ---
    good_table, good_stream_arn = _create_stream_table(ctx)
    good_queue_url, good_queue_arn = _create_queue(ctx)
    good_role_arn = _create_lambda_role(
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
            {"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": good_queue_arn},
        ],
        suffix="good-role",
    )
    good_fn = ctx.unique_name("sim2real-fn-good-")
    _create_function(ctx, good_fn, good_role_arn, _FAILING_HANDLER)
    _create_esm(
        ctx,
        good_fn,
        good_stream_arn,
        BatchSize=1,
        StartingPosition="TRIM_HORIZON",
        MaximumRetryAttempts=0,
        DestinationConfig={"OnFailure": {"Destination": good_queue_arn}},
    )
    ddb.put_item(TableName=good_table, Item={"id": {"S": "trigger-good"}})

    body = _poll_until(
        lambda: _receive_one(ctx, good_queue_url),
        lambda m: m is not None,
        timeout_s=120.0,
        interval_s=4.0,
    )
    record = json.loads(body)
    assert record["requestContext"]["condition"] == "RetryAttemptsExhausted", (
        f"expected condition RetryAttemptsExhausted, got {record['requestContext'].get('condition')!r}"
    )
    assert good_fn in record["requestContext"]["functionArn"], (
        f"expected functionArn to contain {good_fn!r}, got {record['requestContext'].get('functionArn')!r}"
    )
    assert "DDBStreamBatchInfo" in record, f"expected DDBStreamBatchInfo in failure record, got keys {list(record)}"
    assert record["DDBStreamBatchInfo"]["streamArn"] == good_stream_arn, (
        f"expected DDBStreamBatchInfo.streamArn == {good_stream_arn!r}, got {record['DDBStreamBatchInfo'].get('streamArn')!r}"
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


def _create_queue(ctx) -> tuple[str, str]:
    sqs = ctx.client("sqs")
    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-q-"), tags={"sim2real:managed": "true"}
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return url, arn


def _receive_one(ctx, queue_url: str):
    sqs = ctx.client("sqs")
    resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=1, WaitTimeSeconds=5)
    messages = resp.get("Messages", [])
    if not messages:
        return None
    sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=messages[0]["ReceiptHandle"])
    return messages[0]["Body"]


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
