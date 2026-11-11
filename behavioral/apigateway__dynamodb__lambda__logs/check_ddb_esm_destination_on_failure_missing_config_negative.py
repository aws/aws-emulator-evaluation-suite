"""ddb-esm-destination-on-failure-missing-config-negative."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "ddb-esm-destination-on-failure-missing-config-negative"
GROUP = "permission-boundary"
SERVICES = ["apigateway", "dynamodb", "lambda", "logs"]


@tags("axis:negative-delivery", "cap:c2", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """A DynamoDB stream ESM without an OnFailure destination drops an always-failing record after
    MaximumRetryAttempts, while an identical ESM with an SQS OnFailure destination delivers its batch info."""
    ddb = ctx.client("dynamodb")
    sqs = ctx.client("sqs")

    table_neg, stream_neg = _create_stream_table(ctx, "ofneg-src")
    table_pos, stream_pos = _create_stream_table(ctx, "ofpos-src")
    results_table = _create_plain_table(ctx, "ofail-res")

    queue_name = ctx.unique_name("sim2real-ofail-dlq-")
    queue_url = sqs.create_queue(QueueName=queue_name)["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=queue_url))
    queue_arn = sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["QueueArn"])[
        "Attributes"
    ]["QueueArn"]

    role_arn = _create_lambda_role(
        ctx,
        statements=[
            {
                "Effect": "Allow",
                "Action": [
                    "dynamodb:GetRecords",
                    "dynamodb:GetShardIterator",
                    "dynamodb:DescribeStream",
                ],
                "Resource": [f"{stream_neg}*", f"{stream_pos}*"],
            },
            {"Effect": "Allow", "Action": ["dynamodb:ListStreams"], "Resource": "*"},
            {
                "Effect": "Allow",
                "Action": ["dynamodb:PutItem"],
                "Resource": f"arn:aws:dynamodb:{ctx.region}:*:table/{results_table}",
            },
            {"Effect": "Allow", "Action": ["sqs:SendMessage"], "Resource": queue_arn},
        ],
        attach_basic_logs=True,
        name_suffix="ofail-role",
    )

    code = (
        "import boto3, os\n"
        "def handler(event, context):\n"
        "    ddb = boto3.client('dynamodb')\n"
        "    for rec in event.get('Records', []):\n"
        "        img = rec.get('dynamodb', {}).get('NewImage', {})\n"
        "        if img.get('fail', {}).get('S') == 'true':\n"
        "            raise ValueError('deliberate-failure')\n"
        "        rid = img.get('id', {}).get('S', context.aws_request_id)\n"
        "        ddb.put_item(TableName=os.environ['RESULTS_TABLE'], Item={'id': {'S': rid}})\n"
        "    return {'batchItemFailures': []}\n"
    )
    fn_name, _ = _create_lambda_function(
        ctx, role_arn, code, name_suffix="ofail-fn", env={"RESULTS_TABLE": results_table}
    )

    _wire_event_source(
        ctx,
        fn_name,
        stream_neg,
        batch_size=1,
        starting_position="TRIM_HORIZON",
        extra_config={"MaximumRetryAttempts": 0},
    )
    _wire_event_source(
        ctx,
        fn_name,
        stream_pos,
        batch_size=1,
        starting_position="TRIM_HORIZON",
        extra_config={
            "MaximumRetryAttempts": 0,
            "DestinationConfig": {"OnFailure": {"Destination": queue_arn}},
        },
    )

    # negative side: one record that always fails, then one that always succeeds
    ddb.put_item(TableName=table_neg, Item={"id": {"S": "negA"}, "fail": {"S": "true"}})
    ddb.put_item(TableName=table_neg, Item={"id": {"S": "negB"}, "fail": {"S": "false"}})

    def scan_results():
        return {it["id"]["S"] for it in ddb.scan(TableName=results_table)["Items"]}

    # Effect present: the ESM moved past the exhausted, always-failing record and
    # continued delivering later records instead of stalling the shard.
    ids = _wait_for_effect(
        scan_results,
        lambda ids: "negB" in ids,
        timeout_s=150.0,
        interval_s=5.0,
        description="record after the always-failing one was still processed",
    )
    # Effect absent: the always-failing record's own side effect never landed, and (since
    # no destination was configured) it is nowhere else either.
    assert "negA" not in ids, "an always-failing record's side effect was observed despite the handler raising"

    # positive control: same failure, but this mapping HAS an OnFailure destination
    ddb.put_item(TableName=table_pos, Item={"id": {"S": "posA"}, "fail": {"S": "true"}})

    def receive_dlq_message():
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=1, WaitTimeSeconds=5)
        return resp.get("Messages", [])

    messages = _wait_for_effect(
        receive_dlq_message,
        lambda msgs: len(msgs) > 0,
        timeout_s=150.0,
        interval_s=5.0,
        description="OnFailure destination received the failed record's batch info",
    )
    assert len(messages) > 0, "OnFailure destination queue received no message for the always-failing record"
    body = json.loads(messages[0]["Body"])
    assert "DDBStreamBatchInfo" in body, f"unexpected OnFailure destination payload: {body}"



def _poll_until(
    probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"
):
    """Poll probe() until predicate(result) is truthy; return the final result (raises on timeout)."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"{description} not met within {timeout_s}s. Last result: {last!r}"
    )


def _wait_for_effect(
    probe, predicate, timeout_s=120.0, interval_s=2.0, description="effect"
):
    """Poll for an async cross-service effect (default 120s — Kinesis/DDB-stream ESMs can need
    60-120s for cold-start + first delivery; fast effects return as soon as the predicate holds)."""
    return _poll_until(
        probe,
        predicate,
        timeout_s=timeout_s,
        interval_s=interval_s,
        description=description,
    )


def _wire_event_source(
    ctx,
    function_name,
    source_arn,
    batch_size=10,
    starting_position=None,
    extra_config=None,
) -> str:
    """Create an event-source mapping (SQS/DynamoDB Streams/Kinesis/...) and wait until Enabled
    (registers delete_event_source_mapping teardown). Returns the ESM UUID."""
    lam = ctx.client("lambda")
    params: dict[str, Any] = {
        "FunctionName": function_name,
        "EventSourceArn": source_arn,
        "BatchSize": batch_size,
        "Enabled": True,
    }
    if starting_position:
        params["StartingPosition"] = starting_position
    elif any(
        s in source_arn
        for s in [":stream/", "/stream/", ":kinesis:", ":kafka:", ":documentdb:"]
    ):
        params["StartingPosition"] = "LATEST"
    if extra_config:
        params.update(extra_config)
    esm_uuid = lam.create_event_source_mapping(**params)["UUID"]
    ctx.on_cleanup(lambda: lam.delete_event_source_mapping(UUID=esm_uuid))
    _poll_until(
        lambda: lam.get_event_source_mapping(UUID=esm_uuid).get("State"),
        lambda s: s == "Enabled",
        timeout_s=90,
        interval_s=3.0,
        description=f"ESM {esm_uuid} Enabled",
    )
    return esm_uuid


def _create_stream_table(ctx, name_suffix, view_type="NEW_IMAGE"):
    ddb = ctx.client("dynamodb")
    table_name = ctx.unique_name(f"sim2real-{name_suffix}-")
    ddb.create_table(
        TableName=table_name,
        KeySchema=[{"AttributeName": "id", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "id", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        StreamSpecification={"StreamEnabled": True, "StreamViewType": view_type},
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table_name))
    desc = _poll_until(
        lambda: ddb.describe_table(TableName=table_name)["Table"],
        lambda t: t["TableStatus"] == "ACTIVE" and t.get("LatestStreamArn"),
        timeout_s=60,
        interval_s=2.0,
        description=f"table {table_name} ACTIVE with stream",
    )
    return table_name, desc["LatestStreamArn"]


def _create_plain_table(ctx, name_suffix):
    ddb = ctx.client("dynamodb")
    table_name = ctx.unique_name(f"sim2real-{name_suffix}-")
    ddb.create_table(
        TableName=table_name,
        KeySchema=[{"AttributeName": "id", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "id", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table_name))
    _poll_until(
        lambda: ddb.describe_table(TableName=table_name)["Table"]["TableStatus"],
        lambda s: s == "ACTIVE",
        timeout_s=60,
        interval_s=2.0,
        description=f"table {table_name} ACTIVE",
    )
    return table_name


def _create_lambda_role(ctx, statements, attach_basic_logs, name_suffix):
    iam = ctx.client("iam")
    role_name = ctx.unique_name(f"sim2real-{name_suffix}-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust)
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    if statements:
        policy_name = f"{role_name}-inline"
        iam.put_role_policy(
            RoleName=role_name,
            PolicyName=policy_name,
            PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
        )
        ctx.on_cleanup(
            lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
        )
    if attach_basic_logs:
        managed_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
        iam.attach_role_policy(RoleName=role_name, PolicyArn=managed_arn)
        ctx.on_cleanup(
            lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=managed_arn)
        )
    return role_arn


def _create_lambda_function(ctx, role_arn, code_str, name_suffix, env=None, timeout=30):
    lam = ctx.client("lambda")
    fn_name = ctx.unique_name(f"sim2real-{name_suffix}-")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("index.py", code_str)
    kwargs: dict[str, Any] = dict(
        FunctionName=fn_name,
        Runtime="python3.12",
        Role=role_arn,
        Handler="index.handler",
        Code={"ZipFile": buf.getvalue()},
        Timeout=timeout,
        Publish=True,
    )
    if env:
        kwargs["Environment"] = {"Variables": env}
    deadline = time.monotonic() + 60.0
    created = None
    last_err = None
    while time.monotonic() < deadline:
        try:
            ctx.on_cleanup(lambda _n=fn_name: _delete_lambda_log_group(ctx, _n))
            created = lam.create_function(**kwargs)
            break
        except Exception as exc:  # role propagation delay
            last_err = exc
            time.sleep(3)
    if created is None:
        raise AssertionError(f"create_function never succeeded: {last_err}")
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=fn_name))
    _poll_until(
        lambda: lam.get_function(FunctionName=fn_name)["Configuration"]["State"],
        lambda s: s == "Active",
        timeout_s=90,
        interval_s=3.0,
        description=f"function {fn_name} Active",
    )
    return fn_name, created["FunctionArn"]


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
