"""ddb-esm-batch-size-one-record-per-invocation-positive."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "ddb-esm-batch-size-one-record-per-invocation-positive"
GROUP = "event-propagation"
SERVICES = ["apigateway", "dynamodb", "lambda", "logs"]


@tags("axis:happy-path", "cap:c2", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """Configuring BatchSize=1 on a DynamoDB-stream event source mapping delivers exactly
    one stream record per Lambda invocation, regardless of how many records land in the
    stream close together."""
    ddb = ctx.client("dynamodb")
    table_name, stream_arn = _create_stream_table(ctx, "batchone-src")
    results_table = _create_plain_table(ctx, "batchone-res")

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
                "Resource": f"{stream_arn}*",
            },
            {"Effect": "Allow", "Action": ["dynamodb:ListStreams"], "Resource": "*"},
            {
                "Effect": "Allow",
                "Action": ["dynamodb:PutItem"],
                "Resource": f"arn:aws:dynamodb:{ctx.region}:*:table/{results_table}",
            },
        ],
        attach_basic_logs=True,
        name_suffix="batchone-role",
    )

    code = (
        "import boto3, os\n"
        "def handler(event, context):\n"
        "    ddb = boto3.client('dynamodb')\n"
        "    n = len(event.get('Records', []))\n"
        "    ddb.put_item(\n"
        "        TableName=os.environ['RESULTS_TABLE'],\n"
        "        Item={'id': {'S': context.aws_request_id}, 'count': {'N': str(n)}},\n"
        "    )\n"
        "    return {'batchItemFailures': []}\n"
    )
    fn_name, _ = _create_lambda_function(
        ctx, role_arn, code, name_suffix="batchone-fn", env={"RESULTS_TABLE": results_table}
    )

    _wire_event_source(
        ctx,
        fn_name,
        stream_arn,
        batch_size=1,
        starting_position="TRIM_HORIZON",
    )

    for i in range(3):
        ddb.put_item(TableName=table_name, Item={"id": {"S": f"item-{i}"}})

    def scan_results():
        return ddb.scan(TableName=results_table)["Items"]

    items = _wait_for_effect(
        scan_results,
        lambda items: len(items) >= 3,
        timeout_s=150.0,
        interval_s=5.0,
        description="results table has >=3 invocation records",
    )
    assert len(items) >= 3, f"expected >=3 invocation records in results table, got {len(items)}"
    for item in items:
        assert item["count"]["N"] == "1", f"invocation processed {item['count']['N']} records, expected 1"


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
        Tags=[{"Key": "sim2real", "Value": CHECK}],
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
        Tags=[{"Key": "sim2real", "Value": CHECK}],
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
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
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
        Tags={"sim2real": CHECK},
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
