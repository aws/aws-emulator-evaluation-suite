"""ddb-stream-lambda-missing-cloudwatch-permission-negative."""
from __future__ import annotations

import io
import json
import time
import zipfile
from datetime import datetime, timedelta, timezone
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "ddb-stream-lambda-missing-cloudwatch-permission-negative"
GROUP = "permission-boundary"
SERVICES = ["cloudwatch", "dynamodb", "lambda"]

_HANDLER_CODE = (
    "import os\n"
    "import boto3\n"
    "def handler(event, context):\n"
    "    cw = boto3.client('cloudwatch')\n"
    "    try:\n"
    "        cw.put_metric_data(\n"
    "            Namespace=os.environ['METRIC_NS'],\n"
    "            MetricData=[{'MetricName': 'CustomInvoke', 'Value': 1.0, 'Unit': 'Count'}],\n"
    "        )\n"
    "    except Exception:\n"
    "        pass\n"
    "    return {'ok': True}\n"
)


# timing:real-time — metric: 60 s https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/cloudwatch_concepts.html
@tags("axis:negative-delivery", "cap:c2", "cap:c3", "cap:c4", "cap:c7", "concern:data-plane", "concern:e2e", "concern:eventing", "concern:metrics", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """A stream-triggered Lambda whose role lacks cloudwatch:PutMetricData still invokes without
    error (the handler catches AccessDenied) but its custom metric never lands, read after an
    identical permitted function's custom metric has landed."""
    since = datetime.now(timezone.utc) - timedelta(minutes=1)

    ns_ok = ctx.unique_name("sim2real-cwns-ok-")
    ns_bad = ctx.unique_name("sim2real-cwns-bad-")

    role_ok, _ = _create_lambda_role(ctx, extra_actions=["cloudwatch:PutMetricData"])
    role_bad, _ = _create_lambda_role(ctx)  # no cloudwatch:PutMetricData

    table_ok, stream_ok = _create_stream_table(ctx)
    table_bad, stream_bad = _create_stream_table(ctx)

    fn_ok = _create_lambda_function(ctx, role_ok, _HANDLER_CODE, env={"METRIC_NS": ns_ok})
    fn_bad = _create_lambda_function(ctx, role_bad, _HANDLER_CODE, env={"METRIC_NS": ns_bad})

    _wire_event_source(ctx, fn_ok, stream_ok, batch_size=5)
    _wire_event_source(ctx, fn_bad, stream_bad, batch_size=5)

    ddb = ctx.client("dynamodb")
    ddb.put_item(TableName=table_ok, Item={"pk": {"S": "item-0"}})
    ddb.put_item(TableName=table_bad, Item={"pk": {"S": "item-0"}})

    inv_probe_ok = _metric_sum_probe(ctx, fn_ok, "Invocations", since)
    inv_probe_bad = _metric_sum_probe(ctx, fn_bad, "Invocations", since)
    _wait_for_effect(inv_probe_ok, lambda v: v >= 1, timeout_s=240, interval_s=2)
    _wait_for_effect(inv_probe_bad, lambda v: v >= 1, timeout_s=240, interval_s=2)

    # The handler swallows the AccessDenied, so the invocation itself is not an "error".
    err_probe_bad = _metric_sum_probe(ctx, fn_bad, "Errors", since)
    assert err_probe_bad() == 0, "handler should have caught the AccessDenied internally"

    ok_points = _wait_for_effect(
        _custom_metric_probe(ctx, ns_ok, since),
        lambda pts: len(pts) >= 1,
        timeout_s=240,
        interval_s=2,
        description="custom metric with cloudwatch:PutMetricData permission",
    )
    assert len(ok_points) >= 1, f"expected >=1 datapoint for {ns_ok}, got {ok_points!r}"

    bad_points = _custom_metric_probe(ctx, ns_bad, since)()
    assert len(bad_points) == 0, "custom metric must never land without the permission"


# ===== helpers =====


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
        "Tags": {"sim2real-check": CHECK},
    }
    if starting_position:
        params["StartingPosition"] = starting_position
    elif any(
        s in source_arn
        for s in [":stream/", "/stream/", ":kinesis:", ":kafka:", ":documentdb:"]
    ):
        # TRIM_HORIZON avoids a race against LATEST: the ESM's internal shard-iterator
        # position may not be established the instant the mapping reports Enabled, so
        # writes made immediately after wiring could land before the poller's LATEST
        # cursor and be silently skipped. The table is freshly created and empty, so
        # TRIM_HORIZON reads everything from the (empty) start and reliably picks up
        # every record written afterward.
        params["StartingPosition"] = "TRIM_HORIZON"
    if extra_config:
        params.update(extra_config)
    esm_uuid = lam.create_event_source_mapping(**params)["UUID"]
    ctx.on_cleanup(lambda: lam.delete_event_source_mapping(UUID=esm_uuid))
    _poll_until(
        lambda: lam.get_event_source_mapping(UUID=esm_uuid).get("State"),
        lambda s: s == "Enabled",
        timeout_s=90,
        interval_s=2.0,
        description=f"ESM {esm_uuid} Enabled",
    )
    return esm_uuid


def _create_lambda_role(ctx, extra_actions=None, trust_service="lambda.amazonaws.com"):
    """Create an execution role with basic-execution + DynamoDB-streams-read permissions
    (plus any extra_actions) and register teardown. IAM propagation before the role is
    assumable is absorbed by _create_lambda_function's bounded retry, not waited on here."""
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-role-")
    trust_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": trust_service},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role_arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(trust_doc),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))

    managed_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    iam.attach_role_policy(RoleName=name, PolicyArn=managed_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=name, PolicyArn=managed_arn))

    actions = [
        "dynamodb:GetRecords",
        "dynamodb:GetShardIterator",
        "dynamodb:DescribeStream",
        "dynamodb:ListStreams",
    ]
    if extra_actions:
        actions += extra_actions
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": actions, "Resource": "*"}],
    }
    pol_name = f"{name}-inline"
    iam.put_role_policy(
        RoleName=name, PolicyName=pol_name, PolicyDocument=json.dumps(policy_doc)
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=name, PolicyName=pol_name))

    return role_arn, name


def _zip_code(code_str: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("index.py", code_str)
    return buf.getvalue()


def _create_lambda_function(ctx, role_arn, code_str, env=None, timeout=30):
    """Create a Python Lambda function from inline code, retrying while the role
    propagates, and wait for the function to reach Active state."""
    lam = ctx.client("lambda")
    name = ctx.unique_name("sim2real-fn-")
    kwargs: dict[str, Any] = dict(
        FunctionName=name,
        Runtime="python3.12",
        Role=role_arn,
        Handler="index.handler",
        Code={"ZipFile": _zip_code(code_str)},
        Timeout=timeout,
        Publish=True,
        Tags={"sim2real-check": CHECK},
    )
    if env:
        kwargs["Environment"] = {"Variables": env}

    # A new role is not assumable at once: retry the InvalidParameterValueException it causes
    # every 2 s for up to 40 s, capped by the runner's remaining time.
    ctx.on_cleanup(lambda _n=name: _delete_lambda_log_group(ctx, _n))
    left = ctx.time_left()
    deadline = time.monotonic() + (40.0 if left is None else max(1.0, min(40.0, left - 5.0)))
    while True:
        try:
            lam.create_function(**kwargs)
            break
        except lam.exceptions.InvalidParameterValueException:
            if time.monotonic() >= deadline:
                raise
            time.sleep(2)

    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
    _poll_until(
        lambda: lam.get_function_configuration(FunctionName=name).get("State"),
        lambda s: s == "Active",
        timeout_s=90,
        interval_s=2.0,
        description=f"function {name} Active",
    )
    return name


def _create_stream_table(ctx):
    """Create a DynamoDB table with a NEW_AND_OLD_IMAGES stream and wait for ACTIVE."""
    ddb = ctx.client("dynamodb")
    name = ctx.unique_name("sim2real-tbl-")
    ddb.create_table(
        TableName=name,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        StreamSpecification={"StreamEnabled": True, "StreamViewType": "NEW_AND_OLD_IMAGES"},
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=name))
    desc = _poll_until(
        lambda: ddb.describe_table(TableName=name)["Table"],
        lambda t: t.get("TableStatus") == "ACTIVE" and t.get("LatestStreamArn"),
        timeout_s=60,
        interval_s=2.0,
        description=f"table {name} ACTIVE with stream",
    )
    return name, desc["LatestStreamArn"]


def _metric_sum_probe(ctx, function_name, metric_name, since):
    cw = ctx.client("cloudwatch")

    def probe():
        resp = cw.get_metric_statistics(
            Namespace="AWS/Lambda",
            MetricName=metric_name,
            Dimensions=[{"Name": "FunctionName", "Value": function_name}],
            StartTime=since,
            EndTime=datetime.now(timezone.utc) + timedelta(minutes=2),
            Period=60,
            Statistics=["Sum"],
        )
        return sum(dp["Sum"] for dp in resp.get("Datapoints", []))

    return probe


def _custom_metric_probe(ctx, namespace, since):
    cw = ctx.client("cloudwatch")

    def probe():
        resp = cw.get_metric_statistics(
            Namespace=namespace,
            MetricName="CustomInvoke",
            StartTime=since,
            EndTime=datetime.now(timezone.utc) + timedelta(minutes=2),
            Period=60,
            Statistics=["Sum"],
        )
        return resp.get("Datapoints", [])

    return probe


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
