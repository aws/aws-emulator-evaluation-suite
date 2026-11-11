"""ddb-stream-lambda-batch-size-limit-metric."""
from __future__ import annotations

import io
import json
import time
import zipfile
from datetime import datetime, timedelta, timezone
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "ddb-stream-lambda-batch-size-limit-metric"
GROUP = "event-propagation"
SERVICES = ["cloudwatch", "dynamodb", "lambda"]

_ITEM_COUNT = 20


# timing:real-time — metric: 60 s https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/cloudwatch_concepts.html
@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "concern:eventing", "concern:metrics", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """Event source mapping BatchSize controls invocation frequency: over the same burst of
    records, a BatchSize=1 mapping invokes at least once per record and a BatchSize=100 mapping
    invokes fewer times, per the AWS/Lambda Invocations metric."""
    since = datetime.now(timezone.utc) - timedelta(minutes=1)

    role_arn, _ = _create_lambda_role(ctx)
    code = "def handler(event, context):\n    return {'n': len(event.get('Records', []))}\n"

    table_small, stream_small = _create_stream_table(ctx)
    fn_small = _create_lambda_function(ctx, role_arn, code)
    _wire_event_source(ctx, fn_small, stream_small, batch_size=1)

    table_large, stream_large = _create_stream_table(ctx)
    fn_large = _create_lambda_function(ctx, role_arn, code)
    _wire_event_source(ctx, fn_large, stream_large, batch_size=100)

    _batch_put(ctx, table_small, _ITEM_COUNT)
    _batch_put(ctx, table_large, _ITEM_COUNT)

    probe_small = _metric_sum_probe(ctx, fn_small, "Invocations", since)
    probe_large = _metric_sum_probe(ctx, fn_large, "Invocations", since)

    inv_small = _wait_for_effect(
        probe_small, lambda v: v >= _ITEM_COUNT, timeout_s=240, interval_s=2
    )
    _wait_for_effect(probe_large, lambda v: v >= 1, timeout_s=240, interval_s=2)
    # The large-batch mapping's remaining (few) batches may still be draining: wait for the
    # metric to stop moving rather than reading it once.
    inv_large = _wait_until_stable(ctx, probe_large, description="large-batch invocation count")

    assert inv_small >= _ITEM_COUNT, f"expected >= {_ITEM_COUNT} invocations, got {inv_small}"
    assert inv_large < inv_small, (
        f"BatchSize=100 mapping should batch records into fewer invocations than "
        f"BatchSize=1 over the same {_ITEM_COUNT} records: large={inv_large} small={inv_small}"
    )


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


def _wait_until_stable(
    ctx, probe, *, settle_s=30.0, timeout_s=90.0, interval_s=2.0, description="value"
):
    """Poll probe() until its value has not changed for settle_s seconds (the async effect has
    stopped advancing); raises if it never settles before the deadline (capped by ctx.time_left())."""
    left = ctx.time_left()
    if left is not None:
        timeout_s = max(1.0, min(timeout_s, left - 5.0))
    deadline = time.monotonic() + timeout_s
    last = probe()
    since = time.monotonic()
    while time.monotonic() - since < settle_s:
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"{description} did not stabilize within {timeout_s}s (last={last!r})"
            )
        time.sleep(interval_s)
        current = probe()
        if current != last:
            last = current
            since = time.monotonic()
    return last


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
    (plus any extra_actions), wait for IAM propagation, and register teardown."""
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
        Tags=[{"Key": "sim2real", "Value": CHECK}],
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

    # IAM eventual consistency before the role is assumable: no sleep here — the caller
    # (_create_lambda_function) already retries create_function on
    # InvalidParameterValueException, which is how AWS itself signals "not yet propagated".
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
        Tags={"sim2real": CHECK},
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
        Tags=[{"Key": "sim2real", "Value": CHECK}],
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


def _batch_put(ctx, table_name, n):
    """Write n items to table_name in as few DynamoDB API calls as possible so the
    resulting stream records are likely to land together for the ESM to batch."""
    ddb = ctx.client("dynamodb")
    items = [{"PutRequest": {"Item": {"pk": {"S": f"item-{i}"}}}} for i in range(n)]
    for i in range(0, len(items), 25):
        chunk = items[i : i + 25]
        ddb.batch_write_item(RequestItems={table_name: chunk})


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
