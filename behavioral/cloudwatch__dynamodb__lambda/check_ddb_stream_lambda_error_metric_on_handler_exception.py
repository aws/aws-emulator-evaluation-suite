"""ddb-stream-lambda-error-metric-on-handler-exception."""
from __future__ import annotations

import io
import json
import time
import zipfile
from datetime import datetime, timedelta, timezone
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "ddb-stream-lambda-error-metric-on-handler-exception"
GROUP = "event-propagation"
SERVICES = ["cloudwatch", "dynamodb", "lambda"]


# timing:real-time — metric: 60 s https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/cloudwatch_concepts.html
@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "concern:eventing", "concern:metrics", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """A handler exception while processing DynamoDB stream records increments the
    Lambda Errors metric visible in CloudWatch."""
    since = datetime.now(timezone.utc) - timedelta(minutes=1)

    role_arn, _ = _create_lambda_role(ctx)
    table_name, stream_arn = _create_stream_table(ctx)
    code = (
        "def handler(event, context):\n"
        "    raise Exception('intentional-failure-for-behavioral-check')\n"
    )
    fn_name = _create_lambda_function(ctx, role_arn, code)
    # Bound retries so the mapping doesn't hammer the (always-failing) function forever.
    _wire_event_source(
        ctx,
        fn_name,
        stream_arn,
        batch_size=5,
        extra_config={"MaximumRetryAttempts": 1, "BisectBatchOnFunctionError": False},
    )

    ddb = ctx.client("dynamodb")
    ddb.put_item(TableName=table_name, Item={"pk": {"S": "item-0"}})

    # MaximumRetryAttempts=1: the ESM invokes once, retries once on failure, then discards the
    # batch (no destination configured) — exactly 2 failing invocations, each incrementing Errors.
    expected_errors = 2

    probe = _metric_sum_probe(ctx, fn_name, "Errors", since)
    _wait_for_effect(probe, lambda v: v >= expected_errors, timeout_s=240, interval_s=2)
    # Confirm the count has settled (the retry could still be in flight the instant it first
    # touches expected_errors) rather than asserting on the first sighting.
    total = _wait_until_stable(ctx, probe, description="Errors sum")
    assert total == expected_errors, (
        f"expected Errors=={expected_errors} (1 invocation + MaximumRetryAttempts=1 retry before "
        f"the ESM discards the batch), got {total}"
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


def _wait_until_stable(
    ctx, probe, *, settle_s=30.0, timeout_s=60.0, interval_s=2.0, description="value"
):
    """Poll probe() until its value has not changed for settle_s seconds, so a value still
    climbing from an in-flight retry is never reported early; raises at the deadline (capped by
    ctx.time_left())."""
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
        # TRIM_HORIZON avoids a race against LATEST: the ESM's internal shard-iterator
        # position may not be established the instant the mapping reports Enabled, so
        # writes made immediately after wiring could land before the poller's LATEST
        # cursor and be silently skipped. The table is freshly created and empty, so
        # TRIM_HORIZON reads everything from the (empty) start and reliably picks up
        # every record written afterward.
        params["StartingPosition"] = "TRIM_HORIZON"
    if extra_config:
        params.update(extra_config)
    params["Tags"] = {"sim2real": CHECK}
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
