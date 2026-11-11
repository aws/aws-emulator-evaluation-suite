"""check-kinesis-batch-window-aggregation."""

from __future__ import annotations

import json
import textwrap
import time
import zipfile
from io import BytesIO
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "check-kinesis-batch-window-aggregation"

GROUP = "event-propagation"

SERVICES = ["dynamodb", "kinesis", "lambda"]


def _create_stream(ctx, shard_count: int = 1) -> dict:
    """Create a Kinesis data stream, wait for ACTIVE, and register cleanup.

    Returns {"name", "arn", "shard_count"}, matching the shape of
    _create_table().
    """
    kinesis = ctx.client("kinesis")
    name = ctx.unique_name("kin-")
    kinesis.create_stream(StreamName=name, ShardCount=shard_count)
    ctx.on_cleanup(
        lambda: kinesis.delete_stream(StreamName=name, EnforceConsumerDeletion=True)
    )
    desc = _wait_for_effect(
        lambda: kinesis.describe_stream(StreamName=name)["StreamDescription"],
        lambda d: d.get("StreamStatus") == "ACTIVE",
        timeout_s=120,
    )
    return {"name": name, "arn": desc["StreamARN"], "shard_count": shard_count}


# timing:real-time — buffer: 5 s https://docs.aws.amazon.com/lambda/latest/dg/invocation-eventsourcemapping.html#invocation-eventsourcemapping-batching
@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "concern:eventing", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """Kinesis ESM batch window aggregates multiple records into a single Lambda invocation."""
    ddb = ctx.client("dynamodb")
    kinesis = ctx.client("kinesis")
    lambda_client = ctx.client("lambda")
    stream = _create_stream(ctx, shard_count=1)
    sink = _create_table(ctx)
    ddb.put_item(
        TableName=sink["name"], Item={"pk": {"S": "batch-check"}, "sizes": {"L": []}}
    )

    # Each invocation APPENDS its own batch size instead of overwriting the item, so the
    # sink is a record of every invocation's size, not just the last one — a target that
    # (incorrectly) invokes once per record still leaves a trace, and the assertions below
    # can tell that trace apart from real aggregation.
    code = """
import boto3, os
ddb = boto3.client("dynamodb")
SINK_TABLE = os.environ["SINK_TABLE"]

def handler(event, context):
    n = len(event.get("Records", []))
    ddb.update_item(
        TableName=SINK_TABLE,
        Key={"pk": {"S": "batch-check"}},
        UpdateExpression="SET sizes = list_append(sizes, :v)",
        ExpressionAttributeValues={":v": {"L": [{"N": str(n)}]}},
    )
    return {"ok": True}
"""
    fn = _create_lambda(
        ctx,
        code,
        permissions=[
            {
                "Action": [
                    "kinesis:GetRecords",
                    "kinesis:GetShardIterator",
                    "kinesis:DescribeStream",
                    "kinesis:ListShards",
                ],
                "Resource": stream["arn"],
            },
            {"Action": ["dynamodb:UpdateItem"], "Resource": sink["arn"]},
        ],
        env={"SINK_TABLE": sink["name"]},
    )

    resp = lambda_client.create_event_source_mapping(
        EventSourceArn=stream["arn"],
        FunctionName=fn["name"],
        StartingPosition="TRIM_HORIZON",
        BatchSize=10,
        MaximumBatchingWindowInSeconds=5,
    )
    uuid = resp["UUID"]
    ctx.on_cleanup(lambda: lambda_client.delete_event_source_mapping(UUID=uuid))

    _wait_for_effect(
        lambda: lambda_client.get_event_source_mapping(UUID=uuid)["State"],
        lambda s: s == "Enabled",
        timeout_s=120,
    )

    num_records = 5
    for i in range(num_records):
        kinesis.put_record(
            StreamName=stream["name"], Data=f"rec-{i}".encode(), PartitionKey="pk1"
        )

    def probe() -> list[int]:
        item = ddb.get_item(
            TableName=sink["name"], Key={"pk": {"S": "batch-check"}}
        ).get("Item")
        return [int(v["N"]) for v in item["sizes"]["L"]] if item else []

    sizes = _wait_for_effect(
        probe, lambda s: sum(s) >= num_records, timeout_s=150, description="all records delivered"
    )
    total = sum(sizes)
    assert total == num_records, (
        f"expected exactly {num_records} records delivered across all invocations, "
        f"got {total} (per-invocation batch sizes: {sizes})"
    )
    assert max(sizes) > 1, (
        f"MaximumBatchingWindowInSeconds=5 should have aggregated multiple records into a "
        f"single invocation, but the largest observed batch had only {max(sizes)} record(s) "
        f"across invocations {sizes}"
    )


_XSVC_PREFIX = "sim2real-xsvc-"

_MANAGED_TAG_KEY = "sim2real:managed"


def _xsvc_resource_tags() -> dict[str, str]:
    return {_MANAGED_TAG_KEY: "true", "sim2real:prefix": _XSVC_PREFIX.rstrip("-")}


def _xsvc_tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _xsvc_resource_tags().items()]


def _xname(ctx: Any, kind: str) -> str:
    """A unique, prefix-tagged resource name: sim2real-xsvc-<kind>-<uuid>."""
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


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


def _create_role(
    ctx, trust_service, inline_policy=None, managed_policies=None
) -> dict[str, str]:
    """Create an IAM role and register its (policy-detach-then-delete) teardown. Returns {name,arn}."""
    iam = ctx.client("iam")
    role_name = _xname(ctx, f"role-{trust_service.split('.')[0]}")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": trust_service},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Path="/sim2real/",
        Tags=_xsvc_tags_kv(),
    )
    ctx.on_cleanup(lambda: _delete_role(ctx, role_name))
    for policy_arn in managed_policies or []:
        iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    if inline_policy:
        iam.put_role_policy(
            RoleName=role_name,
            PolicyName="inline",
            PolicyDocument=json.dumps(inline_policy),
        )
    # IAM trust/permission propagation is absorbed by the bounded retry in
    # _create_function_with_retry (it retries "cannot be assumed" for up to 30s),
    # not by waiting here — an unconditional sleep has no deadline or failure signal.
    return {"name": role_name, "arn": resp["Role"]["Arn"]}


def _delete_role(ctx, role_name: str) -> None:
    """IAM roles need every attached + inline policy removed before deletion."""
    iam = ctx.client("iam")
    try:
        for p in iam.list_attached_role_policies(RoleName=role_name).get(
            "AttachedPolicies", []
        ):
            iam.detach_role_policy(RoleName=role_name, PolicyArn=p["PolicyArn"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        for pname in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            iam.delete_role_policy(RoleName=role_name, PolicyName=pname)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _wait_function_active(ctx, name: str, timeout_s: float = 60) -> None:
    lam = ctx.client("lambda")
    _poll_until(
        lambda: lam.get_function_configuration(FunctionName=name),
        lambda r: r.get("State") == "Active",
        timeout_s=timeout_s,
        interval_s=2.0,
        description=f"Lambda {name} active",
    )


def _create_function_with_retry(
    ctx, handler_code, role_arn, env, timeout=30, memory=128, runtime="python3.12"
) -> dict[str, str]:
    """Create a Lambda, retrying through the IAM role-propagation window, then wait until Active.
    Registers the function's teardown (LIFO-before its role, since the role was registered first)."""
    name = _xname(ctx, "fn")
    lam = ctx.client("lambda")
    # Normalize inline handler source: dedent (checks often embed indented triple-quoted code) and
    # bind to the fixed entrypoint — the Handler is "lambda_function.lambda_handler", but inline code
    # is conventionally written as `def handler(event, context)`. Without a lambda_handler symbol the
    # function fails at runtime with Runtime.HandlerNotFound before any behavior is exercised. Both are
    # no-ops for code that's already column-0 and defines lambda_handler.
    handler_code = textwrap.dedent(handler_code)
    if "def lambda_handler" not in handler_code and "def handler" in handler_code:
        handler_code = handler_code.rstrip() + "\n\nlambda_handler = handler\n"
    zip_buf = BytesIO()
    with zipfile.ZipFile(zip_buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("lambda_function.py", handler_code)
    kwargs: dict[str, Any] = {
        "FunctionName": name,
        "Runtime": runtime,
        "Role": role_arn,
        "Handler": "lambda_function.lambda_handler",
        "Code": {"ZipFile": zip_buf.getvalue()},
        "Timeout": timeout,
        "MemorySize": memory,
        "Tags": dict(_xsvc_resource_tags()),
    }
    if env:
        kwargs["Environment"] = {"Variables": env}
    deadline = time.monotonic() + 30
    last_err = None
    while time.monotonic() < deadline:
        try:
            resp = lam.create_function(**kwargs)
            ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
            # The function auto-creates /aws/lambda/<name> on first invoke; that log group outlives
            # the function, so delete it too (best-effort — on_cleanup swallows if it was never created).
            ctx.on_cleanup(
                lambda: ctx.client("logs").delete_log_group(
                    logGroupName=f"/aws/lambda/{name}"
                )
            )
            _wait_function_active(ctx, name)
            return {"name": name, "arn": resp["FunctionArn"]}
        except ClientError as e:
            if "cannot be assumed" in str(e) or "InvalidParameterValue" in str(e):
                last_err = e
                time.sleep(3)
                continue
            raise
    raise last_err or RuntimeError(f"Failed to create Lambda {name}")


def _create_lambda(
    ctx,
    handler_code,
    permissions=None,
    env=None,
    timeout=30,
    memory=128,
    runtime="python3.12",
) -> dict[str, str]:
    """Create a Lambda with an execution role scoped to `permissions` (a list of IAM statement
    fragments like [{"Action": ["sqs:SendMessage"], "Resource": queue_arn}]); logs are always
    allowed. Role + function each register their own teardown (function torn down first, LIFO).
    Returns {name,arn}."""
    statements = [
        {
            "Effect": "Allow",
            "Action": [
                "logs:CreateLogGroup",
                "logs:CreateLogStream",
                "logs:PutLogEvents",
            ],
            "Resource": "arn:aws:logs:*:*:*",
        }
    ]
    for perm in permissions or []:
        actions = (
            perm["Action"] if isinstance(perm["Action"], list) else [perm["Action"]]
        )
        resource = (
            perm["Resource"]
            if isinstance(perm["Resource"], list)
            else [perm["Resource"]]
        )
        statements.append({"Effect": "Allow", "Action": actions, "Resource": resource})
    role = _create_role(
        ctx,
        "lambda.amazonaws.com",
        inline_policy={"Version": "2012-10-17", "Statement": statements},
    )
    return _create_function_with_retry(
        ctx, handler_code, role["arn"], env or {}, timeout, memory, runtime
    )


def _create_table(
    ctx,
    key_schema=None,
    attributes=None,
    stream=False,
    stream_view_type="NEW_AND_OLD_IMAGES",
) -> dict[str, str]:
    """Create a DynamoDB table (PAY_PER_REQUEST; waits table_exists; registers delete_table).
    Returns {name,arn[,stream_arn]}."""
    name = _xname(ctx, "tbl")
    ddb = ctx.client("dynamodb")
    params: dict[str, Any] = {
        "TableName": name,
        "KeySchema": key_schema or [{"AttributeName": "pk", "KeyType": "HASH"}],
        "AttributeDefinitions": attributes
        or [{"AttributeName": "pk", "AttributeType": "S"}],
        "BillingMode": "PAY_PER_REQUEST",
        "Tags": _xsvc_tags_kv(),
    }
    if stream:
        params["StreamSpecification"] = {
            "StreamEnabled": True,
            "StreamViewType": stream_view_type,
        }
    resp = ddb.create_table(**params)
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=name))
    ddb.get_waiter("table_exists").wait(
        TableName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 30}
    )
    result = {"name": name, "arn": resp["TableDescription"]["TableArn"]}
    if stream:
        result["stream_arn"] = resp["TableDescription"].get("LatestStreamArn", "")
    return result


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
