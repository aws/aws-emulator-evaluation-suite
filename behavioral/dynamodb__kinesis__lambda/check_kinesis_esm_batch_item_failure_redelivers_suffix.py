"""kinesis-esm-batch-item-failure-redelivers-suffix."""

from __future__ import annotations

import json
import textwrap
import time
import zipfile
from io import BytesIO
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "kinesis-esm-batch-item-failure-redelivers-suffix"

GROUP = "error-propagation"

SERVICES = ["dynamodb", "kinesis", "lambda"]


@tags("axis:happy-path", "cap:c2", "cap:c3", "concern:data-plane", "concern:e2e", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Kinesis mapping with ReportBatchItemFailures redelivers exactly the suffix of the failed batch from the
    reported record on, never a record before it, and every record is processed: redelivering only the item
    drops the records after it, redelivering the whole batch reprocesses the ones before it.
    """
    ddb = ctx.client("dynamodb")
    stream = _create_stream(ctx, shard_count=1)
    sink = _create_table(ctx)
    ddb.put_item(TableName=sink["name"], Item={"pk": {"S": "batches"}, "log": {"L": []}})

    fail_seq = 2
    code = """
    import base64, json, os
    import boto3
    ddb = boto3.client("dynamodb")
    SINK_TABLE = os.environ["SINK_TABLE"]
    FAIL_SEQ = int(os.environ["FAIL_SEQ"])

    def handler(event, context):
        records = event["Records"]
        seqs = [
            json.loads(base64.b64decode(r["kinesis"]["data"]).decode("utf-8"))["seq"]
            for r in records
        ]
        ddb.update_item(
            TableName=SINK_TABLE,
            Key={"pk": {"S": "batches"}},
            UpdateExpression="SET #l = list_append(#l, :v)",
            ExpressionAttributeNames={"#l": "log"},
            ExpressionAttributeValues={":v": {"L": [{"S": json.dumps(seqs)}]}},
        )
        if FAIL_SEQ in seqs:
            # An atomic counter makes the poison pill fail exactly ONCE, so the retry is
            # guaranteed to succeed and the check terminates instead of looping forever.
            bumped = ddb.update_item(
                TableName=SINK_TABLE,
                Key={"pk": {"S": "failures"}},
                UpdateExpression="SET n = if_not_exists(n, :z) + :o",
                ExpressionAttributeValues={":z": {"N": "0"}, ":o": {"N": "1"}},
                ReturnValues="UPDATED_NEW",
            )
            if int(bumped["Attributes"]["n"]["N"]) == 1:
                idx = seqs.index(FAIL_SEQ)
                return {
                    "batchItemFailures": [
                        {"itemIdentifier": records[idx]["kinesis"]["sequenceNumber"]}
                    ]
                }
        return {"batchItemFailures": []}
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
        env={"SINK_TABLE": sink["name"], "FAIL_SEQ": str(fail_seq)},
    )

    _put_ordered_records(
        ctx, stream["name"], "one-partition-key", [{"seq": i} for i in range(5)]
    )
    _wire_stream_esm(
        ctx,
        fn["name"],
        stream["arn"],
        BatchSize=10,
        MaximumBatchingWindowInSeconds=0,
        FunctionResponseTypes=["ReportBatchItemFailures"],
        MaximumRetryAttempts=3,
    )

    def _batches():
        item = ddb.get_item(TableName=sink["name"], Key={"pk": {"S": "batches"}}).get(
            "Item"
        )
        return [json.loads(e["S"]) for e in item["log"]["L"]] if item else []

    def _saw_retry(batches):
        for i, batch in enumerate(batches):
            if fail_seq in batch and i + 1 < len(batches):
                return True
        return False

    # 240s: stream-ESM activation + cold start + the first delivery + the retry delivery, which
    # only starts after the failed batch's invocation completes. Two serialized deliveries.
    batches = _wait_for_effect(
        _batches,
        _saw_retry,
        timeout_s=240,
        interval_s=5.0,
        description="a redelivery after the batch containing the reported failure",
    )

    fail_idx = next(i for i, b in enumerate(batches) if fail_seq in b)
    fail_batch = batches[fail_idx]
    pos = fail_batch.index(fail_seq)
    expected_retry = fail_batch[pos:]
    retry_batch = batches[fail_idx + 1]

    # THE invariant: the redelivered batch is exactly the suffix from the reported item onward.
    assert retry_batch == expected_retry, (
        f"ReportBatchItemFailures must redeliver the suffix starting at the reported item.\n"
        f"failed batch      {fail_batch}\nreported item seq {fail_seq} (index {pos})\n"
        f"expected retry    {expected_retry}\nactual retry      {retry_batch}\n"
        f"all batches       {batches}"
    )
    # Distinguishes suffix semantics from whole-batch retry: nothing before the reported item is
    # ever re-processed.
    already_checkpointed = {s for b in batches[:fail_idx] for s in b} | set(
        fail_batch[:pos]
    )
    redelivered_later = {s for b in batches[fail_idx + 1 :] for s in b}
    assert not (already_checkpointed & redelivered_later), (
        f"records checkpointed before the reported failure were redelivered "
        f"{sorted(already_checkpointed & redelivered_later)}; that is whole-batch retry, "
        f"not ReportBatchItemFailures. batches={batches}"
    )
    # And the pipeline must still drain: every record is processed at least once.
    assert {s for b in batches for s in b} == set(range(5)), (
        f"not every record reached the consumer: batches={batches}"
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
    Registers the function's teardown (LIFO-before its role, as the role was registered first)."""
    name = _xname(ctx, "fn")
    lam = ctx.client("lambda")
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
            # The function creates /aws/lambda/<name> on its first invoke and that log group
            # outlives the function, so it is deleted too.
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


def _wire_stream_esm(ctx, fn_name: str, source_arn: str, **extra) -> str:
    """Create a stream-source ESM reading from TRIM_HORIZON, without waiting for Enabled.

    The records are written before the mapping, so one downstream wait covers activation and delivery.
    """
    lam = ctx.client("lambda")
    params: dict[str, Any] = {
        "FunctionName": fn_name,
        "EventSourceArn": source_arn,
        "Enabled": True,
        "StartingPosition": "TRIM_HORIZON",
    }
    params.update(extra)
    resp = lam.create_event_source_mapping(**params)
    ctx.on_cleanup(lambda: lam.delete_event_source_mapping(UUID=resp["UUID"]))
    return resp["UUID"]


def _create_stream(ctx, shard_count: int = 1) -> dict[str, Any]:
    """Create a Kinesis data stream, wait for ACTIVE, register delete_stream (shards bill, so the
    teardown is registered before the ACTIVE wait). Returns {name,arn,shard_count}.
    """
    kinesis = ctx.client("kinesis")
    name = _xname(ctx, "kin")
    kinesis.create_stream(StreamName=name, ShardCount=shard_count)
    ctx.on_cleanup(
        lambda: kinesis.delete_stream(StreamName=name, EnforceConsumerDeletion=True)
    )
    desc = _wait_for_effect(
        lambda: kinesis.describe_stream(StreamName=name)["StreamDescription"],
        lambda d: d.get("StreamStatus") == "ACTIVE",
        timeout_s=120,
        description=f"Kinesis stream {name} ACTIVE",
    )
    return {"name": name, "arn": desc["StreamARN"], "shard_count": shard_count}


def _put_ordered_records(ctx, stream_name, partition_key, payloads) -> list[str]:
    """Sequential PutRecord calls chained through SequenceNumberForOrdering; returns the
    sequence numbers in the order written.

    PutRecords (the batch op) explicitly does NOT guarantee record order, so a batch put can
    never be the source of an ordering assertion. Chaining SequenceNumberForOrdering across
    sequential PutRecord calls on ONE partition key is the documented way to pin strict order
    within a shard, which is exactly the guarantee under test.
    """
    kinesis = ctx.client("kinesis")
    seqs: list[str] = []
    prev = None
    for payload in payloads:
        kwargs: dict[str, Any] = {
            "StreamName": stream_name,
            "PartitionKey": partition_key,
            "Data": json.dumps(payload).encode(),
        }
        if prev is not None:
            kwargs["SequenceNumberForOrdering"] = prev
        prev = kinesis.put_record(**kwargs)["SequenceNumber"]
        seqs.append(prev)
    return seqs


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
