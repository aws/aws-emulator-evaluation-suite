"""check-lambda-kinesis-putrecord-without-permission."""

from __future__ import annotations

import json
import textwrap
import time
import zipfile
from io import BytesIO
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "check-lambda-kinesis-putrecord-without-permission"

GROUP = "overly-permissive"

SERVICES = ["dynamodb", "kinesis", "lambda"]


def _create_stream(ctx, shard_count: int = 1) -> dict:
    """Create a Kinesis data stream, wait for ACTIVE, and register cleanup.

    Returns {"name", "arn", "shard_count"}.
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


@tags("axis:rejection", "cap:c3", "cap:c7", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A function whose role lacks kinesis:PutRecord gets AccessDeniedException and no record lands on the stream;
    after the permission is added to the same role, the same call succeeds and exactly one record lands.
    """
    stream = _create_stream(ctx, shard_count=1)
    kinesis = ctx.client("kinesis")
    iam = ctx.client("iam")

    code = """
import boto3, os
from botocore.exceptions import ClientError

kinesis = boto3.client("kinesis")
STREAM = os.environ["STREAM"]

def handler(event, context):
    try:
        resp = kinesis.put_record(
            StreamName=STREAM, Data=b"x", PartitionKey=event.get("pk", "pk1")
        )
        return {"ok": True, "sequence_number": resp["SequenceNumber"]}
    except ClientError as e:
        return {"ok": False, "code": e.response["Error"]["Code"], "error": str(e)}
"""
    role = _create_role(
        ctx,
        "lambda.amazonaws.com",
        inline_policy={
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": [
                        "logs:CreateLogGroup",
                        "logs:CreateLogStream",
                        "logs:PutLogEvents",
                    ],
                    "Resource": "arn:aws:logs:*:*:*",
                }
            ],
        },
    )
    fn = _create_function_with_retry(ctx, code, role["arn"], env={"STREAM": stream["name"]})

    denied = _invoke_lambda(ctx, fn["name"], {"pk": "denied"})
    assert denied["payload"]["ok"] is False, (
        "Lambda succeeded putting a Kinesis record without IAM permission"
    )
    assert denied["payload"]["code"] == "AccessDeniedException", (
        f"Expected AccessDeniedException, got {denied['payload']}"
    )
    assert _shard_records(kinesis, stream["name"]) == [], (
        "PutRecord denied by IAM must leave no record on the stream"
    )

    iam.put_role_policy(
        RoleName=role["name"],
        PolicyName="allow-kinesis-put-record",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "kinesis:PutRecord",
                        "Resource": stream["arn"],
                    }
                ],
            }
        ),
    )
    granted = _poll_until(
        lambda: _invoke_lambda(ctx, fn["name"], {"pk": "granted"}),
        lambda r: r["payload"]["ok"] is True,
        timeout_s=60.0,
        interval_s=5.0,
        description="identical PutRecord call succeeding once kinesis:PutRecord is granted",
    )
    assert granted["payload"]["ok"] is True, (
        f"Identical PutRecord call still denied after granting permission: {granted['payload']}"
    )

    records = _poll_until(
        lambda: _shard_records(kinesis, stream["name"]),
        lambda rs: len(rs) >= 1,
        timeout_s=30.0,
        interval_s=2.0,
        description="record visible on the stream after the granted PutRecord",
    )
    assert len(records) == 1, (
        f"Expected exactly one record on the stream after the granted call, got {len(records)}"
    )
    assert records[0].get("PartitionKey") == "granted", f"Unexpected record: {records[0]}"


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
    # IAM propagation is covered by _create_function_with_retry's bounded retry on "cannot be
    # assumed", and run() polls any later grant to a deadline.
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
    # Dedent the inline handler and alias `handler` to the fixed "lambda_function.lambda_handler"
    # entrypoint; without that symbol the function fails with Runtime.HandlerNotFound.
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


def _invoke_lambda(ctx, name: str, payload: dict | None = None) -> dict[str, Any]:
    """Invoke a Lambda synchronously; return {status_code[, error], payload|payload_raw}."""
    resp = ctx.client("lambda").invoke(
        FunctionName=name,
        InvocationType="RequestResponse",
        Payload=json.dumps(payload or {}).encode(),
    )
    body = resp["Payload"].read()
    result: dict[str, Any] = {"status_code": resp["StatusCode"]}
    if resp.get("FunctionError"):
        result["error"] = resp["FunctionError"]
    try:
        result["payload"] = json.loads(body)
    except (json.JSONDecodeError, ValueError):
        result["payload_raw"] = body.decode("utf-8", errors="replace")
    return result


def _shard_records(kinesis, stream_name: str) -> list[dict]:
    """Read every record currently on the stream's only shard via an independent GetRecords
    call — separate from the PutRecord call under test, and issued at the stream itself."""
    shard_id = kinesis.describe_stream(StreamName=stream_name)["StreamDescription"][
        "Shards"
    ][0]["ShardId"]
    iterator = kinesis.get_shard_iterator(
        StreamName=stream_name, ShardId=shard_id, ShardIteratorType="TRIM_HORIZON"
    )["ShardIterator"]
    return kinesis.get_records(ShardIterator=iterator, Limit=10)["Records"]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
