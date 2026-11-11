"""list-event-source-mappings-reflects."""
from __future__ import annotations

import io
import time
import zipfile
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "list-event-source-mappings-reflects"
GROUP = "state-machine"
SERVICES = ["lambda"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx: Any) -> None:
    """An event source mapping created against a real SQS queue appears in
    ListEventSourceMappings and progresses from a transitional state to Enabled."""
    lam = ctx.client("lambda")
    sqs = ctx.client("sqs")

    role_arn = _create_sqs_role(ctx)
    name = ctx.unique_name("sim2real-esm-")
    zip_bytes = _zip_from_source("lambda_function.py", _BASIC_HANDLER)
    _create_function_with_retry(ctx, name=name, role_arn=role_arn, zip_bytes=zip_bytes)

    queue_url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-esm-q-"),
        tags={"sim2real:managed": "true"},
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=queue_url))
    queue_arn = sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]

    uuid = lam.create_event_source_mapping(EventSourceArn=queue_arn, FunctionName=name, BatchSize=5)["UUID"]

    def _cleanup_esm() -> None:
        try:
            lam.delete_event_source_mapping(UUID=uuid)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup_esm)

    mapping = _poll_until(
        lambda: _find_mapping(lam, name, uuid),
        lambda m: m is not None,
        timeout_s=30.0,
        interval_s=2.0,
    )
    assert mapping["EventSourceArn"] == queue_arn, f"expected EventSourceArn {queue_arn!r}, got {mapping['EventSourceArn']!r}"
    assert mapping["BatchSize"] == 5, f"expected BatchSize 5, got {mapping['BatchSize']!r}"
    assert mapping["State"] in ("Creating", "Enabling", "Enabled"), mapping["State"]

    settled = _poll_until(
        lambda: _find_mapping(lam, name, uuid),
        lambda m: m is not None and m["State"] in ("Enabled", "Disabled"),
        timeout_s=90.0,
        interval_s=3.0,
    )
    assert settled["State"] == "Enabled", f"expected mapping to settle Enabled, got {settled['State']!r}"

    lam.delete_event_source_mapping(UUID=uuid)
    gone = _poll_until(
        lambda: _find_mapping(lam, name, uuid),
        lambda m: m is None,
        timeout_s=60.0,
        interval_s=2.0,
    )
    assert gone is None, f"expected mapping {uuid} to disappear from ListEventSourceMappings after delete"

    get_code, get_code_msg = _error(lambda: lam.get_event_source_mapping(UUID=uuid))
    assert get_code == "ResourceNotFoundException", (
        f"expected GetEventSourceMapping on a deleted UUID to raise ResourceNotFoundException, got {get_code!r}"
    )
    assert get_code_msg == "The resource you requested does not exist.", (
        f"expected the exact 'ResourceNotFoundException' message, got {get_code_msg!r}"
    )

    delete_code, delete_code_msg = _error(lambda: lam.delete_event_source_mapping(UUID=uuid))
    assert delete_code == "ResourceNotFoundException", (
        f"expected a second DeleteEventSourceMapping on the same UUID to raise ResourceNotFoundException, got {delete_code!r}"
    )
    assert delete_code_msg == "The resource you requested does not exist.", (
        f"expected the exact 'ResourceNotFoundException' message, got {delete_code_msg!r}"
    )


def _find_mapping(lam, function_name: str, uuid: str):
    for m in lam.list_event_source_mappings(FunctionName=function_name)["EventSourceMappings"]:
        if m["UUID"] == uuid:
            return m
    return None


_BASIC_HANDLER = "def lambda_handler(event, context):\n    return {'ok': True, 'event': event}\n"


def _zip_from_source(filename: str, source: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(filename, source)
    return buf.getvalue()


def _error(fn):
    """Run *fn*, which AWS must refuse; return the refusal's (code, message)."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded with {result!r}")


def _poll_until(probe, predicate, timeout_s: float = 60.0, interval_s: float = 2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _create_sqs_role(ctx: Any) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-lambda-esm-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    import json

    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    role_arn = resp["Role"]["Arn"]
    policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaSQSQueueExecutionRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)

    def _cleanup() -> None:
        try:
            iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup)
    return role_arn


def _create_function_with_retry(
    ctx: Any,
    *,
    name: str,
    role_arn: str,
    zip_bytes: bytes,
    handler: str = "lambda_function.lambda_handler",
    runtime: str = "python3.12",
    timeout_s: float = 90.0,
) -> str:
    from botocore.exceptions import ClientError

    lam = ctx.client("lambda")
    deadline = time.monotonic() + timeout_s
    resp = None
    last_exc = None
    while time.monotonic() < deadline:
        try:
            ctx.on_cleanup(lambda _n=name: _delete_lambda_log_group(ctx, _n))
            resp = lam.create_function(
                FunctionName=name,
                Runtime=runtime,
                Role=role_arn,
                Handler=handler,
                Code={"ZipFile": zip_bytes},
                Timeout=30,
                MemorySize=128,
                Tags={"sim2real:managed": "true"},
            )
            break
        except ClientError as exc:
            last_exc = exc
            code = exc.response["Error"]["Code"]
            if code == "InvalidParameterValueException" and "role" in str(exc).lower():
                time.sleep(3)
                continue
            raise
    if resp is None:
        raise AssertionError(f"could not create function after retries: {last_exc}")
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
    cfg = _poll_until(
        lambda: lam.get_function_configuration(FunctionName=name),
        lambda c: c["State"] in ("Active", "Failed"),
        timeout_s=90.0,
        interval_s=2.0,
    )
    if cfg["State"] != "Active":
        raise AssertionError(f"function failed to activate: {cfg.get('StateReason')}")
    return resp["FunctionArn"]


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
