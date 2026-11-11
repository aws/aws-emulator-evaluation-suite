"""sqs-lambda-esm-partial-batch-failure-requeues."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

import botocore.exceptions

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "sqs-lambda-esm-partial-batch-failure-requeues"
GROUP = "event-source-mapping"
SERVICES = ["lambda", "sns", "sqs"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """Lambda returning batchItemFailures for specific SQS message IDs causes only those
    messages to become visible again for redelivery, while the rest of the batch is deleted
    from the source queue after a single successful processing attempt."""
    role_arn = _create_lambda_role(ctx, "pbf")
    # Real AWS requires the queue's VisibilityTimeout to be >= the function's Timeout (the ESM
    # rejects a mapping otherwise), so pin a short function Timeout and keep VisibilityTimeout
    # just above it — enough headroom for the trivial handler, still fast enough for redelivery.
    function_timeout_s = 5
    visibility_timeout_s = 8
    assert visibility_timeout_s >= function_timeout_s, (
        f"test setup invariant violated: visibility_timeout_s={visibility_timeout_s} "
        f"must be >= function_timeout_s={function_timeout_s}"
    )
    src = _create_queue(
        ctx, "src", attributes={"VisibilityTimeout": str(visibility_timeout_s)}
    )
    out = _create_queue(ctx, "out")

    handler_source = """
import boto3
import json
import os

def handler(event, context):
    sqs = boto3.client("sqs")
    out_url = os.environ["OUTPUT_QUEUE_URL"]
    failures = []
    for r in event["Records"]:
        if "FAIL_MARKER" in r["body"]:
            sqs.send_message(
                QueueUrl=out_url,
                MessageBody=json.dumps({"status": "attempt", "id": r["messageId"], "body": r["body"]}),
            )
            failures.append({"itemIdentifier": r["messageId"]})
        else:
            sqs.send_message(
                QueueUrl=out_url,
                MessageBody=json.dumps({"status": "ok", "id": r["messageId"], "body": r["body"]}),
            )
    return {"batchItemFailures": failures}
"""
    fn = _create_lambda_function(
        ctx,
        handler_source,
        "pbf",
        role_arn,
        timeout=function_timeout_s,
        env={"OUTPUT_QUEUE_URL": out["url"]},
    )
    # ReportBatchItemFailures MUST be enabled on the mapping or Lambda's batchItemFailures
    # return value is ignored entirely and every message in the batch is deleted after a
    # single successful invocation attempt, regardless of what the handler reports.
    _wire_event_source(
        ctx,
        fn["name"],
        src["arn"],
        batch_size=1,
        extra_config={"FunctionResponseTypes": ["ReportBatchItemFailures"]},
    )

    sqs = ctx.client("sqs")
    ok_body = "sqs-pbf-ok-message"
    fail_body = "sqs-pbf-FAIL_MARKER-message"
    sqs.send_message(QueueUrl=src["url"], MessageBody=ok_body)
    sqs.send_message(QueueUrl=src["url"], MessageBody=fail_body)

    accumulated: list[dict] = []

    def _accumulate() -> list[dict]:
        accumulated.extend(_drain_json(ctx, out["url"]))
        return accumulated

    # Wait until we have observed the single "ok" record plus at least two redelivery
    # attempts of the failing record (proving it, and only it, keeps getting requeued).
    events = _wait_for_effect(
        _accumulate,
        lambda evs: sum(1 for e in evs if e["status"] == "ok") >= 1
        and sum(1 for e in evs if e["status"] == "attempt") >= 2,
        timeout_s=90,
        interval_s=2.0,
        description="one success and >=2 redelivery attempts observed",
    )

    ok_events = [e for e in events if e["status"] == "ok"]
    attempt_events = [e for e in events if e["status"] == "attempt"]

    # The successful message was processed exactly once and never reappears.
    assert len(ok_events) == 1, f"expected exactly one successful delivery, got {ok_events}"
    assert ok_events[0]["body"] == ok_body, (
        f"expected ok delivery body {ok_body!r}, got {ok_events[0]['body']!r}"
    )

    # Every "attempt" event refers to the SAME failing message (stable SQS MessageId across
    # redeliveries) — proof that only the failed message is being requeued, not the whole batch.
    fail_message_id = attempt_events[0]["id"]
    assert all(e["id"] == fail_message_id for e in attempt_events), (
        f"expected every redelivery to carry the same messageId {fail_message_id!r}, got "
        f"{[e['id'] for e in attempt_events]}"
    )
    assert all(e["body"] == fail_body for e in attempt_events), (
        f"expected every redelivery body to be {fail_body!r}, got "
        f"{[e['body'] for e in attempt_events]}"
    )
    assert fail_message_id != ok_events[0]["id"], (
        f"the failing message id {fail_message_id!r} must differ from the ok message id "
        f"{ok_events[0]['id']!r}"
    )
    assert len(attempt_events) >= 2, "failing message should have been redelivered at least once"


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


def _lambda_zip(handler_source: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", handler_source)
    return buf.getvalue()


def _create_lambda_role(ctx, name_suffix: str) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name(f"sim2real-role-{name_suffix}-")
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
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "simparity-check", "Value": CHECK}],
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    basic_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    sqs_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaSQSQueueExecutionRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=basic_arn)
    ctx.on_cleanup(
        lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=basic_arn)
    )
    iam.attach_role_policy(RoleName=role_name, PolicyArn=sqs_arn)
    ctx.on_cleanup(
        lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=sqs_arn)
    )
    inline_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": ["sqs:SendMessage"], "Resource": "*"}
        ],
    }
    policy_name = f"{role_name}-inline"
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps(inline_policy),
    )
    ctx.on_cleanup(
        lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
    )
    return role_arn


def _create_lambda_function(
    ctx, handler_source: str, name_suffix: str, role_arn: str, timeout=30, env=None
) -> dict[str, str]:
    lam = ctx.client("lambda")
    fn_name = ctx.unique_name(f"sim2real-fn-{name_suffix}-")
    zip_bytes = _lambda_zip(handler_source)
    params: dict[str, Any] = dict(
        FunctionName=fn_name,
        Runtime="python3.12",
        Role=role_arn,
        Handler="index.handler",
        Code={"ZipFile": zip_bytes},
        Timeout=timeout,
        MemorySize=128,
        Publish=True,
        Tags={"simparity-check": CHECK},
    )
    if env:
        params["Environment"] = {"Variables": env}
    deadline = time.monotonic() + 60
    resp = None
    last_err = None
    while time.monotonic() < deadline:
        try:
            ctx.on_cleanup(lambda _n=fn_name: _delete_lambda_log_group(ctx, _n))
            resp = lam.create_function(**params)
            break
        except botocore.exceptions.ClientError as err:
            if err.response["Error"]["Code"] == "InvalidParameterValueException":
                last_err = err
                time.sleep(3)
                continue
            raise
    if resp is None:
        raise last_err
    fn_arn = resp["FunctionArn"]
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=fn_name))
    _poll_until(
        lambda: lam.get_function_configuration(FunctionName=fn_name).get("State"),
        lambda s: s == "Active",
        timeout_s=60,
        interval_s=2.0,
        description=f"function {fn_name} Active",
    )
    return {"name": fn_name, "arn": fn_arn}


def _create_queue(ctx, name_suffix: str, attributes=None) -> dict[str, str]:
    sqs = ctx.client("sqs")
    q_name = ctx.unique_name(f"sim2real-q-{name_suffix}-")
    params: dict[str, Any] = {"QueueName": q_name}
    if attributes:
        params["Attributes"] = attributes
    url = sqs.create_queue(**params, tags={"simparity-check": CHECK})["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])[
        "Attributes"
    ]["QueueArn"]
    return {"url": url, "arn": arn}


def _drain_json(ctx, queue_url: str, wait_s: int = 3) -> list[dict]:
    sqs = ctx.client("sqs")
    out: list[dict] = []
    resp = sqs.receive_message(
        QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=wait_s
    )
    for msg in resp.get("Messages", []):
        out.append(json.loads(msg["Body"]))
        sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
    return out


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
