"""lambda-role-missing-events-permission-putevents-denied."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "lambda-role-missing-events-permission-putevents-denied"
GROUP = "permission-boundary"
SERVICES = ["events", "lambda", "sns"]

_HANDLER_CODE = """
import json
import boto3

def handler(event, context):
    client = boto3.client("events")
    try:
        resp = client.put_events(Entries=[{
            "Source": event["source"],
            "DetailType": event["detail_type"],
            "Detail": json.dumps(event["detail"]),
        }])
        return {"ok": True, "failed_count": resp.get("FailedEntryCount", 0)}
    except Exception as exc:
        code = getattr(exc, "response", {}).get("Error", {}).get("Code", "Unknown")
        return {"ok": False, "error_code": code}
"""


@tags("axis:rejection", "cap:c3", "cap:c7", "concern:data-plane", "concern:e2e", "concern:eventing", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Lambda whose role lacks events:PutEvents gets AccessDeniedException and no event reaches the bus,
    while the same code with the permission puts an event that reaches the rule's queue."""
    events = ctx.client("events")
    sqs = ctx.client("sqs")
    ctx.client("lambda")

    allowed_role = _create_lambda_role(
        ctx,
        ctx.unique_name("sim2real-evperm-allow-role-"),
        extra_policy={
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "events:PutEvents", "Resource": "*"}],
        },
    )
    denied_role = _create_lambda_role(ctx, ctx.unique_name("sim2real-evperm-deny-role-"))

    allowed_fn = ctx.unique_name("sim2real-evperm-allow-fn-")
    _create_function(ctx, allowed_fn, _HANDLER_CODE, allowed_role)
    denied_fn = ctx.unique_name("sim2real-evperm-deny-fn-")
    _create_function(ctx, denied_fn, _HANDLER_CODE, denied_role)

    source_allowed = ctx.unique_name("sim2real.evperm.allowed.")
    source_denied = ctx.unique_name("sim2real.evperm.denied.")
    detail_type = "sim2real-putevents-check"

    queue_allowed = _create_bound_queue_for_rule(ctx, events, sqs, "allow", source_allowed, detail_type)
    queue_denied = _create_bound_queue_for_rule(ctx, events, sqs, "deny", source_denied, detail_type)

    marker_allowed = ctx.unique_name("sim2real-marker-allow-")
    marker_denied = ctx.unique_name("sim2real-marker-deny-")

    # No fixed wait for queue-policy propagation: _invoke_with_retry (below) and
    # _poll_for_marker_with_reinvoke already retry/re-fire across their own deadlines,
    # which absorbs the same propagation lag without a barrier that could undershoot it.
    allowed_payload = _invoke_with_retry(
        ctx,
        allowed_fn,
        {"source": source_allowed, "detail_type": detail_type, "detail": {"marker": marker_allowed}},
    )
    assert allowed_payload["ok"] is True, f"positive control failed: {allowed_payload}"
    assert allowed_payload["failed_count"] == 0, (
        f"expected failed_count 0 for the permitted role, got {allowed_payload['failed_count']}: {allowed_payload}"
    )

    denied_payload = _invoke_once(ctx, denied_fn, {
        "source": source_denied,
        "detail_type": detail_type,
        "detail": {"marker": marker_denied},
    })
    assert denied_payload["ok"] is False, (
        f"expected the role lacking events:PutEvents to fail the call, got ok=True: {denied_payload}"
    )
    assert denied_payload["error_code"] == "AccessDeniedException", (
        f"expected error_code AccessDeniedException, got {denied_payload['error_code']!r}: {denied_payload}"
    )

    # EventBridge -> SQS delivery can lag briefly right after the target/queue
    # policy was created; re-invoke the allowed function periodically while
    # polling so a transient first-delivery failure doesn't flake the check.
    allowed_body = _poll_for_marker_with_reinvoke(
        ctx,
        queue_allowed,
        marker_allowed,
        reinvoke=lambda: _invoke_once(
            ctx,
            allowed_fn,
            {"source": source_allowed, "detail_type": detail_type, "detail": {"marker": marker_allowed}},
        ),
        timeout_s=90,
    )
    assert allowed_body is not None, "permitted PutEvents call never resulted in an event on the bus"

    denied_body = _poll_for_marker(ctx, queue_denied, marker_denied, timeout_s=30)
    assert denied_body is None, "denied PutEvents call still resulted in an event reaching the bus"


_LAMBDA_ASSUME_ROLE_POLICY = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
)

_BASIC_EXEC_POLICY_ARN = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"


def _zip_code(code: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", code)
    return buf.getvalue()


def _create_lambda_role(ctx, name: str, extra_policy: dict[str, Any] | None = None) -> str:
    iam = ctx.client("iam")
    role_arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=_LAMBDA_ASSUME_ROLE_POLICY,
        Tags=[{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real:check", "Value": CHECK}],
    )["Role"]["Arn"]
    iam.attach_role_policy(RoleName=name, PolicyArn=_BASIC_EXEC_POLICY_ARN)
    if extra_policy:
        iam.put_role_policy(RoleName=name, PolicyName=f"{name}-inline", PolicyDocument=json.dumps(extra_policy))

    def _cleanup():
        try:
            iam.detach_role_policy(RoleName=name, PolicyArn=_BASIC_EXEC_POLICY_ARN)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        if extra_policy:
            try:
                iam.delete_role_policy(RoleName=name, PolicyName=f"{name}-inline")
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NoSuchEntity":
                    raise
        try:
            iam.delete_role(RoleName=name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup)
    return role_arn


def _create_function(ctx, name: str, code: str, role_arn: str, timeout: int = 30) -> str:
    lam = ctx.client("lambda")
    last_exc = None
    resp = None
    for _ in range(15):
        try:
            ctx.on_cleanup(lambda _n=name: _delete_lambda_log_group(ctx, _n))
            resp = lam.create_function(
                FunctionName=name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="index.handler",
                Code={"ZipFile": _zip_code(code)},
                Timeout=timeout,
                Publish=False,
                Tags={"sim2real:managed": "true", "sim2real:check": CHECK},
            )
            break
        except lam.exceptions.InvalidParameterValueException as exc:
            last_exc = exc
            time.sleep(2)
    if resp is None:
        raise AssertionError(f"lambda create_function never succeeded (role propagation?): {last_exc}")
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
    _wait_active(ctx, name)
    return resp["FunctionArn"]


def _wait_active(ctx, name: str, timeout_s: float = 60.0) -> None:
    lam = ctx.client("lambda")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        cfg = lam.get_function_configuration(FunctionName=name)
        if cfg["State"] == "Active":
            return
        time.sleep(2)
    raise AssertionError(f"function {name} never became Active")


def _invoke_once(ctx, function_name: str, payload: dict[str, Any]) -> dict[str, Any]:
    lam = ctx.client("lambda")
    resp = lam.invoke(FunctionName=function_name, Payload=json.dumps(payload).encode("utf-8"))
    return json.loads(resp["Payload"].read())


def _invoke_with_retry(ctx, function_name: str, payload: dict[str, Any], timeout_s: float = 60.0) -> dict[str, Any]:
    # IAM policy propagation can lag by a few seconds after attach; retry the
    # "should succeed" call until it does (or the deadline passes).
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = _invoke_once(ctx, function_name, payload)
        if last.get("ok"):
            return last
        time.sleep(5)
    return last


def _create_bound_queue_for_rule(ctx, events, sqs, tag: str, source_val: str, detail_type: str) -> str:
    queue_url = sqs.create_queue(
        QueueName=ctx.unique_name(f"sim2real-evperm-{tag}-queue-"),
        tags={"sim2real:managed": "true", "sim2real:check": CHECK},
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=queue_url))
    queue_arn = sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]

    rule_name = ctx.unique_name(f"sim2real-evperm-{tag}-rule-")
    events.put_rule(
        Name=rule_name,
        EventPattern=json.dumps({"source": [source_val], "detail-type": [detail_type]}),
        State="ENABLED",
        Tags=[{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real:check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: events.delete_rule(Name=rule_name))
    rule_arn = events.describe_rule(Name=rule_name)["Arn"]

    events.put_targets(Rule=rule_name, Targets=[{"Id": "sqs-target", "Arn": queue_arn}])
    ctx.on_cleanup(lambda: events.remove_targets(Rule=rule_name, Ids=["sqs-target"]))

    queue_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "events.amazonaws.com"},
                "Action": "sqs:SendMessage",
                "Resource": queue_arn,
                "Condition": {"ArnEquals": {"aws:SourceArn": rule_arn}},
            }
        ],
    }
    sqs.set_queue_attributes(QueueUrl=queue_url, Attributes={"Policy": json.dumps(queue_policy)})
    return queue_url


def _poll_for_marker(ctx, queue_url: str, marker: str, timeout_s: float = 60.0):
    sqs = ctx.client("sqs")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
        for msg in resp.get("Messages", []):
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            if marker in msg["Body"]:
                return msg["Body"]
    return None


def _poll_for_marker_with_reinvoke(ctx, queue_url: str, marker: str, reinvoke, timeout_s: float = 90.0):
    # Poll for the marker, and periodically re-fire the source event in case
    # the very first EventBridge -> SQS delivery attempt raced target/queue
    # policy propagation and was dropped.
    sqs = ctx.client("sqs")
    deadline = time.monotonic() + timeout_s
    next_reinvoke = time.monotonic() + 20
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
        for msg in resp.get("Messages", []):
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            if marker in msg["Body"]:
                return msg["Body"]
        if time.monotonic() >= next_reinvoke:
            try:
                reinvoke()
            except Exception:
                pass
            next_reinvoke = time.monotonic() + 20
    return None


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
