"""iam-role-trusts-events-service-for-rule-target-invocation."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "iam-role-trusts-events-service-for-rule-target-invocation"
GROUP = "permission-boundary"
SERVICES = ["cloudfront", "events"]

_LAMBDA_CODE = """
import json
import os
import boto3

def handler(event, context):
    cf = boto3.client("cloudfront")
    try:
        cf.create_invalidation(
            DistributionId="E1234567890ABC",
            InvalidationBatch={
                "Paths": {"Quantity": 1, "Items": ["/*"]},
                "CallerReference": context.aws_request_id,
            },
        )
        cf_outcome = "called"
    except Exception as exc:  # noqa: BLE001
        cf_outcome = "error:" + type(exc).__name__
    sqs = boto3.client("sqs")
    sqs.send_message(
        QueueUrl=os.environ["SIGNAL_QUEUE_URL"],
        MessageBody=json.dumps({"invoked": True, "cf_outcome": cf_outcome, "detail": event.get("detail")}),
    )
    return {"ok": True}
"""


@tags("axis:happy-path", "cap:c3", "cap:c7", "concern:data-plane", "concern:e2e", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """A target RoleArn trusting events.amazonaws.com lets EventBridge assume it and invoke the
    Lambda target, which receives the event detail unchanged; its permitted CreateInvalidation on a
    fabricated distribution fails NoSuchDistribution, not AccessDenied."""
    queue = _create_queue(ctx, "signal")
    exec_role = _create_role(
        ctx,
        "lambda.amazonaws.com",
        statements=[
            {"Effect": "Allow", "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"], "Resource": "*"},
            {"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": queue["arn"]},
            {"Effect": "Allow", "Action": "cloudfront:CreateInvalidation", "Resource": "*"},
        ],
        name_hint="exec",
    )
    fn = _create_lambda_function(ctx, exec_role["arn"], _LAMBDA_CODE, env={"SIGNAL_QUEUE_URL": queue["url"]}, name_hint="fn")

    target_role = _create_role(
        ctx,
        "events.amazonaws.com",
        statements=[{"Effect": "Allow", "Action": "lambda:InvokeFunction", "Resource": fn["arn"]}],
        name_hint="target-role",
    )

    events = ctx.client("events")
    rule_name = ctx.unique_name("sim2real-rbtrust-rule-")
    pattern = {"source": ["sim2real.rbtrust"], "detail-type": ["ping"]}
    events.put_rule(Name=rule_name, EventPattern=json.dumps(pattern), State="ENABLED")["RuleArn"]
    ctx.on_cleanup(lambda: _delete_rule(ctx, rule_name, ["1"]))

    _put_targets_with_retry(
        ctx,
        rule_name,
        [{"Id": "1", "Arn": fn["arn"], "RoleArn": target_role["arn"]}],
    )

    # A freshly-trusted role may not be assumable yet (IAM eventual consistency), so the event is
    # re-sent each round until the target reports in, to a deadline.
    messages: list[dict] = []
    deadline = time.monotonic() + _cap(ctx, 220.0)
    while not messages and time.monotonic() < deadline:
        events.put_events(
            Entries=[{"Source": "sim2real.rbtrust", "DetailType": "ping", "Detail": json.dumps({"token": "hello"})}]
        )
        messages = _drain_queue(ctx, queue["url"], timeout_s=45.0)
    assert len(messages) >= 1, "EventBridge never invoked the Lambda target via the trusted role"
    body = json.loads(messages[0]["Body"])
    assert body["invoked"] is True, f"expected the target Lambda to report invoked=True, got {body!r}"
    assert body["detail"] == {"token": "hello"}, f"expected the original event detail to reach the target unchanged, got {body['detail']!r}"
    assert body["cf_outcome"] == "error:NoSuchDistribution", (
        "expected the exec role's cloudfront:CreateInvalidation permission to reach the "
        f"service and fail only because the fabricated distribution id doesn't exist, got {body['cf_outcome']!r}"
    )


# ===== helpers =====


def _zip_code(code: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", code)
    return buf.getvalue()


def _create_role(ctx, principal: str, statements: list[dict[str, Any]] | None = None, name_hint: str = "role") -> dict[str, str]:
    iam = ctx.client("iam")
    name = ctx.unique_name(f"sim2real-{name_hint}-")
    trust = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"Service": principal}, "Action": "sts:AssumeRole"}]}
    arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(ctx, name))
    if statements:
        iam.put_role_policy(RoleName=name, PolicyName="inline", PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}))
    return {"name": name, "arn": arn}


def _delete_role(ctx, name: str) -> None:
    iam = ctx.client("iam")
    try:
        for p in iam.list_role_policies(RoleName=name).get("PolicyNames", []):
            iam.delete_role_policy(RoleName=name, PolicyName=p)
        iam.delete_role(RoleName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _cap(ctx, timeout_s: float) -> float:
    left = ctx.time_left()
    return timeout_s if left is None else min(timeout_s, left)


def _create_lambda_function(ctx, role_arn: str, code: str, env: dict[str, str] | None = None, name_hint: str = "fn") -> dict[str, str]:
    lam = ctx.client("lambda")
    name = ctx.unique_name(f"sim2real-{name_hint}-")
    zip_bytes = _zip_code(code)
    resp = None
    last_err = None
    # A just-created role is not yet assumable by Lambda (InvalidParameterValueException).
    deadline = time.monotonic() + _cap(ctx, 60.0)
    while time.monotonic() < deadline:
        try:
            ctx.on_cleanup(lambda _n=name: _delete_lambda_log_group(ctx, _n))
            resp = lam.create_function(
                FunctionName=name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="index.handler",
                Code={"ZipFile": zip_bytes},
                Timeout=30,
                Environment={"Variables": env or {}},
                Tags={"sim2real:managed": "true"},
            )
            break
        except lam.exceptions.InvalidParameterValueException as exc:
            last_err = exc
            time.sleep(2)
    if resp is None:
        raise AssertionError(f"lambda create_function never succeeded (IAM role propagation?): {last_err}")
    arn = resp["FunctionArn"]
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
    _wait_lambda_active(ctx, name)
    return {"name": name, "arn": arn}


def _wait_lambda_active(ctx, name: str, timeout_s: float = 90.0) -> None:
    lam = ctx.client("lambda")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        cfg = lam.get_function_configuration(FunctionName=name)
        if cfg["State"] == "Active":
            return
        time.sleep(2)
    raise AssertionError(f"lambda function {name} did not become Active within {timeout_s}s")


def _create_queue(ctx, name_hint: str = "q") -> dict[str, str]:
    sqs = ctx.client("sqs")
    name = ctx.unique_name(f"sim2real-{name_hint}-")
    url = sqs.create_queue(QueueName=name, tags={"sim2real:managed": "true"})["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return {"url": url, "arn": arn}


def _drain_queue(ctx, queue_url: str, timeout_s: float = 60.0) -> list[dict[str, Any]]:
    sqs = ctx.client("sqs")
    out: list[dict[str, Any]] = []
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
        for msg in resp.get("Messages", []):
            out.append(msg)
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
        if out:
            return out
    return out


def _put_targets_with_retry(ctx, rule_name: str, targets: list[dict[str, Any]], timeout_s: float = 60.0) -> None:
    events = ctx.client("events")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        resp = events.put_targets(Rule=rule_name, Targets=targets)
        if resp.get("FailedEntryCount", 0) == 0:
            return
        last = resp
        time.sleep(3)
    raise AssertionError(f"put_targets never succeeded for {rule_name}: {last}")


def _delete_rule(ctx, rule_name: str, target_ids: list[str]) -> None:
    events = ctx.client("events")
    try:
        events.remove_targets(Rule=rule_name, Ids=target_ids)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
    try:
        events.delete_rule(Name=rule_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


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
