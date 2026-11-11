"""iam-role-without-events-trust-rejected-as-rule-target-role."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "iam-role-without-events-trust-rejected-as-rule-target-role"
GROUP = "overly-permissive"
SERVICES = ["cloudfront", "events"]

_LAMBDA_CODE = """
import json
import os
import boto3

def handler(event, context):
    sqs = boto3.client("sqs")
    sqs.send_message(
        QueueUrl=os.environ["SIGNAL_QUEUE_URL"],
        MessageBody=json.dumps({"invoked": True, "detail": event.get("detail")}),
    )
    return {"ok": True}
"""


@tags("axis:negative-delivery", "cap:c3", "cap:c7", "concern:data-plane", "concern:e2e", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """A target RoleArn whose trust policy omits events.amazonaws.com is never assumed: the event
    goes to that target's dead-letter queue with ERROR_CODE=FAILED_TO_ASSUME_ROLE, while a sibling
    target on the same rule using a correctly-trusted role IS invoked with the event detail."""
    signal_queue = _create_queue(ctx, "signal")
    dlq = _create_queue(ctx, "dlq")

    exec_role = _create_role(
        ctx,
        "lambda.amazonaws.com",
        statements=[
            {"Effect": "Allow", "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"], "Resource": "*"},
            {"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": signal_queue["arn"]},
        ],
        name_hint="exec",
    )
    fn = _create_lambda_function(ctx, exec_role["arn"], _LAMBDA_CODE, env={"SIGNAL_QUEUE_URL": signal_queue["url"]}, name_hint="fn")

    good_role = _create_role(
        ctx,
        "events.amazonaws.com",
        statements=[{"Effect": "Allow", "Action": "lambda:InvokeFunction", "Resource": fn["arn"]}],
        name_hint="good-role",
    )
    # Trusts only lambda.amazonaws.com -- events.amazonaws.com can never sts:AssumeRole it.
    bad_role = _create_role(
        ctx,
        "lambda.amazonaws.com",
        statements=[{"Effect": "Allow", "Action": "lambda:InvokeFunction", "Resource": fn["arn"]}],
        name_hint="bad-role",
    )

    events = ctx.client("events")
    rule_name = ctx.unique_name("sim2real-notrust-rule-")
    pattern = {"source": ["sim2real.notrust"], "detail-type": ["ping"]}
    rule_arn = events.put_rule(Name=rule_name, EventPattern=json.dumps(pattern), State="ENABLED")["RuleArn"]
    ctx.on_cleanup(lambda: _delete_rule(ctx, rule_name, ["good", "bad"]))

    _allow_events_to_send_sqs(ctx, dlq["url"], dlq["arn"], rule_arn)

    _put_targets_with_retry(
        ctx,
        rule_name,
        [
            {"Id": "good", "Arn": fn["arn"], "RoleArn": good_role["arn"]},
            {"Id": "bad", "Arn": fn["arn"], "RoleArn": bad_role["arn"], "DeadLetterConfig": {"Arn": dlq["arn"]}, "RetryPolicy": {"MaximumRetryAttempts": 0}},
        ],
    )

    dlq_messages: list[dict] = []
    signal_messages: list[dict] = []
    # Freshly-created roles propagate eventually, so the event is re-sent each round until both
    # the DLQ and the trusted target report in, to a deadline.
    deadline = time.monotonic() + _cap(ctx, 400.0)
    while not (dlq_messages and signal_messages) and time.monotonic() < deadline:
        events.put_events(Entries=[{"Source": "sim2real.notrust", "DetailType": "ping", "Detail": json.dumps({"token": "hi"})}])
        if not dlq_messages:
            dlq_messages = _drain_queue(ctx, dlq["url"], timeout_s=45.0, attribute_names=["All"])
        if not signal_messages:
            signal_messages = _drain_queue(ctx, signal_queue["url"], timeout_s=45.0)

    assert len(dlq_messages) >= 1, "the un-assumable-role target never landed on its DLQ"
    error_code = dlq_messages[0]["MessageAttributes"]["ERROR_CODE"]["StringValue"]
    assert error_code == "FAILED_TO_ASSUME_ROLE", error_code

    assert len(signal_messages) >= 1, f"expected at least 1 invocation (via the trusted role), got {len(signal_messages)}"
    body = json.loads(signal_messages[0]["Body"])
    assert body["invoked"] is True and body["detail"] == {"token": "hi"}, (
        f"expected the trusted-role target's invocation payload to be preserved, got {body!r}"
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


def _allow_events_to_send_sqs(ctx, queue_url: str, queue_arn: str, rule_arn: str) -> None:
    sqs = ctx.client("sqs")
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowEventBridgeDlq",
                "Effect": "Allow",
                "Principal": {"Service": "events.amazonaws.com"},
                "Action": "sqs:SendMessage",
                "Resource": queue_arn,
                "Condition": {"ArnEquals": {"aws:SourceArn": rule_arn}},
            }
        ],
    }
    sqs.set_queue_attributes(QueueUrl=queue_url, Attributes={"Policy": json.dumps(policy)})


def _drain_queue(ctx, queue_url: str, timeout_s: float = 60.0, attribute_names: list[str] | None = None) -> list[dict[str, Any]]:
    sqs = ctx.client("sqs")
    out: list[dict[str, Any]] = []
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        kwargs: dict[str, Any] = {"QueueUrl": queue_url, "MaxNumberOfMessages": 10, "WaitTimeSeconds": 5}
        if attribute_names:
            kwargs["MessageAttributeNames"] = attribute_names
        resp = sqs.receive_message(**kwargs)
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
