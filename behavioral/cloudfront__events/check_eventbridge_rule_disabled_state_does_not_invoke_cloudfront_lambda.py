"""eventbridge-rule-disabled-state-does-not-invoke-cloudfront-lambda."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "eventbridge-rule-disabled-state-does-not-invoke-cloudfront-lambda"
GROUP = "overly-permissive"
SERVICES = ["cloudfront", "events"]

# DisableRule documents that incoming events might continue to match a disabled rule for a short period
# after the call, so matching events are fired one at a time for up to _SETTLE_CAP_S until _CONFIRM_N
# in a row stay undelivered over an absence window each.
_SETTLE_CAP_S = 300.0
_CONFIRM_N = 3

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
    except Exception:  # noqa: BLE001
        pass
    sqs = boto3.client("sqs")
    sqs.send_message(
        QueueUrl=os.environ["SIGNAL_QUEUE_URL"],
        MessageBody=json.dumps({"token": (event.get("detail") or {}).get("token")}),
    )
    return {"ok": True}
"""


@tags("axis:negative-delivery", "cap:c3", "concern:data-plane", "concern:e2e", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """Disabling an EventBridge rule stops it from invoking its CloudFront-invalidation Lambda
    target for matching events, after the ENABLED rule invoked it (in-file positive control), and
    the signal queue's message counters settle to 0."""
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

    events = ctx.client("events")
    rule_name = ctx.unique_name("sim2real-disabledrule-")
    pattern = {"source": ["sim2real.disabledrule"], "detail-type": ["ping"]}
    events.put_rule(Name=rule_name, EventPattern=json.dumps(pattern), State="ENABLED")
    ctx.on_cleanup(lambda: _delete_rule(ctx, rule_name, ["1"]))
    _add_lambda_invoke_permission(ctx, fn["name"], rule_name)
    _put_targets_with_retry(ctx, rule_name, [{"Id": "1", "Arn": fn["arn"]}])

    # Positive control: rule is ENABLED, matching event must be delivered. Its measured
    # latency L calibrates how long absence must be held below: a window shorter than the
    # positive control's own delivery time would score a correct-but-slower target as blocked.
    control_start = time.monotonic()
    events.put_events(Entries=[{"Source": "sim2real.disabledrule", "DetailType": "ping", "Detail": json.dumps({"token": "enabled-run"})}])
    enabled_messages = _drain_matching(ctx, queue["url"], "enabled-run", timeout_s=45.0)
    assert len(enabled_messages) >= 1, "the ENABLED rule never invoked its Lambda target"
    control_latency_s = time.monotonic() - control_start

    # Disable the rule, then fire a distinguishable event that must NOT reach the target.
    events.disable_rule(Name=rule_name)
    desc = _poll_until(
        lambda: events.describe_rule(Name=rule_name)["State"],
        lambda state: state == "DISABLED",
        timeout_s=30.0,
        interval_s=2.0,
    )
    assert desc == "DISABLED", f"expected rule State DISABLED after disable_rule, got {desc!r}"

    absence_window_s = max(15.0, 3.0 * control_latency_s)
    settle_deadline = time.monotonic() + _budget_s(ctx, _SETTLE_CAP_S)
    fired = 0
    streak = 0
    while streak < _CONFIRM_N:
        token = f"disabled-run-{fired}"
        fired += 1
        events.put_events(Entries=[{"Source": "sim2real.disabledrule", "DetailType": "ping", "Detail": json.dumps({"token": token})}])
        disabled_messages = _drain_matching(ctx, queue["url"], token, timeout_s=absence_window_s)
        streak = 0 if disabled_messages else streak + 1
        assert streak >= _CONFIRM_N or time.monotonic() < settle_deadline, (
            f"the DISABLED rule kept invoking its Lambda target: {_CONFIRM_N} matching events in a row "
            f"never went undelivered among {fired} fired over {_SETTLE_CAP_S}s after DisableRule"
        )

    # Second independent observable: the queue itself must show nothing pending or in-flight,
    # not merely that our own receive loop failed to see a match.
    depth = _wait_counters_zero(
        ctx, ctx.client("sqs"), queue["url"],
        ["ApproximateNumberOfMessages", "ApproximateNumberOfMessagesNotVisible"],
    )
    assert depth["ApproximateNumberOfMessages"] == "0" and depth["ApproximateNumberOfMessagesNotVisible"] == "0", (
        f"queue still reports pending/in-flight messages after the DISABLED rule fired: {depth}"
    )


def _zip_code(code: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", code)
    return buf.getvalue()


def _create_role(ctx, principal: str, statements: list[dict[str, Any]] | None = None, name_hint: str = "role") -> dict[str, str]:
    iam = ctx.client("iam")
    name = ctx.unique_name(f"sim2real-{name_hint}-")
    trust = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"Service": principal}, "Action": "sts:AssumeRole"}]}
    arn = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]
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


def _create_lambda_function(ctx, role_arn: str, code: str, env: dict[str, str] | None = None, name_hint: str = "fn") -> dict[str, str]:
    lam = ctx.client("lambda")
    name = ctx.unique_name(f"sim2real-{name_hint}-")
    zip_bytes = _zip_code(code)
    ctx.on_cleanup(lambda: _delete_lambda_log_group(ctx, name))
    # A new role is not assumable by Lambda until IAM propagates it: CreateFunction answers
    # InvalidParameterValueException until then, so it is retried every 2 s for up to 60 s.
    deadline = time.monotonic() + min(60.0, ctx.time_left() or 60.0)
    while True:
        try:
            resp = lam.create_function(
                FunctionName=name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="index.handler",
                Code={"ZipFile": zip_bytes},
                Timeout=30,
                Environment={"Variables": env or {}},
            )
            break
        except lam.exceptions.InvalidParameterValueException:
            if time.monotonic() >= deadline:
                raise
            time.sleep(2)
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


def _add_lambda_invoke_permission(ctx, function_name: str, rule_name: str) -> None:
    lam = ctx.client("lambda")
    events = ctx.client("events")
    rule_arn = events.describe_rule(Name=rule_name)["Arn"]
    lam.add_permission(
        FunctionName=function_name,
        StatementId="allow-eventbridge",
        Action="lambda:InvokeFunction",
        Principal="events.amazonaws.com",
        SourceArn=rule_arn,
    )


def _create_queue(ctx, name_hint: str = "q") -> dict[str, str]:
    sqs = ctx.client("sqs")
    name = ctx.unique_name(f"sim2real-{name_hint}-")
    url = sqs.create_queue(QueueName=name)["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return {"url": url, "arn": arn}


def _drain_matching(ctx, queue_url: str, token: str, timeout_s: float = 45.0) -> list[dict[str, Any]]:
    """Poll the queue and return only messages whose body token matches; non-matching
    (stray/earlier) messages are deleted and discarded so state doesn't leak between phases."""
    sqs = ctx.client("sqs")
    matched: list[dict[str, Any]] = []
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
        msgs = resp.get("Messages", [])
        for msg in msgs:
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            body = json.loads(msg["Body"])
            if body.get("token") == token:
                matched.append(body)
        if matched:
            return matched
    return matched


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


def _poll_until(probe, predicate, timeout_s: float = 60.0, interval_s: float = 2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    return last


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _wait_counters_zero(ctx, sqs, queue_url, names, *, cap_s=90.0, interval_s=3.0):
    """Read the queue's *names* counters until each is "0" or cap_s ends; return the last read.

    SQS documents these counters as eventually consistent: they "may not achieve consistency until
    at least 1 minute after the producers stop sending messages" (GetQueueAttributes).
    """
    start = time.monotonic()
    budget_s = _budget_s(ctx, cap_s)
    deadline = start + min(cap_s, budget_s)
    while True:
        attrs = sqs.get_queue_attributes(
            QueueUrl=queue_url, AttributeNames=list(names))["Attributes"]
        if all(attrs.get(n) == "0" for n in names):
            return attrs
        if time.monotonic() >= deadline:
            if budget_s < cap_s:
                raise TimeoutError(
                    f"the check's time budget ran out after {time.monotonic() - start:.1f}s, before "
                    f"the {cap_s}s wait for the queue counters to settle ended (last={attrs!r}); "
                    "not graded"
                )
            return attrs
        time.sleep(interval_s)


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
